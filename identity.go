package solution

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/url"
	"os"
	"slices"
	"strings"

	codefly "github.com/codefly-dev/sdk-go"
)

// IdentitySource is where this workload's listening identity comes from.
//
// It is a hook, and that is the point: issuing an X.509-SVID is the platform's
// job, not this runtime's. A deployment whose identities come from a mesh CA, a
// SPIFFE workload API, a cert-manager Certificate projected into the pod, or a
// pair the local toolchain mints for a developer run differ in every detail of
// how the leaf arrives and in none of what the listener does with it. The
// default source (the platform projection named by the workload-identity
// configuration group) covers the deployed case and the local one identically,
// because both are "files at a path somebody else wrote"; a consumer whose
// platform hands out leaves another way implements this instead.
//
// A source returns a server configuration rather than a certificate so that an
// issuer with its own rotation, revocation or peer-verification rules keeps
// them: everything the handshake needs is in the value it returns.
type IdentitySource interface {
	// ServerTLSConfig is the configuration this solution's listener serves
	// with. It is called once, at boot, before the listener exists; a source
	// that rotates material does so inside the returned configuration (through
	// GetCertificate), not by being called again.
	ServerTLSConfig() (*tls.Config, error)
}

// Identity sets where the listener's workload identity comes from, replacing
// the platform projection the workload-identity configuration group names.
// Chainable.
func (s *Server) Identity(source IdentitySource) *Server {
	s.identity = source
	return s
}

// projectedIdentity is the default source: the X.509-SVID the platform projects
// for this workload, as files, and the trust anchor its peers are verified
// against.
//
// It is read through the SDK's certificate reloader, which re-reads the pair
// when the files change and keeps serving the last good pair through a
// half-written replacement. That matters more here than anywhere else in this
// runtime: workload leaves are deliberately short-lived and rotated well before
// expiry, so a process that loaded its leaf once at boot — the shape almost
// every Go server has — serves a stale leaf while a valid one sits on disk, and
// then fails every handshake, with the issuer reporting nothing wrong.
type projectedIdentity struct {
	certFile, keyFile, trustBundleFile string
}

func (p projectedIdentity) ServerTLSConfig() (*tls.Config, error) {
	// The anchor is read here only to fail the boot on an unusable one. What
	// the handshake uses is read again, per handshake, below.
	if _, err := peerAnchor(p.trustBundleFile); err != nil {
		return nil, err
	}
	// The SDK owns the floor (TLS 1.3) and the leaf's reload; this runtime owns
	// which files, which anchor, and that a peer is authenticated at all.
	config, err := codefly.ServerTLSConfig(p.certFile, p.keyFile, nil)
	if err != nil {
		return nil, fmt.Errorf("load this workload's X.509-SVID from %q/%q: %w — the listener presents it and there is no plain-HTTP listener; see %s and %s",
			p.certFile, p.keyFile, err, IdentityCertFileEnvironmentVariable, IdentityKeyFileEnvironmentVariable)
	}
	// Peer trust is resolved per handshake rather than snapshotted into
	// ClientCAs at boot.
	//
	// A pool read once is a pool that cannot shrink: removing a compromised
	// root from the projected bundle would leave it authenticating clients for
	// the life of the process, and the SDK's reloader reloads the leaf this
	// listener presents, not the anchor it judges callers by. Revocation that
	// takes effect only on a restart is revocation the operator has to
	// remember to finish.
	//
	// A bundle that has become unreadable or unusable fails the handshake
	// rather than falling back to the last good pool. The two failures are not
	// symmetric: serving a stale *leaf* refuses callers who should be let in,
	// while judging by a stale *anchor* lets in callers who should be refused.
	bundle := p.trustBundleFile
	config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		anchor, err := peerAnchor(bundle)
		if err != nil {
			return nil, err
		}
		fresh := config.Clone()
		fresh.ClientCAs = anchor
		fresh.ClientAuth = tls.RequireAndVerifyClientCert
		fresh.GetConfigForClient = nil
		return fresh, nil
	}
	config.ClientAuth = tls.RequireAndVerifyClientCert
	return config, nil
}

// peerAnchor reads the trust anchor this listener verifies its callers against.
//
// There is no "no anchor" case. A listener that verifies no peer certificate
// accepts any caller that can route to the pod, which bypasses the admission
// and exposure decisions the host makes on its own routes — so an absent anchor
// is a boot refusal naming the value, not a listener that quietly authenticates
// nobody. It was conditional once, on the grounds that the gateway presents no
// client certificate today; that is a statement about a counterpart's current
// state, and leaving a hole open for as long as the counterpart takes is the
// concession this cutover exists to stop making.
func peerAnchor(bundleFile string) (*x509.CertPool, error) {
	if bundleFile == "" {
		return nil, fmt.Errorf("no workload identity trust anchor resolved: this listener requires and verifies a caller's certificate, so it cannot start without the anchor those certificates are issued under. Set %s, or have the platform provision %s/%s",
			IdentityTrustBundleFileEnvironmentVariable, WorkloadIdentityGroup, WorkloadIdentityTrustBundleFileKey)
	}
	pem, err := os.ReadFile(bundleFile)
	if err != nil {
		return nil, fmt.Errorf("read workload identity trust anchor %q: %w — it is what this listener verifies its callers against, so an unreadable one refuses the handshake rather than admitting everyone",
			bundleFile, err)
	}
	anchor := x509.NewCertPool()
	if !anchor.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("workload identity trust anchor %q contains no certificate: the listener would otherwise verify no peer at all", bundleFile)
	}
	return anchor, nil
}

// listen binds this solution's port and wraps it in the workload's identity.
//
// There is no plain-HTTP path. The host refuses a plain-HTTP destination, so a
// listener without an identity would be a solution that boots, looks healthy,
// and is refused at the edge for a reason only the edge can see — which is the
// failure the whole delivered-presence model exists to end. A configuration
// that cannot produce an identity is refused here, naming the material that is
// missing.
func (s *Server) listen() (net.Listener, error) {
	config, err := s.serverIdentity()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", ":"+s.cfg.port)
	if err != nil {
		return nil, err
	}
	return tls.NewListener(ln, config), nil
}

// serverIdentity resolves this workload's identity once and holds it to every
// posture rule, memoised so the boot and the listener are the same identity
// rather than two resolutions that could differ.
//
// It is called *before* the first outbound act, which is the ordering half of a
// real bug: the credential mint used to run before listen(), so a leaf issued
// for a neighbouring workload had already been presented to the host — along
// with this workload's projected token — by the time the principal check
// refused the listener. The check that says "this is the workload the platform
// provisioned" is worth nothing if the mint has already happened under the
// wrong one.
func (s *Server) serverIdentity() (*tls.Config, error) {
	if s.identityConfig != nil {
		return s.identityConfig, nil
	}
	source := s.identity
	if source == nil {
		source = projectedIdentity{
			certFile:        s.cfg.identityCertFile,
			keyFile:         s.cfg.identityKeyFile,
			trustBundleFile: s.cfg.trustBundleFile,
		}
	}
	config, err := source.ServerTLSConfig()
	if err != nil {
		return nil, err
	}
	if err := usableServerIdentity(config); err != nil {
		return nil, err
	}
	if err := presentsThisWorkload(config, s.principal); err != nil {
		return nil, err
	}
	admitOnly(config, parsedAllowedCallers(s.cfg.allowedCallers))
	holdPerConnectionPosture(config, s.principal, parsedAllowedCallers(s.cfg.allowedCallers))
	s.identityConfig = config
	return config, nil
}

// admitOnly decides which authenticated callers this listener actually serves.
//
// Verifying a caller's certificate against the cell's anchor answers "does this
// caller hold an identity the platform issued". It does not answer "may this
// caller call me", and in a cell those are very different sets: every workload
// in the trust domain holds such a certificate, including the modules this
// solution consumes. Without this, any of them could reach a handler or a
// passthrough route directly, bypassing the admission the host decides on its
// own routes — and because gatewayFor reads x-org-id and x-session-id as
// headers the gateway stamped from a verified bearer, such a caller could set
// them itself and have this runtime mint capabilities, under this workload's
// attestation, for an organization and session nobody authenticated. A confused
// deputy, where the deputy is the one process the issuer trusts to say which
// module is asking.
//
// So the admitted set is declared, provisioned, and refused at boot when
// absent (validateSources) — not derived from the anchor, which is exactly the
// set that is too wide. The comparison is the SPIFFE ID in the leaf's URI SAN,
// the same thing the listener's own identity is held to.
func admitOnly(config *tls.Config, allowed []string) {
	if len(allowed) == 0 {
		return
	}
	config.VerifyConnection = verifyCaller(allowed)
}

// verifyCaller is the check itself, so it can be applied to a per-connection
// configuration as well as the base one.
func verifyCaller(allowed []string) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 {
			return fmt.Errorf("refusing a caller that presented no certificate")
		}
		leaf := state.PeerCertificates[0]
		for _, uri := range leaf.URIs {
			if slices.Contains(allowed, uri.String()) {
				return nil
			}
		}
		// The refusal names what arrived, not the allowed set: a caller is not
		// told who else may call.
		return fmt.Errorf("refusing a caller whose identity %s is not one this solution admits: it holds a certificate from this cell's anchor, which is not the same as being a caller this solution serves — see %s and %s/%s",
			presentedIdentities(uriStrings(leaf.URIs)), IdentityAllowedCallersEnvironmentVariable, WorkloadIdentityGroup, WorkloadIdentityAllowedCallersKey)
	}
}

// uriStrings renders a leaf's URI SANs for a refusal.
func uriStrings(uris []*url.URL) []string {
	rendered := make([]string, 0, len(uris))
	for _, uri := range uris {
		rendered = append(rendered, uri.String())
	}
	return rendered
}

// peerAnchorOf is the pool a resolved server configuration verifies its callers
// against — the same pool this runtime verifies the *platform* against when it
// dials out, which is what makes one identity object serve both directions.
//
// A source may carry it on the configuration or resolve it per handshake (the
// projected one does the latter, so a removed root takes effect without a
// restart), so both are read here. usableServerIdentity has already refused a
// configuration that has neither.
func peerAnchorOf(config *tls.Config) (*x509.CertPool, error) {
	if config.ClientCAs != nil {
		return config.ClientCAs, nil
	}
	if config.GetConfigForClient != nil {
		answer, err := config.GetConfigForClient(&tls.ClientHelloInfo{ServerName: "localhost"})
		if err != nil {
			return nil, fmt.Errorf("resolve the trust anchor this workload verifies the platform against: %w", err)
		}
		if answer != nil && answer.ClientCAs != nil {
			return answer.ClientCAs, nil
		}
	}
	return nil, fmt.Errorf("the identity source names no trust anchor, so there is nothing to verify the platform against when this runtime dials it: an https URL alone is checked against this host's system roots, which cannot tell the platform from anything holding a public certificate")
}

// clientTLSFrom derives the configuration this runtime dials the platform with
// from the one its listener serves: the same certificate, the same anchor.
//
// The certificate is taken through the source's own callback rather than copied,
// so a rotated leaf is presented outbound as well — snapshotting it here would
// mean the listener served a fresh leaf while the mint presented an expired one,
// and the failure would name neither.
func clientTLSFrom(config *tls.Config) (*tls.Config, error) {
	anchor, err := peerAnchorOf(config)
	if err != nil {
		return nil, err
	}
	client := &tls.Config{RootCAs: anchor, MinVersion: tls.VersionTLS13}
	switch {
	case config.GetCertificate != nil:
		get := config.GetCertificate
		client.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return get(&tls.ClientHelloInfo{ServerName: "localhost"})
		}
	case len(config.Certificates) > 0:
		client.Certificates = config.Certificates
	default:
		return nil, fmt.Errorf("the identity source produces no certificate this runtime can present to the platform: it would dial the mint and the gateway as an anonymous client, which cannot be held to this installation")
	}
	return client, nil
}

// usableServerIdentity refuses a configuration this listener must not serve
// under. An IdentitySource is consumer code — a mesh CA, a SPIFFE workload API,
// a pair the local toolchain minted — and every one of them has to arrive at
// the same posture, not just the one this package writes itself.
//
// Three things are checked, and each of them was a way in:
//
//   - no certificate at all: a source that returns a bare &tls.Config{}, or one
//     whose material it silently failed to load, produces a listener that
//     completes no handshake and reports a TLS error naming nothing to every
//     caller;
//   - a floor below TLS 1.3: the default source gets its floor from the SDK, so
//     checking only the certificate left a consumer's own config free to accept
//     1.2 — the strongest guarantee in this file silently optional for exactly
//     the callers who wrote their own source;
//   - a peer it does not authenticate: see peerAnchor.
func usableServerIdentity(config *tls.Config) error {
	if config == nil {
		return fmt.Errorf("the identity source returned no TLS configuration: this listener presents this workload's X.509-SVID and there is no plain-HTTP listener to fall back to")
	}
	if config.GetCertificate == nil && config.GetConfigForClient == nil && len(config.Certificates) == 0 {
		return fmt.Errorf("the identity source returned a TLS configuration with no certificate: a handshake would be answered with none, so the listener is refused rather than started")
	}
	if config.MinVersion < tls.VersionTLS13 {
		return fmt.Errorf("the identity source returned a TLS configuration whose floor is below TLS 1.3 (MinVersion 0x%04x): set MinVersion to tls.VersionTLS13, which is what every destination in this model is held to",
			config.MinVersion)
	}
	if config.ClientAuth < tls.RequireAndVerifyClientCert {
		return fmt.Errorf("the identity source returned a TLS configuration that does not require and verify a caller's certificate (ClientAuth %v): a listener that authenticates no peer accepts anything that can route to it, bypassing the admission its host decides on its routes",
			config.ClientAuth)
	}
	// And it has to say *which* anchor a caller is verified against. This is
	// not pedantry about a field: with RequireAndVerifyClientCert and a nil
	// ClientCAs, Go verifies client certificates against the host's system
	// roots, so the listener demands a certificate and then accepts one from
	// any public CA — a posture that reads as mutual TLS in every log line and
	// admits the internet. Requiring a certificate and not saying whose is
	// strictly worse than requiring none, because it looks like the strong
	// thing.
	//
	// A source may resolve the anchor per handshake instead, which is what the
	// projected one does so that a removed root takes effect without a restart;
	// then the callback's answer is where the pool must appear, and
	// holdPerConnectionPosture checks it there.
	if config.ClientCAs == nil && config.GetConfigForClient == nil {
		return fmt.Errorf("the identity source returned a TLS configuration that requires a caller's certificate but names no trust anchor to verify it against (ClientCAs is nil): Go would fall back to this host's system roots, so the listener would accept a client certificate from any public CA. Set ClientCAs, or resolve it per handshake in GetConfigForClient")
	}
	return nil
}

// holdPerConnectionPosture holds a source's per-connection callback to the
// posture its base configuration was checked against.
//
// The checks above read the configuration a source returns *at boot*. Go hands
// each handshake to GetConfigForClient when one is set, and the configuration
// that callback returns replaces the base one for that connection — floor, peer
// requirement and certificate included. So without this, a source could conform
// at boot, pass every check in this file, and then answer each individual
// handshake with TLS 1.2, no peer authentication, or a neighbouring workload's
// leaf.
//
// That is not a theoretical shape: the projected source uses that very callback
// to re-read peer trust, so "a source with a per-connection callback" is the
// documented pattern here rather than an odd one — and a consumer following it
// is one line away from lowering the floor for every connection while the boot
// still reports a conforming listener.
//
// It is the same argument as the rest of this cutover, one layer along:
// boot-time approval is not authorization at use. A callback returning nil is
// Go's "serve the base configuration", which was already checked, so it passes
// through untouched; anything else is checked again, and a configuration below
// the posture fails that handshake rather than serving it weakened — the caller
// that happens to arrive is not what is in question, the configuration the
// listener would answer anyone with is.
func holdPerConnectionPosture(config *tls.Config, principal string, allowed []string) {
	// A source with no per-connection callback still rotates its leaf — the
	// whole reason GetCertificate exists — and the boot checked only the leaf
	// that was current then. A rotation landing a certificate for another
	// workload (the wrong Secret replaced, a mesh CA re-issuing under a changed
	// identity) would then be served for the life of the process, with the one
	// check that would have caught it having run before the file changed. So
	// the leaf is re-held to the frozen principal as it is served.
	if serve := config.GetCertificate; serve != nil {
		config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			pair, err := serve(hello)
			if err != nil {
				return nil, err
			}
			if err := pairPresentsThisWorkload(pair, principal); err != nil {
				return nil, err
			}
			return pair, nil
		}
	}
	inner := config.GetConfigForClient
	if inner == nil {
		return
	}
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		answer, err := inner(hello)
		if err != nil || answer == nil {
			return answer, err
		}
		if err := usableServerIdentity(answer); err != nil {
			return nil, fmt.Errorf("the identity source answered this handshake with a configuration below the posture its boot configuration was held to: %w", err)
		}
		// On a per-connection answer the pool is not optional: this *is* the
		// configuration the handshake runs under, so "resolved per handshake"
		// has to mean resolved, not deferred again to system roots.
		if answer.ClientCAs == nil {
			return nil, fmt.Errorf("the identity source answered this handshake with a configuration that requires a caller's certificate but names no trust anchor (ClientCAs is nil): Go would verify it against this host's system roots, accepting a client certificate from any public CA")
		}
		if err := presentsThisWorkload(answer, principal); err != nil {
			return nil, err
		}
		// Who may call is re-imposed too: a source's callback that returned a
		// configuration without it would serve that connection admitting every
		// identity in the cell.
		admitOnly(answer, allowed)
		return answer, nil
	}
}

// presentsThisWorkload refuses a listener whose leaf is not the identity this
// process froze at boot.
//
// The principal is an authority-bearing value the platform provisioned and this
// process read once; the leaf is what callers actually see. Nothing else in the
// boot compares them, so a pair projected for another workload — the wrong
// Secret mounted, a Certificate issued for a neighbouring service — would be
// served happily, and the mismatch would surface at whatever verifies the
// destination's identity, as a refusal naming neither file.
//
// The comparison is the SPIFFE ID in a URI SAN, which is what names a workload
// in this model (a presence document's expected identity is one). A leaf
// carrying none, or none that matches, is refused here.
func presentsThisWorkload(config *tls.Config, principal string) error {
	if principal == "" {
		// Nothing to hold the leaf to. openAuthority runs before listen on
		// every path, so this is a programming error rather than a
		// deployment's, and it fails rather than skipping the check.
		return fmt.Errorf("this listener has no frozen principal to hold its own certificate to: the authority-bearing values must be read before the listener is built")
	}
	leaf, err := servedLeaf(config)
	if err != nil {
		return err
	}
	return leafPresentsThisWorkload(leaf, principal)
}

// pairPresentsThisWorkload is presentsThisWorkload for one certificate rather
// than a configuration, so a leaf resolved per handshake is held to the same
// rule as the one checked at boot.
func pairPresentsThisWorkload(pair *tls.Certificate, principal string) error {
	if pair == nil || len(pair.Certificate) == 0 {
		return fmt.Errorf("the identity source produced an empty certificate chain for this handshake")
	}
	leaf := pair.Leaf
	if leaf == nil {
		parsed, err := x509.ParseCertificate(pair.Certificate[0])
		if err != nil {
			return fmt.Errorf("the certificate this handshake would be answered with cannot be parsed: %w", err)
		}
		leaf = parsed
	}
	return leafPresentsThisWorkload(leaf, principal)
}

// leafPresentsThisWorkload is the comparison itself.
func leafPresentsThisWorkload(leaf *x509.Certificate, principal string) error {
	for _, uri := range leaf.URIs {
		if uri.String() == principal {
			return nil
		}
	}
	return fmt.Errorf("the certificate this listener would present names %s, and this workload's frozen principal is %q (%s/%s): a pair projected for another workload would otherwise be served, and the mismatch would surface at whatever verifies this destination rather than here",
		presentedIdentities(uriStrings(leaf.URIs)), principal, AuthorityGroup, AuthorityPrincipalKey)
}

// presentedIdentities renders what a leaf does name, so a refusal distinguishes
// "the wrong identity" from "no identity at all".
func presentedIdentities(uris []string) string {
	if len(uris) == 0 {
		return "no URI identity at all"
	}
	return "the identities [" + strings.Join(uris, ", ") + "]"
}

// servedLeaf is the certificate a handshake would be answered with, parsed.
func servedLeaf(config *tls.Config) (*x509.Certificate, error) {
	var pair *tls.Certificate
	switch {
	case config.GetCertificate != nil:
		served, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
		if err != nil {
			return nil, fmt.Errorf("the identity source could not produce the certificate this listener would present: %w", err)
		}
		pair = served
	case len(config.Certificates) > 0:
		pair = &config.Certificates[0]
	default:
		return nil, fmt.Errorf("the identity source produces its certificate per connection (GetConfigForClient only), so the identity this listener presents cannot be checked at boot: return a configuration with GetCertificate or Certificates as well")
	}
	if pair == nil || len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("the identity source produced an empty certificate chain")
	}
	if pair.Leaf != nil {
		return pair.Leaf, nil
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("the certificate this listener would present cannot be parsed: %w", err)
	}
	return leaf, nil
}
