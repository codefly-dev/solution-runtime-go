package solution

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

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
	// The per-connection recheck is installed on the *server*, not here: see
	// watchInboundTrust. A listener that wrapped its connections would hide
	// the *tls.Conn from net/http, which decides from that concrete type alone
	// whether a connection is TLS at all — so r.TLS would be nil in every
	// handler, ALPN and HTTP/2 would not be negotiated, and the handshake
	// deadline would never be set. The recheck must not cost the listener its
	// TLS-ness to get it.
	return tls.NewListener(ln, config), nil
}

// inboundHandshakeTimeout bounds the TLS handshake and the request headers of
// an accepted connection.
//
// http.Server derives its handshake deadline from the smallest of
// ReadHeaderTimeout, ReadTimeout and WriteTimeout, so this one value bounds
// both. With all three unset, as they were, any peer that completes a TCP
// connect and then sends a partial ClientHello — or a header line at a byte a
// minute — holds a goroutine and a file descriptor indefinitely, and every
// ClientHello costs a read of the trust bundle, so the cheap half of that is
// the attacker's. Neither ReadTimeout nor WriteTimeout is set, deliberately:
// they bound the whole body, and a declared long-running stream (up to
// MaxStreamDurationLimit) is a conforming request, not a slow one.
const inboundHandshakeTimeout = 10 * time.Second

// inboundIdleTimeout bounds a keep-alive connection nobody is using. It is pool
// hygiene, not the trust bound — what bounds the trust decision is the recheck,
// because an inactivity timeout cannot bound a connection that is never
// inactive, which is the finding this runtime already answered outbound.
const inboundIdleTimeout = 30 * time.Second

// peerTrustAnchor resolves the anchor this runtime verifies its peers against,
// per call, in whichever direction.
//
// One resolution for both directions because it is one anchor: the listener
// verifies a caller against it and the client verifies the platform against it,
// which is what makes a removed root take effect on both halves at once.
func (s *Server) peerTrustAnchor(identityConfig *tls.Config) func() (*x509.CertPool, error) {
	if s.identity != nil {
		return func() (*x509.CertPool, error) {
			anchor, err := peerAnchorOf(identityConfig)
			if err != nil {
				return nil, fmt.Errorf("resolve the anchor this workload verifies its peers against, from the supplied identity source: %w", err)
			}
			return anchor, nil
		}
	}
	return func() (*x509.CertPool, error) {
		anchor, err := peerAnchor(s.cfg.trustBundleFile)
		if err != nil {
			return nil, fmt.Errorf("resolve the anchor this workload verifies its peers against: %w", err)
		}
		return anchor, nil
	}
}

// watchInboundTrust re-verifies every served connection's caller against
// current trust for as long as the connection lives, and closes it when it
// stops verifying.
//
// It is the inbound half of an argument this file already made outbound, and
// made in one direction only. Re-reading trust per *handshake* bounds nothing
// about a connection that has already had its handshake: a caller whose
// identity was removed from the admitted set, or whose issuing root was pulled
// from the bundle, kept the keep-alive connection it already had and kept being
// served on it. Inbound is where the decision is whom to *admit*, which is the
// direction where judging by something stale lets in whoever should be refused.
//
// Installed through http.Server.ConnState so the connection stays the
// *tls.Conn net/http requires it to be. StateActive is the first point at which
// there is a peer chain to re-verify — crypto/tls handshakes lazily, so at
// Accept there is nothing yet — and StateClosed/StateHijacked is where the
// watch ends.
func (s *Server) watchInboundTrust() (func(net.Conn, http.ConnState), error) {
	config, err := s.serverIdentity()
	if err != nil {
		return nil, err
	}
	trust := s.peerTrustAnchor(config)
	admitted := s.admittedCallers()
	var watching sync.Map
	return func(conn net.Conn, state http.ConnState) {
		switch state {
		case http.StateActive:
			tlsConn, ok := conn.(*tls.Conn)
			if !ok {
				return
			}
			done := make(chan struct{})
			if _, already := watching.LoadOrStore(conn, done); already {
				return
			}
			go recheckCaller(tlsConn, done, trust, admitted)
		case http.StateClosed, http.StateHijacked:
			if done, ok := watching.LoadAndDelete(conn); ok {
				close(done.(chan struct{}))
			}
		}
	}, nil
}

// recheckCaller re-verifies one established caller until the connection ends.
func recheckCaller(conn *tls.Conn, done <-chan struct{}, trust func() (*x509.CertPool, error), admitted func() ([]string, error)) {
	ticker := time.NewTicker(inboundTrustRecheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if err := callerStillAdmitted(conn.ConnectionState(), trust, admitted); err != nil {
				_ = conn.Close()
				return
			}
		}
	}
}

// inboundTrustRecheckInterval bounds how long an accepted connection may
// outlive the trust that admitted it. The outbound interval's reasoning, in the
// direction where being wrong means serving a caller who should be refused.
const inboundTrustRecheckInterval = time.Second

// callerStillAdmitted re-verifies an established caller against the current
// anchor and the current admitted set.
//
// Client auth, not server auth, and no hostname: a caller is held to the chain
// and the identity it presented, which is the same pair of questions the
// handshake answered, asked again against trust as it is now.
func callerStillAdmitted(state tls.ConnectionState, trust func() (*x509.CertPool, error), admitted func() ([]string, error)) error {
	anchor, err := trust()
	if err != nil {
		return err
	}
	if len(state.PeerCertificates) == 0 {
		return fmt.Errorf("the established connection presents no caller certificate to re-verify")
	}
	intermediates := x509.NewCertPool()
	for _, cert := range state.PeerCertificates[1:] {
		intermediates.AddCert(cert)
	}
	if _, err := state.PeerCertificates[0].Verify(x509.VerifyOptions{
		Roots:         anchor,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return fmt.Errorf("the caller this connection was authenticated against no longer verifies: %w", err)
	}
	allowed, err := admitted()
	if err != nil {
		return err
	}
	identity, err := oneURIIdentity(state, "caller")
	if err != nil {
		return err
	}
	if !slices.Contains(allowed, identity) {
		return fmt.Errorf("the established connection's caller %q is no longer one this solution admits", identity)
	}
	return nil
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
	if err := holdServedCertificate(config, s.principal); err != nil {
		return nil, err
	}
	admitOnly(config, s.admittedCallers())
	holdPerConnectionPosture(config, s.principal, s.admittedCallers())
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
func admitOnly(config *tls.Config, allowed func() ([]string, error)) {
	// Composed, not overwritten. A source may have its own VerifyConnection —
	// a mesh CA checking its own claims, a consumer enforcing something this
	// runtime knows nothing about — and assigning over it silently deleted a
	// check the source author wrote, which is the opposite of what adding a
	// check should do. Theirs runs first, since a caller their rules refuse
	// should be refused for their reason.
	theirs := config.VerifyConnection
	mine := verifyCaller(allowed)
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if theirs != nil {
			if err := theirs(state); err != nil {
				return err
			}
		}
		return mine(state)
	}
}

// verifyCaller is the check itself, so it can be applied to a per-connection
// configuration as well as the base one. The set is resolved per handshake, not
// captured: see config.resolveAllowedCallers.
func verifyCaller(allowed func() ([]string, error)) func(tls.ConnectionState) error {
	return func(state tls.ConnectionState) error {
		admitted, err := allowed()
		if err != nil {
			return err
		}
		identity, err := oneURIIdentity(state, "caller")
		if err != nil {
			return err
		}
		if slices.Contains(admitted, identity) {
			return nil
		}
		// The refusal names what arrived, not the allowed set: a caller is not
		// told who else may call.
		return fmt.Errorf("refusing a caller whose identity %q is not one this solution admits: it holds a certificate from this cell's anchor, which is not the same as being a caller this solution serves — see %s and %s/%s",
			identity, IdentityAllowedCallersFileEnvironmentVariable, WorkloadIdentityGroup, WorkloadIdentityAllowedCallersFileKey)
	}
}

// admitOnlyPlatform is admitOnly for the destinations this runtime dials: the
// mint and the gateway.
//
// Verifying the chain and the hostname answers "did this cell issue the
// certificate at this address", which every workload in the cell satisfies —
// and a workload holding a certificate valid for the gateway's hostname
// completed this handshake and was handed the projected service-account token,
// the viewer's bearer and this workload's own credential. Authentication is not
// authorisation outbound either, and outbound is the direction where being
// wrong means handing the credentials over rather than accepting a call.
//
// Composed over whatever the configuration already verifies, never assigned
// over it, for the reason admitOnly records.
func admitOnlyPlatform(config *tls.Config, expected func() ([]string, error)) {
	theirs := config.VerifyConnection
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if theirs != nil {
			if err := theirs(state); err != nil {
				return err
			}
		}
		peers, err := expected()
		if err != nil {
			return err
		}
		identity, err := oneURIIdentity(state, "platform destination")
		if err != nil {
			return err
		}
		if slices.Contains(peers, identity) {
			return nil
		}
		return fmt.Errorf("refusing to present this workload's credentials to %q: it holds a certificate from this cell's anchor for the address this runtime dialled, which is not the same as being the platform — see %s and %s/%s",
			identity, IdentityPlatformPeersFileEnvironmentVariable, WorkloadIdentityGroup, WorkloadIdentityPlatformPeersFileKey)
	}
}

// oneURIIdentity is the SPIFFE ID a verified peer presented.
//
// Exactly one URI SAN, because that is what a SPIFFE certificate has. Accepting
// "any SAN that matches" lets a leaf naming several identities be admitted on
// whichever one is convenient, and a leaf naming several is not a SPIFFE
// identity at all — the one it would be held to elsewhere is unknowable from
// here.
func oneURIIdentity(state tls.ConnectionState, side string) (string, error) {
	if len(state.PeerCertificates) == 0 {
		return "", fmt.Errorf("refusing a %s that presented no certificate", side)
	}
	leaf := state.PeerCertificates[0]
	if len(leaf.URIs) != 1 {
		return "", fmt.Errorf("refusing a %s whose certificate names %d URI identities: a SPIFFE certificate names exactly one, and a leaf naming several could be accepted on whichever happens to match",
			side, len(leaf.URIs))
	}
	return leaf.URIs[0].String(), nil
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
//
// The per-connection answer is asked FIRST, and the base pool is the fallback.
// The other order looks equivalent and is not: a *x509.CertPool on the base
// configuration is one object fixed when the source built it, so a source
// carrying a base pool *and* a callback had its anchor snapshotted at boot for
// every outbound dial, however often the callback was re-resolving it. That is
// the stale-anchor defect this file argues against, surviving in the one source
// shape the per-connection posture check tells a source to adopt — the refusal
// for a nil answer says to set ClientCAs on the base, so following the advice
// was what triggered it.
func peerAnchorOf(config *tls.Config) (*x509.CertPool, error) {
	if config.GetConfigForClient != nil {
		answer, err := config.GetConfigForClient(&tls.ClientHelloInfo{})
		if err != nil {
			return nil, fmt.Errorf("resolve the trust anchor this workload verifies the platform against: %w", err)
		}
		if answer != nil && answer.ClientCAs != nil {
			return answer.ClientCAs, nil
		}
	}
	// A nil answer is Go's "serve the base", so the base pool is this source's
	// current anchor rather than a stale one.
	if config.ClientCAs != nil {
		return config.ClientCAs, nil
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
			// An empty hello, not a synthetic name. "localhost" is a server
			// name nothing in a cell dials by, and a source keyed on it
			// answered the probe with one identity and the real handshake with
			// another; an empty ServerName is what a peer addressed by IP
			// actually sends. Whatever comes back is held to the principal by
			// holdPresentedCertificate below, at the moment it is presented.
			return get(&tls.ClientHelloInfo{})
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
	return unsubvertedPosture(config)
}

// unsubvertedPosture refuses the fields that leave every check above passing
// and the posture gone.
//
// The checks above enumerate what a conforming listener must *have*, which
// answers the wrong question on its own: a source can satisfy all of them and
// still hand back a configuration whose certificate validity is judged against
// a clock it chose, whose session secrets it writes to a file, whose key
// material comes from a reader it supplies, or whose resumption it encodes and
// decodes itself — and resumption is the sharpest of them, because a resumed
// connection does not re-present a certificate, so a source that controls
// ticket encoding controls who gets in without the rest of this file ever
// seeing a handshake.
//
// Each of these has a safe zero value that means "use Go's own", so refusing a
// non-zero one is exact rather than a guess about intent. That is also the
// limit worth stating: this is a denylist over a struct this package does not
// own, so it is complete for the fields that exist in the Go version in go.mod
// and not by construction. A field added later that lowers posture would pass
// until it is named here, which is why the per-connection answer is checked by
// the same function rather than by a copy of its reasoning.
func unsubvertedPosture(config *tls.Config) error {
	for _, field := range []struct {
		name, why string
		set       bool
	}{
		{"Time", "certificate expiry and validity are judged against this clock, so a source supplying one decides that an expired certificate is current", config.Time != nil},
		{"Rand", "the handshake's key material comes from this reader, so a source supplying one decides how guessable this connection's secrets are", config.Rand != nil},
		{"KeyLogWriter", "the session secrets of every connection are written here in the clear, which is a decryption key for the traffic this listener exists to protect", config.KeyLogWriter != nil},
		{"WrapSession", "resumption tickets are encoded by this, and a resumed connection presents no certificate, so a source encoding its own tickets admits callers without a handshake this package sees", config.WrapSession != nil},
		{"UnwrapSession", "resumption tickets are decoded by this, with the same consequence as WrapSession", config.UnwrapSession != nil},
		{"InsecureSkipVerify", "the peer's certificate chain is not verified at all", config.InsecureSkipVerify},
	} {
		if field.set {
			return fmt.Errorf("the identity source returned a TLS configuration that sets %s: %s. Leave it unset and Go's own is used — this listener's posture is not a thing a source may replace, only a thing it may satisfy", field.name, field.why)
		}
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
func holdPerConnectionPosture(config *tls.Config, principal string, allowed func() ([]string, error)) {
	// The base configuration's own certificate is already held at use by
	// holdServedCertificate, which serverIdentity calls first — a rotation
	// landing a certificate for another workload is refused as it is served,
	// not as it was at boot. This function used to wrap GetCertificate a second
	// time for that, and the duplicate quietly made the real wrapper
	// untestable: a mutation that disabled it left the copy here passing every
	// certificate-selection test, so the check this file argues for could have
	// been broken with nothing to notice.
	inner := config.GetConfigForClient
	if inner == nil {
		return
	}
	// Whether the base configuration stands on its own, decided here rather
	// than at the handshake: a callback is allowed to answer nil, which is
	// Go's "serve the base configuration", and the base was only admitted at
	// boot *because* a callback would resolve the anchor per handshake. A
	// source that answered nil for the hello that actually arrived therefore
	// served a configuration requiring a caller's certificate against no
	// anchor at all — system roots — while every check in this file had
	// passed. A conditional nil answer was demonstrated doing exactly that.
	baseStandsAlone := config.ClientCAs != nil
	config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		answer, err := inner(hello)
		if err != nil {
			return nil, err
		}
		if answer == nil {
			if !baseStandsAlone {
				return nil, fmt.Errorf("the identity source answered this handshake with nothing, which serves its base configuration — and that one names no trust anchor to verify a caller against (ClientCAs is nil), so Go would accept a client certificate from any public CA. A source that resolves the anchor per handshake has to resolve it for every handshake, or carry a usable one on the configuration it returned at boot")
			}
			return nil, nil
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
		// Who may call is re-imposed too: a source's callback that returned a
		// configuration without it would serve that connection admitting every
		// identity in the cell.
		//
		// On a clone, never on what the callback handed back. crypto/tls does
		// not promise a fresh configuration per call — a source may return one
		// it keeps, and the projected source here returns a clone only because
		// it happens to — so mutating the answer is a write to a value another
		// handshake may be reading, which is both a data race and a violation
		// of the rule that a configuration in use is not modified.
		admitted := answer.Clone()
		// Held to the frozen principal here, on the clone, and not by probing
		// the answer: a per-connection answer selects its own certificate, and
		// an answer whose GetCertificate returned the approved leaf for a
		// synthetic probe and another workload's for the hello that actually
		// arrived was demonstrated completing the handshake as the other
		// workload. holdServedCertificate wraps that selection instead.
		if err := holdServedCertificate(admitted, principal); err != nil {
			return nil, fmt.Errorf("the identity source answered this handshake with a configuration whose certificate is not this workload's: %w", err)
		}
		admitOnly(admitted, allowed)
		return admitted, nil
	}
}

// holdServedCertificate rewrites config so that whichever certificate a
// handshake actually selects is this workload's.
//
// The check this replaces read one certificate and approved a configuration:
// it called GetCertificate with a synthetic hello naming "localhost", parsed
// what came back, compared it to the frozen principal, and left the
// configuration alone. Every part of that is a different certificate from the
// one a caller is served, and four separate shapes were demonstrated serving a
// neighbouring workload's leaf through a configuration that had passed:
//
//   - a source keyed on SNI answered the synthetic "localhost" probe with the
//     approved leaf and the real (no-SNI, IP-addressed) hello with another —
//     the probe is a name nothing in a cell dials by;
//   - NameToCertificate selected a second certificate by name;
//   - the base configuration carried GetCertificate returning the approved leaf
//     *and* a static Certificates[0] that was not, and Go consults
//     GetCertificate only when there is a certificate list to fall back from or
//     an SNI name to key on (crypto/tls, (*Config).getCertificate) — so a
//     caller addressing this pod by IP was served the static one, unprobed. The
//     SDK's own ServerTLSConfig documents that trap and sets GetCertificate
//     alone for exactly this reason; a consumer's source need not;
//   - tls.Certificate.Leaf described the approved identity while the DER beside
//     it described another. Leaf is a parse cache the holder fills in, not the
//     bytes the handshake sends.
//
// So nothing here trusts a probe. The selection surface is narrowed to one
// certificate, a static one is checked as itself, and the callback is wrapped
// so the pair *it returns for this handshake* is what gets compared — the
// certificate is validated at use and the validated pair is what is served.
//
// The principal is an authority-bearing value the platform provisioned and this
// process read once; the leaf is what callers actually see. Nothing else in the
// boot compares them, so a pair projected for another workload — the wrong
// Secret mounted, a Certificate issued for a neighbouring service — would be
// served happily, and the mismatch would surface at whatever verifies the
// destination's identity, as a refusal naming neither file.
func holdServedCertificate(config *tls.Config, principal string) error {
	if principal == "" {
		// Nothing to hold the leaf to. openAuthority runs before listen on
		// every path, so this is a programming error rather than a
		// deployment's, and it fails rather than skipping the check.
		return fmt.Errorf("this listener has no frozen principal to hold its own certificate to: the authority-bearing values must be read before the listener is built")
	}
	if err := oneCertificateToChooseFrom(config, "this listener"); err != nil {
		return err
	}
	// A static certificate is reachable whatever else is set, so it is checked
	// as itself rather than through a callback that may not be consulted.
	if len(config.Certificates) == 1 {
		if err := pairPresentsThisWorkload(&config.Certificates[0], principal); err != nil {
			return err
		}
	}
	if serve := config.GetCertificate; serve != nil {
		config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			pair, err := serve(hello)
			if err != nil {
				return nil, err
			}
			if pair == nil {
				// Go's documented "nothing for this hello, use the list",
				// which was checked above or does not exist.
				return nil, nil
			}
			if err := pairPresentsThisWorkload(pair, principal); err != nil {
				return nil, err
			}
			return pair, nil
		}
		// And asked once now, so a misprovisioned boot is refused at boot
		// rather than at every handshake — which also keeps the ordering this
		// check exists for: serverIdentity runs before the first outbound act,
		// so a pair issued for a neighbouring workload is caught before the
		// projected token has been presented to anyone under it.
		//
		// The hello is empty, which is not a synthetic name but the hello a
		// peer addressing this pod by IP actually sends — the previous check
		// made one up ("localhost") and a source keyed on it answered the probe
		// and the real handshake differently. And it can only *refuse* a boot,
		// never approve one: a source that cannot answer an empty hello is left
		// to the wrapper above, which is where the guarantee is.
		if pair, err := serve(&tls.ClientHelloInfo{}); err == nil && pair != nil {
			if err := pairPresentsThisWorkload(pair, principal); err != nil {
				return err
			}
		}
		return nil
	}
	if len(config.Certificates) == 1 {
		return nil
	}
	return fmt.Errorf("the identity source produces its certificate per connection (GetConfigForClient only), so the identity this listener presents cannot be held to this workload's: return a configuration with GetCertificate or Certificates as well")
}

// oneCertificateToChooseFrom refuses a configuration that selects between
// several certificates.
//
// A workload has one X.509-SVID. A configuration offering a choice is one whose
// served identity is decided at handshake time — by the name a caller sends, by
// which chain happens to be compatible with their signature algorithms — and
// "the one that was checked" is then a property of the caller rather than of
// this configuration. Narrowing the surface is what makes validating at use
// complete instead of validating whichever branch a test happened to take.
func oneCertificateToChooseFrom(config *tls.Config, side string) error {
	if config.NameToCertificate != nil {
		return fmt.Errorf("the identity source selects %s's certificate by server name (NameToCertificate): this workload has exactly one identity, and a configuration that chooses between several serves whichever the caller's name selects, not the one held to the frozen principal", side)
	}
	if len(config.Certificates) > 1 {
		return fmt.Errorf("the identity source offers %s %d certificates to choose from: a workload has one X.509-SVID, and with several Go selects one at handshake time by name and by what the caller supports, so the certificate checked is not the certificate served",
			side, len(config.Certificates))
	}
	return nil
}

// pairPresentsThisWorkload holds one certificate — the exact pair a handshake
// selected — to the frozen principal.
func pairPresentsThisWorkload(pair *tls.Certificate, principal string) error {
	if pair == nil || len(pair.Certificate) == 0 {
		return fmt.Errorf("the identity source produced an empty certificate chain for this handshake")
	}
	// The DER that will be sent, never pair.Leaf.
	//
	// Leaf is a parse cache its holder fills in and nothing keeps it honest: a
	// pair carrying the approved identity in Leaf and another workload's
	// certificate in Certificate[0] was demonstrated passing this check and
	// completing a handshake as the other workload. The bytes on the wire are
	// the identity; a struct field describing them is a claim. Parsing costs a
	// few microseconds per handshake, which is the same trade this file already
	// makes to re-read the trust anchor.
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("the certificate this handshake would be answered with cannot be parsed: %w", err)
	}
	return leafPresentsThisWorkload(leaf, principal)
}

// leafPresentsThisWorkload is the comparison itself.
//
// The comparison is the SPIFFE ID in a URI SAN, which is what names a workload
// in this model (a presence document's expected identity is one). A leaf
// carrying none, or none that matches, is refused.
func leafPresentsThisWorkload(leaf *x509.Certificate, principal string) error {
	// Exactly one, for the same reason a caller's is: a leaf naming several
	// identities is not a SPIFFE identity, and holding it to "one of them
	// matches" means this workload is whichever of them the far end chooses.
	if len(leaf.URIs) == 1 && leaf.URIs[0].String() == principal {
		return nil
	}
	if len(leaf.URIs) > 1 {
		return fmt.Errorf("the certificate this workload would present names %d URI identities (%s): a SPIFFE certificate names exactly one, and this workload cannot be held to a leaf that claims several",
			len(leaf.URIs), strings.Join(uriStrings(leaf.URIs), ", "))
	}
	return fmt.Errorf("the certificate this workload would present names %s, and its frozen principal is %q (%s/%s): a pair projected for another workload would otherwise be served, and the mismatch would surface at whatever verifies this destination rather than here",
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

// holdPresentedCertificate holds an *outbound* configuration's certificate to
// the frozen principal, at the moment it is presented.
//
// The listener's leaf was checked and the client's was not, on the default path
// where they come from two separate reloaders over the same files. So a pair
// that rotated to a neighbouring workload's identity was presented to the mint
// and the gateway by this client while the listener refused to serve it — the
// check existed, ran on one of the two things it had to cover, and the half it
// missed is the half that talks to the party holding the projected token.
//
// Then the check it grew was a *preflight*: it called GetClientCertificate
// once, compared what came back, and left the source's own callback installed
// for the handshake. Rotating the files between the two was demonstrated
// presenting the other workload's leaf successfully — the same check/use gap as
// the inbound side, and the reason this wraps the callback rather than calling
// it. What a dial presents is what gets compared.
func holdPresentedCertificate(config *tls.Config, principal string) error {
	if principal == "" {
		return fmt.Errorf("this workload's outbound client has no frozen principal to hold its own certificate to: the authority-bearing values must be read before any outbound act")
	}
	if err := oneCertificateToChooseFrom(config, "this workload's outbound client"); err != nil {
		return err
	}
	if len(config.Certificates) == 1 {
		if err := pairPresentsThisWorkload(&config.Certificates[0], principal); err != nil {
			return err
		}
	}
	if get := config.GetClientCertificate; get != nil {
		config.GetClientCertificate = func(info *tls.CertificateRequestInfo) (*tls.Certificate, error) {
			pair, err := get(info)
			if err != nil {
				return nil, fmt.Errorf("the identity source could not produce the certificate this runtime presents to the platform: %w", err)
			}
			if err := pairPresentsThisWorkload(pair, principal); err != nil {
				return nil, err
			}
			return pair, nil
		}
		// Refused at boot as well, for the reason holdServedCertificate
		// records: a mismatch found at the first dial is a mismatch found after
		// the projected token has gone out under it.
		if pair, err := get(&tls.CertificateRequestInfo{}); err == nil && pair != nil {
			if err := pairPresentsThisWorkload(pair, principal); err != nil {
				return err
			}
		}
		return nil
	}
	if len(config.Certificates) == 1 {
		return nil
	}
	return fmt.Errorf("this workload's outbound client would present no certificate, so the platform cannot tell this workload from anything else that reached it")
}
