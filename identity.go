package solution

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net"
	"os"

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
// against when the platform projects one.
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
	var clientCAs *x509.CertPool
	if p.trustBundleFile != "" {
		pem, err := os.ReadFile(p.trustBundleFile)
		if err != nil {
			return nil, fmt.Errorf("read workload identity trust bundle %q: %w — set %s to the anchor this listener verifies its peers against, or leave it unset to verify no peer certificate",
				p.trustBundleFile, err, IdentityTrustBundleFileEnvironmentVariable)
		}
		clientCAs = x509.NewCertPool()
		if !clientCAs.AppendCertsFromPEM(pem) {
			// An unusable bundle is refused rather than dropped. Dropped, the
			// listener would come up accepting any peer — the one outcome
			// configuring a bundle was meant to prevent — and nothing would say
			// so.
			return nil, fmt.Errorf("workload identity trust bundle %q contains no certificate: the listener would otherwise come up verifying no peer at all", p.trustBundleFile)
		}
	}
	// The SDK owns the floor (TLS 1.3) and the reload; this runtime owns only
	// which files and which anchor.
	config, err := codefly.ServerTLSConfig(p.certFile, p.keyFile, clientCAs)
	if err != nil {
		return nil, fmt.Errorf("load this workload's X.509-SVID from %q/%q: %w — the listener presents it and there is no plain-HTTP listener; see %s and %s",
			p.certFile, p.keyFile, err, IdentityCertFileEnvironmentVariable, IdentityKeyFileEnvironmentVariable)
	}
	return config, nil
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
	ln, err := net.Listen("tcp", ":"+s.cfg.port)
	if err != nil {
		return nil, err
	}
	if config.ClientAuth < tls.RequireAndVerifyClientCert {
		// Said once, loudly, because it is the difference between "only this
		// mesh may reach me" and "anyone who can route to this pod may". The
		// anchor is the platform's to project, so this is a report on the
		// deployment and not a defect in the solution.
		log.Printf("solution %q: listener presents its workload identity but verifies no peer certificate: set %s to the anchor its callers' identities are issued under",
			s.manifest.ID, IdentityTrustBundleFileEnvironmentVariable)
	}
	return tls.NewListener(ln, config), nil
}

// usableServerIdentity refuses a configuration that would hand a handshake no
// certificate. An IdentitySource is consumer code, and a source that returns a
// bare &tls.Config{} — or one whose material it silently failed to load — would
// otherwise produce a listener that completes no handshake at all, reported to
// every caller as a TLS error naming nothing.
func usableServerIdentity(config *tls.Config) error {
	if config == nil {
		return fmt.Errorf("the identity source returned no TLS configuration: this listener presents this workload's X.509-SVID and there is no plain-HTTP listener to fall back to")
	}
	if config.GetCertificate == nil && config.GetConfigForClient == nil && len(config.Certificates) == 0 {
		return fmt.Errorf("the identity source returned a TLS configuration with no certificate: a handshake would be answered with none, so the listener is refused rather than started")
	}
	return nil
}
