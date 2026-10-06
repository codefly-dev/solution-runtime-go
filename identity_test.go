package solution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"github.com/codefly-dev/sdk-go/workcontext"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestABootWithoutAWorkloadIdentityIsRefusedByName is the acceptance criterion
// for removing plain HTTP: the runtime refuses a listener configuration it
// cannot present an identity for, and names the material that is missing. A
// solution that came up on plain HTTP would be refused at the edge instead,
// for a reason only the edge can see.
func TestABootWithoutAWorkloadIdentityIsRefusedByName(t *testing.T) {
	certFile, keyFile, bundleFile, _, _ := workloadIdentity(t, testPrincipal)
	for _, tc := range []struct {
		name     string
		cert     string
		key      string
		token    string
		bundle   string
		callers  string
		peers    string
		names    string
		variable string
	}{
		{name: "no certificate", peers: testGatewayPrincipal, key: keyFile, token: "t", bundle: bundleFile, callers: testGatewayPrincipal, names: "certificate", variable: IdentityCertFileEnvironmentVariable},
		{name: "no private key", peers: testGatewayPrincipal, cert: certFile, token: "t", bundle: bundleFile, callers: testGatewayPrincipal, names: "private key", variable: IdentityKeyFileEnvironmentVariable},
		{name: "no trust anchor", peers: testGatewayPrincipal, cert: certFile, key: keyFile, token: "t", callers: testGatewayPrincipal, names: "trust anchor", variable: IdentityTrustBundleFileEnvironmentVariable},
		{name: "no projected token", peers: testGatewayPrincipal, cert: certFile, key: keyFile, bundle: bundleFile, callers: testGatewayPrincipal, names: "projected service-account token", variable: ProjectedTokenFileEnvironmentVariable},
		// Not material this workload presents, but the other half of the
		// posture: a listener that verifies every caller in the cell and
		// admits all of them is a listener with no admission at all, so the
		// admitted set is provisioned and named when it is absent.
		{name: "no allowed callers", cert: certFile, key: keyFile, token: "t", bundle: bundleFile, peers: testGatewayPrincipal, names: "allowed caller identities", variable: IdentityAllowedCallersFileEnvironmentVariable},
		// And the same question outbound. Every workload in the cell holds a
		// certificate from the same anchor, so a chain and a hostname do not
		// say a destination is the platform — and outbound is the direction
		// where being wrong hands over the projected token rather than
		// accepting a call.
		{name: "no platform peers", cert: certFile, key: keyFile, token: "t", bundle: bundleFile, callers: testGatewayPrincipal, names: "credential mint peer identity", variable: IdentityMintPeersFileEnvironmentVariable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := New(Manifest{ID: testSolutionID})
			server.cfg = config{
				port:               "8080",
				gatewayURL:         "https://gateway:42152",
				mintURL:            "https://gateway:42152" + credentialMintPath,
				identityCertFile:   tc.cert,
				identityKeyFile:    tc.key,
				projectedTokenPath: tc.token,
				trustBundleFile:    tc.bundle,
				allowedCallersFile: optionalIdentitiesFile(t, tc.callers),
				mintPeersFile:      optionalIdentitiesFile(t, tc.peers),
				gatewayPeersFile:   optionalIdentitiesFile(t, tc.peers),
				profile:            localProfile,
			}
			if err := server.cfg.validate(); err != nil {
				t.Fatalf("the resolved configuration itself is unusable: %v", err)
			}
			err := server.validateSources()
			if err == nil {
				t.Fatal("the boot accepted a configuration with no workload identity")
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Errorf("refusal %q does not name the missing %s", err, tc.names)
			}
			if !strings.Contains(err.Error(), tc.variable) {
				t.Errorf("refusal %q does not name %s, the override that sets it", err, tc.variable)
			}
			if !strings.Contains(err.Error(), WorkloadIdentityGroup) {
				t.Errorf("refusal %q does not name the %q group the platform provisions", err, WorkloadIdentityGroup)
			}
		})
	}
}

// TestACredentialBearingDestinationMustBeHTTPS: a TLS listener protects what
// callers send to this process and nothing it sends out. Over http:// the mint
// hands this workload's projected token to anything on the path, and a viewer's
// mint hands over their bearer and the capability minted for them.
func TestACredentialBearingDestinationMustBeHTTPS(t *testing.T) {
	for _, tc := range []struct {
		name     string
		gateway  string
		mint     string
		names    string
		variable string
	}{
		{"a plaintext gateway", "http://gateway:42152", "https://gateway:42152" + credentialMintPath, "viewer's bearer", "GATEWAY_URL"},
		{"a plaintext mint", "https://gateway:42152", "http://gateway:42152" + credentialMintPath, "service-account token", CredentialMintURLEnvironmentVariable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config{port: "8080", gatewayURL: tc.gateway, mintURL: tc.mint, profile: localProfile}
			err := cfg.validate()
			if err == nil {
				t.Fatal("validate accepted a plaintext credential-bearing destination")
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Errorf("refusal %q does not say what a plaintext hop would disclose (%s)", err, tc.names)
			}
			if !strings.Contains(err.Error(), tc.variable) {
				t.Errorf("refusal %q does not name %s", err, tc.variable)
			}
		})
	}
}

// TestASuppliedSourceNeedsNoProvisioningItDoesNotRead: a consumer that supplied
// an identity source has said where its identity comes from, so requiring the
// projected file paths as well would be requiring provisioning nothing reads.
// What no source changes is the authority identity.
func TestASuppliedSourceNeedsNoProvisioningItDoesNotRead(t *testing.T) {
	base := config{
		port:       "8080",
		gatewayURL: "https://gateway:42152",
		mintURL:    "https://gateway:42152" + credentialMintPath,
		profile:    localProfile,
		// Required whatever the identity source is: the source says who this
		// workload is, this says which callers it serves — and which
		// destinations are the platform.
		allowedCallersFile: identitiesFile(t, testGatewayPrincipal),
		mintPeersFile:      identitiesFile(t, testGatewayPrincipal),
		gatewayPeersFile:   identitiesFile(t, testGatewayPrincipal),
	}
	t.Run("an identity source replaces the projected pair", func(t *testing.T) {
		server := New(Manifest{ID: testSolutionID}).Identity(staticIdentity{})
		server.cfg = base
		server.cfg.projectedTokenPath = "/var/run/token"
		if err := server.validateSources(); err != nil {
			t.Errorf("the boot required material the selected source does not read: %v", err)
		}
	})
	t.Run("a credential source replaces the projected token", func(t *testing.T) {
		certFile, keyFile, bundleFile, _, _ := workloadIdentity(t, testPrincipal)
		server := New(Manifest{ID: testSolutionID}).Credential(stubCredentialSource{})
		server.cfg = base
		server.cfg.identityCertFile, server.cfg.identityKeyFile, server.cfg.trustBundleFile = certFile, keyFile, bundleFile
		if err := server.validateSources(); err != nil {
			t.Errorf("the boot required material the selected source does not read: %v", err)
		}
	})
}

// TestAnIdentitySourceReachesTheSamePostureAsTheProjectedOne: a source is
// consumer code — a mesh CA, a SPIFFE workload API, a pair the local toolchain
// minted — and every one of them has to arrive at the same posture. Checking
// only that a certificate was returned left the TLS floor and peer
// authentication silently optional for exactly the callers who wrote their own
// source.
func TestAnIdentitySourceReachesTheSamePostureAsTheProjectedOne(t *testing.T) {
	certFile, keyFile, bundleFile, _, _ := workloadIdentity(t, testPrincipal)
	usable, err := projectedIdentity{certFile: certFile, keyFile: keyFile, trustBundleFile: bundleFile}.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		config *tls.Config
		says   string
	}{
		{"no configuration at all", nil, "plain-HTTP"},
		{"no certificate", &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert}, "no certificate"},
		{"a floor below TLS 1.3", withFloor(usable, tls.VersionTLS12), "TLS 1.3"},
		{"no peer authentication", withClientAuth(usable, tls.NoClientCert), "authenticates no peer"},
		{"a peer it verifies but does not require", withClientAuth(usable, tls.VerifyClientCertIfGiven), "authenticates no peer"},
		// Requiring a certificate and naming no anchor is strictly worse than
		// requiring none, because it reads as mutual TLS in every log line:
		// with ClientCAs nil, Go verifies the caller against this host's
		// system roots, so the listener demands a certificate and then accepts
		// one from any public CA.
		{"a required certificate with no anchor to verify it against", withoutAnchor(usable), "system roots"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := New(Manifest{ID: testSolutionID}).Identity(staticIdentity{config: tc.config})
			server.cfg = config{port: listenOn(t, server)}
			server.principal = testPrincipal
			ln, err := server.listen()
			if ln != nil {
				_ = ln.Close()
			}
			if err == nil {
				t.Fatal("listen came up on a configuration below this model's posture")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("refusal %q does not say %q", err, tc.says)
			}
		})
	}

	t.Run("a source that reaches the posture is accepted", func(t *testing.T) {
		server := New(Manifest{ID: testSolutionID}).Identity(staticIdentity{config: usable})
		server.cfg = config{port: listenOn(t, server)}
		server.principal = testPrincipal
		ln, err := server.listen()
		if err != nil {
			t.Fatalf("listen refused a conforming source: %v", err)
		}
		_ = ln.Close()
	})
}

// TestAListenerIsHeldToItsOwnFrozenPrincipal: the pair a platform projects and
// the principal it provisioned are two facts nothing else in the boot compares.
// A Secret mounted for a neighbouring workload would otherwise be served
// happily, and the mismatch would surface at whatever verifies this
// destination, as a refusal naming neither file.
func TestAListenerIsHeldToItsOwnFrozenPrincipal(t *testing.T) {
	certFile, keyFile, bundleFile, _, _ := workloadIdentity(t, "spiffe://codefly.test/ns/solutions/sa/another-workload")
	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{port: listenOn(t, server), identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile}
	server.principal = testPrincipal
	ln, err := server.listen()
	if ln != nil {
		_ = ln.Close()
	}
	if err == nil {
		t.Fatal("listen served a certificate issued for another workload")
	}
	for _, want := range []string{"another-workload", testPrincipal, AuthorityGroup} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}

	t.Run("a leaf with no URI identity at all", func(t *testing.T) {
		config, err := projectedIdentity{certFile: certFile, keyFile: keyFile, trustBundleFile: bundleFile}.ServerTLSConfig()
		if err != nil {
			t.Fatal(err)
		}
		stripped := config.Clone()
		stripped.GetCertificate = nil
		stripped.GetConfigForClient = nil
		stripped.Certificates = []tls.Certificate{{Certificate: [][]byte{selfSignedWithoutURI(t)}}}
		if err := holdServedCertificate(stripped, testPrincipal); err == nil || !strings.Contains(err.Error(), "no URI identity at all") {
			t.Errorf("holdServedCertificate = %v, want a refusal distinguishing no identity from the wrong one", err)
		}
	})
}

// TestPeerTrustIsReadAtEveryHandshake: a pool read once cannot shrink. Removing
// a compromised root from the projected bundle has to stop it authenticating
// callers without a restart, because revocation that takes effect only on a
// restart is revocation an operator has to remember to finish.
func TestPeerTrustIsReadAtEveryHandshake(t *testing.T) {
	certFile, keyFile, bundleFile, _, _ := workloadIdentity(t, testPrincipal)
	config, err := projectedIdentity{certFile: certFile, keyFile: keyFile, trustBundleFile: bundleFile}.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	first, err := config.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("first handshake: %v", err)
	}
	if first.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert", first.ClientAuth)
	}
	if first.ClientCAs == nil {
		t.Fatal("the handshake was offered no peer anchor")
	}

	// The anchor is replaced with a different one: a caller issued under the
	// old root must no longer authenticate, and the pool the next handshake
	// uses must be the new one.
	replacement, _, _ := issueAnchor(t)
	writeFile(t, bundleFile, string(replacement))
	second, err := config.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("handshake after the anchor was replaced: %v", err)
	}
	if second.ClientCAs.Equal(first.ClientCAs) {
		t.Error("the handshake still judges callers by the anchor that was removed: peer trust was snapshotted at boot")
	}

	// An anchor that has become unreadable fails the handshake rather than
	// falling back to the last good pool: judging by a stale anchor lets in
	// callers who should be refused, which is not symmetric with serving a
	// stale leaf.
	if err := os.Remove(bundleFile); err != nil {
		t.Fatal(err)
	}
	if _, err := config.GetConfigForClient(&tls.ClientHelloInfo{}); err == nil {
		t.Error("a handshake was answered after the trust anchor became unreadable")
	}
}

// TestAnUnusableTrustAnchorIsRefusedNotDropped: dropped, the listener comes up
// verifying no peer at all — exactly what configuring an anchor was meant to
// prevent — and nothing says so.
func TestAnUnusableTrustAnchorIsRefusedNotDropped(t *testing.T) {
	certFile, keyFile, _, _, _ := workloadIdentity(t, testPrincipal)
	bundle := filepath.Join(t.TempDir(), "ca.crt")
	writeFile(t, bundle, "not a certificate")
	_, err := projectedIdentity{certFile: certFile, keyFile: keyFile, trustBundleFile: bundle}.ServerTLSConfig()
	if err == nil || !strings.Contains(err.Error(), "no certificate") {
		t.Errorf("an unparseable anchor was reported as %v, want a refusal saying it carries no certificate", err)
	}

	_, err = projectedIdentity{certFile: certFile, keyFile: keyFile}.ServerTLSConfig()
	if err == nil || !strings.Contains(err.Error(), IdentityTrustBundleFileEnvironmentVariable) {
		t.Errorf("an absent anchor was reported as %v, want a refusal naming %s", err, IdentityTrustBundleFileEnvironmentVariable)
	}
}

// TestTheListenerServesTheRotatedLeaf: workload leaves are short-lived and
// rotated well before expiry, so a listener that loaded its pair once at boot
// serves a stale leaf while a valid one sits on disk, and then fails every
// handshake with the issuer reporting nothing wrong.
func TestTheListenerServesTheRotatedLeaf(t *testing.T) {
	certFile, keyFile, bundleFile, _, _ := workloadIdentity(t, testPrincipal)
	config, err := projectedIdentity{certFile: certFile, keyFile: keyFile, trustBundleFile: bundleFile}.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	first, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	rotatedCert, rotatedKey, _, _, _ := workloadIdentity(t, testPrincipal)
	writeFile(t, certFile, readFile(t, rotatedCert))
	writeFile(t, keyFile, readFile(t, rotatedKey))
	second, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	if string(first.Certificate[0]) == string(second.Certificate[0]) {
		t.Error("the listener served the boot-time leaf after the projection rotated")
	}
}

// staticIdentity is a consumer-supplied identity source, including the
// degenerate ones a consumer can write by mistake.
type staticIdentity struct {
	config *tls.Config
	// anchor, when set, is what this source says its current anchor is. Unset,
	// it answers with the pool on the configuration — truthful for a source
	// whose anchor really is static, which is every source in these tests.
	anchor func() *x509.CertPool
}

func (s staticIdentity) ServerTLSConfig() (*tls.Config, error) { return s.config, nil }

// PeerAnchor makes this source askable, which a source setting
// GetConfigForClient now has to be: the runtime re-verifies established peers
// and verifies the platform it dials, and neither can be answered by probing a
// per-handshake callback with a hello nobody sent.
func (s staticIdentity) PeerAnchor() (*x509.CertPool, error) {
	if s.anchor != nil {
		return s.anchor(), nil
	}
	if s.config.ClientCAs != nil {
		return s.config.ClientCAs, nil
	}
	// Mirrors what the projected source does: resolve it now rather than hold
	// a pool from boot.
	if s.config.GetConfigForClient != nil {
		answer, err := s.config.GetConfigForClient(&tls.ClientHelloInfo{})
		if err == nil && answer != nil && answer.ClientCAs != nil {
			return answer.ClientCAs, nil
		}
	}
	return nil, fmt.Errorf("this test source names no anchor")
}

// withoutAnchor is a source that requires a caller's certificate and names
// nothing to verify it against, with no per-connection callback to resolve one
// later either.
func withoutAnchor(base *tls.Config) *tls.Config {
	changed := base.Clone()
	changed.ClientCAs = nil
	changed.GetConfigForClient = nil
	return changed
}

func withFloor(base *tls.Config, floor uint16) *tls.Config {
	changed := base.Clone()
	changed.MinVersion = floor
	return changed
}

func withClientAuth(base *tls.Config, auth tls.ClientAuthType) *tls.Config {
	changed := base.Clone()
	changed.ClientAuth = auth
	return changed
}

// selfSignedWithoutURI is a leaf whose identity is a DNS name and nothing else:
// the shape a pair projected by something that does not know about SPIFFE has.
func selfSignedWithoutURI(t *testing.T) []byte {
	t.Helper()
	_, anchor, anchorKey := issueAnchor(t)
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(99),
		Subject:      pkix.Name{CommonName: "no-uri"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{"localhost"},
	}, anchor, public, anchorKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestASourcesPerConnectionCallbackCannotLowerThePosture closes the last way
// into this file, and it is the same argument the rest of the cutover is built
// on: boot-time approval is not authorization at use.
//
// usableServerIdentity and holdServedCertificate read the configuration a source
// returns at boot. Go hands each handshake to GetConfigForClient when one is
// set, and the configuration that callback returns replaces the base one for
// that connection. So a source could conform at boot, pass every other check
// here, and serve each individual handshake under TLS 1.2, with no peer
// authentication, or holding a neighbouring workload's leaf.
//
// The projected source uses that callback to re-read peer trust, so this is the
// documented pattern in this package, not an odd one — a consumer following it
// is one line from lowering the floor on every connection while the boot still
// reports a conforming listener.
//
// A configuration below the posture fails the handshake outright rather than
// serving it in a weakened form: the caller that happens to arrive is not the
// thing in question, the configuration the listener would answer anyone with
// is.
func TestASourcesPerConnectionCallbackCannotLowerThePosture(t *testing.T) {
	// One anchor for the whole test, so a rival leaf is one a caller would
	// actually verify — issued by the same CA, naming another workload.
	c := newCell(t)
	certFile, keyFile, bundleFile, caller, roots := c.workload(t, testPrincipal)
	rival := c.identity(t, "spiffe://codefly.test/ns/solutions/sa/another-workload")
	conforming, err := projectedIdentity{certFile: certFile, keyFile: keyFile, trustBundleFile: bundleFile}.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	authenticated := func() *tls.Config {
		return &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{*caller}, MinVersion: tls.VersionTLS13, ServerName: "localhost"}
	}

	// A source conforming at boot — certificate, TLS 1.3,
	// RequireAndVerifyClientCert — that downgrades per connection.
	downgrading := func(change func(*tls.Config)) *tls.Config {
		base := conforming.Clone()
		base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			answer := conforming.Clone()
			answer.GetConfigForClient = nil
			anchor, err := peerAnchor(bundleFile)
			if err != nil {
				return nil, err
			}
			answer.ClientCAs = anchor
			answer.ClientAuth = tls.RequireAndVerifyClientCert
			change(answer)
			return answer, nil
		}
		return base
	}

	for _, tc := range []struct {
		name string
		// what the callback does to each connection's configuration
		change func(*tls.Config)
		// a caller the lowered posture would have admitted, and that must not
		// be, alongside the authenticated one which is refused with it
		exploits func() *tls.Config
	}{
		{
			"a floor below TLS 1.3 per connection",
			func(cfg *tls.Config) { cfg.MinVersion = tls.VersionTLS12 },
			func() *tls.Config {
				return &tls.Config{RootCAs: roots, Certificates: []tls.Certificate{*caller}, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, ServerName: "localhost"}
			},
		},
		{
			"no peer authentication per connection",
			func(cfg *tls.Config) { cfg.ClientAuth = tls.NoClientCert },
			func() *tls.Config {
				return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, ServerName: "localhost"}
			},
		},
		{
			"a peer verified but not required per connection",
			func(cfg *tls.Config) { cfg.ClientAuth = tls.VerifyClientCertIfGiven },
			func() *tls.Config {
				return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, ServerName: "localhost"}
			},
		},
		{
			// Resolving the anchor per handshake has to mean resolved: a
			// callback that answers with no pool defers to the system roots
			// for that connection, which is the same hole one layer along.
			"no trust anchor per connection",
			func(cfg *tls.Config) { cfg.ClientCAs = nil },
			func() *tls.Config {
				return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, ServerName: "localhost"}
			},
		},
		{
			// And the same with the answer carrying a further callback. Go
			// calls GetConfigForClient once, on the base configuration, so a
			// callback *on the answer* is never called and cannot be where the
			// pool arrives — the connection runs on this configuration, with
			// system roots. It is the one shape the boot-time check reads as
			// "resolved later".
			"no trust anchor per connection, deferred to a callback Go never calls",
			func(cfg *tls.Config) {
				cfg.ClientCAs = nil
				cfg.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil }
			},
			func() *tls.Config {
				return &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13, ServerName: "localhost"}
			},
		},
		{
			// Nothing extra is admitted here; what changes is whose identity
			// the listener presents, so the authenticated caller is the one
			// that reads the defect.
			"another workload's leaf per connection",
			func(cfg *tls.Config) { cfg.Certificates, cfg.GetCertificate = []tls.Certificate{*rival}, nil },
			nil,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := New(Manifest{ID: testSolutionID}).Identity(staticIdentity{config: downgrading(tc.change)})
			server.cfg = config{port: listenOn(t, server), allowedCallersFile: identitiesFile(t, testGatewayPrincipal)}
			server.principal = testPrincipal
			// The two failures listen() returns as one are separated here.
			// Refusing the *identity* at boot is an acceptable answer — what
			// must not happen is a handshake served under the lowered posture —
			// but failing to *bind* is this test not running, and returning on
			// it made every subtest below pass for a reason that has nothing to
			// do with the posture.
			config, refused := server.serverIdentity()
			if refused != nil {
				// A boot refusal is an acceptable answer, but only the right
				// one. Returning on *any* error made every subtest below pass
				// the moment serverIdentity failed for an unrelated reason —
				// an unresolved path, a missing admission file, a mutated
				// helper — which is the shape that makes a negative test
				// report success for a cause it never exercised.
				if !strings.Contains(refused.Error(), "identity source") {
					t.Fatalf("the boot refused the identity for something other than its posture, so this case never ran: %v", refused)
				}
				return
			}
			// The listener this server was handed, not a second bind of the
			// same port. The distinction the comment above cares about — a
			// boot that refuses the identity versus a test that could not
			// bind — is kept and sharpened: the bind happened in boundPort,
			// which fails the test outright, so reaching here means a
			// listener exists and only the posture is in question.
			ln := tls.NewListener(server.boundListener, config)
			defer func() { _ = ln.Close() }()
			serve(t, ln)

			if tc.exploits != nil {
				if conn, err := tls.Dial("tcp", ln.Addr().String(), tc.exploits()); err == nil {
					state := conn.ConnectionState()
					_ = conn.Close()
					t.Errorf("a caller the boot configuration would have refused was served over TLS 0x%04x with %d peer certificate(s): the per-connection configuration is not held to the posture the boot checked",
						state.Version, len(state.PeerCertificates))
				}
			}
			// And the lowered configuration is refused for everyone, not
			// weakened for whoever asks: the configuration is what is wrong.
			conn, err := tls.Dial("tcp", ln.Addr().String(), authenticated())
			if err == nil {
				state := conn.ConnectionState()
				served := "none"
				if len(state.PeerCertificates) > 0 && len(state.PeerCertificates[0].URIs) > 0 {
					served = state.PeerCertificates[0].URIs[0].String()
				}
				_ = conn.Close()
				t.Errorf("the listener answered a handshake under a configuration below its boot posture (TLS 0x%04x, presenting %s)", state.Version, served)
			}
		})
	}

	// The other direction, or the check above is just a broken listener: a
	// per-connection callback that keeps the posture is served normally. This
	// is the projected source's own shape — it uses the callback to re-read
	// peer trust on every handshake.
	t.Run("a conforming callback is served", func(t *testing.T) {
		server := New(Manifest{ID: testSolutionID}).Identity(staticIdentity{config: conforming})
		// The admitted set is provisioned, because listen() is the production
		// path and a deployment reaching it has been through validateSources.
		// Without it this subtest dialled a listener that refused the caller
		// and read as a success anyway: in TLS 1.3 the client finishes before
		// it learns whether the server accepted its certificate, so a
		// server-side refusal is invisible to tls.Dial.
		server.cfg = config{port: listenOn(t, server), allowedCallersFile: identitiesFile(t, testGatewayPrincipal)}
		server.principal = testPrincipal
		ln, err := server.listen()
		if err != nil {
			t.Fatalf("listen refused the projected source's own per-connection shape: %v", err)
		}
		// This one may fail for a bind, and says so rather than skipping.
		defer func() { _ = ln.Close() }()
		serve(t, ln)

		good, err := tls.Dial("tcp", ln.Addr().String(), authenticated())
		if err != nil {
			t.Fatalf("a conforming caller was refused, so the per-connection check broke the listener: %v", err)
		}
		state := good.ConnectionState()
		_ = good.Close()
		if state.Version < tls.VersionTLS13 {
			t.Errorf("the connection was served TLS 0x%04x, want a 1.3 floor", state.Version)
		}
		leaf := state.PeerCertificates[0]
		if len(leaf.URIs) == 0 || leaf.URIs[0].String() != testPrincipal {
			t.Errorf("the connection was served %v, want this workload's frozen principal %q", leaf.URIs, testPrincipal)
		}
	})
}

// serve accepts and handshakes until the listener closes, so a refused
// handshake is refused by the listener's own configuration rather than by
// nobody being there.
func serve(t *testing.T, ln net.Listener) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				if tlsConn, ok := conn.(*tls.Conn); ok {
					_ = tlsConn.Handshake()
				}
				_ = conn.Close()
			}()
		}
	}()
	t.Cleanup(func() { <-done })
}

// suppliedIdentity is a consumer's IdentitySource that happens to produce a
// conforming configuration — the shape the README's example implies, built over
// the same anchor the fake host is served under so the boot fails on the
// property under test and not on verifying the host.
type suppliedIdentity struct{ certFile, keyFile, bundleFile string }

func (c suppliedIdentity) inner() projectedIdentity {
	return projectedIdentity{certFile: c.certFile, keyFile: c.keyFile, trustBundleFile: c.bundleFile}
}

func (c suppliedIdentity) ServerTLSConfig() (*tls.Config, error) {
	return c.inner().ServerTLSConfig()
}

// PeerAnchor is delegated too, and a consumer wrapping a source has to do the
// same: this source resolves its anchor per handshake, which is the right
// shape, and that is exactly the shape that has to be able to answer what the
// anchor currently is rather than be probed with a handshake nobody made.
func (c suppliedIdentity) PeerAnchor() (*x509.CertPool, error) {
	return c.inner().PeerAnchor()
}

// TestASuppliedSourceBootsAndStaysAuthenticatedOutbound drives the two bugs a
// second reviewer found behind the "custom sources work through the boot
// contract" answer. The test that answered it before stopped at
// validateSources, so neither was reachable by it.
//
// The outbound client was built `if s.credential == nil || s.identity == nil`:
//
//   - supply **both** sources and it was never built, so s.outbound stayed nil
//     and every gateway call fell through to the unauthenticated transport —
//     system roots, no client certificate. The one posture this cutover exists
//     to remove, reached by configuring more rather than less.
//   - supply **only Identity** and the condition was true, so the client read
//     the projected files validateSources had just declared unnecessary for
//     that boot. The README's own example could not start.
func TestASuppliedSourceBootsAndStaysAuthenticatedOutbound(t *testing.T) {
	// No projected identity files at all, so a boot that reads them fails and a
	// boot that honours the supplied source does not.
	withoutProjectedIdentity := func(t *testing.T) {
		t.Helper()
		t.Setenv(IdentityCertFileEnvironmentVariable, "")
		t.Setenv(IdentityKeyFileEnvironmentVariable, "")
		t.Setenv(IdentityTrustBundleFileEnvironmentVariable, "")
	}

	t.Run("identity only, the README's own example", func(t *testing.T) {
		mint := newHostMint(t, &hostMint{})
		certFile, keyFile, bundleFile, _, _ := bootIdentity(t, mint, testPrincipal)
		withoutProjectedIdentity(t)

		server := New(Manifest{ID: testSolutionID}).
			Identity(suppliedIdentity{certFile: certFile, keyFile: keyFile, bundleFile: bundleFile})
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		ln, err := takeListener(server).start(ctx)
		if err != nil {
			t.Fatalf("a boot supplying only Identity(...) was refused: %v\nthe supplied source says where the identity comes from, so the projected files are provisioning this boot does not read", err)
		}
		defer func() { _ = ln.Close() }()
		if server.outbound == nil {
			t.Fatal("the boot came up with no outbound client at all")
		}
		if got := mint.count(); got != 1 {
			t.Errorf("the host was asked %d times, want the one mint: the supplied-identity boot must still obtain its credential", got)
		}
	})

	t.Run("both sources supplied: outbound still presents this workload", func(t *testing.T) {
		mint := newHostMint(t, &hostMint{})
		certFile, keyFile, bundleFile, caller, roots := bootIdentity(t, mint, testPrincipal)
		tokenFile := filepath.Join(t.TempDir(), "token")
		writeFile(t, tokenFile, "projected-token")
		withoutProjectedIdentity(t)

		// The fake host is served over TLS under the cell's anchor, and a
		// supplied credential source brings its own transport — the runtime
		// hands it none, which is the point of supplying one.
		//
		// It no longer brings a transport: the SDK's mint client builds and
		// owns that, and takes only the roots. A consumer supplying a
		// credential source therefore supplies the anchor the mint endpoint is
		// verified against and nothing else about how it is dialled.
		_, _ = caller, roots
		server := New(Manifest{ID: testSolutionID}).
			Identity(suppliedIdentity{certFile: certFile, keyFile: keyFile, bundleFile: bundleFile}).
			Credential(mintClientFor(t, mint, tokenFile))
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		ln, err := takeListener(server).start(ctx)
		if err != nil {
			t.Fatalf("a boot supplying both sources was refused: %v", err)
		}
		defer func() { _ = ln.Close() }()

		if server.outbound == nil {
			t.Fatal("s.outbound is nil with both sources supplied, so every gateway call falls through to the unauthenticated transport: system roots, no client certificate")
		}
		transport, ok := server.outbound.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("outbound transport is %T, want *http.Transport", server.outbound.Transport)
		}
		if transport.DialTLSContext == nil {
			t.Fatal("the outbound client has no per-connection dialler, so its trust is snapshotted")
		}
		// What that dialler builds, checked directly: identity and anchor from
		// the supplied source, floor at 1.3.
		built, err := clientTLSFrom(server.identity, server.identityConfig)
		if err != nil {
			t.Fatalf("derive the outbound configuration from the supplied source: %v", err)
		}
		switch {
		case built.RootCAs == nil:
			t.Error("the outbound client verifies the platform against system roots, not the anchor the supplied source named")
		case built.GetClientCertificate == nil && len(built.Certificates) == 0:
			t.Error("the outbound client presents no identity, so the platform cannot tell this workload from anything else that reached it")
		case built.MinVersion != tls.VersionTLS13:
			t.Errorf("the outbound floor is 0x%04x, want TLS 1.3", built.MinVersion)
		}
		// And the gateway a handler is handed carries it, rather than the
		// unauthenticated fallback.
		if server.gatewayFor(http.Header{}).transport == nil {
			t.Error("a handler's gateway carries no transport, so it dials the platform unauthenticated")
		}
	})
}

// TestAMismatchedLeafIsRefusedBeforeTheMint is the ordering half of the same
// finding: the principal check is worth nothing after the fact.
//
// openCredential used to run before listen(), so a leaf issued for a
// neighbouring workload — the wrong Secret mounted, a Certificate issued for
// another service — had already been presented to the host, together with this
// workload's projected service-account token, by the time the listener refused
// it. The refusal was real and the disclosure had already happened.
func TestAMismatchedLeafIsRefusedBeforeTheMint(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	bootIdentity(t, mint, "spiffe://codefly.test/ns/solutions/sa/another-workload")

	// Not bootFails: that helper re-provisions the environment, which would
	// replace the mismatched leaf with a matching one and assert nothing.
	ln, err := takeListener(New(Manifest{ID: testSolutionID})).start(context.Background())
	if ln != nil {
		_ = ln.Close()
	}
	if err == nil {
		t.Fatal("the boot came up serving a leaf issued for another workload")
	}
	if !strings.Contains(err.Error(), "another-workload") {
		t.Errorf("the boot was refused with %v, want a refusal naming the identity actually served", err)
	}
	if got := mint.count(); got != 0 {
		t.Errorf("the host was asked %d time(s) before the leaf was checked: a mismatched identity must reach nothing, and the projected token travels on that request", got)
	}
}

// TestAnAuthenticatedCallerIsNotAutomaticallyAnAuthorisedOne is the confused
// deputy a second reviewer found behind "authenticated peers, both directions".
//
// Verifying a caller's certificate against the cell's anchor answers whether it
// holds an identity the platform issued. In a cell that is every workload,
// including the modules this solution consumes. So any of them could reach a
// handler or a passthrough route directly, bypassing the admission the host
// decides on its own routes — and since gatewayFor reads x-org-id and
// x-session-id as headers the gateway stamped from a verified bearer, such a
// caller could set them itself and have this runtime mint capabilities under
// *this workload's* attestation for an org and session nobody authenticated.
// The deputy being confused is the one process the issuer trusts to say which
// module is asking.
//
// Authentication was added in the previous round and authorisation was not,
// which is why the first reviewer asked for "authenticated, authorized peers".
func TestAnAuthenticatedCallerIsNotAutomaticallyAnAuthorisedOne(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	cell := newCell(t)
	certFile, keyFile, bundleFile, _, _ := cell.workload(t, testPrincipal)
	mint.serveTLS(t, cell)
	authorityValues(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected-token")
	func() { ln, port := boundPort(t); provideListener(t, ln); t.Setenv("PORT", port) }()
	t.Setenv("GATEWAY_URL", mint.URL)
	t.Setenv(CredentialMintURLEnvironmentVariable, mint.URL+credentialMintPath)
	t.Setenv(ProjectedTokenFileEnvironmentVariable, tokenFile)
	t.Setenv(IdentityCertFileEnvironmentVariable, certFile)
	t.Setenv(IdentityKeyFileEnvironmentVariable, keyFile)
	t.Setenv(IdentityTrustBundleFileEnvironmentVariable, bundleFile)
	t.Setenv(IdentityAllowedCallersFileEnvironmentVariable, identitiesFile(t, testGatewayPrincipal))
	t.Setenv(IdentityMintPeersFileEnvironmentVariable, identitiesFile(t, testGatewayPrincipal))
	t.Setenv(IdentityGatewayPeersFileEnvironmentVariable, identitiesFile(t, testGatewayPrincipal))
	t.Setenv(ContractProfileEnvironmentVariable, localProfile)
	t.Setenv("ASSETS_DIR", t.TempDir())

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	reached := make(chan struct{}, 8)
	server := New(Manifest{ID: testSolutionID}).Handle("/thing", func(context.Context, *Gateway) (any, error) {
		reached <- struct{}{}
		return map[string]string{"ok": "yes"}, nil
	})
	ln, err := takeListener(server).start(ctx)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- server.serve(ctx, ln) }()
	t.Cleanup(func() { cancel(); <-served })
	base := "https://127.0.0.1:" + os.Getenv("PORT")

	call := func(identity string) (*http.Response, error) {
		client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      cell.roots,
			Certificates: []tls.Certificate{*cell.identity(t, identity)},
			MinVersion:   tls.VersionTLS13,
		}}}
		request, err := http.NewRequest(http.MethodGet, base+"/thing", nil)
		if err != nil {
			t.Fatal(err)
		}
		request.Header.Set("authorization", viewerBearer())
		// The headers a caller must not be able to assert for itself.
		request.Header.Set(orgHeader, "org-the-caller-chose")
		request.Header.Set(sessionHeader, "session-the-caller-chose")
		request.Header.Set(workcontext.InstallationIDHeaderName, testInstallation)
		return client.Do(request)
	}

	t.Run("the gateway is served", func(t *testing.T) {
		resp, err := call(testGatewayPrincipal)
		if err != nil {
			t.Fatalf("the admitted caller was refused, so this check is just a broken listener: %v", err)
		}
		_ = resp.Body.Close()
		select {
		case <-reached:
		default:
			t.Error("the admitted caller did not reach the handler")
		}
	})

	for _, identity := range []string{
		// A module this solution consumes: holds a cell certificate, and is
		// precisely the party that must not be able to drive this runtime's
		// mints.
		"spiffe://codefly.test/ns/modules/sa/things",
		// Any other workload in the trust domain.
		"spiffe://codefly.test/ns/solutions/sa/someone-else",
	} {
		t.Run("refused: "+identity, func(t *testing.T) {
			resp, err := call(identity)
			if err == nil {
				defer func() { _ = resp.Body.Close() }()
				t.Errorf("a caller authenticated as %s was served %d: holding a certificate from this cell's anchor is not the same as being a caller this solution serves, and this one set its own %s and %s",
					identity, resp.StatusCode, orgHeader, sessionHeader)
			}
			select {
			case <-reached:
				t.Error("the handler ran for a caller this solution does not admit")
			default:
			}
		})
	}
}

// TestARotatedLeafIsStillHeldToTheFrozenPrincipal closes the half of the
// leaf check that only ran at boot.
//
// A source with no per-connection callback still rotates its leaf — that is what
// GetCertificate is for, and the projected pair is deliberately short-lived. The
// principal check ran once, against whatever was current then, so a rotation
// landing a certificate for a *different* workload (the wrong Secret replaced, a
// mesh CA re-issuing under a changed identity) would be served for the life of
// the process, with the one check that would have caught it having run before
// the file changed.
func TestARotatedLeafIsStillHeldToTheFrozenPrincipal(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)
	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{port: listenOn(t, server), identityCertFile: certFile, identityKeyFile: keyFile,
		trustBundleFile: bundleFile, allowedCallersFile: identitiesFile(t, testGatewayPrincipal), mintPeersFile: identitiesFile(t, testGatewayPrincipal),
		gatewayPeersFile: identitiesFile(t, testGatewayPrincipal)}
	server.principal = testPrincipal

	config, err := server.serverIdentity()
	if err != nil {
		t.Fatalf("the boot refused a conforming pair: %v", err)
	}
	if _, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"}); err != nil {
		t.Fatalf("the leaf current at boot was refused: %v", err)
	}

	// The projection is replaced with a pair for another workload, under the
	// same anchor so nothing else about it is wrong.
	rivalCert, rivalKey, _, _, _ := c.workload(t, "spiffe://codefly.test/ns/solutions/sa/another-workload")
	writeFile(t, certFile, readFile(t, rivalCert))
	writeFile(t, keyFile, readFile(t, rivalKey))

	_, err = config.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
	if err == nil {
		t.Fatal("a leaf issued for another workload was served after rotation: the principal check only ran at boot, against a file that has since changed")
	}
	if !strings.Contains(err.Error(), "another-workload") || !strings.Contains(err.Error(), testPrincipal) {
		t.Errorf("refusal %q does not name both the identity served and this workload's frozen principal", err)
	}
}

// anchorAnnouncingIdentity is a source that says what its anchor is, which is
// the only sound way for one that rotates to be re-checkable.
type anchorAnnouncingIdentity struct {
	config *tls.Config
	anchor func() *x509.CertPool
}

func (a anchorAnnouncingIdentity) ServerTLSConfig() (*tls.Config, error) { return a.config, nil }
func (a anchorAnnouncingIdentity) PeerAnchor() (*x509.CertPool, error)   { return a.anchor(), nil }

// TestASourcesAnchorIsAskedForAndNeverFabricated covers both halves of how a
// consumer's anchor is obtained, which pull in opposite directions.
//
// A *x509.CertPool carried on the base configuration is one object fixed when
// the source built it, so a source that rotates its anchor had every peer
// judged by the pool this process booted with. The previous answer to that was
// to call the source's GetConfigForClient with a fabricated ClientHelloInfo and
// read the pool off the answer — which is the blocker this cutover already has
// a name for: a source keyed on the hello answers a synthetic probe with one
// thing and the real handshake with another, demonstrably. Trading a stale
// anchor for a forged one is not a fix.
//
// So the source is asked directly, and a source that can only answer through a
// handshake is refused.
func TestASourcesAnchorIsAskedForAndNeverFabricated(t *testing.T) {
	boot := newCell(t)
	current := newCell(t)

	t.Run("a source that announces its anchor is followed", func(t *testing.T) {
		announced := boot.roots
		source := anchorAnnouncingIdentity{
			config: &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: boot.roots},
			anchor: func() *x509.CertPool { return announced },
		}
		anchor, err := peerAnchorFrom(source, source.config)
		if err != nil {
			t.Fatalf("peerAnchorFrom: %v", err)
		}
		if anchor != boot.roots {
			t.Fatal("the announced anchor was not used")
		}
		// It rotates, and nothing is rebuilt.
		announced = current.roots
		anchor, err = peerAnchorFrom(source, source.config)
		if err != nil {
			t.Fatalf("peerAnchorFrom after the rotation: %v", err)
		}
		if anchor != current.roots {
			t.Error("the anchor came from the base configuration after the source rotated: a pool on the base is fixed when the source built it, so every peer would be judged by the one this process booted with")
		}
	})

	t.Run("a source carrying only a base anchor uses it", func(t *testing.T) {
		config := &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: boot.roots}
		anchor, err := peerAnchorFrom(unaskableIdentity{config: config}, config)
		if err != nil {
			t.Fatalf("peerAnchorFrom: %v", err)
		}
		if anchor != boot.roots {
			t.Error("a source that carries its anchor on the configuration it returned had it ignored")
		}
	})

	t.Run("a per-handshake anchor with no way to ask for it is refused", func(t *testing.T) {
		// The shape that used to be answered with a fabricated hello: the pool
		// exists only inside the callback's answer.
		config := &tls.Config{
			MinVersion: tls.VersionTLS13,
			ClientAuth: tls.RequireAndVerifyClientCert,
			GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
				return &tls.Config{MinVersion: tls.VersionTLS13, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: current.roots}, nil
			},
		}
		anchor, err := peerAnchorFrom(unaskableIdentity{config: config}, config)
		if err == nil {
			t.Fatal("an anchor was obtained from a source that can only answer through a handshake: the only way to get one is to fabricate a ClientHelloInfo, and a source keyed on the hello answers a probe and a real handshake differently — which is the blocker this runtime was already held up on, one field along")
		}
		if anchor != nil {
			t.Error("a refusal returned a pool anyway")
		}
		if !strings.Contains(err.Error(), "PeerAnchor") {
			t.Errorf("the refusal %q does not name the interface that fixes it", err)
		}
	})
}

// unaskableIdentity is a source that does NOT implement PeerAnchorSource,
// which the test sources here otherwise do. It exists so the refusal for a
// source that can only answer through a handshake stays reachable.
type unaskableIdentity struct{ config *tls.Config }

func (u unaskableIdentity) ServerTLSConfig() (*tls.Config, error) { return u.config, nil }

// TestASourceCannotReplaceThePostureItIsHeldTo: the posture checks enumerate
// what a conforming listener must have, which a source can satisfy completely
// while handing back a configuration whose clock, randomness, session secrets
// or ticket encoding it controls.
//
// Resumption is the sharpest of them: a resumed connection presents no
// certificate, so a source encoding its own tickets decides who gets in
// without any check in this file seeing a handshake.
func TestASourceCannotReplaceThePostureItIsHeldTo(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)
	conforming := func(t *testing.T) *tls.Config {
		t.Helper()
		config, err := projectedIdentity{certFile: certFile, keyFile: keyFile, trustBundleFile: bundleFile}.ServerTLSConfig()
		if err != nil {
			t.Fatal(err)
		}
		return config
	}
	// The control: the shape every case below starts from is accepted.
	if err := usableServerIdentity(conforming(t)); err != nil {
		t.Fatalf("the conforming projected configuration was refused, so nothing below is about the field it changes: %v", err)
	}

	for _, tc := range []struct {
		name  string
		lower func(*tls.Config)
	}{
		{"a clock of its own", func(cfg *tls.Config) {
			cfg.Time = func() time.Time { return time.Unix(0, 0) }
		}},
		//nolint:staticcheck // Deliberately sets the deprecated field, to prove the refusal fires.
		{"a randomness source of its own", func(cfg *tls.Config) { cfg.Rand = strings.NewReader("not random") }},
		{"the session secrets written out", func(cfg *tls.Config) { cfg.KeyLogWriter = io.Discard }},
		{"resumption tickets it encodes", func(cfg *tls.Config) {
			cfg.WrapSession = func(tls.ConnectionState, *tls.SessionState) ([]byte, error) { return nil, nil }
		}},
		{"resumption tickets it decodes", func(cfg *tls.Config) {
			cfg.UnwrapSession = func([]byte, tls.ConnectionState) (*tls.SessionState, error) { return nil, nil }
		}},
		{"no verification at all", func(cfg *tls.Config) { cfg.InsecureSkipVerify = true }},
		{"a resumption ticket key of its own", func(cfg *tls.Config) {
			//nolint:staticcheck // Deliberately sets the deprecated field, to prove the refusal fires.
			cfg.SessionTicketKey = [32]byte{1}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := conforming(t)
			tc.lower(config)
			if err := usableServerIdentity(config); err == nil {
				t.Error("a configuration that keeps every enumerated requirement and replaces a posture Go owns was accepted: the checks answer whether the description is acceptable, which is not whether the handshake is")
			}
		})
	}

	// And a per-connection answer is held to the same list, not a copy of its
	// reasoning: the answer replaces the base for that connection.
	//
	// The answer carries a real anchor, which is the part this case got wrong
	// before: without one it was refused for the missing pool, so the
	// assertion held whether or not the denylist was applied to the answer at
	// all, and the mutant that stopped applying it survived.
	anchor, err := peerAnchor(bundleFile)
	if err != nil {
		t.Fatal(err)
	}
	answered := func(lower func(*tls.Config)) *tls.Config {
		base := conforming(t)
		base.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
			answer := conforming(t)
			answer.GetConfigForClient = nil
			answer.ClientCAs = anchor
			lower(answer)
			return answer, nil
		}
		holdPerConnectionPosture(base, testPrincipal, func() ([]string, error) { return []string{testGatewayPrincipal}, nil })
		return base
	}

	// The control: a conforming answer, with the anchor, is served.
	if _, err := answered(func(*tls.Config) {}).GetConfigForClient(&tls.ClientHelloInfo{}); err != nil {
		t.Fatalf("a conforming per-connection answer was refused, so nothing below is about the denylist: %v", err)
	}
	for _, tc := range []struct {
		name, names string
		lower       func(*tls.Config)
	}{
		{"the session secrets written out", "KeyLogWriter", func(cfg *tls.Config) { cfg.KeyLogWriter = io.Discard }},
		{"a clock of its own", "Time", func(cfg *tls.Config) { cfg.Time = func() time.Time { return time.Unix(0, 0) } }},
		{"its own chain verifier", "VerifyPeerCertificate", func(cfg *tls.Config) {
			cfg.VerifyPeerCertificate = func([][]byte, [][]*x509.Certificate) error { return nil }
		}},
	} {
		t.Run("per connection: "+tc.name, func(t *testing.T) {
			_, err := answered(tc.lower).GetConfigForClient(&tls.ClientHelloInfo{})
			if err == nil {
				t.Fatalf("a per-connection answer setting %s was served: the configuration a callback returns replaces the base one, so it is held to the same posture", tc.names)
			}
			// And refused for THAT, not for something else the answer happens
			// to be missing.
			if !strings.Contains(err.Error(), tc.names) {
				t.Errorf("the refusal %q does not name %s, so this case does not cover it", err, tc.names)
			}
		})
	}
}

// TestASourcesConfigurationIsNotMutated: serverIdentity wraps GetCertificate,
// composes over VerifyConnection and wraps GetConfigForClient — all writes —
// and it did them to the configuration the source handed back.
//
// A source is under no obligation to return a fresh one. Returning a
// configuration it builds once and keeps is the ordinary way to write a source,
// and then those writes land on a value another handshake may be reading, and a
// second resolution wraps the wrapper. holdPerConnectionPosture says exactly
// this about a per-connection answer, in those words, and this function did the
// thing that comment forbids one level up.
func TestASourcesConfigurationIsNotMutated(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)
	shared, err := projectedIdentity{certFile: certFile, keyFile: keyFile, trustBundleFile: bundleFile}.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	before := struct {
		verify   bool
		perConn  bool
		getCert  bool
		numCerts int
	}{
		verify:   shared.VerifyConnection != nil,
		perConn:  shared.GetConfigForClient != nil,
		getCert:  shared.GetCertificate != nil,
		numCerts: len(shared.Certificates),
	}

	server := New(Manifest{ID: testSolutionID}).Identity(staticIdentity{config: shared})
	server.cfg = config{allowedCallersFile: identitiesFile(t, testGatewayPrincipal)}
	server.principal = testPrincipal
	config, err := server.serverIdentity()
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	if config == shared {
		t.Fatal("serverIdentity returned the source's own configuration: everything it applies is a write, so the source's value is being modified while it may be in use elsewhere")
	}
	if (shared.VerifyConnection != nil) != before.verify {
		t.Error("the source's VerifyConnection was written: the admission check belongs on this runtime's copy, not on the value the source keeps")
	}
	if (shared.GetConfigForClient != nil) != before.perConn {
		t.Error("the source's GetConfigForClient was wrapped in place")
	}
	if (shared.GetCertificate != nil) != before.getCert || len(shared.Certificates) != before.numCerts {
		t.Error("the source's certificate selection was rewritten in place")
	}
	// And the copy this runtime serves does carry the checks, or the test
	// above is satisfied by a runtime that applies nothing at all.
	if config.VerifyConnection == nil {
		t.Error("the configuration this listener serves carries no caller admission")
	}
}
