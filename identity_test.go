package solution

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
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
		names    string
		variable string
	}{
		{name: "no certificate", key: keyFile, token: "t", bundle: bundleFile, names: "certificate", variable: IdentityCertFileEnvironmentVariable},
		{name: "no private key", cert: certFile, token: "t", bundle: bundleFile, names: "private key", variable: IdentityKeyFileEnvironmentVariable},
		{name: "no trust anchor", cert: certFile, key: keyFile, token: "t", names: "trust anchor", variable: IdentityTrustBundleFileEnvironmentVariable},
		{name: "no projected token", cert: certFile, key: keyFile, bundle: bundleFile, names: "projected service-account token", variable: ProjectedTokenFileEnvironmentVariable},
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
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := New(Manifest{ID: testSolutionID}).Identity(staticIdentity{config: tc.config})
			server.cfg = config{port: freePort(t)}
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
		server.cfg = config{port: freePort(t)}
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
	server.cfg = config{port: freePort(t), identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile}
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
		if err := presentsThisWorkload(stripped, testPrincipal); err == nil || !strings.Contains(err.Error(), "no URI identity at all") {
			t.Errorf("presentsThisWorkload = %v, want a refusal distinguishing no identity from the wrong one", err)
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
type staticIdentity struct{ config *tls.Config }

func (s staticIdentity) ServerTLSConfig() (*tls.Config, error) { return s.config, nil }

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
