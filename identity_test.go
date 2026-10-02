package solution

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestABootWithoutAWorkloadIdentityIsRefusedByName is the acceptance criterion
// for removing plain HTTP: the runtime refuses a listener configuration it
// cannot present an identity for, and names the material that is missing. A
// solution that came up on plain HTTP would be refused at the edge instead,
// for a reason only the edge can see.
func TestABootWithoutAWorkloadIdentityIsRefusedByName(t *testing.T) {
	certFile, keyFile, _ := workloadIdentity(t)
	for _, tc := range []struct {
		name     string
		cert     string
		key      string
		token    string
		names    string
		variable string
	}{
		{name: "no certificate", key: keyFile, token: "t", names: "certificate", variable: IdentityCertFileEnvironmentVariable},
		{name: "no private key", cert: certFile, token: "t", names: "private key", variable: IdentityKeyFileEnvironmentVariable},
		{name: "no projected token", cert: certFile, key: keyFile, names: "projected service-account token", variable: ProjectedTokenFileEnvironmentVariable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config{
				port:               "8080",
				gatewayURL:         "http://gateway:42152",
				mintURL:            "http://gateway:42152" + credentialMintPath,
				identityCertFile:   tc.cert,
				identityKeyFile:    tc.key,
				projectedTokenPath: tc.token,
				profile:            localProfile,
			}
			err := cfg.validate()
			if err == nil {
				t.Fatal("validate accepted a configuration with no workload identity")
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

// TestAnIdentitySourceThatPresentsNothingIsRefused: a source is consumer code,
// and one that returns a bare configuration would produce a listener that
// completes no handshake at all — reported to every caller as a TLS error
// naming nothing.
func TestAnIdentitySourceThatPresentsNothingIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source IdentitySource
	}{
		{"no configuration at all", staticIdentity{}},
		{"a configuration with no certificate", staticIdentity{config: &tls.Config{MinVersion: tls.VersionTLS13}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := New(Manifest{ID: "lastlogin-go"}).Identity(tc.source)
			server.cfg = config{port: freePort(t)}
			ln, err := server.listen()
			if ln != nil {
				_ = ln.Close()
			}
			if err == nil {
				t.Fatal("listen came up on an identity source that presents no certificate")
			}
			if !strings.Contains(err.Error(), "plain-HTTP") && !strings.Contains(err.Error(), "no certificate") {
				t.Errorf("refusal %q says neither that there is no certificate nor that there is no plain-HTTP fallback", err)
			}
		})
	}
}

// TestAnUnusableTrustBundleIsRefusedNotDropped: a bundle that cannot be parsed
// is the one case where carrying on is worse than refusing. Dropped, the
// listener comes up verifying no peer at all — exactly what configuring a
// bundle was meant to prevent — and nothing says so.
func TestAnUnusableTrustBundleIsRefusedNotDropped(t *testing.T) {
	certFile, keyFile, _ := workloadIdentity(t)
	bundle := filepath.Join(t.TempDir(), "ca.crt")
	writeFile(t, bundle, "not a certificate")
	_, err := projectedIdentity{certFile: certFile, keyFile: keyFile, trustBundleFile: bundle}.ServerTLSConfig()
	if err == nil {
		t.Fatal("an unparseable trust bundle was accepted")
	}
	if !strings.Contains(err.Error(), "no certificate") {
		t.Errorf("refusal %q does not say the bundle carries no certificate", err)
	}

	if err := os.Remove(bundle); err != nil {
		t.Fatal(err)
	}
	_, err = projectedIdentity{certFile: certFile, keyFile: keyFile, trustBundleFile: bundle}.ServerTLSConfig()
	if err == nil || !strings.Contains(err.Error(), IdentityTrustBundleFileEnvironmentVariable) {
		t.Errorf("a missing trust bundle was reported as %v, want a refusal naming %s", err, IdentityTrustBundleFileEnvironmentVariable)
	}
}

// TestAProjectedTrustBundleMakesTheListenerVerifyItsPeers: with an anchor
// projected, the listener requires and verifies a client certificate. Without
// one it cannot, which is why its absence is logged rather than assumed.
func TestAProjectedTrustBundleMakesTheListenerVerifyItsPeers(t *testing.T) {
	certFile, keyFile, _ := workloadIdentity(t)
	withBundle, err := projectedIdentity{certFile: certFile, keyFile: keyFile, trustBundleFile: certFile}.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if withBundle.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Errorf("ClientAuth = %v, want RequireAndVerifyClientCert when the platform projects an anchor", withBundle.ClientAuth)
	}
	if withBundle.MinVersion != tls.VersionTLS13 {
		t.Errorf("MinVersion = %x, want TLS 1.3", withBundle.MinVersion)
	}
	withoutBundle, err := projectedIdentity{certFile: certFile, keyFile: keyFile}.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	if withoutBundle.ClientAuth != tls.NoClientCert {
		t.Errorf("ClientAuth = %v with no anchor projected, want NoClientCert: the runtime cannot invent the anchor its callers are issued under", withoutBundle.ClientAuth)
	}
	if withoutBundle.GetCertificate == nil {
		t.Error("GetCertificate is nil: a rotated leaf would never reach a handshake")
	}
}

// TestTheListenerServesTheRotatedLeaf: workload leaves are short-lived and
// rotated well before expiry, so a listener that loaded its pair once at boot
// serves a stale leaf while a valid one sits on disk, and then fails every
// handshake with the issuer reporting nothing wrong.
func TestTheListenerServesTheRotatedLeaf(t *testing.T) {
	certFile, keyFile, _ := workloadIdentity(t)
	config, err := projectedIdentity{certFile: certFile, keyFile: keyFile}.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	first, err := config.GetCertificate(&tls.ClientHelloInfo{ServerName: "localhost"})
	if err != nil {
		t.Fatal(err)
	}
	rotatedCert, rotatedKey, _ := workloadIdentity(t)
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

func readFile(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
