package solution

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// The mint request carries the declared prefix and, beside it, the dynamic half
// of this runtime's registration: where it serves and the manifest it serves.
// Nothing else — a field the host does not read is a field nobody reviewed.
var brokerBodyKeys = map[string]bool{"prefix": true, "upstream": true, "manifest": true}

func onlyBrokerBodyKeys(body map[string]string) bool {
	for key := range body {
		if !brokerBodyKeys[key] {
			return false
		}
	}
	return true
}

// requireBrokerBody holds a mint body to the protocol: exactly the declared
// prefix, an https origin when an upstream is reported, and this solution's own
// manifest when one is reported.
func requireBrokerBody(t *testing.T, raw []byte, prefix string) map[string]string {
	t.Helper()
	var body map[string]string
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatalf("broker body is not a flat JSON object of strings: %s", raw)
	}
	if body["prefix"] != prefix || !onlyBrokerBodyKeys(body) {
		t.Fatalf("broker body must carry the declared prefix and only the dynamic half beside it: %s", raw)
	}
	if upstream, reported := body["upstream"]; reported {
		parsed, err := url.Parse(upstream)
		if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.Port() == "" || (parsed.Path != "" && parsed.Path != "/") || parsed.RawQuery != "" || parsed.User != nil {
			t.Fatalf("a reported upstream must be an https origin and nothing more: %q", upstream)
		}
	}
	if manifest, reported := body["manifest"]; reported {
		var document struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal([]byte(manifest), &document); err != nil || document.ID != prefix {
			t.Fatalf("a reported manifest must be this solution's own: %s", manifest)
		}
	}
	return body
}

// The host records a solution's backend origin and frontend manifest from the
// mint, under the identity the projected token proves, since nothing
// self-registers. A runtime that knows where it serves therefore says so, and a
// runtime that does not — no resolved endpoint — reports no origin rather than
// a guessed one.
func TestTheMintReportsWhereThisRuntimeServesAndItsManifest(t *testing.T) {
	for _, tc := range []struct {
		name, upstream string
	}{
		{"with a resolved endpoint", "https://localhost:22631"},
		{"without one", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, host, _ := brokerFixture(t)
			s.cfg.upstream = tc.upstream
			options := s.mintOptions("accounts", func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }, func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil })
			options.Authority = fixedAuthority{audience: testAudience}
			source, err := newBrokerCredentialSource(options)
			if err != nil {
				t.Fatal(err)
			}
			var sent map[string]string
			source.client.Transport = mintRoundTrip(func(r *http.Request) (*http.Response, error) {
				raw, err := io.ReadAll(r.Body)
				if err != nil {
					t.Fatal(err)
				}
				sent = requireBrokerBody(t, raw, testSolutionID)
				r.Body = io.NopCloser(strings.NewReader(string(raw)))
				response := httptest.NewRecorder()
				host.serve(response, r)
				return response.Result(), nil
			})
			if _, err := source.Credential(context.Background()); err != nil {
				t.Fatal(err)
			}
			if got, reported := sent["upstream"]; got != tc.upstream || reported != (tc.upstream != "") {
				t.Fatalf("upstream reported as %q (present: %v), want %q", got, reported, tc.upstream)
			}
			if sent["manifest"] == "" {
				t.Fatal("the mint did not report this solution's manifest")
			}
		})
	}
}
