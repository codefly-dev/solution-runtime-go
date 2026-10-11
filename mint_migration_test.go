package solution

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workcontext"
)

func TestProjectedTokenDefaultsToTheCLIProjection(t *testing.T) {
	t.Setenv(ProjectedTokenFileEnvironmentVariable, "")
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__WORKLOAD_IDENTITY__TOKEN_FILE", "")
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })
	cfg := loadConfig(context.Background(), testSolutionID, nil)
	if cfg.projectedTokenPath != "/var/run/secrets/codefly/token" {
		t.Fatalf("token path = %q, want the CLI projection", cfg.projectedTokenPath)
	}
	t.Setenv(ProjectedTokenFileEnvironmentVariable, "/operator/token")
	if got := loadConfig(context.Background(), testSolutionID, nil).projectedTokenPath; got != "/operator/token" {
		t.Fatalf("explicit token path = %q", got)
	}
}

func TestRuntimeProjectedTokenReaderReadsFreshAndFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "token")
	source := projectedTokenFile(path)
	for _, value := range []string{"first-projection", "rotated-projection"} {
		writeFile(t, path, "\n"+value+"\n")
		got, err := source.ProjectedToken()
		if err != nil || got != value {
			t.Fatalf("fresh token = %q, %v", got, err)
		}
	}
	for _, value := range []string{"", " \n\t", strings.Repeat("x", 65537)} {
		writeFile(t, path, value)
		got, err := source.ProjectedToken()
		if got != "" || !errors.Is(err, workcontext.ErrMintUnavailable) {
			t.Fatalf("unusable projection returned a token or wrong class: %v", err)
		}
	}
}

// Exercise the production source, including its TLS readers and error boundary.
func productionMintSource(t *testing.T, mint *hostMint, tokenFile string) *brokerCredentialSource {
	t.Helper()
	cert, key, bundle, _, _, _ := bootIdentityIn(t, mint, testPrincipal)
	s := New(Manifest{ID: testSolutionID})
	s.cfg = config{
		identityCertFile: cert, identityKeyFile: key, trustBundleFile: bundle,
		allowedCallersFile:  identitiesFile(t, testGatewayPrincipal),
		mintPeersFile:       identitiesFile(t, testGatewayPrincipal),
		gatewayPeersFile:    identitiesFile(t, testGatewayPrincipal),
		brokerInternalToken: "broker-perimeter-token",
		mintURL:             mint.URL + credentialMintPath, projectedTokenPath: tokenFile,
	}
	s.principal = testPrincipal
	s.authority = authorityFor(t, context.Background())
	source, err := s.platformCredentialSource()
	if err != nil {
		t.Fatal(err)
	}
	return source
}

func TestUnusableProjectedTokenNeverReachesTheMint(t *testing.T) {
	for _, kind := range []string{"missing", "unreadable", "empty", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "token")
			switch kind {
			case "unreadable":
				// A directory fails a read even under an elevated test runner.
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			case "empty":
				writeFile(t, path, " \n")
			case "oversized":
				writeFile(t, path, strings.Repeat("x", 65537))
			}
			mint := newHostMint(t, &hostMint{})
			source := productionMintSource(t, mint, path)
			credential, err := source.Credential(context.Background())
			if credential.Token() != "" || !terminalCredentialFailure(err) {
				t.Fatalf("unusable projection did not fail closed: %v", err)
			}
			if !strings.Contains(err.Error(), "projected service-account token") || strings.Contains(err.Error(), path) {
				t.Fatalf("projection error is unclear or discloses its raw path: %v", err)
			}
			if mint.count() != 0 {
				t.Fatal("unusable token reached the broker")
			}
		})
	}
}

func TestExecutionMintErrorsDiscardTheirEntireCauseChain(t *testing.T) {
	const diagnostic = "broker-reflected-credential"
	for _, class := range []error{workcontext.ErrMintRefused, workcontext.ErrMintUnavailable, errors.New("unclassified")} {
		raw := fmt.Errorf("%w: %s", class, diagnostic)
		source := New(Manifest{ID: testSolutionID}).Credential(refusingSource{err: raw}).credential
		_, err := source.Credential(context.Background())
		if err == nil || strings.Contains(err.Error(), diagnostic) || errors.Is(err, raw) {
			t.Fatalf("broker diagnostic escaped: %v", err)
		}
		if class == workcontext.ErrMintRefused || class == workcontext.ErrMintUnavailable {
			if !errors.Is(err, class) {
				t.Fatalf("lost mint classification: %v", err)
			}
		}
	}
}

type reflectedCredentialSource struct{ calls atomic.Int64 }

func (s *reflectedCredentialSource) Credential(context.Context) (workcontext.Credential, error) {
	s.calls.Add(1)
	return workcontext.Credential{}, fmt.Errorf("%w: broker-reflected-credential", workcontext.ErrMintRefused)
}

func TestCredentialRefusalNeverLogsDiagnosticsOrRetries(t *testing.T) {
	output := &syncBuffer{}
	previous := log.Writer()
	log.SetOutput(output)
	defer log.SetOutput(previous)
	source := &reflectedCredentialSource{}
	server := New(Manifest{ID: testSolutionID}).Credential(source)
	for range 3 {
		err := server.actingForAViewer(context.Background())
		if !errors.Is(err, ErrCredentialRefused) || strings.Contains(err.Error(), "broker-reflected-credential") {
			t.Fatalf("credential refusal lost its class or exposed diagnostics: %v", err)
		}
	}
	if source.calls.Load() != 1 {
		t.Fatalf("refused source was asked %d times", source.calls.Load())
	}
	if strings.Contains(output.String(), "broker-reflected-credential") || !strings.Contains(output.String(), "refused") {
		t.Fatalf("refusal log disclosed diagnostics or omitted its classification: %s", output.String())
	}
}

type mintRoundTrip func(*http.Request) (*http.Response, error)

func (f mintRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestViewerMintDiscardsResponseAndTransportDiagnostics(t *testing.T) {
	const diagnostic = "broker-reflected-credential"
	for _, kind := range []string{"401", "403", "503", "redirect", "malformed-json", "transport"} {
		t.Run(kind, func(t *testing.T) {
			gw := newGateway("https://gateway.example", "viewer", "org", "session")
			source := attestingSource(t)
			gw.workload = func(ctx context.Context) (executionCredential, error) { return source.Credential(ctx) }
			calls := 0
			gw.transport = mintRoundTrip(func(r *http.Request) (*http.Response, error) {
				calls++
				if kind == "transport" {
					return nil, errors.New(diagnostic)
				}
				status := map[string]int{"401": 401, "403": 403, "503": 503, "redirect": 307, "malformed-json": 200}[kind]
				return &http.Response{
					StatusCode: status, Request: r,
					Header: http.Header{"Location": {"https://elsewhere.example/" + diagnostic}, "X-Diagnostic": {diagnostic}},
					Body:   io.NopCloser(strings.NewReader(`{"expiresAt":"` + diagnostic + `","message":"` + diagnostic + `"}`)),
				}, nil
			})
			_, _, err := gw.mint(context.Background(), startTaskRequest{Audience: "documents"})
			if err == nil || strings.Contains(err.Error(), diagnostic) || strings.Contains(relayedError(err).Error(), diagnostic) {
				t.Fatalf("mint error disclosed response or transport text: %v", err)
			}
			if calls != 1 {
				t.Fatalf("mint followed a redirect or retried: %d calls", calls)
			}
			var refusal *WorkContextRefusal
			if kind == "401" || kind == "403" || kind == "503" || kind == "redirect" {
				if !errors.As(err, &refusal) {
					t.Fatalf("lost response classification: %v", err)
				}
			}
		})
	}
}

func TestViewerMintRefusalsAreTerminalForTheSameAsk(t *testing.T) {
	for _, status := range []int{401, 403} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			cache := newWorkContextCache()
			var calls atomic.Int64
			refusal := &WorkContextRefusal{StatusCode: status}
			mint := func(context.Context) (string, time.Time, error) { calls.Add(1); return "", time.Time{}, refusal }
			var wait sync.WaitGroup
			for range 20 {
				wait.Add(1)
				go func() {
					defer wait.Done()
					if _, err := cache.resolve(context.Background(), "same-ask", mint); err != refusal {
						t.Errorf("refusal = %v", err)
					}
				}()
			}
			wait.Wait()
			for range 3 {
				if _, err := cache.resolve(context.Background(), "same-ask", mint); err != refusal {
					t.Fatalf("refusal = %v", err)
				}
			}
			if calls.Load() != 1 {
				t.Fatalf("refusal automatically re-minted %d times", calls.Load())
			}
			_, _ = cache.resolve(context.Background(), "different-ask", mint)
			if calls.Load() != 2 {
				t.Fatal("refusal incorrectly latched a different ask")
			}
		})
	}
}
