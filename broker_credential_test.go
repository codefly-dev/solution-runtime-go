package solution

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workcontext"
)

// The fake broker runs as an HTTP handler through an in-memory transport. This
// tests the actual request/response boundary even where listening is forbidden.
func brokerFixture(t *testing.T) (*Server, *hostMint, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "projection")
	writeFile(t, path, "projected-first")
	host := &hostMint{ttl: time.Hour}
	host.prepareAuthority(t)
	s := New(Manifest{ID: testSolutionID})
	s.cfg.mintURL = "https://broker.example/modules/_work-context"
	s.cfg.brokerInternalToken = "broker-perimeter-token"
	s.cfg.projectedTokenPath = path
	options := s.mintOptions("accounts", func() (*x509.CertPool, error) { return x509.NewCertPool(), nil }, func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil })
	options.Authority = fixedAuthority{audience: testAudience}
	c, err := newBrokerCredentialSource(options)
	if err != nil {
		t.Fatal(err)
	}
	c.client.Transport = mintRoundTrip(func(r *http.Request) (*http.Response, error) {
		response := httptest.NewRecorder()
		host.serve(response, r)
		return response.Result(), nil
	})
	s.brokerCredential = c
	return s, host, path
}

func TestBrokerExecutionProtocolConformance(t *testing.T) {
	s, host, path := brokerFixture(t)
	c := s.brokerCredential
	wire := c.client.Transport
	expectedProjection := "projected-first"
	c.client.Transport = mintRoundTrip(func(r *http.Request) (*http.Response, error) {
		if r.Method != "POST" || r.URL.String() != "https://broker.example/modules/_work-context" {
			t.Fatalf("wrong broker method or endpoint: %s %s", r.Method, r.URL)
		}
		for key, want := range map[string]string{"Authorization": "Bearer " + expectedProjection, "X-Codefly-Internal-Token": "broker-perimeter-token", "Content-Type": "application/json", "Accept": "application/json"} {
			if r.Header.Get(key) != want {
				t.Fatalf("wrong broker header %s", key)
			}
		}
		if r.Header.Get("X-Codefly-Module-Secret") != "" || r.Header.Get("X-Codefly-Module-Registration") != "" {
			t.Fatal("legacy credential header reached broker")
		}
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		requireBrokerBody(t, raw, "widgets-go")
		r.Body = io.NopCloser(strings.NewReader(string(raw)))
		return wire.RoundTrip(r)
	})
	if err := s.openCredential(context.Background()); err != nil {
		t.Fatal(err)
	}
	first, err := s.acquireCredential(context.Background())
	if err != nil || first.Token() == "" {
		t.Fatalf("broker response was not accepted: %v", err)
	}
	for range 20 {
		held, err := s.acquireCredential(context.Background())
		if err != nil || held.Token() != first.Token() {
			t.Fatalf("cached execution changed: %v", err)
		}
	}
	if host.count() != 1 {
		t.Fatalf("cached execution minted %d times", host.count())
	}
	// The controller's viewer gateway and health gate both see the broker source.
	if s.gatewayFor(http.Header{}).workload == nil {
		t.Fatal("viewer mint lost execution attestation")
	}
	expectedProjection = "projected-rotated"
	writeFile(t, path, expectedProjection)
	c.renewAt = time.Time{}
	renewed, err := s.acquireCredential(context.Background())
	if err != nil || renewed.Token() == first.Token() || host.count() != 2 {
		t.Fatalf("renewal did not re-read projection: %v", err)
	}
}

type unreadBrokerBody struct{}

func (unreadBrokerBody) Read([]byte) (int, error) { panic("non-200 broker body was read") }
func (unreadBrokerBody) Close() error             { return nil }

func TestBrokerStatusClassesAndRetryAllowlist(t *testing.T) {
	for _, status := range []int{201, 204, 301, 307, 400, 401, 403, 404, 408, 409, 422, 429, 500, 502, 503, 504} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			s, _, _ := brokerFixture(t)
			var calls atomic.Int64
			s.brokerCredential.client.Transport = mintRoundTrip(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return &http.Response{StatusCode: status, Body: unreadBrokerBody{}, Header: http.Header{"Location": {"https://elsewhere.example/private-token"}}}, nil
			})
			_, firstErr := s.brokerCredential.Credential(context.Background())
			s.firstMintWindow = 60 * time.Millisecond
			err := s.openCredential(context.Background())
			var broker *brokerMintError
			if !errors.As(firstErr, &broker) || broker.status != status {
				t.Fatalf("lost status: %v", err)
			}
			retry := status == 503
			refused := status == 401 || status == 403
			if broker.retryable() != retry || errors.Is(firstErr, workcontext.ErrMintRefused) != refused || errors.Is(firstErr, workcontext.ErrMintUnavailable) != retry || errors.Is(err, workcontext.ErrMintUnavailable) != retry {
				t.Fatalf("incorrect classification: %v", err)
			}
			if strings.Contains(err.Error(), "private-token") {
				t.Fatal("broker diagnostics escaped")
			}
			if retry {
				if calls.Load() < 2 {
					t.Fatalf("503 not retried: %d", calls.Load())
				}
			} else {
				if calls.Load() != 1 {
					t.Fatalf("terminal HTTP %d retried %d times", status, calls.Load())
				}
				// A renewal uses the same classification and records it even with no waiter.
				for range 3 {
					_, _ = s.acquireCredential(context.Background())
				}
				if calls.Load() != 1 || s.terminalErr.Load() == nil {
					t.Fatal("terminal result was not retained by renewal controller")
				}
			}
		})
	}
}

func TestBrokerTransportCategoriesAndRetryAllowlist(t *testing.T) {
	for _, tc := range []struct {
		name     string
		cause    error
		category brokerTransportCategory
		retry    bool
	}{
		{"deadline", context.DeadlineExceeded, brokerTransportTimeout, true},
		{"timeout", &net.DNSError{Err: "private-token", IsTimeout: true}, brokerTransportTimeout, true},
		{"refused", syscall.ECONNREFUSED, brokerTransportRefused, true},
		{"reset", syscall.ECONNRESET, brokerTransportReset, true},
		{"cancelled", context.Canceled, brokerTransportOther, false},
		{"tls", x509.UnknownAuthorityError{}, brokerTransportTLS, false},
		{"dns", &net.DNSError{Err: "private-token", IsNotFound: true}, brokerTransportOther, false},
		{"parser", errors.New("private-token: malformed HTTP response"), brokerTransportOther, false},
		{"eof", io.ErrUnexpectedEOF, brokerTransportOther, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _, _ := brokerFixture(t)
			var calls atomic.Int64
			raw := &url.Error{Op: "POST", URL: "https://private-token.example", Err: fmt.Errorf("private-token: %w", tc.cause)}
			s.brokerCredential.client.Transport = mintRoundTrip(func(*http.Request) (*http.Response, error) { calls.Add(1); return nil, raw })
			_, firstErr := s.brokerCredential.Credential(context.Background())
			s.firstMintWindow = 60 * time.Millisecond
			err := s.openCredential(context.Background())
			var broker *brokerMintError
			if !errors.As(firstErr, &broker) || broker.transport != tc.category || broker.retryable() != tc.retry || errors.Is(err, workcontext.ErrMintUnavailable) != tc.retry {
				t.Fatalf("incorrect transport class: %v", err)
			}
			if strings.Contains(err.Error(), "private-token") || errors.Is(err, raw) || errors.Is(err, tc.cause) {
				t.Fatalf("raw transport cause escaped: %v", err)
			}
			if tc.retry && calls.Load() < 2 || !tc.retry && calls.Load() != 1 {
				t.Fatalf("retry=%v, calls=%d", tc.retry, calls.Load())
			}
		})
	}
}

func TestBrokerInvalidResponsesAreTerminal(t *testing.T) {
	for _, raw := range []string{`{}`, `null`, `{"work_context":"old-protocol"}`, `{"token":"invalid","expiresAt":"2099-01-01T00:00:00Z","principalId":"principal","tenant":"tenant"}`, `{"token":"private-token","expiresAt":"private-token"}`, `{"token":`, strings.Repeat("x", (64<<10)+1)} {
		s, _, _ := brokerFixture(t)
		calls := 0
		s.brokerCredential.client.Transport = mintRoundTrip(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(raw))}, nil
		})
		for range 2 {
			_, err := s.brokerCredential.Credential(context.Background())
			if !terminalCredentialFailure(err) || errors.Is(err, workcontext.ErrMintUnavailable) || strings.Contains(err.Error(), "private-token") {
				t.Fatalf("invalid broker answer not safely terminal: %v", err)
			}
		}
		if calls != 1 {
			t.Fatalf("invalid response retried: %d", calls)
		}
	}
}

func TestBrokerConfigurationUsesDeclaredSecretAndRefusesMissingValues(t *testing.T) {
	authorityValues(t)
	t.Setenv("CODEFLY_INTERNAL_TOKEN", "legacy-token-must-not-be-used")
	cfg := loadConfig(context.Background(), testSolutionID, nil)
	if cfg.brokerInternalToken != "broker-perimeter-token" {
		t.Fatal("broker did not read declared workspace secret")
	}
	t.Setenv("CODEFLY__WORKSPACE_SECRET_CONFIGURATION__MODULE_AUTHORITY__INTERNAL_TOKEN", "")
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	cfg = loadConfig(context.Background(), testSolutionID, nil)
	cfg.port, cfg.gatewayURL, cfg.mintURL, cfg.profile = "8080", "https://broker.example", "https://broker.example/modules/_work-context", localProfile
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "module-authority/INTERNAL_TOKEN") {
		t.Fatalf("missing declared perimeter token was accepted: %v", err)
	}
	s, _, _ := brokerFixture(t)
	options := s.brokerCredential.options
	for _, field := range []string{"prefix", "secret", "audience", "path"} {
		bad := options
		switch field {
		case "prefix":
			bad.Prefix = ""
		case "secret":
			bad.InternalToken = ""
		case "audience":
			bad.ProjectionAudience = "different"
		case "path":
			bad.URL = "https://broker.example/platform/_credential"
		}
		if _, err := newBrokerCredentialSource(bad); err == nil {
			t.Fatalf("accepted missing/wrong %s", field)
		}
	}
}

type brokerTokenRead func() (string, error)

func (read brokerTokenRead) ProjectedToken() (string, error) { return read() }

func TestBrokerProjectionWaitIsBoundedAndDoesNotAccumulateReaders(t *testing.T) {
	s, host, _ := brokerFixture(t)
	c := s.brokerCredential
	release := make(chan struct{})
	var calls atomic.Int64
	c.options.ProjectedToken = brokerTokenRead(func() (string, error) {
		calls.Add(1)
		<-release
		return "late-projection", nil
	})
	for range 3 {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, err := c.Credential(ctx)
		cancel()
		if !errors.Is(err, workcontext.ErrMintUnavailable) {
			t.Fatalf("blocked read lost its timeout category: %v", err)
		}
	}
	if calls.Load() != 1 || host.count() != 0 {
		t.Fatal("blocked reads accumulated or disclosed a late projection")
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for c.tokenReading.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if c.tokenReading.Load() {
		t.Fatal("reader slot not released")
	}
	if host.count() != 0 {
		t.Fatal("late token sent a mint")
	}
}

func TestBrokerTransientRenewalKeepsHeldCredentialAndBacksOff(t *testing.T) {
	s, host, _ := brokerFixture(t)
	if err := s.openCredential(context.Background()); err != nil {
		t.Fatal(err)
	}
	initial, _ := s.heldCredential()
	s.brokerCredential.renewAt = time.Time{}
	host.status = 503
	for range 20 {
		held, err := s.acquireCredential(context.Background())
		if err != nil || held.Token() != initial.Token() {
			t.Fatalf("transient renewal discarded held credential: %v", err)
		}
	}
	if host.count() != 2 || s.terminalErr.Load() != nil {
		t.Fatalf("transient renewal did not back off: %d mints", host.count())
	}
}

func TestBrokerTerminalRenewalDiscardsHeldAuthority(t *testing.T) {
	s, host, _ := brokerFixture(t)
	if err := s.openCredential(context.Background()); err != nil {
		t.Fatal(err)
	}
	s.brokerCredential.renewAt = time.Time{}
	host.status = 429
	for range 3 {
		_, err := s.acquireCredential(context.Background())
		var broker *brokerMintError
		if !errors.Is(err, ErrCredentialRefused) || !errors.As(err, &broker) || broker.status != 429 {
			t.Fatalf("terminal renewal served held authority or lost classification: %v", err)
		}
	}
	if host.count() != 2 {
		t.Fatalf("terminal renewal retried: %d", host.count())
	}
	if err := s.actingForAViewer(context.Background()); err == nil {
		t.Fatal("viewer gate ignored terminal broker failure")
	}
	recorder := httptest.NewRecorder()
	s.handleHealth(recorder, httptest.NewRequest("GET", "/health", nil))
	if recorder.Code == http.StatusOK {
		t.Fatal("health accepted terminal broker failure")
	}
}

type brokerAuthorityPin struct {
	fixedAuthority
	drift atomic.Bool
}

func (p *brokerAuthorityPin) Recheck(context.Context) error {
	if p.drift.Load() {
		return errors.New("private-authority-diagnostic")
	}
	return nil
}

func TestBrokerHoldsAuthorityAndExecutionAcrossRenewals(t *testing.T) {
	for _, when := range []string{"before", "during"} {
		t.Run("authority-"+when, func(t *testing.T) {
			s, host, _ := brokerFixture(t)
			c := s.brokerCredential
			pin := &brokerAuthorityPin{fixedAuthority: fixedAuthority{audience: testAudience}}
			c.options.Authority = pin
			if _, err := c.Credential(context.Background()); err != nil {
				t.Fatal(err)
			}
			c.renewAt = time.Time{}
			if when == "before" {
				pin.drift.Store(true)
			} else {
				wire := c.client.Transport
				c.client.Transport = mintRoundTrip(func(r *http.Request) (*http.Response, error) {
					response, err := wire.RoundTrip(r)
					pin.drift.Store(true)
					return response, err
				})
			}
			for range 2 {
				if _, err := c.Credential(context.Background()); !errors.Is(err, workcontext.ErrMintRefused) || strings.Contains(err.Error(), "private-authority") {
					t.Fatalf("authority drift was accepted or exposed: %v", err)
				}
			}
			want := int64(1)
			if when == "during" {
				want = 2
			}
			if host.count() != want {
				t.Fatalf("drift minted %d times, want %d", host.count(), want)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		after *hostMint
	}{
		{"execution missing", &hostMint{executionFree: true}},
		{"execution changed", &hostMint{incarnation: 99}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, host, _ := brokerFixture(t)
			host.switchTo = tc.after
			host.switchTo.prepareAuthority(t)
			host.switchAfter = 1
			if err := s.openCredential(context.Background()); err != nil {
				t.Fatal(err)
			}
			s.brokerCredential.renewAt = time.Time{}
			for range 2 {
				if _, err := s.acquireCredential(context.Background()); !errors.Is(err, workcontext.ErrMintRefused) || !errors.Is(err, ErrCredentialRefused) {
					t.Fatalf("execution change accepted or not terminal: %v", err)
				}
			}
			if host.count() != 2 {
				t.Fatalf("execution change retried: %d", host.count())
			}
			// Exercise the native broker through the controller without a
			// socket. The booted test separately proves serve observes this
			// signal and returns without cancellation by the test.
			select {
			case <-s.credentialRefusedC():
			default:
				t.Fatal("the execution refusal did not signal serve to stop")
			}
			if terminal := s.terminalErr.Load(); terminal == nil || !errors.Is(*terminal, workcontext.ErrMintRefused) {
				t.Fatal("the execution refusal was not recorded for serve")
			}
		})
	}
}
