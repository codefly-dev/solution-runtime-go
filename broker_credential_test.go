package solution

import (
	"context"
	"crypto/x509"
	"encoding/json"
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
	"testing/synctest"
	"time"

	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workcontext"
)

// The fake broker runs as an HTTP handler through an in-memory transport. This
// tests the actual request/response boundary even where listening is forbidden.
func brokerFixture(t *testing.T) (*brokerHarness, *hostMint, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "projection")
	writeFile(t, path, "projected-first")
	host := &hostMint{ttl: time.Hour}
	host.prepareAuthority(t)
	s := New(Manifest{ID: testSolutionID})
	s.cfg.mintURL = "https://broker.example/modules/_work-context"
	s.cfg.brokerInternalToken = "broker-perimeter-token"
	s.cfg.projectedTokenPath = path
	options := s.mintOptions("accounts")
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
	h := &brokerHarness{Server: s, brokerCredential: c, controller: &credentialController{nextCredential: c.Credential}}
	return h, host, path
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
		// The prefix and nothing else: where this runtime serves and what
		// its frontend declares travel in the presence document, not here.
		var body map[string]any
		if err := json.Unmarshal(raw, &body); err != nil || len(body) != 1 || body["prefix"] != "widgets-go" {
			t.Fatalf("the mint body is %s, want exactly {\"prefix\":\"widgets-go\"}", raw)
		}
		r.Body = io.NopCloser(strings.NewReader(string(raw)))
		return wire.RoundTrip(r)
	})
	if _, err := s.acquireCredential(context.Background()); err != nil {
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
			_, err := s.brokerCredential.Credential(context.Background())
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
				if calls.Load() != 1 || s.controller.terminalErr.Load() == nil {
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
			_, err := s.brokerCredential.Credential(context.Background())
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
	s, _, _ := brokerFixture(t)
	options := s.brokerCredential.options
	for _, field := range []string{"prefix", "secret", "audience", "path", "plaintext to a host the mesh does not carry", "plaintext to loopback in a deployment", "a misspelled mesh assertion"} {
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
		case "plaintext to a host the mesh does not carry":
			bad.URL = "http://broker.example/modules/_work-context"
			bad.Transport = meshTransport{value: "true", set: true}
		case "plaintext to loopback in a deployment":
			bad.URL = "http://127.0.0.1:8080/modules/_work-context"
			bad.Transport = meshTransport{}
		case "a misspelled mesh assertion":
			bad.URL = "http://auth-gateway.platform.svc:8080/modules/_work-context"
			bad.Transport = meshTransport{value: "yes", set: true}
		}
		if _, err := newBrokerCredentialSource(bad); err == nil {
			t.Fatalf("accepted missing/wrong %s", field)
		}
	}
	// And admitted exactly where the SDK's rule admits plaintext: the mint
	// hop carries the projected token, so it is held to the same rule the
	// gateway URL is held to at validation, through the same function.
	for name, admitted := range map[string]brokerMintOptions{
		"loopback on a local run":                   {URL: "http://127.0.0.1:8080/modules/_work-context", Transport: meshTransport{local: true}},
		"an in-cluster Service under the assertion": {URL: "http://auth-gateway.platform.svc.cluster.local:8080/modules/_work-context", Transport: meshTransport{value: "true", set: true}},
	} {
		good := options
		good.URL, good.Transport = admitted.URL, admitted.Transport
		if _, err := newBrokerCredentialSource(good); err != nil {
			t.Fatalf("%s was refused by the native mint client: %v", name, err)
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
	for projectionBusy(c.options.projectionRead) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if projectionBusy(c.options.projectionRead) {
		t.Fatal("reader slot not released")
	}
	if host.count() != 0 {
		t.Fatal("late token sent a mint")
	}
}

func TestBrokerTransientRenewalKeepsHeldCredentialAndBacksOff(t *testing.T) {
	s, host, _ := brokerFixture(t)
	if _, err := s.acquireCredential(context.Background()); err != nil {
		t.Fatal(err)
	}
	initial, _ := s.controller.heldCredential()
	s.brokerCredential.renewAt = time.Time{}
	host.status = 503
	for range 20 {
		held, err := s.acquireCredential(context.Background())
		if err != nil || held.Token() != initial.Token() {
			t.Fatalf("transient renewal discarded held credential: %v", err)
		}
	}
	if host.count() != 2 || s.controller.terminalErr.Load() != nil {
		t.Fatalf("transient renewal did not back off: %d mints", host.count())
	}
}

func TestBrokerTerminalRenewalDiscardsHeldAuthority(t *testing.T) {
	s, host, _ := brokerFixture(t)
	if _, err := s.acquireCredential(context.Background()); err != nil {
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
	recorder := httptest.NewRecorder()
	s.handleHealth(recorder, httptest.NewRequest("GET", "/health", nil))
	if recorder.Code != 200 {
		t.Fatal("scoped refusal affected process health")
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
		// A renewal sealed to another installation is another deployment: the one
		// identity a credential still seals since the host stopped sealing a build
		// (core #812) and binds it at every mint instead.
		{"installation changed", &hostMint{installation: "installation-somewhere-else"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, host, _ := brokerFixture(t)
			host.switchTo = tc.after
			host.switchTo.prepareAuthority(t)
			host.switchAfter = 1
			if _, err := s.acquireCredential(context.Background()); err != nil {
				t.Fatal(err)
			}
			s.brokerCredential.renewAt = time.Time{}
			for range 2 {
				if _, err := s.acquireCredential(context.Background()); !errors.Is(err, workcontext.ErrMintRefused) || !errors.Is(err, ErrCredentialRefused) {
					t.Fatalf("installation change accepted or not terminal: %v", err)
				}
			}
			if host.count() != 2 {
				t.Fatalf("installation change retried: %d", host.count())
			}
			// Exercise the native broker through the controller without a
			// socket. The booted test separately proves serve observes this
			// signal and returns without cancellation by the test.

			if terminal := s.controller.terminalErr.Load(); terminal == nil || !errors.Is(*terminal, workcontext.ErrMintRefused) {
				t.Fatal("the installation refusal was not recorded for serve")
			}
		})
	}
}

// brokerHarness supplies an in-memory wire to the production acquisition controller.
type brokerHarness struct {
	*Server
	brokerCredential *brokerCredentialSource
	controller       *credentialController
}

func (h *brokerHarness) acquireCredential(ctx context.Context) (executionCredential, error) {
	return h.controller.credentialWithin(ctx, routeCredentialTimeout)
}

func TestProjectionReadSlotSurvivesScopeReplacement(t *testing.T) {
	h, host, _ := brokerFixture(t)
	release := make(chan struct{})
	var reads atomic.Int32
	options := h.brokerCredential.options
	options.ProjectedToken = brokerTokenRead(func() (string, error) { reads.Add(1); <-release; return "late", nil })
	for range 8 {
		source, err := newBrokerCredentialSource(options)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(t.Context(), 5*time.Millisecond)
		_, err = source.Credential(ctx)
		cancel()
		if err == nil {
			t.Fatal("blocked projection succeeded")
		}
	}
	if reads.Load() != 1 || host.count() != 0 {
		t.Fatalf("readers=%d mints=%d", reads.Load(), host.count())
	}
	close(release)
	deadline := time.Now().Add(time.Second)
	for projectionBusy(options.projectionRead) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if projectionBusy(options.projectionRead) {
		t.Fatal("late reader retained shared slot")
	}
}

func projectionBusy(r *brokerProjectionReader) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flight != nil
}

func TestConcurrentScopesShareSuccessfulProjectionRead(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		reader := &brokerProjectionReader{}
		release := make(chan struct{})
		var calls atomic.Int32
		source := brokerTokenRead(func() (string, error) { calls.Add(1); <-release; return "rotated", nil })
		result := make(chan error, 2)
		for range 2 {
			go func() {
				token, err := reader.read(t.Context(), source)
				if err == nil && token != "rotated" {
					err = errors.New("wrong token")
				}
				result <- err
			}()
		}
		// Both callers are blocked on the same flight before the source completes.
		synctest.Wait()
		if calls.Load() != 1 {
			t.Fatalf("concurrent source reads = %d, want 1", calls.Load())
		}
		if len(result) != 0 {
			t.Fatal("projection caller returned before source completion")
		}
		close(release)
		for range 2 {
			if err := <-result; err != nil {
				t.Fatal(err)
			}
		}
		// A later mint reads again, even if the projection has not changed.
		if _, err := reader.read(t.Context(), source); err != nil {
			t.Fatal(err)
		}
		if calls.Load() != 2 {
			t.Fatalf("source reads after later mint = %d, want 2", calls.Load())
		}
	})
}
