package solution

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	codefly "github.com/codefly-dev/sdk-go"
)

// solutionExchange is what /solutions/_registration-token received: the id the
// solution asks a credential for, plus the two headers the gateway requires —
// its own perimeter token and the solution's registration secret.
type solutionExchange struct {
	ID       string `json:"id"`
	Secret   string `json:"-"`
	Internal string `json:"-"`
}

// solutionRegistration is one self-registration as a surface saw it: which
// surface, the credential presented, and whether the shared cluster-internal
// token rode along.
type solutionRegistration struct {
	Surface  string
	Token    string
	Internal string
	Status   int
}

// fakeHost stands in for the host's two solution-registration surfaces and the
// gateway exchange that credentials them, with the real refusal semantics: the
// exchange mints only against the declared secret, and each surface burns a
// token's single use — a replay is refused.
type fakeHost struct {
	*httptest.Server
	secret        string
	exchanges     chan solutionExchange
	registrations chan solutionRegistration
	// registerStatus, when non-zero, is what both surfaces answer instead of
	// 200, with registerBody as the body.
	registerStatus int
	registerBody   string

	mu     sync.Mutex
	minted int
	burned map[string]bool
}

func newFakeHost(t *testing.T, secret string) *fakeHost {
	t.Helper()
	h := &fakeHost{
		secret:        secret,
		exchanges:     make(chan solutionExchange, 16),
		registrations: make(chan solutionRegistration, 16),
		burned:        map[string]bool{},
	}
	h.Server = httptest.NewServer(http.HandlerFunc(h.serve))
	t.Cleanup(h.Close)
	return h
}

func (h *fakeHost) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case solutionRegistrationTokenPath:
		var exchange solutionExchange
		_ = json.NewDecoder(r.Body).Decode(&exchange)
		exchange.Secret = r.Header.Get(solutionSecretHeader)
		exchange.Internal = r.Header.Get(internalTokenHeader)
		send(h.exchanges, exchange)
		if exchange.Internal != internalTokenTest || h.secret == "" || exchange.Secret != h.secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		h.mu.Lock()
		h.minted++
		token := fmt.Sprintf("solution-token-%d", h.minted)
		h.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{
			"token":     token,
			"expiresAt": time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
		})
	case solutionRegisterPath, "/api/solutions/register":
		surface := "gateway"
		if r.URL.Path != solutionRegisterPath {
			surface = "host"
		}
		token := r.Header.Get(solutionRegistrationHeader)
		status := http.StatusOK
		h.mu.Lock()
		switch {
		case token == "" || h.burned[surface+":"+token]:
			// The cluster-internal token is not a registration credential, and a
			// token is presented once per surface.
			status = http.StatusUnauthorized
		default:
			h.burned[surface+":"+token] = true
		}
		h.mu.Unlock()
		if status == http.StatusOK && h.registerStatus != 0 {
			status = h.registerStatus
		}
		send(h.registrations, solutionRegistration{
			Surface:  surface,
			Token:    token,
			Internal: r.Header.Get(internalTokenHeader),
			Status:   status,
		})
		w.WriteHeader(status)
		if status != http.StatusOK && h.registerBody != "" {
			_, _ = w.Write([]byte(h.registerBody))
		}
	default:
		w.WriteHeader(http.StatusOK)
	}
}

// bootAgainst boots a real solution against h with the given secret, beating
// fast enough for a test to observe several registrations.
func bootAgainst(t *testing.T, h *fakeHost, secret string) func() {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := New(Manifest{ID: "lastlogin-go", Title: "Last Login"})
	s.registrationInterval = 20 * time.Millisecond
	s.cfg = config{
		port:               strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
		publicURL:          "http://127.0.0.1",
		hostRegisterURL:    h.URL + "/api/solutions/register",
		gatewayRegisterURL: h.URL + solutionRegisterPath,
		moduleRegisterURL:  h.URL + moduleRegisterPath,
		moduleTokenURL:     h.URL + moduleRegistrationTokenPath,
		solutionTokenURL:   h.URL + solutionRegistrationTokenPath,
		internalToken:      internalTokenTest,
		solutionSecret:     secret,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.serve(ctx, ln); close(done) }()
	return func() {
		cancel()
		<-done
	}
}

func awaitRegistrations(t *testing.T, h *fakeHost, n int) []solutionRegistration {
	t.Helper()
	var seen []solutionRegistration
	deadline := time.After(5 * time.Second)
	for len(seen) < n {
		select {
		case r := <-h.registrations:
			seen = append(seen, r)
		case <-deadline:
			t.Fatalf("saw %d registrations within timeout, want %d", len(seen), n)
		}
	}
	return seen
}

// TestServeRegistersWithSolutionCredential proves the publisher-bound handshake
// end to end on the runtime's side: with a registration secret provisioned, the
// runtime exchanges it (with the cluster-internal token as the gateway's
// perimeter check) for a signed, solution-bound token, presents that token — and
// not the cluster-internal one — on both the host and the gateway registration,
// and mints a fresh one per beat, because each surface burns a token on use.
func TestServeRegistersWithSolutionCredential(t *testing.T) {
	h := newFakeHost(t, "s3cret")
	stop := bootAgainst(t, h, "s3cret")
	defer stop()

	select {
	case exchange := <-h.exchanges:
		if exchange.ID != "lastlogin-go" {
			t.Errorf("exchange asked for id %q, want the solution's own id", exchange.ID)
		}
		if exchange.Secret != "s3cret" {
			t.Errorf("exchange presented %s = %q, want the provisioned secret", solutionSecretHeader, exchange.Secret)
		}
		if exchange.Internal != internalTokenTest {
			t.Errorf("exchange presented %s = %q, want the cluster-internal token for the gateway's perimeter check", internalTokenHeader, exchange.Internal)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no registration token exchange within timeout")
	}

	seen := awaitRegistrations(t, h, 6)
	surfaces := map[string]int{}
	tokens := map[string]int{}
	for _, r := range seen {
		surfaces[r.Surface]++
		tokens[r.Token]++
		if r.Status != http.StatusOK {
			t.Errorf("%s registration presenting %q was refused (status %d): a fresh token must be accepted", r.Surface, r.Token, r.Status)
		}
		if !strings.HasPrefix(r.Token, "solution-token-") {
			t.Errorf("%s registration presented %s = %q, want a token minted by the exchange", r.Surface, solutionRegistrationHeader, r.Token)
		}
		if r.Internal != "" {
			t.Errorf("%s registration also presented %s = %q; the credential proves the publisher, the shared token proves nothing and must not ride along", r.Surface, internalTokenHeader, r.Internal)
		}
	}
	if surfaces["host"] == 0 || surfaces["gateway"] == 0 {
		t.Fatalf("registrations by surface = %v, want both host and gateway", surfaces)
	}
	for token, n := range tokens {
		if n != 1 {
			t.Errorf("token %q was presented %d times; a registration credential is single-use and must be minted per beat", token, n)
		}
	}
}

// TestServeFallsBackToInternalTokenWithoutSecret pins the compatibility path: a
// composition that provisioned no secret still registers as before, presenting
// the cluster-internal token, and is told in the log which half is missing —
// because on a host that refuses that token, "rejected (status 401)" alone
// would send the reader to the wrong place.
func TestServeFallsBackToInternalTokenWithoutSecret(t *testing.T) {
	buf := &syncBuffer{}
	log.SetOutput(buf)
	defer log.SetOutput(os.Stderr)

	h := newFakeHost(t, "s3cret")
	stop := bootAgainst(t, h, "")
	defer stop()

	seen := awaitRegistrations(t, h, 2)
	for _, r := range seen {
		if r.Internal != internalTokenTest {
			t.Errorf("%s registration presented %s = %q, want the cluster-internal token when no secret is provisioned", r.Surface, internalTokenHeader, r.Internal)
		}
		if r.Token != "" {
			t.Errorf("%s registration presented %s = %q, want none without a secret to exchange", r.Surface, solutionRegistrationHeader, r.Token)
		}
	}
	select {
	case exchange := <-h.exchanges:
		t.Fatalf("an exchange ran (%+v) although no secret was provisioned", exchange)
	default:
	}
	if out := buf.String(); !strings.Contains(out, "no registration secret provisioned") ||
		!strings.Contains(out, SolutionRegistrationSecretEnvironmentVariable) ||
		!strings.Contains(out, SolutionRegistrationSecretGroup+"/"+SolutionRegistrationSecretKey) {
		t.Fatalf("log does not name the missing provisioning:\n%s", out)
	}
}

// TestSolutionCredentialRefusedExchangeNamesTheCause proves a refused exchange
// surfaces as a failed beat whose error names the two indistinguishable causes
// the host relays identically: an undeclared id and a mismatched secret.
func TestSolutionCredentialRefusedExchangeNamesTheCause(t *testing.T) {
	buf := &syncBuffer{}
	log.SetOutput(buf)
	defer log.SetOutput(os.Stderr)

	h := newFakeHost(t, "s3cret")
	stop := bootAgainst(t, h, "wrong")
	defer stop()

	select {
	case <-h.exchanges:
	case <-time.After(5 * time.Second):
		t.Fatal("no exchange within timeout")
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		if out := buf.String(); strings.Contains(out, "registration with host failed") &&
			strings.Contains(out, "SOLUTION_REGISTRATION_SECRETS") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("refused exchange was not reported:\n%s", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case r := <-h.registrations:
		t.Fatalf("a registration reached the host (%+v) although the exchange refused the secret", r)
	default:
	}
}

// TestSolutionCredentialRefusalIsReportedOnce proves a refusal of a token minted
// for the same beat is diagnosed as what it is — not staleness, since nothing
// is cached — and diagnosed once per episode rather than on every beat.
func TestSolutionCredentialRefusalIsReportedOnce(t *testing.T) {
	buf := &syncBuffer{}
	log.SetOutput(buf)
	defer log.SetOutput(os.Stderr)

	credential := &solutionCredential{id: "lastlogin-go"}
	credential.invalidate()
	credential.invalidate()
	if n := strings.Count(buf.String(), "was refused while presenting a token minted for that same beat"); n != 1 {
		t.Fatalf("fresh-token refusal diagnosed %d times, want once per episode:\n%s", n, buf.String())
	}
	credential.succeeded()
	credential.invalidate()
	if n := strings.Count(buf.String(), "was refused while presenting a token minted for that same beat"); n != 2 {
		t.Fatalf("a refusal after a success is a new episode and earns its own line; got %d lines", n)
	}
}

// TestHeartbeatLogsTheHostsRefusalReasons proves the reasons a host attaches to
// a refusal reach the log: an incompatible_runtime refusal is only actionable
// with them.
func TestHeartbeatLogsTheHostsRefusalReasons(t *testing.T) {
	buf := &syncBuffer{}
	log.SetOutput(buf)
	defer log.SetOutput(os.Stderr)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusConflict, map[string]any{
			"error":   "incompatible_runtime",
			"reasons": []string{"frontend.hostContract 2 does not satisfy host contract 1", "reactRange ^18 does not match React 19.1.0"},
		})
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{manifest: Manifest{ID: "lastlogin-go"}, registrationInterval: 20 * time.Millisecond}
	done := make(chan struct{})
	go func() {
		s.heartbeat(ctx, srv.URL, []byte("{}"), "host", internalTokenAuth(""))
		close(done)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), "rejected (status 409)") {
		if time.Now().After(deadline) {
			cancel()
			t.Fatalf("refusal not logged:\n%s", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	want := `rejected (status 409) for "lastlogin-go": incompatible_runtime: frontend.hostContract 2 does not satisfy host contract 1; reactRange ^18 does not match React 19.1.0`
	if !strings.Contains(buf.String(), want) {
		t.Fatalf("log lacks the host's reasons; want %q in:\n%s", want, buf.String())
	}
}

// TestLoadConfigDerivesSolutionTokenURL proves the exchange follows the
// registration endpoint — the same gateway, even one mounted under a path —
// and that an override of the registration alone cannot split the pair.
func TestLoadConfigDerivesSolutionTokenURL(t *testing.T) {
	t.Setenv("PORT", "1234")
	t.Setenv("GATEWAY_URL", "http://gateway:8080/gw")
	t.Setenv("HOST_REGISTER_URL", "http://frontend:3000/api/solutions/register")
	t.Setenv("GATEWAY_REGISTER_URL", "http://gateway:8080/gw/solutions/_register")
	cfg := loadConfig(context.Background(), "lastlogin-go")
	if want := "http://gateway:8080/gw/solutions/_registration-token"; cfg.solutionTokenURL != want {
		t.Fatalf("solutionTokenURL = %q, want %q", cfg.solutionTokenURL, want)
	}

	t.Setenv("GATEWAY_SOLUTION_REGISTRATION_TOKEN_URL", "http://other:9090/solutions/_registration-token")
	cfg = loadConfig(context.Background(), "lastlogin-go")
	if want := "http://other:9090/solutions/_registration-token"; cfg.solutionTokenURL != want {
		t.Fatalf("explicit solutionTokenURL = %q, want %q", cfg.solutionTokenURL, want)
	}
}

// TestValidateRequiresSolutionTokenURLOnlyWithASecret proves the exchange
// endpoint is part of the boot contract exactly when a secret makes the
// exchange run: a composition on a host that still admits the cluster-internal
// token is not refused for an endpoint it never calls, and one that will
// exchange fails loud at boot rather than on every beat.
func TestValidateRequiresSolutionTokenURLOnlyWithASecret(t *testing.T) {
	base := config{
		port:               "1234",
		gatewayURL:         "http://gateway:42152",
		hostRegisterURL:    "http://frontend:21931/api/solutions/register",
		gatewayRegisterURL: "http://gateway:42152/solutions/_register",
		moduleRegisterURL:  "http://gateway:42152/modules/_register",
		moduleTokenURL:     "http://gateway:42152/modules/_registration-token",
	}
	if err := base.validate(); err != nil {
		t.Fatalf("no secret, no token URL: validate() = %v, want nil", err)
	}
	withSecret := base
	withSecret.solutionSecret = "s3cret"
	if err := withSecret.validate(); err == nil || !strings.Contains(err.Error(), "solution token URL") {
		t.Fatalf("secret without a token URL: validate() = %v, want an error naming the solution token URL", err)
	}
	withSecret.solutionTokenURL = "http://gateway:42152/solutions/_registration-token"
	if err := withSecret.validate(); err != nil {
		t.Fatalf("secret with a token URL: validate() = %v, want nil", err)
	}
}

// TestSolutionRegistrationSecretResolvesThroughTheSDK proves the declared
// provisioning path: the secret arrives as the namespaced workspace secret
// Codefly injects for the `solution-registration` group, resolved by name
// through the SDK, and an explicit environment override wins over it.
func TestSolutionRegistrationSecretResolvesThroughTheSDK(t *testing.T) {
	// The SDK snapshots injected values process-wide; registered before Setenv
	// so it runs after the environment is restored and leaves no secret behind
	// for the boot tests that follow.
	t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })
	t.Setenv("CODEFLY__WORKSPACE_SECRET_CONFIGURATION__SOLUTION_REGISTRATION__SECRET", "from-workspace")
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	if got := solutionRegistrationSecret(context.Background()); got != "from-workspace" {
		t.Fatalf("solutionRegistrationSecret() = %q, want the workspace secret", got)
	}
	t.Setenv(SolutionRegistrationSecretEnvironmentVariable, "from-override")
	if got := solutionRegistrationSecret(context.Background()); got != "from-override" {
		t.Fatalf("solutionRegistrationSecret() = %q, want the explicit override", got)
	}
}

// TestManifestDeclaresItsContractMajors proves the manifest says which host
// contract it is built against instead of relying on the host's default for a
// silent manifest.
func TestManifestDeclaresItsContractMajors(t *testing.T) {
	s := New(Manifest{ID: "lastlogin-go", Title: "Last Login"})
	m := s.manifestMap()
	if got := m["schemaVersion"]; got != solutionManifestSchemaMajor {
		t.Fatalf("schemaVersion = %v, want %d", got, solutionManifestSchemaMajor)
	}
	frontend := m["frontend"].(map[string]any)
	if got := frontend["hostContract"]; got != solutionHostContractMajor {
		t.Fatalf("frontend.hostContract = %v, want %d", got, solutionHostContractMajor)
	}
}
