package solution

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestHeartbeatSendsInternalToken(t *testing.T) {
	tests := []struct {
		name      string
		token     string
		wantToken string
	}{
		{name: "with token", token: "local-dev-only-replace-me", wantToken: "local-dev-only-replace-me"},
		{name: "without token", token: "", wantToken: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := make(chan string, 1)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got <- r.Header.Get("x-codefly-internal-token")
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			s := &Server{cfg: config{internalToken: tt.token}}
			done := make(chan struct{})
			go func() { s.heartbeat(ctx, srv.URL, []byte("{}"), "host"); close(done) }()

			select {
			case header := <-got:
				if header != tt.wantToken {
					t.Errorf("x-codefly-internal-token = %q, want %q", header, tt.wantToken)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("heartbeat did not POST within timeout")
			}
			cancel()
			<-done
		})
	}
}

// TestServeRegistersOnListenPort is the solution↔host regression guard: it boots
// a real solution on an OS-assigned port against fake host and gateway registries
// and asserts the invariants that a wrong port / wrong host URL broke — the
// runtime binds and advertises the same port, registers with both host and
// gateway, and routes an unauthenticated call to a 401 rather than a 502.
func TestServeRegistersOnListenPort(t *testing.T) {
	buf := &syncBuffer{}
	log.SetOutput(buf)
	defer log.SetOutput(os.Stderr)

	hostSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer hostSrv.Close()
	gatewaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer gatewaySrv.Close()

	assets := t.TempDir()
	if err := os.WriteFile(filepath.Join(assets, "mf-manifest.json"), []byte(`{"name":"test"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port)

	t.Setenv("PORT", port)
	t.Setenv("HOST_REGISTER_URL", hostSrv.URL)
	t.Setenv("GATEWAY_REGISTER_URL", gatewaySrv.URL)
	t.Setenv("GATEWAY_URL", gatewaySrv.URL)
	t.Setenv("ASSETS_DIR", assets)

	s := New(Manifest{ID: "lastlogin-go", Title: "Last Login"}).
		Handle("/audit", func(context.Context, *Gateway) (any, error) {
			return map[string]string{"ok": "yes"}, nil
		})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.cfg = loadConfig(ctx, s.manifest.ID)
	if s.cfg.port != port {
		t.Fatalf("loadConfig port = %q, want assigned listen port %q", s.cfg.port, port)
	}
	done := make(chan struct{})
	go func() { _ = s.serve(ctx, ln); close(done) }()

	base := "http://127.0.0.1:" + port
	waitFor(t, "health", func() bool { return getStatus(t, base+"/health") == http.StatusOK })

	// The advertised manifest port must equal the port the runtime actually binds.
	manifestURL := frontendManifestURL(t, base)
	u, err := url.Parse(manifestURL)
	if err != nil {
		t.Fatalf("parse manifestUrl %q: %v", manifestURL, err)
	}
	if u.Port() != port {
		t.Errorf("manifestUrl port = %q, want listen port %q", u.Port(), port)
	}
	if code := getStatus(t, base+u.Path); code != http.StatusOK {
		t.Errorf("GET manifestUrl = %d, want 200", code)
	}

	// A solution route without a bearer is rejected as 401 (auth). A 502 would
	// mean the request never reached a live upstream — the failure mode this
	// registration path exists to avoid.
	if code := getStatus(t, base+"/audit"); code != http.StatusUnauthorized {
		t.Errorf("GET /audit without bearer = %d, want 401", code)
	}

	waitFor(t, "host registration", func() bool { return strings.Contains(buf.String(), `registered with host`) })
	waitFor(t, "gateway registration", func() bool { return strings.Contains(buf.String(), `registered with gateway`) })

	// Exactly one process owns the backend port: a second bind must fail.
	if extra, err := net.Listen("tcp", "127.0.0.1:"+port); err == nil {
		extra.Close()
		t.Errorf("port %s bound a second time; runtime is not its sole owner", port)
	}

	cancel()
	<-done
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func getStatus(t *testing.T, target string) int {
	t.Helper()
	resp, err := http.Get(target)
	if err != nil {
		return 0
	}
	resp.Body.Close()
	return resp.StatusCode
}

func frontendManifestURL(t *testing.T, base string) string {
	t.Helper()
	resp, err := http.Get(base + "/.well-known/solution.json")
	if err != nil {
		t.Fatalf("GET solution.json: %v", err)
	}
	defer resp.Body.Close()
	var manifest struct {
		Frontend struct {
			ManifestURL string `json:"manifestUrl"`
		} `json:"frontend"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&manifest); err != nil {
		t.Fatalf("decode solution.json: %v", err)
	}
	if manifest.Frontend.ManifestURL == "" {
		t.Fatal("solution.json has no frontend.manifestUrl")
	}
	return manifest.Frontend.ManifestURL
}

// TestConfigValidate guards the boot-time floor: an unresolved value (empty port,
// or a scheme-less register URL as loadConfig produces when the SDK resolves
// nothing and no override is set) must be rejected, not silently accepted into a
// ":"+"" bind and heartbeats to relative URLs.
func TestConfigValidate(t *testing.T) {
	valid := config{
		port:               "8090",
		gatewayURL:         "http://gateway:42152",
		hostRegisterURL:    "http://frontend:21931/api/solutions/register",
		gatewayRegisterURL: "http://gateway:42152/solutions/_register",
	}
	if err := valid.validate(); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}

	cases := []struct {
		name   string
		mutate func(*config)
	}{
		{"empty port", func(c *config) { c.port = "" }},
		{"non-numeric port", func(c *config) { c.port = "http" }},
		{"port out of range", func(c *config) { c.port = "70000" }},
		{"empty gateway URL", func(c *config) { c.gatewayURL = "" }},
		{"relative host register URL", func(c *config) { c.hostRegisterURL = "/api/solutions/register" }},
		{"relative gateway register URL", func(c *config) { c.gatewayRegisterURL = "/solutions/_register" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := valid
			tc.mutate(&c)
			if err := c.validate(); err == nil {
				t.Errorf("validate accepted an unresolved config (%s)", tc.name)
			}
		})
	}
}

// TestServeRejectsUnresolvedConfig proves Serve refuses to boot on an unresolved
// config instead of binding a random port and registering into the void. A
// relative HOST_REGISTER_URL stands in for the empty frontendURL loadConfig
// yields when the SDK cannot resolve the host frontend endpoint.
func TestServeRejectsUnresolvedConfig(t *testing.T) {
	t.Setenv("PORT", "8090")
	t.Setenv("GATEWAY_URL", "http://127.0.0.1:1")
	t.Setenv("GATEWAY_REGISTER_URL", "http://127.0.0.1:1/solutions/_register")
	t.Setenv("HOST_REGISTER_URL", "/api/solutions/register")

	s := New(Manifest{ID: "lastlogin-go", Title: "Last Login"})
	err := s.Serve()
	if err == nil {
		t.Fatal("Serve returned nil for an unresolved config; expected a boot error and no bind")
	}
	if !strings.Contains(err.Error(), "host register URL") {
		t.Errorf("boot error should name the unresolved field, got: %v", err)
	}
}

// TestHeartbeatLogsTransportError guards finding #4: a round trip that never
// yields an HTTP status (scheme-less URL, connection refused) must be logged, not
// swallowed — a permanently-failing registration was previously indistinguishable
// from a working one.
func TestHeartbeatLogsTransportError(t *testing.T) {
	buf := &syncBuffer{}
	log.SetOutput(buf)
	defer log.SetOutput(os.Stderr)

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{cfg: config{internalToken: "t"}}
	done := make(chan struct{})
	go func() { s.heartbeat(ctx, "/solutions/_register", []byte("{}"), "gateway"); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), "failed") {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("no transport failure logged within timeout, got: %q", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	if strings.Contains(buf.String(), "registered with") {
		t.Errorf("logged success on a transport failure: %q", buf.String())
	}
}

func TestHeartbeatLogsRejection(t *testing.T) {
	buf := &syncBuffer{}
	log.SetOutput(buf)
	defer log.SetOutput(os.Stderr)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{cfg: config{internalToken: "wrong-token"}}
	done := make(chan struct{})
	go func() { s.heartbeat(ctx, srv.URL, []byte("{}"), "host"); close(done) }()

	deadline := time.Now().Add(5 * time.Second)
	for !strings.Contains(buf.String(), "rejected") {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatalf("no rejection logged within timeout, got: %q", buf.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done

	out := buf.String()
	if strings.Contains(out, "registered with") {
		t.Errorf("logged success on 401 response: %q", out)
	}
	if !strings.Contains(out, "401") {
		t.Errorf("expected rejection log naming the status, got: %q", out)
	}
}
