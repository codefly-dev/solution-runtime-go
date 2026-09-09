package solution

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	codefly "github.com/codefly-dev/sdk-go"
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
			go func() {
				s.heartbeat(ctx, srv.URL, []byte("{}"), "host", internalTokenAuth(tt.token))
				close(done)
			}()

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

// sampleDataGraph is a minimal but structurally complete DataGraph
// (events / metrics / dashboards) a solution might declare, matching the shape
// the host's @codefly/saas-plugin-manifest validates.
func sampleDataGraph() map[string]any {
	return map[string]any{
		"events": []any{
			map[string]any{"name": "signin", "type": "user.signed_in.v1"},
		},
		"metrics": []any{
			map[string]any{
				"id":          "logins",
				"kind":        "source",
				"filter":      map[string]any{"event": "signin"},
				"groupBy":     "time",
				"bucket":      "day",
				"aggregation": "count",
			},
		},
		"dashboards": []any{
			map[string]any{
				"id":     "activity",
				"layout": "grid",
				"widgets": []any{
					map[string]any{"id": "logins_over_time", "metric": "logins", "visualization": "line"},
				},
			},
		},
	}
}

// The served manifest must carry a declared dashboard data-graph verbatim
// through JSON, so the host receives exactly what the solution declared.
func TestServedManifestCarriesDashboardVerbatim(t *testing.T) {
	graph := sampleDataGraph()
	s := &Server{manifest: Manifest{ID: "lastlogin-go", Dashboard: graph}}

	var got map[string]any
	body, err := json.Marshal(s.manifestMap())
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	if !reflect.DeepEqual(got["dashboard"], graph) {
		t.Errorf("served dashboard = %#v, want %#v", got["dashboard"], graph)
	}
}

// A solution that declares no dashboard must not gain a dashboard key at all —
// not even a null one, which would break a host that feeds a present slot into
// its data-graph validator and would perturb the existing wire contract.
func TestManifestOmitsAbsentDashboard(t *testing.T) {
	s := &Server{manifest: Manifest{ID: "lastlogin-go"}}
	if _, ok := s.manifestMap()["dashboard"]; ok {
		t.Errorf("emitted a dashboard key with no dashboard declared")
	}
}

// The host registration payload (the heartbeat body) must carry the declared
// data-graph verbatim, not just the GET manifest — that is the surface the host
// self-registration path reads.
func TestRegistrationPayloadCarriesDashboardVerbatim(t *testing.T) {
	graph := sampleDataGraph()

	body := make(chan []byte, 1)
	hostSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		select {
		case body <- b:
		default:
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer hostSrv.Close()
	gatewaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer gatewaySrv.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	s := New(Manifest{ID: "lastlogin-go", Title: "Last Login", Dashboard: graph})
	s.cfg = config{
		port:               strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
		publicURL:          "http://127.0.0.1",
		hostRegisterURL:    hostSrv.URL,
		gatewayRegisterURL: gatewaySrv.URL,
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _ = s.serve(ctx, ln); close(done) }()

	var raw []byte
	select {
	case raw = <-body:
	case <-time.After(5 * time.Second):
		t.Fatal("host did not receive a registration within timeout")
	}
	cancel()
	<-done

	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("unmarshal registration body: %v", err)
	}
	if !reflect.DeepEqual(payload["dashboard"], graph) {
		t.Errorf("registration dashboard = %#v, want %#v", payload["dashboard"], graph)
	}
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
		moduleRegisterURL:  "http://gateway:42152/modules/_register",
		moduleTokenURL:     "http://gateway:42152/modules/_registration-token",
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
		{"relative module register URL", func(c *config) { c.moduleRegisterURL = "/modules/_register" }},
		{"relative module token URL", func(c *config) { c.moduleTokenURL = "/modules/_registration-token" }},
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
	go func() {
		s.heartbeat(ctx, "/solutions/_register", []byte("{}"), "gateway", internalTokenAuth("t"))
		close(done)
	}()

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
	go func() {
		s.heartbeat(ctx, srv.URL, []byte("{}"), "host", internalTokenAuth("wrong-token"))
		close(done)
	}()

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

// setEndpoint injects a single Codefly endpoint into the SDK's env-var snapshot
// for the duration of the test, then restores the snapshot on cleanup.
func setEndpoint(t *testing.T, key, addr string) {
	t.Helper()
	if err := os.Setenv(key, addr); err != nil {
		t.Fatal(err)
	}
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Unsetenv(key)
		_ = codefly.LoadEnvironmentVariables()
	})
}

// TestLoadConfigResolvesRenamedGateway proves the gateway default follows the
// saas-starter auth-sidecar → auth-gateway rename (v0.0.49): loadConfig resolves
// the gateway URL from the SDK against either service name, with no explicit
// CODEFLY_HOST_GATEWAY or GATEWAY_URL override — so a solution boots against both
// the renamed host and older ones.
func TestLoadConfigResolvesRenamedGateway(t *testing.T) {
	const addr = "http://gateway:42152"
	cases := []struct {
		name    string
		service string
	}{
		{"auth-gateway (v0.0.49+)", "auth-gateway"},
		{"auth-sidecar (pre-v0.0.49 fallback)", "auth-sidecar"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			key := "CODEFLY__ENDPOINT__SAAS__" +
				strings.ToUpper(strings.ReplaceAll(tc.service, "-", "_")) + "__REST__REST"
			setEndpoint(t, key, addr)

			cfg := loadConfig(context.Background(), "lastlogin-go")
			if cfg.gatewayURL != addr {
				t.Fatalf("gatewayURL = %q, want %q resolved from %s without an override", cfg.gatewayURL, addr, tc.service)
			}
			// The gateway module-register URL defaults to the resolved gateway plus
			// the /modules/_register path, with no explicit override.
			if want := addr + "/modules/_register"; cfg.moduleRegisterURL != want {
				t.Errorf("moduleRegisterURL = %q, want %q derived from the resolved gateway", cfg.moduleRegisterURL, want)
			}
		})
	}
}

// TestLoadConfigResolvesHostByRole proves the host gateway/frontend resolve by
// service role alone, independent of the host module's workspace name: loadConfig
// resolves both URLs with no CODEFLY_HOST_MODULE override whether the host module
// is the current saas (auth-gateway service), the pre-rename saas-starter
// (auth-sidecar), or any other name a solution composes it under (codefly-dev/core#382).
func TestLoadConfigResolvesHostByRole(t *testing.T) {
	const (
		gatewayAddr  = "http://gateway:42152"
		frontendAddr = "http://frontend:42153"
	)
	cases := []struct {
		name    string
		module  string
		gateway string
	}{
		{"saas host (post-rename)", "SAAS", "AUTH_GATEWAY"},
		{"saas-starter host (pre-rename)", "SAAS_STARTER", "AUTH_SIDECAR"},
		{"arbitrary host module name", "SOME_OTHER_HOST", "AUTH_GATEWAY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setEndpoint(t, "CODEFLY__ENDPOINT__"+tc.module+"__"+tc.gateway+"__REST__REST", gatewayAddr)
			setEndpoint(t, "CODEFLY__ENDPOINT__"+tc.module+"__FRONTEND__HTTP__HTTP", frontendAddr)

			cfg := loadConfig(context.Background(), "lastlogin-go")
			if cfg.gatewayURL != gatewayAddr {
				t.Errorf("gatewayURL = %q, want %q resolved without a CODEFLY_HOST_MODULE override", cfg.gatewayURL, gatewayAddr)
			}
			if want := frontendAddr + "/api/solutions/register"; cfg.hostRegisterURL != want {
				t.Errorf("hostRegisterURL = %q, want %q resolved without a CODEFLY_HOST_MODULE override", cfg.hostRegisterURL, want)
			}
		})
	}
}

// writeFile writes content to path, creating parent directories, for building
// on-disk workspace fixtures.
func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestResolveGatewayAmbiguousModuleFailsLoud proves that when more than one host
// module exposes the same role, host resolution returns "" — so validate() fails
// loud at boot — instead of silently returning whichever module the injected env
// happened to surface first. The single-module control shows "" is caused by the
// ambiguity, not by resolution being broken.
func TestResolveGatewayAmbiguousModuleFailsLoud(t *testing.T) {
	// Hermetic: no workspace on disk, so local-native discovery finds nothing
	// and only the injected carriers drive resolution.
	t.Chdir(t.TempDir())

	t.Run("single owning module resolves", func(t *testing.T) {
		setEndpoint(t, "CODEFLY__ENDPOINT__SAAS__AUTH_GATEWAY__REST__REST", "http://gateway:42152")
		if got := resolveGateway(context.Background(), "", "auth-gateway"); got != "http://gateway:42152" {
			t.Fatalf("resolveGateway = %q, want the single module's address", got)
		}
	})

	t.Run("two modules owning the same role are ambiguous", func(t *testing.T) {
		setEndpoint(t, "CODEFLY__ENDPOINT__SAAS__AUTH_GATEWAY__REST__REST", "http://gateway-a:42152")
		setEndpoint(t, "CODEFLY__ENDPOINT__SAAS_STARTER__AUTH_GATEWAY__REST__REST", "http://gateway-b:42152")
		if got := resolveGateway(context.Background(), "", "auth-gateway"); got != "" {
			t.Fatalf("resolveGateway = %q, want %q so validate() fails loud on the ambiguous host", got, "")
		}
	})
}

// TestResolveHostByRoleFromWorkspace proves host-by-role resolution works in a
// local run with no injected endpoint carriers: the owning module is discovered
// from the workspace on disk, so resolving by role alone (module "") matches
// resolving with the module named explicitly. This is the regression the empty
// CODEFLY_HOST_MODULE default introduced — the env scan finds nothing locally,
// and without workspace discovery the host would never resolve.
func TestResolveHostByRoleFromWorkspace(t *testing.T) {
	ctx := context.Background()
	root := t.TempDir()

	writeFile(t, filepath.Join(root, "workspace.codefly.yaml"), `name: solution-test
layout: modules
modules:
  - name: platform
`)
	writeFile(t, filepath.Join(root, "modules", "platform", "module.codefly.yaml"), `kind: module
name: platform
services:
  - name: auth-gateway
  - name: frontend
`)
	writeFile(t, filepath.Join(root, "modules", "platform", "services", "auth-gateway", "service.codefly.yaml"), `kind: service
name: auth-gateway
version: 0.0.0
agent:
  kind: codefly:service
  name: go
  version: 0.0.1
  publisher: codefly.dev
endpoints:
  - name: rest
`)
	writeFile(t, filepath.Join(root, "modules", "platform", "services", "frontend", "service.codefly.yaml"), `kind: service
name: frontend
version: 0.0.0
agent:
  kind: codefly:service
  name: go
  version: 0.0.1
  publisher: codefly.dev
endpoints:
  - name: http
`)

	// Force the SDK's local-native resolution (no injected carriers), and restore
	// the shared env snapshot afterwards so later tests see a clean state.
	t.Setenv("CODEFLY__ENVIRONMENT", "")
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })
	t.Chdir(root)

	// Resolving by role alone must match resolving with the module named, and
	// both must actually resolve (non-empty) from the workspace map.
	gotGW := resolveGateway(ctx, "", "auth-gateway")
	wantGW := resolveGateway(ctx, "platform", "auth-gateway")
	if wantGW == "" {
		t.Fatal("resolveGateway with explicit module resolved empty; the workspace fixture did not expose the gateway endpoint")
	}
	if gotGW != wantGW {
		t.Errorf("resolveGateway(module=\"\") = %q, want %q discovered from the workspace", gotGW, wantGW)
	}

	gotFE := resolveFrontend(ctx, "", "frontend")
	wantFE := resolveFrontend(ctx, "platform", "frontend")
	if wantFE == "" {
		t.Fatal("resolveFrontend with explicit module resolved empty; the workspace fixture did not expose the frontend endpoint")
	}
	if gotFE != wantFE {
		t.Errorf("resolveFrontend(module=\"\") = %q, want %q discovered from the workspace", gotFE, wantFE)
	}
}

// moduleRegistration is the wire payload the gateway's /modules/_register
// accepts: a bare single-segment prefix (the gateway builds /v1/<prefix>/* from
// it) and the resolved upstream. Registration and Internal are not part of the
// body — they are the captured credential headers, so a test can assert the
// registration presents the signed, prefix-bound token and not the shared
// cluster-internal one.
type moduleRegistration struct {
	Prefix       string `json:"prefix"`
	Upstream     string `json:"upstream"`
	Registration string `json:"-"`
	Internal     string `json:"-"`
}

// moduleExchange is what the credential exchange (/modules/_registration-token)
// received: the prefix a module asks for, plus the two credentials the gateway
// requires — its own perimeter token and the module's registration secret.
type moduleExchange struct {
	Prefix   string `json:"prefix"`
	Secret   string `json:"-"`
	Internal string `json:"-"`
}

// fakeGateway stands in for the host gateway on the two endpoints module
// federation uses. It mirrors the real refusal semantics: the exchange mints a
// token only for a prefix whose declared secret the caller presents, and answers
// 401 otherwise (accounts' refusal, relayed).
type fakeGateway struct {
	*httptest.Server
	registrations chan moduleRegistration
	exchanges     chan moduleExchange

	// declared maps a prefix to the secret the composition provisioned for it —
	// the plaintext twin of the digest accounts holds.
	declared map[string]string
	// tokenTTL is how long a minted token is claimed to be valid.
	tokenTTL time.Duration
	// registerStatus, when non-zero, is what /modules/_register answers instead
	// of 200.
	registerStatus int

	mu     sync.Mutex
	minted int
}

func newFakeGateway(t *testing.T, gw *fakeGateway) *fakeGateway {
	t.Helper()
	gw.registrations = make(chan moduleRegistration, 8)
	gw.exchanges = make(chan moduleExchange, 8)
	if gw.tokenTTL == 0 {
		gw.tokenTTL = time.Hour
	}
	gw.Server = httptest.NewServer(http.HandlerFunc(gw.serve))
	t.Cleanup(gw.Close)
	return gw
}

func (g *fakeGateway) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case moduleRegistrationTokenPath:
		var exchange moduleExchange
		_ = json.NewDecoder(r.Body).Decode(&exchange)
		exchange.Secret = r.Header.Get(moduleSecretHeader)
		exchange.Internal = r.Header.Get(internalTokenHeader)
		send(g.exchanges, exchange)
		if g.declared[exchange.Prefix] == "" || g.declared[exchange.Prefix] != exchange.Secret {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		g.mu.Lock()
		g.minted++
		token := fmt.Sprintf("minted-%s-%d", exchange.Prefix, g.minted)
		g.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]string{
			"token":     token,
			"expiresAt": time.Now().Add(g.tokenTTL).UTC().Format(time.RFC3339),
		})
	case moduleRegisterPath:
		var registration moduleRegistration
		_ = json.NewDecoder(r.Body).Decode(&registration)
		registration.Registration = r.Header.Get(moduleRegistrationHeader)
		registration.Internal = r.Header.Get(internalTokenHeader)
		send(g.registrations, registration)
		if g.registerStatus != 0 {
			w.WriteHeader(g.registerStatus)
			return
		}
		w.WriteHeader(http.StatusOK)
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (g *fakeGateway) mintCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.minted
}

// send records an observation without ever blocking the fake gateway's handler:
// a heartbeat re-POSTs forever, so a full channel must not wedge the server.
func send[T any](ch chan T, value T) {
	select {
	case ch <- value:
	default:
	}
}

// bootWithModuleRegistry boots a real solution on ln against gw. The host and
// gateway self-registrations point at the same fake so their heartbeats don't
// spew transport errors into the test log.
func bootWithModuleRegistry(t *testing.T, ln net.Listener, gw *fakeGateway) func() {
	t.Helper()
	s := New(Manifest{ID: "lastlogin-go", Title: "Last Login"})
	s.cfg = config{
		port:               strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
		publicURL:          "http://127.0.0.1",
		hostRegisterURL:    gw.URL + "/host",
		gatewayRegisterURL: gw.URL + "/gateway",
		moduleRegisterURL:  gw.URL + moduleRegisterPath,
		moduleTokenURL:     gw.URL + moduleRegistrationTokenPath,
		internalToken:      internalTokenTest,
		moduleSecrets:      parseModuleRegistrationSecrets(os.Getenv(ModuleRegistrationSecretsEnvironmentVariable)),
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.serve(ctx, ln); close(done) }()
	return func() {
		cancel()
		<-done
	}
}

// internalTokenTest is the cluster-internal token the fake gateway's perimeter
// check expects on the credential exchange.
const internalTokenTest = "internal-token-xyz"

// consumesDocuments is the api.consumes projection core surfaces to a running
// backend for the wiki→documents federation. The literal key is
// manifest.APIConsumesEnvironmentVariable (a wire contract).
const consumesDocuments = `[{"id":"docstore.documents","module":"docstore","service":"documents","endpoint":"rest","protocol":"rest","as":"documents"}]`

// TestServeRegistersConsumedAPIUpstreams proves the api.consumes federation end
// to end on the runtime's side: for each consumed target core surfaces in
// CODEFLY__API_CONSUMES, the runtime exchanges the registration secret its
// composition provisioned for a signed, prefix-bound token, then registers
// /v1/<as> → the SDK-resolved upstream with that token. The shared
// cluster-internal token authenticates only the exchange — the gateway rejects
// it on /modules/_register, so it must not be what the registration presents.
func TestServeRegistersConsumedAPIUpstreams(t *testing.T) {
	const upstream = "http://docstore-upstream:9100"
	// The consumed endpoint's address is injected because the backend depends on
	// the consumed service; resolve it via the SDK snapshot.
	setEndpoint(t, "CODEFLY__ENDPOINT__DOCSTORE__DOCUMENTS__REST__REST", upstream)
	t.Setenv("CODEFLY__API_CONSUMES", consumesDocuments)
	t.Setenv(ModuleRegistrationSecretsEnvironmentVariable, "documents:s3cret")

	gw := newFakeGateway(t, &fakeGateway{declared: map[string]string{"documents": "s3cret"}})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bootWithModuleRegistry(t, ln, gw)()

	select {
	case exchange := <-gw.exchanges:
		if exchange.Prefix != "documents" {
			t.Errorf("exchanged for prefix %q, want %q", exchange.Prefix, "documents")
		}
		if exchange.Secret != "s3cret" {
			t.Errorf("exchange presented secret %q, want the provisioned %q", exchange.Secret, "s3cret")
		}
		if exchange.Internal != internalTokenTest {
			t.Errorf("exchange presented internal token %q, want %q — the gateway's perimeter check requires it", exchange.Internal, internalTokenTest)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not receive a registration-token exchange within timeout")
	}

	select {
	case reg := <-gw.registrations:
		if reg.Prefix != "documents" {
			t.Errorf("registered prefix = %q, want %q (the facade as core projected)", reg.Prefix, "documents")
		}
		if reg.Upstream != upstream {
			t.Errorf("registered upstream = %q, want %q resolved via the SDK", reg.Upstream, upstream)
		}
		if reg.Registration != "minted-documents-1" {
			t.Errorf("registered with %s = %q, want the minted token", moduleRegistrationHeader, reg.Registration)
		}
		if reg.Internal != "" {
			t.Errorf("registration carried the shared internal token %q; the gateway refuses it and it must not leak to this path", reg.Internal)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("gateway did not receive a module registration within timeout")
	}
}

// TestServeSkipsConsumedAPIWithoutSecret proves the provisioning gap fails loud
// rather than hammering the gateway: with no secret for the prefix there is no
// credential to exchange, so every registration would be a guaranteed 401. The
// runtime neither exchanges nor registers, and says which variable is missing.
func TestServeSkipsConsumedAPIWithoutSecret(t *testing.T) {
	buf := &syncBuffer{}
	log.SetOutput(buf)
	defer log.SetOutput(os.Stderr)

	setEndpoint(t, "CODEFLY__ENDPOINT__DOCSTORE__DOCUMENTS__REST__REST", "http://docstore-upstream:9100")
	t.Setenv("CODEFLY__API_CONSUMES", consumesDocuments)
	t.Setenv(ModuleRegistrationSecretsEnvironmentVariable, "")

	gw := newFakeGateway(t, &fakeGateway{})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bootWithModuleRegistry(t, ln, gw)()

	select {
	case exchange := <-gw.exchanges:
		t.Fatalf("exchanged a registration token for %q with no provisioned secret", exchange.Prefix)
	case reg := <-gw.registrations:
		t.Fatalf("registered module %q → %q with no provisioned secret", reg.Prefix, reg.Upstream)
	case <-time.After(500 * time.Millisecond):
	}

	if out := buf.String(); !strings.Contains(out, ModuleRegistrationSecretsEnvironmentVariable) {
		t.Errorf("missing secret was not reported against %s, got: %q", ModuleRegistrationSecretsEnvironmentVariable, out)
	}
}

// TestServeIsolatesFailedModuleRegistration proves a per-module failure stays
// per-module: the composition provisions a secret for one consumed module and a
// stale one for another, so the first federates while the second's exchange is
// refused. The refused module must not take down the backend or the sibling
// registration — it just retries on its own heartbeat.
func TestServeIsolatesFailedModuleRegistration(t *testing.T) {
	setEndpoint(t, "CODEFLY__ENDPOINT__DOCSTORE__DOCUMENTS__REST__REST", "http://docstore-upstream:9100")
	setEndpoint(t, "CODEFLY__ENDPOINT__BILLING__INVOICES__REST__REST", "http://billing-upstream:9200")
	t.Setenv("CODEFLY__API_CONSUMES", `[`+
		`{"id":"billing.invoices","module":"billing","service":"invoices","endpoint":"rest","protocol":"rest","as":"billing"},`+
		`{"id":"docstore.documents","module":"docstore","service":"documents","endpoint":"rest","protocol":"rest","as":"documents"}]`)
	t.Setenv(ModuleRegistrationSecretsEnvironmentVariable, "documents:s3cret,billing:stale")

	gw := newFakeGateway(t, &fakeGateway{declared: map[string]string{
		"documents": "s3cret",
		"billing":   "rotated",
	}})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bootWithModuleRegistry(t, ln, gw)()

	select {
	case reg := <-gw.registrations:
		if reg.Prefix != "documents" {
			t.Errorf("registered prefix = %q, want only %q to reach registration", reg.Prefix, "documents")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the module with a valid secret did not register within timeout")
	}

	// The backend is still serving: the refused module's failure did not take it
	// down with it.
	resp, err := http.Get("http://127.0.0.1:" + strconv.Itoa(ln.Addr().(*net.TCPAddr).Port) + "/health")
	if err != nil {
		t.Fatalf("backend stopped serving after a module registration failure: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("health = %d, want 200", resp.StatusCode)
	}
}

// TestServeSkipsConsumedAPIWithoutFacade proves the runtime never guesses a
// facade prefix. Core derives an omitted `as` from the producing endpoint's
// proto package — a value the runtime cannot reconstruct from the projected
// identity — so an entry that arrives with no `as` is skipped rather than
// registered under a fabricated prefix (e.g. the module name), which would proxy
// a route the generated client never calls and could steal another facade's
// prefix. The consumed endpoint resolves fine; only the missing `as` suppresses
// registration.
func TestServeSkipsConsumedAPIWithoutFacade(t *testing.T) {
	setEndpoint(t, "CODEFLY__ENDPOINT__DOCSTORE__DOCUMENTS__REST__REST", "http://docstore-upstream:9100")
	t.Setenv("CODEFLY__API_CONSUMES",
		`[{"id":"docstore.documents","module":"docstore","service":"documents","endpoint":"rest","protocol":"rest"}]`)
	t.Setenv(ModuleRegistrationSecretsEnvironmentVariable, "documents:s3cret")

	gw := newFakeGateway(t, &fakeGateway{declared: map[string]string{"documents": "s3cret"}})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bootWithModuleRegistry(t, ln, gw)()

	select {
	case reg := <-gw.registrations:
		t.Fatalf("registered module %q → %q for a consumed api with no facade entry-point (as); the runtime must not invent a prefix", reg.Prefix, reg.Upstream)
	case <-time.After(500 * time.Millisecond):
		// No registration, as expected.
	}
}

// TestServeRegistersNoModulesWithoutConsumes proves the no-op: a solution that
// declares no api.consumes (empty CODEFLY__API_CONSUMES) registers no module
// upstream at all, so nothing changes for the solutions that consume nothing.
func TestServeRegistersNoModulesWithoutConsumes(t *testing.T) {
	t.Setenv("CODEFLY__API_CONSUMES", "")

	gw := newFakeGateway(t, &fakeGateway{})

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer bootWithModuleRegistry(t, ln, gw)()

	select {
	case reg := <-gw.registrations:
		t.Fatalf("registered module %q → %q for a solution that declares no api.consumes", reg.Prefix, reg.Upstream)
	case <-time.After(500 * time.Millisecond):
		// No registration, as expected.
	}
}

// TestModuleCredentialReusesTokenUntilRenewal proves the beat does not re-mint
// every 15 seconds: a registration token lives 5 minutes, and each mint is an
// audited security event on accounts, so a token still comfortably inside its
// lifetime is reused.
func TestModuleCredentialReusesTokenUntilRenewal(t *testing.T) {
	gw := newFakeGateway(t, &fakeGateway{declared: map[string]string{"documents": "s3cret"}})
	credential := &moduleCredential{
		tokenURL:      gw.URL + moduleRegistrationTokenPath,
		internalToken: internalTokenTest,
		prefix:        "documents",
		secret:        "s3cret",
	}

	for beat := range 3 {
		req, err := http.NewRequest(http.MethodPost, gw.URL+moduleRegisterPath, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := credential.authorize(context.Background(), req); err != nil {
			t.Fatalf("beat %d: authorize: %v", beat, err)
		}
		if got := req.Header.Get(moduleRegistrationHeader); got != "minted-documents-1" {
			t.Errorf("beat %d presented %q, want the first minted token reused", beat, got)
		}
	}
	if got := gw.mintCount(); got != 1 {
		t.Errorf("minted %d tokens across 3 beats, want 1 — a live token must be reused", got)
	}
}

// TestModuleCredentialReExchangesAfterRejection proves recovery from a refused
// registration: the gateway answering 401 means the token it was handed is no
// longer honoured (a restarted gateway, a rotated key), so replaying it for the
// rest of its lifetime would strand the module. Invalidating forces a fresh
// exchange on the next beat.
func TestModuleCredentialReExchangesAfterRejection(t *testing.T) {
	gw := newFakeGateway(t, &fakeGateway{declared: map[string]string{"documents": "s3cret"}})
	credential := &moduleCredential{
		tokenURL:      gw.URL + moduleRegistrationTokenPath,
		internalToken: internalTokenTest,
		prefix:        "documents",
		secret:        "s3cret",
	}

	req, err := http.NewRequest(http.MethodPost, gw.URL+moduleRegisterPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.authorize(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	credential.invalidate()
	if err := credential.authorize(context.Background(), req); err != nil {
		t.Fatal(err)
	}

	if got := req.Header.Get(moduleRegistrationHeader); got != "minted-documents-2" {
		t.Errorf("presented %q after invalidation, want a freshly minted token", got)
	}
	if got := gw.mintCount(); got != 2 {
		t.Errorf("minted %d tokens, want 2 — a refused credential must be re-exchanged", got)
	}
}

// TestHeartbeatReExchangesOnRejectedRegistration proves the invalidation is
// actually wired to the beat loop, not just available on the credential: a
// gateway that answers 401 to /modules/_register makes the next beat run a new
// exchange rather than replay the refused token.
func TestHeartbeatReExchangesOnRejectedRegistration(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	gw := newFakeGateway(t, &fakeGateway{
		declared:       map[string]string{"documents": "s3cret"},
		registerStatus: http.StatusUnauthorized,
	})
	credential := &moduleCredential{
		tokenURL:      gw.URL + moduleRegistrationTokenPath,
		internalToken: internalTokenTest,
		prefix:        "documents",
		secret:        "s3cret",
	}

	restore := registrationInterval
	registrationInterval = time.Millisecond
	defer func() { registrationInterval = restore }()

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{manifest: Manifest{ID: "lastlogin-go"}}
	done := make(chan struct{})
	go func() {
		s.heartbeat(ctx, gw.URL+moduleRegisterPath, []byte(`{"prefix":"documents"}`), "gateway module documents", credential)
		close(done)
	}()
	defer func() { cancel(); <-done }()

	seen := map[string]bool{}
	for range 2 {
		select {
		case reg := <-gw.registrations:
			if seen[reg.Registration] {
				t.Fatalf("replayed the refused token %q on the next beat", reg.Registration)
			}
			seen[reg.Registration] = true
		case <-time.After(5 * time.Second):
			t.Fatal("gateway did not receive two registration attempts within timeout")
		}
	}
}

func TestParseModuleRegistrationSecrets(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want map[string]string
	}{
		{name: "empty", raw: "", want: map[string]string{}},
		{name: "one", raw: "documents:s3cret", want: map[string]string{"documents": "s3cret"}},
		{
			name: "several, spaced",
			raw:  "documents:s3cret, billing:other",
			want: map[string]string{"documents": "s3cret", "billing": "other"},
		},
		// A secret is opaque and base64 may contain "=" and "+"; only the first
		// ":" separates it from the prefix.
		{name: "secret keeps inner colons", raw: "documents:a:b", want: map[string]string{"documents": "a:b"}},
		{name: "unpaired entry dropped", raw: "documents", want: map[string]string{}},
		{name: "empty secret dropped", raw: "documents:", want: map[string]string{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseModuleRegistrationSecrets(tt.raw); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseModuleRegistrationSecrets(%q) = %v, want %v", tt.raw, got, tt.want)
			}
		})
	}
}
