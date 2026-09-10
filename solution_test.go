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

	mu sync.Mutex
	// registerRefusals, while positive, makes /modules/_register answer 401 and
	// counts down — a gateway that has stopped honouring the token it was handed
	// and accepts the next one.
	registerRefusals int
	minted           int
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
		g.mu.Lock()
		refusing := g.registerRefusals > 0
		if refusing {
			g.registerRefusals--
		}
		g.mu.Unlock()
		if refusing {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
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
// registration: the gateway answering 401 means the token it was handed may no
// longer be honoured (a restarted gateway, a rotated key), so replaying it for
// the rest of its lifetime would strand the module. A refusal of a token held
// from an earlier beat forces a fresh exchange on the next one.
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
	// A later beat presents the held token; that beat's refusal is the one that
	// can be blamed on staleness, so it drops the credential.
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

// TestModuleCredentialKeepsATokenMintedForThisBeat proves the one refusal a
// fresh mint cannot fix is not answered with another mint. A gateway that
// refuses a token minted moments ago is refusing it for a reason that has
// nothing to do with staleness — it does not trust the issuer, the prefix is not
// this module's to claim, its own clock is skewed, or a perimeter check rejected
// the request before the token was ever read. Dropping the credential there put
// a mint on every single beat: an audited security event on the issuer four
// times a minute per module, indefinitely, and silent after the first log line
// because the status never changes.
func TestModuleCredentialKeepsATokenMintedForThisBeat(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

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
	credential.invalidate() // refused the token this beat just minted
	if credential.token == "" {
		t.Fatal("dropped a token minted for this very beat; re-minting cannot fix a refusal that was never about staleness")
	}
	if err := credential.authorize(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if got := gw.mintCount(); got != 1 {
		t.Errorf("minted %d tokens, want 1 — a refusal of a just-minted token must not buy another mint", got)
	}
}

// TestHeartbeatReExchangesOnRejectedRegistration proves the invalidation is
// actually wired to the beat loop, not just available on the credential: a
// gateway that answers 401 once — having stopped honouring the token it was
// handed — makes the next beat present a freshly exchanged one.
func TestHeartbeatReExchangesOnRejectedRegistration(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	// Refuse the first two registrations. The first presents a token minted for
	// that same beat, which re-minting cannot fix; the second presents that
	// token held over from the earlier beat, and that is the refusal staleness
	// explains — so it must be answered with a fresh exchange.
	gw := newFakeGateway(t, &fakeGateway{
		declared:         map[string]string{"documents": "s3cret"},
		registerRefusals: 2,
	})
	credential := &moduleCredential{
		tokenURL:      gw.URL + moduleRegistrationTokenPath,
		internalToken: internalTokenTest,
		prefix:        "documents",
		secret:        "s3cret",
	}

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{manifest: Manifest{ID: "lastlogin-go"}, registrationInterval: time.Millisecond}
	done := make(chan struct{})
	go func() {
		s.heartbeat(ctx, gw.URL+moduleRegisterPath, []byte(`{"prefix":"documents"}`), "gateway module documents", credential)
		close(done)
	}()
	defer func() { cancel(); <-done }()

	first, deadline := "", time.After(10*time.Second)
	for {
		select {
		case reg := <-gw.registrations:
			switch {
			case reg.Registration == "":
				t.Fatal("registered with no token")
			case first == "":
				first = reg.Registration
			case reg.Registration != first:
				return // recovered: a fresh credential replaced the stale one
			}
		case <-deadline:
			t.Fatalf("kept replaying %q: a token refused after being held across beats must be re-exchanged", first)
		}
	}
}

// TestHeartbeatDoesNotMintPerBeatOnAPersistentRefusal is the regression guard
// for the mint storm. A gateway that refuses every registration does so for a
// reason no new token can repair, and the old loop answered each refusal with a
// fresh exchange: at the production 15s beat that is four mints a minute per
// module, forever, each one an audited security event on the issuer — and
// silent after the first log line, because the status never changes.
//
// The refusal is now worth exactly one re-mint, and failing beats back off, so
// the mint count stays flat however long the gateway stays broken.
func TestHeartbeatDoesNotMintPerBeatOnAPersistentRefusal(t *testing.T) {
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

	ctx, cancel := context.WithCancel(context.Background())
	s := &Server{manifest: Manifest{ID: "lastlogin-go"}, registrationInterval: time.Millisecond}
	done := make(chan struct{})
	go func() {
		s.heartbeat(ctx, gw.URL+moduleRegisterPath, []byte(`{"prefix":"documents"}`), "gateway module documents", credential)
		close(done)
	}()
	defer func() { cancel(); <-done }()

	const beats = 5
	for range beats {
		select {
		case <-gw.registrations:
		case <-time.After(10 * time.Second):
			t.Fatalf("gateway saw fewer than %d registration attempts", beats)
		}
	}
	// One mint to obtain the credential, at most one more to answer the refusal.
	if got := gw.mintCount(); got > 2 {
		t.Errorf("minted %d tokens across %d refused beats, want at most 2 — a refusal that a new token cannot fix must not re-mint on every beat", got, beats)
	}
}

// TestModuleCredentialRetriesAgainAfterRecovering proves a spent retry budget is
// restored by a successful registration, so a second, independent refusal — a
// gateway rotating its key twice inside one credential lifetime — is answered
// with a fresh token instead of inheriting the first refusal's spent attempt and
// stranding the module until the token renews on its own.
func TestModuleCredentialRetriesAgainAfterRecovering(t *testing.T) {
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
	authorize := func() {
		t.Helper()
		if err := credential.authorize(context.Background(), req); err != nil {
			t.Fatal(err)
		}
	}
	authorize()             // beat 1: mint
	authorize()             // beat 2: replay the held token
	credential.invalidate() // refused: spends the retry, drops
	authorize()             // beat 3: mint the replacement
	credential.succeeded()  // ... which the gateway accepts

	authorize()             // beat 4: replay
	credential.invalidate() // a second, independent refusal
	if credential.token != "" {
		t.Fatal("kept a token refused after an intervening success: a new fault must earn its own re-mint")
	}
	authorize()
	if got := gw.mintCount(); got != 3 {
		t.Errorf("minted %d tokens, want 3 — one per refusal episode plus the original", got)
	}
}

// TestHeartbeatDropsACredentialRefusedWith403 proves 403 recovers like 401. A
// gateway answering "forbidden" to a lapsed token would otherwise have that
// token replayed until it renewed naturally, stranding the module for most of
// the credential's lifetime.
func TestHeartbeatDropsACredentialRefusedWith403(t *testing.T) {
	credential := &moduleCredential{prefix: "documents", token: "held", renewAt: time.Now().Add(time.Hour)}
	// A token held from an earlier beat: this beat did not mint it.
	credential.invalidate()
	if credential.token != "" {
		t.Fatal("a refused credential held from an earlier beat must be dropped")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	if status := statusOfOneBeat(t, srv.URL); status != http.StatusForbidden {
		t.Fatalf("beat status = %d, want 403", status)
	}
}

// statusOfOneBeat runs a single beat against target and returns its status.
func statusOfOneBeat(t *testing.T, target string) int {
	t.Helper()
	s := &Server{manifest: Manifest{ID: "lastlogin-go"}}
	status, err := s.beat(context.Background(), target, []byte(`{}`), internalTokenAuth("tok"))
	if err != nil {
		t.Fatal(err)
	}
	return status
}

// TestExchangeRejectsAnUnusableExpiry proves the credential refuses an expiry
// it cannot act on instead of caching it as "already expired". Treated as
// expired it would re-run the exchange on every beat while every registration
// still returned 200 — an unlogged mint, and an audited security event on the
// issuer, four times a minute for as long as the solution runs.
func TestExchangeRejectsAnUnusableExpiry(t *testing.T) {
	for _, tc := range []struct {
		name string
		body map[string]string
	}{
		// A response whose expiry field never arrives (an unset timestamp on the
		// issuer, or a rename to the protobuf JSON spelling) decodes to the zero
		// time.
		{name: "absent", body: map[string]string{"token": "t"}},
		{name: "epoch zero", body: map[string]string{"token": "t", "expiresAt": "1970-01-01T00:00:00Z"}},
		// Stands in for a host clock skewed past the credential's own lifetime.
		{name: "already past", body: map[string]string{
			"token": "t", "expiresAt": time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)}},
		// Below the minimum usable lifetime: it would lapse in flight.
		{name: "lapses in flight", body: map[string]string{
			"token": "t", "expiresAt": time.Now().Add(2 * time.Second).UTC().Format(time.RFC3339)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exchanges := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				exchanges++
				writeJSON(w, http.StatusOK, tc.body)
			}))
			defer srv.Close()

			credential := &moduleCredential{
				tokenURL: srv.URL, internalToken: internalTokenTest,
				prefix: "documents", secret: "s3cret",
			}
			req, err := http.NewRequest(http.MethodPost, srv.URL, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := credential.authorize(context.Background(), req); err == nil {
				t.Fatal("accepted a token the runtime cannot hold; a beat loop would re-mint forever")
			}
			// A second beat must not have cached anything either.
			_ = credential.authorize(context.Background(), req)
			if exchanges != 2 {
				t.Errorf("exchanged %d times across 2 beats, want 2 attempts and 0 cached", exchanges)
			}
			if credential.token != "" {
				t.Errorf("cached a token with an unusable expiry: %q", credential.token)
			}
		})
	}
}

// TestRegistrationRequestsAreBounded is the regression guard for a wedged
// heartbeat. The beat's context carries no deadline, so without a client timeout
// a gateway that accepts a registration and never answers blocked the beat in
// Do forever: no further beats, no log, and no recovery short of a restart —
// for that module, or for this whole solution when it happened on one of the two
// self-registrations. Asserted on the client rather than by holding a real
// request open, so the guard costs no wall clock.
func TestRegistrationRequestsAreBounded(t *testing.T) {
	if registrationClient.Timeout != registrationTimeout {
		t.Errorf("registrationClient.Timeout = %s, want %s: a gateway that never answers must surface as a failed beat, not wedge the loop",
			registrationClient.Timeout, registrationTimeout)
	}
	if registrationTimeout <= 0 {
		t.Error("registrationTimeout must be positive")
	}
}

// TestExchangeOmitsAnUnconfiguredInternalToken proves the exchange sends no
// header at all rather than an empty one, matching internalTokenAuth. A caller
// claiming a credential it does not hold is the harder shape to diagnose at the
// gateway.
func TestExchangeOmitsAnUnconfiguredInternalToken(t *testing.T) {
	seen := make(chan http.Header, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen <- r.Header.Clone()
		writeJSON(w, http.StatusOK, map[string]string{
			"token": "t", "expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339)})
	}))
	defer srv.Close()

	credential := &moduleCredential{tokenURL: srv.URL, prefix: "documents", secret: "s3cret"}
	req, err := http.NewRequest(http.MethodPost, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := credential.authorize(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if _, ok := (<-seen)[http.CanonicalHeaderKey(internalTokenHeader)]; ok {
		t.Errorf("sent %s with no token configured, want the header absent", internalTokenHeader)
	}
}

// TestExchangeAcceptsAShortButUsableExpiry proves the renewal lead is a ceiling
// on how early the credential renews, not a floor on what the issuer may issue.
// Conflating the two refused every token whose whole life was shorter than the
// 30s lead — a 30s credential was rejected outright, and the error blamed this
// host's clock for an issuer setting that was deliberate and fine. A short token
// is now held and renewed at half its life.
func TestExchangeAcceptsAShortButUsableExpiry(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)

	for _, ttl := range []time.Duration{10 * time.Second, 30 * time.Second, 5 * time.Minute} {
		t.Run(ttl.String(), func(t *testing.T) {
			gw := newFakeGateway(t, &fakeGateway{
				declared: map[string]string{"documents": "s3cret"},
				tokenTTL: ttl,
			})
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
				t.Fatalf("refused a usable %s credential: %v", ttl, err)
			}
			if req.Header.Get(moduleRegistrationHeader) == "" {
				t.Error("presented no token")
			}
			// Renewal is at half-life for a short token, and a full lead ahead
			// of expiry for a long one — never after expiry, and never so early
			// that the token is discarded unused.
			wantLead := min(moduleTokenRenewal, ttl/2)
			held := time.Until(credential.renewAt)
			if held <= 0 || held > ttl-wantLead+time.Second {
				t.Errorf("renewAt is %s away for a %s credential, want about %s", held, ttl, ttl-wantLead)
			}
		})
	}
}

// TestSiblingURLFollowsAnOverriddenGateway proves the two federation endpoints
// stay on one gateway. The credential a registration presents is minted by the
// exchange, so an explicitly overridden registration URL must carry the
// exchange with it — minting against one host and registering with another
// yields a token the second never trusts.
func TestSiblingURLFollowsAnOverriddenGateway(t *testing.T) {
	t.Setenv("PORT", "8090")
	t.Setenv("GATEWAY_URL", "http://gateway:42152")
	t.Setenv("HOST_REGISTER_URL", "http://frontend:21931/api/solutions/register")
	t.Setenv("GATEWAY_MODULE_REGISTER_URL", "https://other-gateway:9999/modules/_register")

	cfg := loadConfig(context.Background(), "lastlogin-go")
	want := "https://other-gateway:9999" + moduleRegistrationTokenPath
	if cfg.moduleTokenURL != want {
		t.Errorf("module token URL = %q, want %q — it must follow the overridden register URL", cfg.moduleTokenURL, want)
	}
}

// An unparseable override must surface as itself, so validate() names the one
// URL the operator actually set instead of a second one derived from it.
func TestSiblingURLPassesThroughAnUnusableBase(t *testing.T) {
	if got := siblingURL("/modules/_register", moduleRegisterPath, moduleRegistrationTokenPath); got != "/modules/_register" {
		t.Errorf("siblingURL(relative) = %q, want the base handed back unchanged", got)
	}
}

// TestSiblingURLKeepsTheGatewayBasePath proves the derived endpoint stays on the
// gateway's mount, not just its host. Rebuilding the URL from scheme+host
// dropped any path between them, so a gateway served under a prefix registered
// at /gw/modules/_register while exchanging at /modules/_registration-token —
// still absolute, so validate() passed it, and a 404 on every beat after that.
func TestSiblingURLKeepsTheGatewayBasePath(t *testing.T) {
	t.Setenv("PORT", "8090")
	t.Setenv("GATEWAY_URL", "http://gateway:42152/gw")
	t.Setenv("HOST_REGISTER_URL", "http://frontend:21931/api/solutions/register")

	cfg := loadConfig(context.Background(), "lastlogin-go")
	if want := "http://gateway:42152/gw" + moduleRegisterPath; cfg.moduleRegisterURL != want {
		t.Errorf("module register URL = %q, want %q", cfg.moduleRegisterURL, want)
	}
	if want := "http://gateway:42152/gw" + moduleRegistrationTokenPath; cfg.moduleTokenURL != want {
		t.Errorf("module token URL = %q, want %q — the derived endpoint must keep the gateway's base path", cfg.moduleTokenURL, want)
	}
	if err := cfg.validate(); err != nil {
		t.Errorf("validate() = %v, want nil", err)
	}
}

// TestSiblingURLRefusesAnUnpairableOverride proves an override whose sibling
// cannot be derived fails loud at boot rather than resolving to a plausible
// guess that 404s on every beat. The operator must then name the token URL.
func TestSiblingURLRefusesAnUnpairableOverride(t *testing.T) {
	t.Setenv("PORT", "8090")
	t.Setenv("GATEWAY_URL", "http://gateway:42152")
	t.Setenv("HOST_REGISTER_URL", "http://frontend:21931/api/solutions/register")
	t.Setenv("GATEWAY_MODULE_REGISTER_URL", "https://other-gateway:9999/custom/registration-endpoint")

	cfg := loadConfig(context.Background(), "lastlogin-go")
	if cfg.moduleTokenURL != "" {
		t.Errorf("module token URL = %q, want empty so validate() names it", cfg.moduleTokenURL)
	}
	err := cfg.validate()
	if err == nil || !strings.Contains(err.Error(), "module token URL") {
		t.Errorf("validate() = %v, want an error naming the module token URL", err)
	}

	// Naming it explicitly is the documented way out.
	t.Setenv("GATEWAY_MODULE_REGISTRATION_TOKEN_URL", "https://other-gateway:9999/custom/token-endpoint")
	if err := loadConfig(context.Background(), "lastlogin-go").validate(); err != nil {
		t.Errorf("validate() with an explicit token URL = %v, want nil", err)
	}
}

// TestBackoffGrowsWhileBrokenAndResetsWhenHealthy pins the retry schedule that
// bounds every failure path on the credential exchange.
func TestBackoffGrowsWhileBrokenAndResetsWhenHealthy(t *testing.T) {
	const interval = 15 * time.Second
	for _, tc := range []struct {
		failures int
		want     time.Duration
	}{
		{0, interval},
		{1, 30 * time.Second},
		{2, time.Minute},
		{3, registrationBackoffCap},
		{50, registrationBackoffCap},
	} {
		if got := backoff(interval, tc.failures); got != tc.want {
			t.Errorf("backoff(%s, %d) = %s, want %s", interval, tc.failures, got, tc.want)
		}
	}
	// An interval longer than the cap is the caller's choice, not something to
	// shorten.
	if got := backoff(time.Hour, 0); got != time.Hour {
		t.Errorf("backoff(1h, 0) = %s, want 1h", got)
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
		// The registrar trims both halves of its digest twin; parsing the two
		// asymmetrically turns a pair it accepts into a lookup miss here.
		{name: "spaces around both halves", raw: "documents : s3cret", want: map[string]string{"documents": "s3cret"}},
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

// --- Work Context ---

// mintRequest is what the accounts StartTask RPC received: the ask itself, plus
// the credentials it was presented with — the bearer, which decides whose Task
// is minted, and any capability that rode along, which none should.
type mintRequest struct {
	OrgID           string             `json:"orgId"`
	TaskID          string             `json:"taskId"`
	SessionID       string             `json:"sessionId"`
	Audience        string             `json:"audience"`
	AuthorityScopes []workContextScope `json:"authorityScopes"`
	Bearer          string             `json:"-"`
	WorkContext     string             `json:"-"`
}

// moduleCall is what a composed module behind the gateway received: the two
// credentials the read is authenticated with.
type moduleCall struct {
	Bearer      string
	WorkContext string
}

// workContextGateway stands in for the host gateway on the two routes a
// Work-Context-authenticated read crosses: the accounts mint, and the module
// itself. A module answers only a request carrying a context minted for it, as
// the real one does — a bearer alone is Unauthenticated.
type workContextGateway struct {
	*httptest.Server
	mints chan mintRequest
	calls chan moduleCall

	// tokenTTL is how long an issued capability is claimed to be valid, on the
	// issuer's clock. Negative stands in for this host's clock running ahead of
	// the issuer's, which is indistinguishable here from an expiry gone by.
	tokenTTL time.Duration
	// omitExpiry drops expiresAt from the issued capability — the shape an
	// issuer spelling it expires_at (protobuf JSON) produces on this decoder.
	omitExpiry bool
	// mintStatus, when non-zero, is what StartTask answers instead of issuing.
	mintStatus int
	// mintDelay holds each mint open, so concurrent asks genuinely overlap
	// rather than serialising by luck.
	mintDelay time.Duration

	mu     sync.Mutex
	minted int
}

const modulePath = "/v1/documents/collection"

func newWorkContextGateway(t *testing.T, gw *workContextGateway) *workContextGateway {
	t.Helper()
	gw.mints = make(chan mintRequest, 16)
	gw.calls = make(chan moduleCall, 16)
	if gw.tokenTTL == 0 {
		gw.tokenTTL = 5 * time.Minute
	}
	gw.Server = httptest.NewServer(http.HandlerFunc(gw.serve))
	t.Cleanup(gw.Close)
	return gw
}

func (g *workContextGateway) serve(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case workContextStartTaskProcedure:
		var mint mintRequest
		_ = json.NewDecoder(r.Body).Decode(&mint)
		mint.Bearer = r.Header.Get("authorization")
		mint.WorkContext = r.Header.Get(codefly.WorkContextHeaderName)
		send(g.mints, mint)
		if g.mintStatus != 0 {
			writeJSON(w, g.mintStatus, map[string]string{
				"code":    "permission_denied",
				"message": "caller holds no such authority",
			})
			return
		}
		g.mu.Lock()
		g.minted++
		// Two segments: the wire shape sdk-go accepts for a signed capability.
		token := fmt.Sprintf("context-%s.%d", mint.Audience, g.minted)
		g.mu.Unlock()
		if g.mintDelay > 0 {
			time.Sleep(g.mintDelay)
		}
		issued := map[string]any{"token": token}
		if !g.omitExpiry {
			issued["expiresAt"] = time.Now().Add(g.tokenTTL).UTC().Format(time.RFC3339Nano)
		}
		writeJSON(w, http.StatusOK, issued)
	case modulePath:
		call := moduleCall{
			Bearer:      r.Header.Get("authorization"),
			WorkContext: r.Header.Get(codefly.WorkContextHeaderName),
		}
		send(g.calls, call)
		if call.WorkContext == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"collection": "handbook"})
	default:
		w.WriteHeader(http.StatusOK)
	}
}

func (g *workContextGateway) mintCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.minted
}

// getThrough issues one module read on an already-derived gateway.
func getThrough(ctx context.Context, gw *Gateway) (int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, gw.BaseURL()+modulePath, nil)
	if err != nil {
		return 0, err
	}
	resp, err := gw.HTTPClient().Do(req)
	if err != nil {
		return 0, err
	}
	defer drainAndClose(resp)
	return resp.StatusCode, nil
}

// readModule drives the composed-module read the way a solution handler does:
// derive a gateway for the module, then call it through that gateway's client.
func readModule(ctx context.Context, gw *Gateway, audience string) (int, error) {
	module, err := gw.ForModule(ctx, audience, Scope{ResourceKind: "documents", Actions: []string{"read"}})
	if err != nil {
		return 0, err
	}
	return getThrough(ctx, module)
}

// lapseCachedCapabilities backdates every capability the request has cached,
// standing in for the issuer's TTL running out while a handler still holds a
// gateway it derived earlier.
func lapseCachedCapabilities(gw *Gateway) {
	gw.contexts.mu.Lock()
	defer gw.contexts.mu.Unlock()
	for key, issued := range gw.contexts.minted {
		issued.reuseUntil = time.Now().Add(-time.Second)
		gw.contexts.minted[key] = issued
	}
}

// serveHandler runs one solution handler behind the runtime's own wrapper, so a
// test exercises the same Gateway a real request produces — including the
// viewer identity the gateway injects, which wrap is the only place to read.
func serveHandler(t *testing.T, gatewayURL string, handler Handler) *httptest.Server {
	t.Helper()
	s := New(Manifest{ID: "wiki", Title: "Wiki"})
	s.cfg = config{gatewayURL: gatewayURL}
	server := httptest.NewServer(s.wrap(handler))
	t.Cleanup(server.Close)
	return server
}

const viewerOrg = "6f1d0a2e-6a21-4d0e-9a0e-2b8f6d2f0b11"

// viewerRequest is the request the gateway forwards to a solution: the viewer's
// bearer, plus the canonical identity headers it injects after authenticating.
func viewerRequest(t *testing.T, target string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, target, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("authorization", "Bearer viewer-token")
	req.Header.Set(orgHeader, viewerOrg)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("call solution: %v", err)
	}
	return resp
}

// TestForModuleMintsAndPresentsTheViewersWorkContext is the whole point of the
// feature: a module that authenticates by signed Work Context refuses the
// bearer the runtime used to forward alone, so the read only succeeds because
// the runtime minted a capability for the viewer and presented it alongside.
func TestForModuleMintsAndPresentsTheViewersWorkContext(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	var status int
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		var err error
		status, err = readModule(ctx, g, "documents")
		return status, err
	})

	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("solution answered %d, want 200", resp.StatusCode)
	}
	if status != http.StatusOK {
		t.Fatalf("module answered %d, want 200 — the read was not authenticated", status)
	}

	mint := <-gw.mints
	if mint.Bearer != "Bearer viewer-token" {
		t.Errorf("mint presented bearer %q, want the viewer's — accounts must resolve the viewer as owner", mint.Bearer)
	}
	if mint.OrgID != viewerOrg {
		t.Errorf("mint org = %q, want the org the gateway injected", mint.OrgID)
	}
	if mint.Audience != "documents" {
		t.Errorf("mint audience = %q, want %q", mint.Audience, "documents")
	}
	want := []workContextScope{{ResourceKind: "documents", Actions: []string{"read"}}}
	if !reflect.DeepEqual(mint.AuthorityScopes, want) {
		t.Errorf("mint scopes = %v, want %v", mint.AuthorityScopes, want)
	}
	// A Task and its root Session are named per mint, and accounts requires
	// both to be UUIDs — an empty or reused id is refused before the handler.
	if mint.TaskID == "" || mint.SessionID == "" || mint.TaskID == mint.SessionID {
		t.Errorf("mint task/session = %q/%q, want two distinct ids", mint.TaskID, mint.SessionID)
	}

	call := <-gw.calls
	if call.WorkContext != "context-documents.1" {
		t.Errorf("module read carried work context %q, want the minted one", call.WorkContext)
	}
	if call.Bearer != "Bearer viewer-token" {
		t.Errorf("module read carried bearer %q, want the viewer's — the context is presented alongside it, not instead", call.Bearer)
	}
}

// TestForModuleMintsOncePerAsk pins the cache: minting is an audited event on
// accounts, so a handler reading the same module repeatedly must not mint per
// read. A different audience is a different ask and does mint again.
func TestForModuleMintsOncePerAsk(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		for range 3 {
			if _, err := readModule(ctx, g, "documents"); err != nil {
				return nil, err
			}
		}
		if _, err := g.ForModule(ctx, "billing", Scope{ResourceKind: "invoices", Actions: []string{"read"}}); err != nil {
			return nil, err
		}
		return "done", nil
	})

	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("solution answered %d, want 200", resp.StatusCode)
	}
	if got := gw.mintCount(); got != 2 {
		t.Errorf("minted %d capabilities, want 2 (one per distinct ask)", got)
	}
}

// TestForModuleMintsOncePerAskUnderConcurrency covers the fan-out a sequential
// test cannot see: a handler deriving the same ask from several goroutines must
// spend one audited mint, not one per goroutine.
func TestForModuleMintsOncePerAskUnderConcurrency(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{mintDelay: 50 * time.Millisecond})
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := readModule(ctx, g, "documents"); err != nil {
					errs <- err
				}
			}()
		}
		wg.Wait()
		close(errs)
		return "done", <-errs
	})

	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("solution answered %d, want 200", resp.StatusCode)
	}
	if got := gw.mintCount(); got != 1 {
		t.Errorf("minted %d capabilities for one ask across 8 goroutines, want 1", got)
	}
}

// TestForModuleReusesAShortLivedCapability is the test the silent-flood bug
// needed. An issuer whose lifetime is shorter than the renewal lead must not
// make every capability uncacheable: the lead is clamped to half the lifetime,
// so the cache still holds. Without that clamp this mints once per read while
// answering every read correctly — no error, no log.
func TestForModuleReusesAShortLivedCapability(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{tokenTTL: 6 * time.Second})
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		for range 3 {
			if _, err := readModule(ctx, g, "documents"); err != nil {
				return nil, err
			}
		}
		return "done", nil
	})

	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("solution answered %d, want 200", resp.StatusCode)
	}
	if got := gw.mintCount(); got != 1 {
		t.Errorf("minted %d capabilities across 3 reads, want 1 — a lifetime shorter than the renewal lead must clamp the lead, not defeat the cache", got)
	}
}

// TestForModuleRefusesACapabilityWithNoExpiry refuses loudly rather than
// caching something that can never be reused. Treated as "already lapsed" this
// mints on every read forever while every read still succeeds, which is the
// failure mode that never shows up in a log.
func TestForModuleRefusesACapabilityWithNoExpiry(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{omitExpiry: true})
	var mintErr error
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		_, mintErr = g.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
		return nil, mintErr
	})

	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)
	if mintErr == nil {
		t.Fatal("ForModule accepted a capability with no expiry")
	}
	// The spelling hint is the whole value of the message: expires_at is what a
	// protobuf-JSON issuer sends, and it decodes to the zero time in silence.
	for _, want := range []string{"documents", "no expiry", "expires_at"} {
		if !strings.Contains(mintErr.Error(), want) {
			t.Errorf("error %q does not mention %q", mintErr, want)
		}
	}
	select {
	case call := <-gw.calls:
		t.Errorf("module was read anyway, with work context %q", call.WorkContext)
	default:
	}
}

// TestForModuleRefusesAnExpiryThisHostCannotUse covers clock skew, which needs
// no misconfiguration anywhere: accounts would still accept the capability, so
// left alone every read succeeds and every read mints.
func TestForModuleRefusesAnExpiryThisHostCannotUse(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{tokenTTL: -time.Minute})
	var mintErr error
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		_, mintErr = g.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
		return nil, mintErr
	})

	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)
	if mintErr == nil {
		t.Fatal("ForModule accepted an expiry already gone by")
	}
	if !strings.Contains(mintErr.Error(), "clock") {
		t.Errorf("error %q does not point at the clock, the one thing that explains it", mintErr)
	}
}

// TestWorkContextCacheReMintsALapsedCapability pins the cache's own expiry rule
// without waiting on a real TTL: a capability past its reuse deadline is minted
// afresh rather than presented.
func TestWorkContextCacheReMintsALapsedCapability(t *testing.T) {
	cache := newWorkContextCache()
	mints := 0
	lapsed := func(context.Context) (codefly.WorkContextToken, time.Time, error) {
		mints++
		token, err := codefly.ParseWorkContextToken(fmt.Sprintf("payload.%d", mints))
		if err != nil {
			t.Fatalf("parse token: %v", err)
		}
		return token, time.Now().Add(-time.Second), nil
	}
	for range 2 {
		if _, err := cache.resolve(context.Background(), "ask", lapsed); err != nil {
			t.Fatalf("resolve: %v", err)
		}
	}
	if mints != 2 {
		t.Errorf("minted %d times, want 2 — a capability past its reuse deadline must not be handed out", mints)
	}
}

// TestDerivedGatewayResolvesTheCapabilityPerRequest is the fix for a gateway
// that snapshotted its capability at derivation. A handler may hold the derived
// gateway for as long as it holds the request; when the capability lapses
// mid-request the next call must carry a fresh one. Snapshotted, it carries the
// stale one and the edge rejects it before the module is ever reached — worse
// than the bearer-only gateway this replaced.
func TestDerivedGatewayResolvesTheCapabilityPerRequest(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		docs, err := g.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
		if err != nil {
			return nil, err
		}
		if _, err := getThrough(ctx, docs); err != nil {
			return nil, err
		}
		lapseCachedCapabilities(g)
		if _, err := getThrough(ctx, docs); err != nil {
			return nil, err
		}
		return "done", nil
	})

	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("solution answered %d, want 200", resp.StatusCode)
	}
	first, second := <-gw.calls, <-gw.calls
	if first.WorkContext != "context-documents.1" {
		t.Errorf("first read carried %q, want the first capability", first.WorkContext)
	}
	if second.WorkContext != "context-documents.2" {
		t.Errorf("read after the capability lapsed carried %q, want a freshly minted one — the derived gateway is holding a snapshot", second.WorkContext)
	}
	if got := gw.mintCount(); got != 2 {
		t.Errorf("minted %d capabilities, want 2", got)
	}
}

// TestMintCarriesNoOtherModulesCapability keeps the mint on a bearer-only
// client. Riding a capability minted for one module along on the request that
// mints another's is harmless only until the first lapses: the edge verifies
// every presented context, so it would then 401 the call meant to replace it.
func TestMintCarriesNoOtherModulesCapability(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		docs, err := g.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
		if err != nil {
			return nil, err
		}
		// Chaining off a derived gateway is the natural reach: ForModule is a
		// method on every Gateway, including one already acting for a module.
		if _, err := docs.ForModule(ctx, "billing", Scope{ResourceKind: "invoices", Actions: []string{"read"}}); err != nil {
			return nil, err
		}
		return "done", nil
	})

	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("solution answered %d, want 200", resp.StatusCode)
	}
	for range 2 {
		mint := <-gw.mints
		if mint.WorkContext != "" {
			t.Errorf("mint for %q carried work context %q, want none", mint.Audience, mint.WorkContext)
		}
		if mint.Bearer != "Bearer viewer-token" {
			t.Errorf("mint for %q carried bearer %q, want the viewer's", mint.Audience, mint.Bearer)
		}
	}
}

// TestGatewayTrafficIsNeverProxied keeps the viewer's credentials off an
// arbitrary egress host. Every gateway target is composition-local, and these
// requests carry the bearer and the capability minted for it in headers — the
// same reasoning that already forbids proxying registration traffic.
func TestGatewayTrafficIsNeverProxied(t *testing.T) {
	if gatewayTransport.Proxy != nil {
		t.Error("gatewayTransport carries a proxy: with HTTP(S)_PROXY set and a NO_PROXY that misses the in-cluster gateway, the viewer's bearer and Work Context would be dialled to an arbitrary egress host")
	}
}

// TestForModuleSurfacesARefusedMint keeps the Connect code and message the
// authority gave. Without them a refusal is a bare 502 at the solution, which
// is exactly the dead end this issue started from.
func TestForModuleSurfacesARefusedMint(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{mintStatus: http.StatusForbidden})
	var mintErr error
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		_, mintErr = g.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
		return nil, mintErr
	})

	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("solution answered %d, want 502", resp.StatusCode)
	}
	if mintErr == nil {
		t.Fatal("ForModule succeeded against a refusing authority")
	}
	for _, want := range []string{"documents", "403", "permission_denied", "caller holds no such authority"} {
		if !strings.Contains(mintErr.Error(), want) {
			t.Errorf("mint error %q does not mention %q", mintErr, want)
		}
	}
	select {
	case call := <-gw.calls:
		t.Errorf("module was read anyway, with work context %q", call.WorkContext)
	default:
	}
}

// TestForModuleRefusesWithoutTheViewersOrg fails on the runtime side rather than
// sending a mint accounts is certain to refuse: a Task is minted inside exactly
// one organization, and the bearer alone does not name it. The message must own
// the common case — the gateway does inject the header, and injects it empty
// for a viewer with no organization selected.
func TestForModuleRefusesWithoutTheViewersOrg(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	_, err := newGateway(gw.URL, "Bearer viewer-token", "").
		ForModule(context.Background(), "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
	if err == nil {
		t.Fatal("ForModule minted a work context with no organization")
	}
	for _, want := range []string{orgHeader, "empty"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q: the header is present-but-empty for a viewer with no org, and naming only the absent case misdirects", err, want)
		}
	}
	if got := gw.mintCount(); got != 0 {
		t.Errorf("minted %d capabilities, want 0", got)
	}
}

// TestGatewayWithoutAModuleCarriesOnlyTheBearer pins that nothing changed for a
// solution calling the gateway directly: the Work Context header appears only
// on a gateway derived for a module.
func TestGatewayWithoutAModuleCarriesOnlyTheBearer(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		return getThrough(ctx, g)
	})

	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)

	call := <-gw.calls
	if call.WorkContext != "" {
		t.Errorf("undelegated gateway sent work context %q, want none", call.WorkContext)
	}
	if call.Bearer != "Bearer viewer-token" {
		t.Errorf("undelegated gateway sent bearer %q, want the viewer's", call.Bearer)
	}
	if got := gw.mintCount(); got != 0 {
		t.Errorf("minted %d capabilities without ForModule, want 0", got)
	}
}
