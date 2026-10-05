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
	gatewaySrv := httptest.NewServer(http.HandlerFunc(answeringTheExchange))
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
	t.Setenv("GATEWAY_REGISTER_URL", gatewaySrv.URL+solutionRegisterPath)
	t.Setenv("GATEWAY_URL", gatewaySrv.URL)
	t.Setenv("ASSETS_DIR", assets)
	t.Setenv(SolutionRegistrationSecretEnvironmentVariable, "s3cret")

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

	// With no PUBLIC_URL the manifest is registered as a path on this backend —
	// never on its own loopback listen address, which no browser but the
	// developer's can reach — and that path is one this backend serves.
	manifestURL := frontendManifestURL(t, base)
	u, err := url.Parse(manifestURL)
	if err != nil {
		t.Fatalf("parse manifestUrl %q: %v", manifestURL, err)
	}
	if u.IsAbs() || u.Host != "" || manifestURL != federationManifestPath {
		t.Errorf("manifestUrl = %q, want the root-relative path %q", manifestURL, federationManifestPath)
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

// wordFootnote is the surface shape the wiki declares for a Word document: the
// whole set of slots a client reads, so a test can assert on all of them.
func wordFootnote() Surface {
	return Surface{
		ID:          "footnote",
		Client:      "word",
		Title:       "Footnote",
		Description: "Cite a claim from the wiki.",
		Module:      "/surfaces/word/footnote.js",
		Contract:    1,
		Applies:     "always",
		Events:      []string{"documents.entry.*"},
	}
}

// A client discovers what a solution offers it from the served manifest alone,
// so every declared slot must survive the trip through JSON — including the
// applies selector, which the runtime carries without interpreting.
func TestServedManifestCarriesDeclaredSurfaces(t *testing.T) {
	s := &Server{manifest: Manifest{ID: "wiki", Surfaces: []Surface{wordFootnote()}}}

	var got map[string]any
	body, err := json.Marshal(s.manifestMap())
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	want := []any{map[string]any{
		"id":          "footnote",
		"client":      "word",
		"title":       "Footnote",
		"description": "Cite a claim from the wiki.",
		"module":      "/surfaces/word/footnote.js",
		"contract":    float64(1),
		"applies":     "always",
		"events":      []any{"documents.entry.*"},
	}}
	if !reflect.DeepEqual(got["surfaces"], want) {
		t.Errorf("served surfaces = %#v, want %#v", got["surfaces"], want)
	}
}

// A tagged selector is a structure, not a keyword, and the runtime must hand it
// to the client exactly as declared rather than flattening it.
func TestServedSurfaceCarriesTaggedAppliesVerbatim(t *testing.T) {
	applies := map[string]any{"tagged": []any{"legal", "finance"}}
	surface := wordFootnote()
	surface.Applies = applies
	s := &Server{manifest: Manifest{ID: "wiki", Surfaces: []Surface{surface}}}

	var got map[string]any
	body, _ := json.Marshal(s.manifestMap())
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	entry := got["surfaces"].([]any)[0].(map[string]any)
	if !reflect.DeepEqual(entry["applies"], applies) {
		t.Errorf("served applies = %#v, want %#v", entry["applies"], applies)
	}
}

// A solution that offers nothing inside a client must not gain the key at all.
func TestManifestOmitsAbsentSurfaces(t *testing.T) {
	bare := &Server{manifest: Manifest{ID: "lastlogin-go"}}
	if _, ok := bare.manifestMap()["surfaces"]; ok {
		t.Errorf("emitted a surfaces key with no surface declared")
	}
}

// A surface is in the manifest whether or not it declares a selector, so an
// absent applies is not the absence of the surface — it is the default the
// contract names, and every client would otherwise have to invent it alike.
// Nothing to show and nothing to reconcile on are different: those slots say
// what they mean by being absent.
func TestManifestDefaultsAppliesAndOmitsEmptySurfaceSlots(t *testing.T) {
	surface := wordFootnote()
	surface.Applies = nil
	surface.Events = nil
	surface.Description = ""
	s := &Server{manifest: Manifest{ID: "wiki", Surfaces: []Surface{surface}}}

	entry := s.manifestMap()["surfaces"].([]any)[0].(map[string]any)
	if got := entry["applies"]; got != "always" {
		t.Errorf("applies with no selector declared = %#v, want %q", got, "always")
	}
	if _, ok := entry["description"]; ok {
		t.Errorf("emitted a description key with no description declared")
	}
	if _, ok := entry["events"]; ok {
		t.Errorf("emitted an events key with no namespaces declared")
	}
}

// A surface no client could load must fail the boot, not register quietly and
// show up as a solution that simply never appears in the add-in.
func TestSurfaceValidationRejectsUnusableDeclarations(t *testing.T) {
	cases := []struct {
		name     string
		surfaces []Surface
		want     string
	}{
		{"no id", []Surface{func() Surface { s := wordFootnote(); s.ID = ""; return s }()}, "no id"},
		{"id with uppercase", []Surface{func() Surface { s := wordFootnote(); s.ID = "Footnote"; return s }()}, "id must be"},
		{"id with a slash", []Surface{func() Surface { s := wordFootnote(); s.ID = "word/footnote"; return s }()}, "id must be"},
		{"id with a leading dash", []Surface{func() Surface { s := wordFootnote(); s.ID = "-footnote"; return s }()}, "id must be"},
		{"id with a trailing dash", []Surface{func() Surface { s := wordFootnote(); s.ID = "footnote-"; return s }()}, "id must be"},
		{"id of one dash", []Surface{func() Surface { s := wordFootnote(); s.ID = "-"; return s }()}, "id must be"},
		{"duplicate id in one client", []Surface{wordFootnote(), wordFootnote()}, "declared twice"},
		{"no title", []Surface{func() Surface { s := wordFootnote(); s.Title = ""; return s }()}, "no title"},
		{"unknown client", []Surface{func() Surface { s := wordFootnote(); s.Client = "notion"; return s }()}, "unknown client kind"},
		{"no client", []Surface{func() Surface { s := wordFootnote(); s.Client = ""; return s }()}, "unknown client kind"},
		{"undeclared contract", []Surface{func() Surface { s := wordFootnote(); s.Contract = 0; return s }()}, "contract"},
		{"negative contract", []Surface{func() Surface { s := wordFootnote(); s.Contract = -1; return s }()}, "contract"},
		{"absolute module URL", []Surface{func() Surface {
			s := wordFootnote()
			s.Module = "https://evil.example/footnote.js"
			return s
		}()}, "own origin"},
		{"protocol-relative module", []Surface{func() Surface {
			s := wordFootnote()
			s.Module = "//evil.example/footnote.js"
			return s
		}()}, "own origin"},
		// A browser reads the backslash beside the leading slash as a slash and
		// what follows as a host, so each of these loads third-party code even
		// though net/url reports no host in any of them.
		{"backslash authority module", []Surface{func() Surface {
			s := wordFootnote()
			s.Module = `/\evil.example/footnote.js`
			return s
		}()}, "own origin"},
		{"backslash-slash authority module", []Surface{func() Surface {
			s := wordFootnote()
			s.Module = `/\/evil.example/footnote.js`
			return s
		}()}, "own origin"},
		{"tab-smuggled authority module", []Surface{func() Surface {
			s := wordFootnote()
			s.Module = "/\t/evil.example/footnote.js"
			return s
		}()}, "own origin"},
		{"newline-smuggled authority module", []Surface{func() Surface {
			s := wordFootnote()
			s.Module = "/\n//evil.example/footnote.js"
			return s
		}()}, "own origin"},
		{"relative module", []Surface{func() Surface { s := wordFootnote(); s.Module = "surfaces/footnote.js"; return s }()}, "own origin"},
		{"no module", []Surface{func() Surface { s := wordFootnote(); s.Module = ""; return s }()}, "own origin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := Manifest{ID: "wiki", Surfaces: tc.surfaces}.validateSurfaces()
			if err == nil {
				t.Fatalf("validateSurfaces accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
		})
	}
}

// The same offering in two clients carries the same id — the wiki's footnote is
// "footnote" in Word and in PowerPoint — and neither client can see the other's,
// so that is not a collision. Only two surfaces of one client are ambiguous.
func TestSurfaceIDsAreUniquePerClientNotPerSolution(t *testing.T) {
	powerpoint := wordFootnote()
	powerpoint.Client = "powerpoint"
	powerpoint.Module = "/surfaces/powerpoint/footnote.js"
	if err := (Manifest{ID: "wiki", Surfaces: []Surface{wordFootnote(), powerpoint}}).validateSurfaces(); err != nil {
		t.Errorf("validateSurfaces refused one id shared across two clients: %v", err)
	}

	second := wordFootnote()
	second.Title = "Footnote, again"
	second.Module = "/surfaces/word/footnote-2.js"
	err := (Manifest{ID: "wiki", Surfaces: []Surface{wordFootnote(), second}}).validateSurfaces()
	if err == nil {
		t.Fatal("validateSurfaces accepted two surfaces sharing an id within one client")
	}
	if !strings.Contains(err.Error(), "declared twice") {
		t.Errorf("error %q does not say the id was declared twice", err)
	}
}

// Serve must refuse a manifest whose surface no client could load, and name the
// surface — the mistake is in the author's code, and it is the same mistake in
// every environment, so it must not wait on the environment resolving first.
func TestServeRejectsUnusableSurface(t *testing.T) {
	surface := wordFootnote()
	surface.Module = `/\evil.example/footnote.js`

	s := New(Manifest{ID: "wiki", Title: "Wiki", Surfaces: []Surface{surface}})
	err := s.Serve()
	if err == nil {
		t.Fatal("Serve returned nil for an off-origin surface module; expected a boot error and no bind")
	}
	if !strings.Contains(err.Error(), "footnote") {
		t.Errorf("boot error should name the surface, got: %v", err)
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
	gatewaySrv := httptest.NewServer(http.HandlerFunc(answeringTheExchange))
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
		gatewayRegisterURL: gatewaySrv.URL + solutionRegisterPath,
		solutionTokenURL:   gatewaySrv.URL + solutionRegistrationTokenPath,
		solutionSecret:     "s3cret",
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
		solutionTokenURL:   "http://gateway:42152/solutions/_registration-token",
		solutionSecret:     "s3cret",
		selfUpstream:       "http://backend:8080",
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
		{"relative solution token URL", func(c *config) { c.solutionTokenURL = "/solutions/_registration-token" }},
		{"no solution registration secret", func(c *config) { c.solutionSecret = "" }},
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
			// The solution's own register URL defaults to the resolved gateway
			// plus the /solutions/_register path, with no explicit override.
			if want := addr + solutionRegisterPath; cfg.gatewayRegisterURL != want {
				t.Errorf("gatewayRegisterURL = %q, want %q derived from the resolved gateway", cfg.gatewayRegisterURL, want)
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

// send records an observation without ever blocking the fake gateway's handler:
// a heartbeat re-POSTs forever, so a full channel must not wedge the server.
func send[T any](ch chan T, value T) {
	select {
	case ch <- value:
	default:
	}
}

// internalTokenTest is the cluster-internal token the fake gateway's perimeter
// check expects on the credential exchange.
const internalTokenTest = "internal-token-xyz"

// consumesDocuments is the api.consumes projection core surfaces to a running
// backend for the wiki→documents federation. The literal key is
// manifest.APIConsumesEnvironmentVariable (a wire contract).
const consumesDocuments = `[{"id":"docstore.documents","module":"docstore","service":"documents","endpoint":"rest","protocol":"rest","as":"documents"}]`

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

	credential := &solutionCredential{tokenURL: srv.URL, id: "solution-under-test", secret: "s3cret"}
	req, err := http.NewRequest(http.MethodPost, srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := credential.authorize(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	if _, ok := (<-seen)[http.CanonicalHeaderKey(internalTokenHeader)]; ok {
		t.Errorf("sent %s with no token configured, want the header absent", internalTokenHeader)
	}
}

// TestSiblingURLFollowsAnOverriddenGateway proves the register endpoint and the
// exchange that credentials it stay on one gateway. The token a registration
// presents is minted by the exchange, so an explicitly overridden register URL
// must carry the exchange with it — minting against one host and registering
// with another yields a token the second never trusts.
func TestSiblingURLFollowsAnOverriddenGateway(t *testing.T) {
	t.Setenv("PORT", "8090")
	t.Setenv("GATEWAY_URL", "http://gateway:42152")
	t.Setenv("HOST_REGISTER_URL", "http://frontend:21931/api/solutions/register")
	t.Setenv("GATEWAY_REGISTER_URL", "https://other-gateway:9999"+solutionRegisterPath)

	cfg := loadConfig(context.Background(), "solution-under-test")
	want := "https://other-gateway:9999" + solutionRegistrationTokenPath
	if cfg.solutionTokenURL != want {
		t.Errorf("solution token URL = %q, want %q — it must follow the overridden register URL", cfg.solutionTokenURL, want)
	}
}

// An unparseable override must surface as itself, so validate() names the one
// URL the operator actually set instead of a second one derived from it.
func TestSiblingURLPassesThroughAnUnusableBase(t *testing.T) {
	if got := siblingURL(solutionRegisterPath, solutionRegisterPath, solutionRegistrationTokenPath); got != solutionRegisterPath {
		t.Errorf("siblingURL(relative) = %q, want the base handed back unchanged", got)
	}
}

// TestSiblingURLKeepsTheGatewayBasePath proves the derived endpoint stays on the
// gateway's mount, not just its host. Rebuilding the URL from scheme+host
// dropped any path between them, so a gateway served under a prefix registered
// at /gw/solutions/_register while exchanging at /solutions/_registration-token
// — still absolute, so validate() passed it, and a 404 on every beat after that.
func TestSiblingURLKeepsTheGatewayBasePath(t *testing.T) {
	t.Setenv("PORT", "8090")
	t.Setenv("GATEWAY_URL", "http://gateway:42152/gw")
	t.Setenv("HOST_REGISTER_URL", "http://frontend:21931/api/solutions/register")
	t.Setenv(SolutionRegistrationSecretEnvironmentVariable, "s3cret")

	cfg := loadConfig(context.Background(), "solution-under-test")
	if want := "http://gateway:42152/gw" + solutionRegisterPath; cfg.gatewayRegisterURL != want {
		t.Errorf("gateway register URL = %q, want %q", cfg.gatewayRegisterURL, want)
	}
	if want := "http://gateway:42152/gw" + solutionRegistrationTokenPath; cfg.solutionTokenURL != want {
		t.Errorf("solution token URL = %q, want %q — the derived endpoint must keep the gateway's base path", cfg.solutionTokenURL, want)
	}
	if err := cfg.validate(); err != nil {
		t.Errorf("validate() = %v, want nil", err)
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
		if got := backoff(interval, tc.failures, registrationBackoffCap); got != tc.want {
			t.Errorf("backoff(%s, %d) = %s, want %s", interval, tc.failures, got, tc.want)
		}
	}
	// An interval longer than the cap is the caller's choice, not something to
	// shorten — at any number of failures, not only at zero. Shortening it would
	// have a failing beat retry sooner than a healthy one.
	for _, failures := range []int{0, 1, 50} {
		if got := backoff(time.Hour, failures, registrationBackoffCap); got != time.Hour {
			t.Errorf("backoff(1h, %d, cap) = %s, want 1h", failures, got)
		}
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
		issued := map[string]any{"token": token, "orgId": mint.OrgID, "ownerPrincipalId": "viewer-principal", "currentActorPrincipalId": "viewer-principal"}
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

// viewerSession is the session the gateway stamps from the verified claims —
// the one accounts sealed viewerOrg into when the viewer selected it.
const viewerSession = "019240b1-3f5a-7c21-9d4e-8a2b7c1e5f30"

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
	req.Header.Set(sessionHeader, viewerSession)
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
	// The Task is named per mint; the session it is rooted in is the viewer's
	// own, not one this runtime invented.
	if mint.SessionID != viewerSession {
		t.Errorf("mint session = %q, want the viewer's %q", mint.SessionID, viewerSession)
	}
	if mint.TaskID == "" || mint.TaskID == mint.SessionID {
		t.Errorf("mint task = %q, want an id of its own", mint.TaskID)
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

// A refused mint retains diagnostics for the handler but returns an actionable
// status, without disclosing upstream details, to the browser.
func TestForModuleSurfacesARefusedMint(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{mintStatus: http.StatusForbidden})
	var mintErr error
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		_, mintErr = g.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
		return nil, mintErr
	})

	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("solution answered %d, want 403", resp.StatusCode)
	}
	if mintErr == nil {
		t.Fatal("ForModule succeeded against a refusing authority")
	}
	for _, want := range []string{"documents", "403", "permission_denied", "caller holds no such authority"} {
		if !strings.Contains(mintErr.Error(), want) {
			t.Errorf("mint error %q does not mention %q", mintErr, want)
		}
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "caller holds no such authority") || strings.Contains(string(body), "documents") {
		t.Fatalf("upstream diagnostic disclosed: %s", body)
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
	_, err := newGateway(gw.URL, "Bearer viewer-token", "", viewerSession).
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

// TestMintRootsTheTaskInTheViewersVerifiedSession pins what the mint is built
// from. Accounts seals the selected organization into the viewer's session, so
// a Task rooted in a session id this runtime invented names no session at all:
// it is a well-formed UUID that passes validation while an organization switch,
// an ended impersonation, a revocation or the session's own expiry never reach
// the capability minted under it. One session carries many Tasks, so the Task
// id — and only it — is named per mint.
func TestMintRootsTheTaskInTheViewersVerifiedSession(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		if _, err := readModule(ctx, g, "documents"); err != nil {
			return nil, err
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

	first, second := <-gw.mints, <-gw.mints
	for _, mint := range []mintRequest{first, second} {
		if mint.SessionID != viewerSession {
			t.Errorf("mint for %q rooted in session %q, want the viewer's %q", mint.Audience, mint.SessionID, viewerSession)
		}
	}
	if first.TaskID == second.TaskID {
		t.Errorf("both mints named task %q, want one Task per mint under the one session", first.TaskID)
	}
}

// TestForModuleRefusesWithoutTheViewersSession is the session twin of the org
// refusal: a capability accounts cannot tie to a live session is refused here
// rather than bought with an audited mint. The gateway stamps the header for
// every authenticated caller, so the common cause is a caller that has no
// session to name at all — an API key.
func TestForModuleRefusesWithoutTheViewersSession(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	_, err := newGateway(gw.URL, "Bearer viewer-token", viewerOrg, "").
		ForModule(context.Background(), "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
	if err == nil {
		t.Fatal("ForModule minted a work context with no viewer session")
	}
	if !strings.Contains(err.Error(), sessionHeader) {
		t.Errorf("error %q does not name %s, the header whoever reads it must inspect", err, sessionHeader)
	}
	if got := gw.mintCount(); got != 0 {
		t.Errorf("minted %d capabilities, want 0", got)
	}
}

// TestBrowserSuppliedWorkContextIsNeverForwarded guards a property that holds
// structurally today: the runtime builds its outbound requests instead of
// relaying the inbound one, so there is no path by which a caller-presented
// capability could authenticate the mint or the read. It cannot fail as the code
// stands — it is here to fail the day someone relays inbound headers onto a
// gateway request, which is the change that would quietly let a browser pick the
// credential a module read is authenticated with.
func TestBrowserSuppliedWorkContextIsNeverForwarded(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		return readModule(ctx, g, "documents")
	})

	req, err := http.NewRequest(http.MethodGet, solution.URL, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("authorization", "Bearer viewer-token")
	req.Header.Set(orgHeader, viewerOrg)
	req.Header.Set(sessionHeader, viewerSession)
	req.Header.Set(codefly.WorkContextHeaderName, "forged.capability")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("call solution: %v", err)
	}
	defer drainAndClose(resp)

	if mint := <-gw.mints; mint.WorkContext != "" {
		t.Errorf("mint carried work context %q, want none — a caller-supplied capability must not authenticate the mint", mint.WorkContext)
	}
	if call := <-gw.calls; call.WorkContext != "context-documents.1" {
		t.Errorf("module read carried work context %q, want the minted one", call.WorkContext)
	}
}

// TestRefusedBoundariesAnswerAStatusTheCallerCanAct pins how a refusal reaches
// the browser. Both boundaries fail before any mint, but as bare errors they
// arrive as the runtime's generic 502, where "select an organization" — which
// the viewer fixes in one click — is indistinguishable from "this solution is
// down". The diagnostic naming internal headers stays out of the response body:
// that separation is the other half of what ClientError is for.
func TestRefusedBoundariesAnswerAStatusTheCallerCanAct(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		if _, err := g.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}}); err != nil {
			return nil, err
		}
		return "minted", nil
	})

	for _, tt := range []struct {
		name    string
		org     string
		session string
		status  int
		message string
		header  string
	}{
		{"no organization selected", "", viewerSession, http.StatusConflict, "no organization selected", orgHeader},
		{"no session", viewerOrg, "", http.StatusForbidden, "a user session is required to read composed modules", sessionHeader},
	} {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, solution.URL, nil)
			if err != nil {
				t.Fatalf("new request: %v", err)
			}
			req.Header.Set("authorization", "Bearer viewer-token")
			req.Header.Set(orgHeader, tt.org)
			req.Header.Set(sessionHeader, tt.session)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("call solution: %v", err)
			}
			defer drainAndClose(resp)

			if resp.StatusCode != tt.status {
				t.Errorf("solution answered %d, want %d — a bare error answers 502, which reads as an outage", resp.StatusCode, tt.status)
			}
			var body struct {
				Error string `json:"error"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if body.Error != tt.message {
				t.Errorf("body error = %q, want %q", body.Error, tt.message)
			}
			if strings.Contains(body.Error, tt.header) {
				t.Errorf("body %q names the internal header %q: the diagnostic belongs in the handler's error, not the caller's response", body.Error, tt.header)
			}
			if got := gw.mintCount(); got != 0 {
				t.Errorf("minted %d capabilities, want 0", got)
			}
		})
	}
}

// internalTokenAuth presents the shared cluster-internal token and nothing else.
// It is a test stub, not a credential this runtime can present: both
// registration surfaces refuse the shared token, so no production path builds
// one (module-saas-starter#540). It lives here so heartbeat's status handling
// can be exercised without standing up a credential exchange — and so that the
// fallback this runtime deliberately removed cannot be reinstated by wiring one
// line, which is what leaving it in the package would have allowed.
type internalTokenAuth string

func (t internalTokenAuth) authorize(_ context.Context, req *http.Request) (time.Time, error) {
	if t != "" {
		req.Header.Set(internalTokenHeader, string(t))
	}
	// No expiry: injected configuration, so it cannot lapse mid-request.
	return time.Time{}, nil
}

func (internalTokenAuth) invalidate() {}

func (internalTokenAuth) succeeded() {}

// TestManifestURLIsNeverTheListenAddress pins where the registered manifestUrl
// points. Unset PUBLIC_URL used to yield "http://localhost:<port>/assets/...",
// this process's own loopback address, so every deployed solution registered a
// manifest no browser could load and the product showed it as failed to load.
// Without an explicit origin the URL is now the path on this backend, which the
// host resolves against the route by which it reaches the solution.
func TestManifestURLIsNeverTheListenAddress(t *testing.T) {
	for _, tc := range []struct {
		public string
		want   string
	}{
		{public: "", want: "/assets/mf-manifest.json"},
		{public: "https://solutions.example.com/lastlogin", want: "https://solutions.example.com/lastlogin/assets/mf-manifest.json"},
		{public: "https://solutions.example.com/", want: "https://solutions.example.com/assets/mf-manifest.json"},
	} {
		t.Setenv("PUBLIC_URL", tc.public)
		t.Setenv("PORT", "8080")
		s := New(Manifest{ID: "lastlogin-go"})
		s.cfg = loadConfig(context.Background(), s.manifest.ID)
		frontend, _ := s.manifestMap()["frontend"].(map[string]any)
		if got := frontend["manifestUrl"]; got != tc.want {
			t.Errorf("PUBLIC_URL=%q: manifestUrl = %v, want %q", tc.public, got, tc.want)
		}
	}
}

// TestWorkContextPrincipalsReportsWhomAccountsIssuedFor: a handler comparing a
// claimed owner against the capability reads accounts' own answer to the mint,
// and a gateway acting under no capability has none to report.
func TestWorkContextPrincipalsReportsWhomAccountsIssuedFor(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	var got WorkContextPrincipals
	var bare error
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		_, bare = g.WorkContextPrincipals(ctx)
		docs, err := g.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
		if err != nil {
			return nil, err
		}
		got, err = docs.WorkContextPrincipals(ctx)
		return "done", err
	})
	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("solution answered %d, want 200", resp.StatusCode)
	}
	want := WorkContextPrincipals{OrgID: viewerOrg, OwnerPrincipalID: "viewer-principal", CurrentActorPrincipalID: "viewer-principal"}
	if got != want {
		t.Fatalf("principals = %+v, want %+v", got, want)
	}
	if bare == nil {
		t.Fatal("a gateway acting under no work context reported principals")
	}
	if n := gw.mintCount(); n != 1 {
		t.Fatalf("minted %d capabilities, want 1: reading the principals reuses the capability", n)
	}
}
