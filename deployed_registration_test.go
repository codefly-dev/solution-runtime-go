package solution

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

// clearSelfEnvironment unsets every carrier these tests key on, so a variable
// exported in the shell running the suite cannot decide an assertion.
func clearSelfEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"SELF_UPSTREAM", "PUBLIC_URL", "CODEFLY__RUNTIME_CONTEXT",
		"CODEFLY__MODULE", "CODEFLY__SERVICE", "CODEFLY__ENVIRONMENT",
		"CODEFLY__SELF_ENDPOINT__LASTLOGIN_GO__BACKEND__HTTP__HTTP"} {
		t.Setenv(key, "")
	}
}

// TestSelfUpstreamIsTheReachableSelfEndpoint proves the upstream registered
// with the gateway is the address Codefly injects for reaching this service,
// not its own listen address. A deployed solution registered
// "http://localhost:8080" — its listen address, via the public URL default —
// and the gateway, dialling its own localhost, proxied the solution to itself.
func TestSelfUpstreamIsTheReachableSelfEndpoint(t *testing.T) {
	const reachable = "http://backend.solutions-lastlogin.svc.cluster.local:8080"
	for _, tc := range []struct {
		name     string
		carrier  string
		override string
		want     string
	}{
		{name: "the injected self endpoint", carrier: reachable, want: reachable},
		{name: "the listen address when none is injected", want: "http://localhost:8080"},
		{name: "an explicit override over the carrier", carrier: reachable, override: "http://upstream.example.com:9000/", want: "http://upstream.example.com:9000"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clearSelfEnvironment(t)
			t.Setenv("PORT", "8080")
			t.Setenv("CODEFLY__MODULE", "lastlogin-go")
			t.Setenv("CODEFLY__SERVICE", "backend")
			// The key is normalised as CODEFLY__ENDPOINT__ keys are: upper
			// case, dashes to underscores.
			t.Setenv("CODEFLY__SELF_ENDPOINT__LASTLOGIN_GO__BACKEND__HTTP__HTTP", tc.carrier)
			t.Setenv("SELF_UPSTREAM", tc.override)
			cfg := loadConfig(context.Background(), "lastlogin-go")
			if cfg.selfUpstream != tc.want {
				t.Fatalf("selfUpstream = %q, want %q", cfg.selfUpstream, tc.want)
			}
			// PUBLIC_URL is the browser's origin, not the gateway's upstream:
			// it no longer feeds the registered upstream at all.
			t.Setenv("PUBLIC_URL", "https://solutions.example.com")
			if got := loadConfig(context.Background(), "lastlogin-go").selfUpstream; got != tc.want {
				t.Fatalf("with PUBLIC_URL set, selfUpstream = %q, want %q", got, tc.want)
			}
		})
	}
}

// TestGatewayRegistrationCarriesTheReachableUpstream proves the carrier reaches
// the wire: the body the gateway is sent names the injected self endpoint.
func TestGatewayRegistrationCarriesTheReachableUpstream(t *testing.T) {
	const reachable = "http://backend.solutions-lastlogin.svc.cluster.local:8080"
	bodies := make(chan string, 16)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == solutionRegisterPath {
			body, _ := io.ReadAll(r.Body)
			send(bodies, string(body))
		}
		answeringTheExchange(w, r)
	}))
	defer srv.Close()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := New(Manifest{ID: "lastlogin-go", Title: "Last Login"})
	s.cfg = config{
		port:               strconv.Itoa(ln.Addr().(*net.TCPAddr).Port),
		hostRegisterURL:    srv.URL + "/api/solutions/register",
		gatewayRegisterURL: srv.URL + solutionRegisterPath,
		moduleRegisterURL:  srv.URL + moduleRegisterPath,
		moduleTokenURL:     srv.URL + moduleRegistrationTokenPath,
		solutionTokenURL:   srv.URL + solutionRegistrationTokenPath,
		internalToken:      internalTokenTest,
		solutionSecret:     "s3cret",
		selfUpstream:       reachable,
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.serve(ctx, ln); close(done) }()
	defer func() { cancel(); <-done }()

	select {
	case body := <-bodies:
		if !strings.Contains(body, `"upstream":"`+reachable+`"`) {
			t.Fatalf("gateway registration body = %s, want upstream %q", body, reachable)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no gateway registration within timeout")
	}
}

// TestValidateRefusesLoopbackInADeployedRuntime proves a deployed process
// cannot boot registering an address only it can reach — and that the signal
// is the explicit runtime context, never the environment's name.
func TestValidateRefusesLoopbackInADeployedRuntime(t *testing.T) {
	base := config{
		port:               "8080",
		gatewayURL:         "http://gateway:42152",
		hostRegisterURL:    "http://frontend:21931/api/solutions/register",
		gatewayRegisterURL: "http://gateway:42152/solutions/_register",
		moduleRegisterURL:  "http://gateway:42152/modules/_register",
		moduleTokenURL:     "http://gateway:42152/modules/_registration-token",
		solutionTokenURL:   "http://gateway:42152/solutions/_registration-token",
		solutionSecret:     "s3cret",
		selfUpstream:       "http://backend.solutions-lastlogin.svc.cluster.local:8080",
	}
	loopbacks := []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080",
		"http://0.0.0.0:8080", "http://app.localhost:8080", "http://LOCALHOST.:8080"}

	for _, upstream := range loopbacks {
		c := base
		c.runtimeContext = "kubernetes"
		c.selfUpstream = upstream
		err := c.validate()
		if err == nil || !strings.Contains(err.Error(), "self upstream") || !strings.Contains(err.Error(), selfEndpointCarrierPrefix) {
			t.Errorf("deployed with upstream %q: validate() = %v, want a refusal naming the self upstream and its carrier", upstream, err)
		}
		// Every runtime context `codefly run` uses locally accepts it: there
		// the gateway shares the machine.
		for _, local := range []string{"", "native", "nix", "container", "free"} {
			c.runtimeContext = local
			if err := c.validate(); err != nil {
				t.Errorf("runtime context %q with upstream %q: validate() = %v, want nil", local, upstream, err)
			}
		}
	}

	c := base
	c.runtimeContext = "kubernetes"
	c.publicURL = "http://localhost:8080"
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "PUBLIC_URL") {
		t.Errorf("deployed with a loopback PUBLIC_URL: validate() = %v, want a refusal naming PUBLIC_URL", err)
	}
	c.publicURL = "https://solutions.example.com"
	if err := c.validate(); err != nil {
		t.Errorf("deployed with a reachable upstream and public URL: validate() = %v, want nil", err)
	}
	c.selfUpstream = "/relative"
	if err := c.validate(); err == nil || !strings.Contains(err.Error(), "SELF_UPSTREAM") {
		t.Errorf("relative upstream: validate() = %v, want a refusal naming SELF_UPSTREAM", err)
	}
}

// TestLoopbackRefusalIgnoresTheEnvironmentName proves the environment's name
// decides nothing: an environment named like a local one still refuses a
// loopback upstream when the runtime context says it is deployed, and one
// named like a deployment accepts it when nothing says so.
func TestLoopbackRefusalIgnoresTheEnvironmentName(t *testing.T) {
	for _, tc := range []struct {
		environment, runtimeContext string
		refused                     bool
	}{
		{environment: "local-dogfood", runtimeContext: "kubernetes", refused: true},
		{environment: "local", runtimeContext: "kubernetes", refused: true},
		{environment: "staging", runtimeContext: "native", refused: false},
		{environment: "local-dogfood", runtimeContext: "container", refused: false},
	} {
		clearSelfEnvironment(t)
		t.Setenv("PORT", "8080")
		t.Setenv("GATEWAY_URL", "http://gateway:42152")
		t.Setenv("HOST_REGISTER_URL", "http://frontend:21931/api/solutions/register")
		t.Setenv(SolutionRegistrationSecretEnvironmentVariable, "s3cret")
		t.Setenv("CODEFLY__ENVIRONMENT", tc.environment)
		t.Setenv("CODEFLY__RUNTIME_CONTEXT", tc.runtimeContext)
		err := loadConfig(context.Background(), "lastlogin-go").validate()
		if refused := err != nil && strings.Contains(err.Error(), "loopback"); refused != tc.refused || (err != nil && !refused) {
			t.Errorf("environment %q, runtime context %q: validate() = %v, want refused=%v",
				tc.environment, tc.runtimeContext, err, tc.refused)
		}
	}
}

// TestAssetsServeFromTheManifestFS proves a solution that ships its frontend
// in Manifest.Assets serves it with nothing on disk — ASSETS_DIR points
// nowhere, as on a pod with a read-only root filesystem — and that the
// root-relative manifestUrl it registers resolves to a file that FS holds.
func TestAssetsServeFromTheManifestFS(t *testing.T) {
	assets := fstest.MapFS{
		"mf-manifest.json":                {Data: []byte(`{"name":"lastlogin"}`)},
		"static/js/async/123.3f9a1c2b.js": {Data: []byte(`export default 1`)},
	}
	base := bootWithAssets(t, Manifest{ID: "lastlogin-go", Assets: assets}, filepath.Join(t.TempDir(), "absent"))

	manifestURL := frontendManifestURL(t, base)
	if manifestURL != federationManifestPath {
		t.Fatalf("manifestUrl = %q, want %q", manifestURL, federationManifestPath)
	}
	resp := get(t, base+manifestURL)
	if resp.status != http.StatusOK || resp.body != `{"name":"lastlogin"}` {
		t.Fatalf("GET %s = %d %q, want the manifest from Manifest.Assets", manifestURL, resp.status, resp.body)
	}
	if !strings.HasPrefix(resp.header.Get("content-type"), "application/json") {
		t.Errorf("manifest content-type = %q, want application/json", resp.header.Get("content-type"))
	}
	if resp.header.Get("access-control-allow-origin") != "*" {
		t.Errorf("manifest served without CORS")
	}
	if got := resp.header.Get("cache-control"); got != "no-cache" {
		t.Errorf("manifest cache-control = %q, want no-cache: its name is fixed, so a cached copy outlives a redeploy", got)
	}

	chunk := get(t, base+"/assets/static/js/async/123.3f9a1c2b.js")
	if chunk.status != http.StatusOK || !strings.Contains(chunk.header.Get("content-type"), "javascript") {
		t.Fatalf("hashed chunk = %d %q", chunk.status, chunk.header.Get("content-type"))
	}
	if got := chunk.header.Get("cache-control"); got != "public, max-age=31536000, immutable" {
		t.Errorf("hashed chunk cache-control = %q, want immutable", got)
	}

	missing := get(t, base+"/assets/static/js/async/456.0badc0de.js")
	if missing.status != http.StatusNotFound {
		t.Fatalf("missing chunk = %d, want 404", missing.status)
	}
	if got := missing.header.Get("cache-control"); got != "no-cache" {
		t.Errorf("missing hashed chunk cache-control = %q, want no-cache: a 404 must not be cached for a year under the name the next build serves", got)
	}
}

// TestAssetsServeFromAssetsDirWithoutAnFS proves the directory path is kept
// for a solution that sets no Manifest.Assets, with the same cache policy.
func TestAssetsServeFromAssetsDirWithoutAnFS(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mf-manifest.json"), []byte(`{"name":"disk"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	base := bootWithAssets(t, Manifest{ID: "lastlogin-go"}, dir)
	resp := get(t, base+federationManifestPath)
	if resp.status != http.StatusOK || resp.body != `{"name":"disk"}` {
		t.Fatalf("GET manifest = %d %q, want the file from ASSETS_DIR", resp.status, resp.body)
	}
	if got := resp.header.Get("cache-control"); got != "no-cache" {
		t.Errorf("manifest cache-control = %q, want no-cache", got)
	}
}

func TestAssetCacheControl(t *testing.T) {
	for name, want := range map[string]string{
		"/mf-manifest.json":                "no-cache",
		"/remoteEntry.js":                  "no-cache",
		"/static/js/123.3f9a1c2b.js":       "public, max-age=31536000, immutable",
		"/static/css/index-3f9a1c2b0d.css": "public, max-age=31536000, immutable",
		"/static/js/lib-react.js":          "no-cache",
		"/static/js/deadbeef.js":           "no-cache",
	} {
		if got := assetCacheControl(name); got != want {
			t.Errorf("assetCacheControl(%q) = %q, want %q", name, got, want)
		}
	}
}

type response struct {
	status int
	header http.Header
	body   string
}

func get(t *testing.T, target string) response {
	t.Helper()
	resp, err := http.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return response{status: resp.StatusCode, header: resp.Header, body: string(body)}
}

// bootWithAssets serves m on an ephemeral port with assetsDir as ASSETS_DIR
// and returns its base URL. Registration targets a closed port: these tests
// are about what the solution serves, not whom it registers with.
func bootWithAssets(t *testing.T, m Manifest, assetsDir string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	s := New(m)
	s.cfg = config{port: strconv.Itoa(ln.Addr().(*net.TCPAddr).Port), assetsDir: assetsDir}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { _ = s.serve(ctx, ln); close(done) }()
	t.Cleanup(func() { cancel(); <-done })
	base := "http://" + ln.Addr().String()
	waitFor(t, "health", func() bool { return getStatus(t, base+"/health") == http.StatusOK })
	return base
}
