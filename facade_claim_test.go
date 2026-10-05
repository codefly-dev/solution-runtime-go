package solution

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// --- A solution claims no module's facade route ---
//
// SP-GW-04 and SP-SOL-03, the two invariants SA-F-GWREGISTRY broke: a facade
// route for a module is claimed only by the module that serves it, under a
// credential bound to that module, and a solution holds no credential that
// decides where another module's traffic is routed.
//
// This runtime used to claim one for every module its composition let it
// consume. The paths and headers of that surface are written out here, as
// literals this test owns, for two reasons: nothing in the package names them
// any more, and these are the wire shapes a solution must never present. The
// static guard below keeps them out of the package proper.

const (
	// claimedFacadePath and facadeCredentialPath are the gateway's module
	// route-claim surface and the exchange that mints the credential for it.
	claimedFacadePath    = "/modules/_register"
	facadeCredentialPath = "/modules/_registration-token"
	// facadeSecretHeader carries a module's own route-claim secret, and
	// facadeCredentialHeader the credential minted from it.
	facadeSecretHeader     = "X-Codefly-Module-Secret"
	facadeCredentialHeader = "X-Codefly-Module-Registration"
	// facadeSecretsVariable is the carrier that delivered another module's
	// route-claim secret into a solution's own environment.
	facadeSecretsVariable = "CODEFLY__MODULE_REGISTRATION_SECRETS"
)

// facadeWatcher is a host gateway that answers this runtime's own registration
// exchange and records every request it receives, so a test can assert on the
// ones that never arrive.
type facadeWatcher struct {
	*httptest.Server

	mu    sync.Mutex
	paths []string
	// secrets is every value seen in a header that carries another module's
	// route-claim credential, on any path.
	secrets []string
	// ownRegistrations counts this solution's own upstream registration, which
	// proves the boot reached the point where it would have claimed a facade.
	ownRegistrations int
}

func newFacadeWatcher(t *testing.T) *facadeWatcher {
	t.Helper()
	w := &facadeWatcher{}
	w.Server = httptest.NewServer(http.HandlerFunc(w.serve))
	t.Cleanup(w.Close)
	return w
}

func (g *facadeWatcher) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.paths = append(g.paths, r.URL.Path)
	for _, header := range []string{facadeSecretHeader, facadeCredentialHeader} {
		if value := r.Header.Get(header); value != "" {
			g.secrets = append(g.secrets, header+": "+value)
		}
	}
	if r.URL.Path == solutionRegisterPath {
		g.ownRegistrations++
	}
	g.mu.Unlock()
	answeringTheExchange(w, r)
}

func (g *facadeWatcher) seen() ([]string, []string, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.paths...), append([]string(nil), g.secrets...), g.ownRegistrations
}

// TestSolutionClaimsNoModuleFacadeRoute boots a real solution in the shape the
// finding describes: a composition that projects a consumed module and
// provisions that module's route-claim secret into this backend's environment.
// Nothing the runtime does may turn either into a claim on that module's
// facade route — not the projection, which says only what this solution reads,
// and not the secret, which is another module's credential however it got here.
//
// The solution's own upstream registration is asserted too, so the test cannot
// pass by failing to boot.
func TestSolutionClaimsNoModuleFacadeRoute(t *testing.T) {
	gw := newFacadeWatcher(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	setEndpoint(t, "CODEFLY__ENDPOINT__DOCSTORE__DOCUMENTS__REST__REST", "http://docstore-upstream:9100")
	t.Setenv("CODEFLY__API_CONSUMES", consumesDocuments)
	// Provisioned, and still never used: the fix is not that the composition
	// stops delivering this (that is the composition's half of the finding),
	// it is that a runtime holding it claims nothing with it.
	t.Setenv(facadeSecretsVariable, "documents:another-modules-secret")
	t.Setenv("GATEWAY_URL", gw.URL)
	t.Setenv("HOST_REGISTER_URL", gw.URL+"/api/solutions/register")
	t.Setenv("PORT", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
	t.Setenv("SELF_UPSTREAM", "http://backend.svc.cluster.local:8080")
	t.Setenv("CODEFLY__SOLUTION_REGISTRATION_SECRET", "s3cret")
	t.Setenv("CODEFLY_INTERNAL_TOKEN", internalTokenTest)

	s := New(Manifest{ID: "solution-under-test", Title: "Solution Under Test"})
	ctx, cancel := context.WithCancel(context.Background())
	s.cfg = loadConfig(ctx, s.manifest.ID)
	done := make(chan struct{})
	go func() { _ = s.serve(ctx, ln); close(done) }()
	defer func() { cancel(); <-done }()

	waitFor(t, "this solution's own upstream registration", func() bool {
		_, _, own := gw.seen()
		return own > 0
	})

	paths, secrets, _ := gw.seen()
	for _, path := range paths {
		if path == claimedFacadePath || path == facadeCredentialPath {
			t.Errorf("the solution called %q: a facade route is claimed only by the module that serves it, never by a solution that consumes it", path)
		}
	}
	if len(secrets) > 0 {
		t.Errorf("the solution presented another module's route-claim credential: %s", strings.Join(secrets, ", "))
	}
}

// TestNoModuleFacadeClaimOnTheSDKSurface is the static half: the behaviour test
// above can only prove that one boot claimed nothing, and the capability is
// what the invariant is about. A solution built on this SDK must not be able to
// claim a module's facade route at all, so the package carries neither the
// surface nor the credential — no claim path, no exchange, no header, and no
// reader of the carrier that delivered another module's secret.
func TestNoModuleFacadeClaimOnTheSDKSurface(t *testing.T) {
	forbidden := map[string]string{
		claimedFacadePath:      "the gateway's module route-claim path",
		facadeCredentialPath:   "the exchange that mints a module route-claim credential",
		facadeSecretHeader:     "the header carrying a module's route-claim secret",
		facadeCredentialHeader: "the header carrying a module route-claim credential",
		facadeSecretsVariable:  "the carrier delivering another module's route-claim secret",
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	scanned := 0
	for _, entry := range entries {
		name := entry.Name()
		// Test sources are exempt: this file names every one of these on
		// purpose, and a test that could not write them down could not assert
		// their absence.
		if filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		scanned++
		for literal, what := range forbidden {
			if strings.Contains(string(source), literal) {
				t.Errorf("%s names %q (%s): a solution holds no credential deciding where another module's traffic is routed, and claims no module's facade route",
					name, literal, what)
			}
		}
	}
	if scanned == 0 {
		t.Fatal("no package sources scanned: this guard is inert")
	}
}
