package solution

import (
	"context"
	"go/scanner"
	"go/token"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codefly-dev/core/solution/manifest"
)

// --- A solution claims no module's facade route ---
//
// Two invariants, both pinned here (SA-F-GWREGISTRY):
//
//   - a facade route for a module is claimed only by the module that serves
//     it, under a credential bound to that module;
//   - a solution holds no credential that decides where another module's
//     traffic is routed.
//
// So a solution registers itself and nothing else, and the package carries
// neither a module route-claim surface nor a credential for one. The wire
// shapes below are named by these tests alone, because a test that cannot
// write a shape down cannot assert its absence.

const (
	// claimedFacadePath and facadeCredentialPath are the gateway's module
	// route-claim surface and the exchange that credentials it.
	claimedFacadePath    = "/modules/_register"
	facadeCredentialPath = "/modules/_registration-token"
	// facadeSecretHeader carries a module's own route-claim secret, and
	// facadeCredentialHeader the credential minted from it.
	facadeSecretHeader     = "X-Codefly-Module-Secret"
	facadeCredentialHeader = "X-Codefly-Module-Registration"
	// facadeSecretsVariable is the carrier a composition may deliver another
	// module's route-claim secret in. Nothing here reads it.
	facadeSecretsVariable = "CODEFLY__MODULE_REGISTRATION_SECRETS"
)

// selfRegistrationPaths is what a solution registering only itself may call:
// its manifest to the host frontend, its own upstream to the gateway, and the
// exchange that credentials both. It is an allowlist rather than a list of
// forbidden paths, so a claim on any other route fails this test whatever that
// route is named — a denylist only catches the spellings it was given.
var selfRegistrationPaths = map[string]bool{
	"/api/solutions/register":     true,
	solutionRegisterPath:          true,
	solutionRegistrationTokenPath: true,
}

// selfRegistrationHeaders is the same allowlist for the credential headers a
// registration may carry.
var selfRegistrationHeaders = map[string]bool{
	http.CanonicalHeaderKey(solutionRegistrationHeader): true,
	http.CanonicalHeaderKey(solutionSecretHeader):       true,
	http.CanonicalHeaderKey(internalTokenHeader):        true,
}

// facadeWatcher is a host that answers this runtime's own registration
// exchange and records every request it receives — the path, and every
// Codefly credential header on it — so a test can judge the whole of what a
// booted solution sends rather than the absence of two known shapes.
type facadeWatcher struct {
	*httptest.Server

	mu      sync.Mutex
	paths   map[string]int
	headers map[string]string
	beats   int
}

func newFacadeWatcher(t *testing.T) *facadeWatcher {
	t.Helper()
	w := &facadeWatcher{paths: map[string]int{}, headers: map[string]string{}}
	w.Server = httptest.NewServer(http.HandlerFunc(w.serve))
	t.Cleanup(w.Close)
	return w
}

func (g *facadeWatcher) serve(w http.ResponseWriter, r *http.Request) {
	g.mu.Lock()
	g.paths[r.URL.Path]++
	for name, values := range r.Header {
		if strings.HasPrefix(strings.ToLower(name), "x-codefly-") {
			g.headers[http.CanonicalHeaderKey(name)] = strings.Join(values, ",")
		}
	}
	if r.URL.Path == solutionRegisterPath {
		g.beats++
	}
	g.mu.Unlock()
	answeringTheExchange(w, r)
}

func (g *facadeWatcher) observed() (map[string]int, map[string]string, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	paths := map[string]int{}
	for k, v := range g.paths {
		paths[k] = v
	}
	headers := map[string]string{}
	for k, v := range g.headers {
		headers[k] = v
	}
	return paths, headers, g.beats
}

// TestSolutionRegistersOnlyItself boots a real solution against a recording
// host and judges every request it makes: the path must be one of this
// solution's own registration surfaces, and any Codefly credential header on
// it one of its own.
//
// It waits for several beats rather than the first. A registration beat is a
// goroutine on a timer, so sampling once the self-registration has succeeded
// proves only that nothing else had started yet — a claim that began a moment
// later would land after the assertions.
//
// The inputs vary because the invariant does not: whatever the composition
// projects as consumable, and whatever it delivers alongside, the answer is
// the same.
func TestSolutionRegistersOnlyItself(t *testing.T) {
	for _, tc := range []struct {
		name string
		// consumes is the api.consumes projection, and secrets whatever the
		// composition delivered in the route-claim carrier.
		consumes, secrets string
		// legacyOverrides sets the env overrides that used to point the claim
		// surface and its exchange somewhere; they name nothing now.
		legacyOverrides bool
	}{
		{name: "nothing consumed"},
		{name: "one target", consumes: consumesDocuments, secrets: "documents:another-modules-secret"},
		{
			name:     "a renamed facade",
			consumes: `[{"id":"a.b","module":"a","service":"b","endpoint":"rest","protocol":"rest","as":"renamed"}]`,
			secrets:  "renamed:another-modules-secret",
		},
		{
			name: "several targets",
			consumes: `[{"id":"a.b","module":"a","service":"b","endpoint":"rest","protocol":"rest","as":"first"},` +
				`{"id":"c.d","module":"c","service":"d","endpoint":"rest","protocol":"rest","as":"second"}]`,
			secrets: " first : s1 , second:s2 ",
		},
		{
			name:            "a secret delivered with the old overrides set",
			consumes:        consumesDocuments,
			secrets:         "documents:another-modules-secret",
			legacyOverrides: true,
		},
		{name: "a secret delivered for a module nothing consumes", secrets: "documents:another-modules-secret"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw := newFacadeWatcher(t)
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}

			setEndpoint(t, "CODEFLY__ENDPOINT__DOCSTORE__DOCUMENTS__REST__REST", "http://docstore-upstream:9100")
			t.Setenv(manifest.APIConsumesEnvironmentVariable, tc.consumes)
			// Delivered, and still unused: the fix is not that a composition
			// stops delivering this — that is the composition's half — it is
			// that a runtime holding it claims nothing with it.
			t.Setenv(facadeSecretsVariable, tc.secrets)
			if tc.legacyOverrides {
				t.Setenv("GATEWAY_MODULE_REGISTER_URL", gw.URL+claimedFacadePath)
				t.Setenv("GATEWAY_MODULE_REGISTRATION_TOKEN_URL", gw.URL+facadeCredentialPath)
			}
			t.Setenv("GATEWAY_URL", gw.URL)
			t.Setenv("HOST_REGISTER_URL", gw.URL+"/api/solutions/register")
			t.Setenv("PORT", strconv.Itoa(ln.Addr().(*net.TCPAddr).Port))
			t.Setenv("SELF_UPSTREAM", "http://backend.svc.cluster.local:8080")
			t.Setenv(SolutionRegistrationSecretEnvironmentVariable, "s3cret")
			t.Setenv("CODEFLY_INTERNAL_TOKEN", internalTokenTest)

			s := New(Manifest{ID: "solution-under-test", Title: "Solution Under Test"})
			// Beat fast, so several beats pass inside the test rather than one.
			s.registrationInterval = 20 * time.Millisecond
			ctx, cancel := context.WithCancel(context.Background())
			s.cfg = loadConfig(ctx, s.manifest.ID)
			if err := s.cfg.validate(); err != nil {
				t.Fatalf("the test environment does not boot: %v", err)
			}
			done := make(chan struct{})
			go func() { _ = s.serve(ctx, ln); close(done) }()
			defer func() { cancel(); <-done }()

			// Several beats, not the first: a claim beat starting late must
			// still fall inside the window being judged.
			const beatsWatched = 5
			waitFor(t, "this solution's own registration to beat repeatedly", func() bool {
				_, _, beats := gw.observed()
				return beats >= beatsWatched
			})

			paths, headers, beats := gw.observed()
			if beats < beatsWatched {
				t.Fatalf("watched only %d self-registration beats, want %d", beats, beatsWatched)
			}
			for path, count := range paths {
				if !selfRegistrationPaths[path] {
					t.Errorf("the solution called %q (%d times): a solution registers only itself, and a facade route for a module is claimed by the module that serves it",
						path, count)
				}
			}
			for name, value := range headers {
				if !selfRegistrationHeaders[name] {
					t.Errorf("the solution presented the credential header %q: a solution holds no credential that decides where another module's traffic is routed", name)
				}
				if tc.secrets != "" && strings.Contains(value, "another-modules-secret") {
					t.Errorf("header %q carried a delivered route-claim secret", name)
				}
			}
		})
	}
}

// claimShapes are the shapes a module route claim is made of, normalised. A
// source carrying any of them carries the capability.
var claimShapes = map[string]string{
	claimedFacadePath:      "the gateway's module route-claim path",
	facadeCredentialPath:   "the exchange that credentials a module route claim",
	facadeSecretHeader:     "the header carrying a module's route-claim secret",
	facadeCredentialHeader: "the header carrying a module route-claim credential",
	facadeSecretsVariable:  "the carrier delivering another module's route-claim secret",
}

// TestNoModuleFacadeClaimOnTheSDKSurface is the static half, because one clean
// boot proves one boot. The invariant is about the capability: a solution
// built on this SDK must not be able to claim a module's facade route, so the
// package carries neither the surface nor the credential.
//
// It compares normalised string literals, not source text. A route or header
// is the same wire shape however it is spelled in Go — split across a
// concatenation, cased differently, assembled from its segments — so the
// comparison folds exactly the characters that spelling is free to move:
// literal boundaries, case, and the separators inside these names.
func TestNoModuleFacadeClaimOnTheSDKSurface(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	scanned, literals := 0, 0
	for _, entry := range entries {
		name := entry.Name()
		// Test sources are exempt: these shapes are written down here on
		// purpose, which is what lets this assert their absence elsewhere.
		if filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		scanned++
		runs := stringLiteralRuns(t, name, source)
		literals += len(runs)
		for _, run := range runs {
			for shape, what := range claimShapes {
				if strings.Contains(fold(run), fold(shape)) {
					t.Errorf("%s builds the string %q, which is %s (%s): a solution claims no module's facade route and holds no credential that could",
						name, run, what, shape)
				}
			}
		}
	}
	if scanned == 0 || literals == 0 {
		t.Fatalf("scanned %d sources and %d string literals: this guard is inert", scanned, literals)
	}
}

// stringLiteralRuns is every string a file builds out of literals: each
// literal on its own, and each run of them joined by `+` as the one string
// that concatenation produces. A shape split across a concatenation is
// therefore seen whole, while identifiers are never joined to anything — an
// adjacency between unrelated names must not read as a wire shape.
func stringLiteralRuns(t *testing.T, name string, source []byte) []string {
	t.Helper()

	var s scanner.Scanner
	fset := token.NewFileSet()
	s.Init(fset.AddFile(name, fset.Base(), len(source)), source, func(pos token.Position, msg string) {
		t.Fatalf("scan %s: %s: %s", name, pos, msg)
	}, 0)

	var runs []string
	var current strings.Builder
	// joining is true between a string literal and the `+` that may extend it,
	// so only `STRING + STRING` keeps a run open.
	joining := false
	flush := func() {
		if current.Len() > 0 {
			runs = append(runs, current.String())
			current.Reset()
		}
	}
	for {
		_, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		switch {
		case tok == token.STRING:
			value, err := strconv.Unquote(lit)
			if err != nil {
				value = lit // a raw literal this unquoter dislikes is still worth scanning
			}
			if !joining {
				flush()
			}
			current.WriteString(value)
			runs = append(runs, value)
			joining = false
		case tok == token.ADD && current.Len() > 0:
			joining = true
		default:
			flush()
			joining = false
		}
	}
	flush()
	return runs
}

// fold removes what spelling is free to change without changing the wire
// shape: case, and the separators these paths, headers and carriers are
// punctuated with. "/modules/_register" and "Modules.Register" fold alike,
// which is the point — the guard is about the shape, not the typing.
func fold(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch r {
		case '-', '_', '/', '.', ' ', '\t':
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
