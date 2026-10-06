package solution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	corework "github.com/codefly-dev/core/workcontext"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workcontext"
)

// capability is a stand-in issuer's capability, minted per seed.
//
// It is minted by **core's** authority, from core's own conformance fixture
// identities and key — the one implementation of a Work Context, which this
// runtime neither signs nor parses. The private key is public by design (core
// derives it from a seed in its own source), so this is a real sealed
// capability that a conforming verifier accepts, without a signer or a payload
// struct living here. That matters beyond convenience: a fixture issuer with
// its own encoding is how two implementations of a capability format start.
//
// Memoised by seed so a test can recompute the capability it expects to have
// been presented: every mint carries a fresh nonce, so minting the same seed
// twice would otherwise produce two different strings.
func capability(seed string) string {
	capabilityMu.Lock()
	defer capabilityMu.Unlock()
	if issued, ok := issuedCapabilities[seed]; ok {
		return issued
	}
	token, _, err := standInAuthority().Start(context.Background(), corework.StartInput{
		TenantID:           corework.FixtureTenant,
		OwnerPrincipalID:   corework.FixturePrincipal,
		OwnerPrincipalKind: "human",
		TaskID:             seed,
		Audience:           corework.FixtureAudience,
		OrganizationID:     corework.FixtureOrganization,
		InstallationID:     corework.FixtureInstallation,
		TTL:                10 * time.Minute,
		Execution: corework.Execution{
			ImageDigest:      corework.FixtureImageDigest,
			BuildIncarnation: corework.FixtureBuildIncarnation,
		},
	})
	if err != nil {
		panic("stand-in capability: " + err.Error())
	}
	issuedCapabilities[seed] = token
	return token
}

var (
	capabilityMu       sync.Mutex
	issuedCapabilities = map[string]string{}
	standInAuthorityV  *corework.Authority
)

// standInAuthority is core's minter, configured from core's fixture identities.
func standInAuthority() *corework.Authority {
	if standInAuthorityV == nil {
		_, key := corework.FixtureKeyPair()
		standInAuthorityV = &corework.Authority{
			Issuer:    corework.FixtureIssuer,
			KeyID:     corework.FixtureKeyID,
			Key:       key,
			Revisions: corework.FixtureRevisions(),
			Seals:     corework.FixtureSeals(),
		}
	}
	return standInAuthorityV
}

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
	s := &Server{manifest: Manifest{ID: testSolutionID, Dashboard: graph}}

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
	s := &Server{manifest: Manifest{ID: testSolutionID}}
	if _, ok := s.manifestMap()["dashboard"]; ok {
		t.Errorf("emitted a dashboard key with no dashboard declared")
	}
}

// wordFootnote is the surface shape the notes solution declares for a Word document: the
// whole set of slots a client reads, so a test can assert on all of them.
func wordFootnote() Surface {
	return Surface{
		ID:          "footnote",
		Client:      "word",
		Title:       "Footnote",
		Description: "Cite a claim from the notes solution.",
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
	s := &Server{manifest: Manifest{ID: "notes", Surfaces: []Surface{wordFootnote()}}}

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
		"description": "Cite a claim from the notes solution.",
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
	s := &Server{manifest: Manifest{ID: "notes", Surfaces: []Surface{surface}}}

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
	bare := &Server{manifest: Manifest{ID: testSolutionID}}
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
	s := &Server{manifest: Manifest{ID: "notes", Surfaces: []Surface{surface}}}

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
			err := Manifest{ID: "notes", Surfaces: tc.surfaces}.validateSurfaces()
			if err == nil {
				t.Fatalf("validateSurfaces accepted %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q does not say %q", err, tc.want)
			}
		})
	}
}

// The same offering in two clients carries the same id — the notes solution's footnote is
// "footnote" in Word and in PowerPoint — and neither client can see the other's,
// so that is not a collision. Only two surfaces of one client are ambiguous.
func TestSurfaceIDsAreUniquePerClientNotPerSolution(t *testing.T) {
	powerpoint := wordFootnote()
	powerpoint.Client = "powerpoint"
	powerpoint.Module = "/surfaces/powerpoint/footnote.js"
	if err := (Manifest{ID: "notes", Surfaces: []Surface{wordFootnote(), powerpoint}}).validateSurfaces(); err != nil {
		t.Errorf("validateSurfaces refused one id shared across two clients: %v", err)
	}

	second := wordFootnote()
	second.Title = "Footnote, again"
	second.Module = "/surfaces/word/footnote-2.js"
	err := (Manifest{ID: "notes", Surfaces: []Surface{wordFootnote(), second}}).validateSurfaces()
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

	s := New(Manifest{ID: "notes", Title: "Notes", Surfaces: []Surface{surface}})
	err := s.Serve()
	if err == nil {
		t.Fatal("Serve returned nil for an off-origin surface module; expected a boot error and no bind")
	}
	if !strings.Contains(err.Error(), "footnote") {
		t.Errorf("boot error should name the surface, got: %v", err)
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

// TestOnlyTheCurrentGatewayRoleResolves reverses an acceptance test this PR
// deleted the behaviour of.
//
// Gateway resolution used to fall back to the pre-v0.0.49 `auth-sidecar` role
// when the current one did not resolve, and a test asserted a solution booted
// against either host version. That is a compatibility path: in this cutover an
// unresolved current gateway silently selecting a legacy service is worse than a
// boot that fails naming the role, because the legacy service is the one that
// served the registration endpoints being deleted.
func TestOnlyTheCurrentGatewayRoleResolves(t *testing.T) {
	const addr = "https://gateway:42152"
	t.Run("the current role resolves", func(t *testing.T) {
		setEndpoint(t, "CODEFLY__ENDPOINT__SAAS__AUTH_GATEWAY__REST__REST", addr)
		cfg := loadConfig(context.Background(), testSolutionID, nil)
		if cfg.gatewayURL != addr {
			t.Fatalf("gatewayURL = %q, want %q resolved from the current role without an override", cfg.gatewayURL, addr)
		}
		// And the mint URL is NOT derived from it. A resolved gateway says
		// where the gateway is, not where the host mints a credential: that
		// endpoint is unsettled and undeployed, and the address this runtime
		// POSTs its projected service-account token to is not one to assume.
		if cfg.mintURL != "" {
			t.Errorf("mintURL = %q, want empty: a resolved gateway must not produce a mint address, because the attestation this runtime sends there would be going somewhere nobody published", cfg.mintURL)
		}
	})

	t.Run("the legacy role resolves to nothing", func(t *testing.T) {
		// Hermetic: no workspace on disk, so only the injected carriers drive
		// resolution and the only role present is the legacy one.
		t.Chdir(t.TempDir())
		setEndpoint(t, "CODEFLY__ENDPOINT__SAAS__AUTH_SIDECAR__REST__REST", addr)
		if got := resolveGateway(context.Background(), "", "auth-gateway"); got != "" {
			t.Fatalf("resolveGateway = %q, want %q: a host exposing only the pre-rename role is one to re-render, and the boot must fail naming the role rather than selecting a legacy service", got, "")
		}
	})
}

// TestLoadConfigResolvesHostByRole proves the host gateway resolves by service
// role alone, independent of the host module's workspace name: loadConfig
// resolves it with no CODEFLY_HOST_MODULE override whether the host module is
// the current host module (auth-gateway service), a pre-rename one
// (auth-sidecar), or any other name a solution composes it under (codefly-dev/core#382).
func TestLoadConfigResolvesHostByRole(t *testing.T) {
	const gatewayAddr = "https://gateway:42152"
	cases := []struct {
		name    string
		module  string
		gateway string
	}{
		{"a host module named saas", "SAAS", "AUTH_GATEWAY"},
		{"a host module under a pre-rename name", "SAAS_STARTER", "AUTH_GATEWAY"},
		{"any other name a solution composes it under", "SOME_OTHER_HOST", "AUTH_GATEWAY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setEndpoint(t, "CODEFLY__ENDPOINT__"+tc.module+"__"+tc.gateway+"__REST__REST", gatewayAddr)

			cfg := loadConfig(context.Background(), testSolutionID, nil)
			if cfg.gatewayURL != gatewayAddr {
				t.Errorf("gatewayURL = %q, want %q resolved without a CODEFLY_HOST_MODULE override", cfg.gatewayURL, gatewayAddr)
			}
		})
	}
}

// identitiesFile writes an admission set to a file and returns its path, which
// is the form both admission sets are provisioned in: they are read per
// handshake and per dial, so they have to be something this process can re-read
// rather than a value fixed when it started.
func identitiesFile(t *testing.T, identities ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "identities")
	writeFile(t, path, strings.Join(identities, "\n")+"\n")
	return path
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
		setEndpoint(t, "CODEFLY__ENDPOINT__SAAS__AUTH_GATEWAY__REST__REST", "https://gateway:42152")
		if got := resolveGateway(context.Background(), "", "auth-gateway"); got != "https://gateway:42152" {
			t.Fatalf("resolveGateway = %q, want the single module's address", got)
		}
	})

	t.Run("two modules owning the same role are ambiguous", func(t *testing.T) {
		setEndpoint(t, "CODEFLY__ENDPOINT__SAAS__AUTH_GATEWAY__REST__REST", "https://gateway-a:42152")
		setEndpoint(t, "CODEFLY__ENDPOINT__SAAS_STARTER__AUTH_GATEWAY__REST__REST", "https://gateway-b:42152")
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

}

// send records an observation without ever blocking a fake host's handler: a
// full channel must not wedge the server a test is driving.
func send[T any](ch chan T, value T) {
	select {
	case ch <- value:
	default:
	}
}

// --- Work Context ---

// mintRequest is what the accounts StartTask RPC received: the ask itself, plus
// the credentials it was presented with — the bearer, which decides whose Task
// is minted, and any capability that rode along, which none should.
type mintRequest struct {
	OrgID           string             `json:"orgId"`
	InstallationID  string             `json:"installationId"`
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
	// supersedeFirstCall answers the first module call the way a far end
	// answers a capability sealed to state it has moved past: 409, with the
	// installation headers the carrier put beside it.
	supersedeFirstCall bool
	// conflictFirstCall answers the first module call with an ORDINARY 409 —
	// a duplicate, a lost update — carrying an installation header that names
	// somebody else's installation. It is the shape the supersession check
	// used to accept, and it must retire nothing.
	conflictFirstCall bool

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
		mint.WorkContext = r.Header.Get(workcontext.HeaderName)
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
		token := capability(fmt.Sprintf("context-%s.%d", mint.Audience, g.minted))
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
			WorkContext: r.Header.Get(workcontext.HeaderName),
		}
		send(g.calls, call)
		if call.WorkContext == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthenticated"})
			return
		}
		g.mu.Lock()
		supersede := g.supersedeFirstCall
		g.supersedeFirstCall = false
		conflict := g.conflictFirstCall
		g.conflictFirstCall = false
		g.mu.Unlock()
		if conflict {
			// An ordinary business conflict, carrying the SAME installation
			// the capability is sealed to — which is what a real module
			// answers with, because a module handling this viewer's call IS in
			// their installation. A foreign id here is what hid the finding:
			// it made comparing the installation look sufficient.
			w.Header().Set(workcontext.InstallationIDHeaderName, corework.FixtureInstallation)
			w.Header().Set(workcontext.InstallationRevisionHeaderName, "9")
			writeJSON(w, http.StatusConflict, map[string]string{"error": "that page already exists"})
			return
		}
		if supersede {
			w.Header().Set(workcontext.InstallationIDHeaderName, corework.FixtureInstallation)
			w.Header().Set(workcontext.InstallationRevisionHeaderName, "4")
			writeJSON(w, http.StatusConflict, map[string]string{"error": "installation revision superseded"})
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
// serveHandler serves one handler against a fake gateway, with the execution
// credential a booted runtime holds: minting for a viewer is fail-closed, so a
// handler whose solution cannot attest which module is asking never reaches the
// gateway at all.
func serveHandler(t *testing.T, gatewayURL string, handler Handler) *httptest.Server {
	t.Helper()
	return serveHandlerWith(t, gatewayURL, attestingSource(t), handler)
}

// serveHandlerWith is serveHandler against a credential source the test holds,
// for an assertion about the credential itself.
func serveHandlerWith(t *testing.T, gatewayURL string, source CredentialSource, handler Handler) *httptest.Server {
	t.Helper()
	s := New(Manifest{ID: "notes", Title: "Notes"}).Credential(source)
	s.cfg = config{gatewayURL: gatewayURL}
	server := httptest.NewServer(s.wrapRequest(func(r *http.Request, gw *Gateway) (any, error) {
		return handler(r.Context(), gw)
	}))
	t.Cleanup(server.Close)
	return server
}

// viewerBearer is the bearer a real gateway forwards: the viewer's own sealed
// capability, minted by core's authority from core's fixture identities.
//
// It was a placeholder string, which was enough while nothing here read the
// bearer. A real gateway forwards the viewer's own capability, so the fixture
// does too — one that cannot answer a question the code might ask is a fixture
// that tests the refusal path forever.
//
// The installation does NOT come from it. That was the design for one round
// and the comment here said so; the installation is read from the stamped
// x-codefly-installation-id header, because inbound a carried capability is
// caller-controlled. See viewerInstallation. The sealed bearer stays because
// it is what a gateway actually forwards, not because anything reads a seal
// out of it.
func viewerBearer() string { return sealedBearer("viewer") }

// sealedBearer is a bearer for a named viewer, sealed the same way: a test that
// needs two distinct callers gets two capabilities rather than one placeholder
// string each.
func sealedBearer(seed string) string { return "Bearer " + capability(seed) }

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
	req.Header.Set("authorization", viewerBearer())
	req.Header.Set(orgHeader, viewerOrg)
	req.Header.Set(sessionHeader, viewerSession)
	req.Header.Set(workcontext.InstallationIDHeaderName, testInstallation)
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
	if mint.Bearer != viewerBearer() {
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
	if call.WorkContext != capability("context-documents.1") {
		t.Errorf("module read carried work context %q, want the minted one", call.WorkContext)
	}
	if call.Bearer != viewerBearer() {
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
	lapsed := func(context.Context) (string, time.Time, error) {
		mints++
		return capability(fmt.Sprintf("lapsed-%d", mints)), time.Now().Add(-time.Second), nil
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
	if first.WorkContext != capability("context-documents.1") {
		t.Errorf("first read carried %q, want the first capability", first.WorkContext)
	}
	if second.WorkContext != capability("context-documents.2") {
		t.Errorf("read after the capability lapsed carried %q, want a freshly minted one — the derived gateway is holding a snapshot", second.WorkContext)
	}
	if got := gw.mintCount(); got != 2 {
		t.Errorf("minted %d capabilities, want 2", got)
	}
}

// TestMintCarriesThisWorkloadsCredentialAndNoOthers pins what rides on a mint.
//
// One capability belongs there — this execution's own, which says which module
// is asking and is the same on every mint of the process. A capability minted
// for a *module* must not: riding one along on the request that mints another's
// is harmless only until the first lapses, since the edge verifies every
// presented context and would then refuse the call meant to replace it.
func TestMintCarriesThisWorkloadsCredentialAndNoOthers(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	source := attestingSource(t)
	workload, err := source.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	solution := serveHandlerWith(t, gw.URL, source, func(ctx context.Context, g *Gateway) (any, error) {
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
		if mint.WorkContext != workload.Token() {
			t.Errorf("mint for %q carried work context %q, want this execution's own credential: the issuer has to know which module is asking", mint.Audience, mint.WorkContext)
		}
		if mint.Bearer != viewerBearer() {
			t.Errorf("mint for %q carried bearer %q, want the viewer's", mint.Audience, mint.Bearer)
		}
	}
}

// TestA409IsNotReadAsSupersessionAtAll replaces
// TestASupersededCapabilityIsDroppedNotReused, and the replacement is the
// finding rather than a weakening of it.
//
// That test asserted the capability is DROPPED when a module answers 409 with
// an installation header, and the behaviour it pinned was wrong in three
// successive ways: any 409 with any installation header; then any 409 whose
// header named the installation the capability is sealed to — and a module
// answering an ordinary business conflict IS in that installation, so a
// duplicate or a lost update evicted a valid capability and the next call
// minted again.
//
// The two cases cannot be told apart on the wire: 409 means "the state you
// were sealed to has moved" and it means "that page already exists". So this
// runtime infers nothing from one. A genuinely superseded capability is
// refused call by call by the far end, which is correct if noisy, and the
// renewal replaces it on the credential's own schedule. What would make an
// inference sound is a host-side discriminator — follow-up 11.
func TestA409IsNotReadAsSupersessionAtAll(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{supersedeFirstCall: true})
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		docs, err := g.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
		if err != nil {
			return nil, err
		}
		// Two reads through one derived gateway. The first is refused as
		// superseded; the second must present a freshly minted capability
		// rather than the dropped one.
		if _, err := getThrough(ctx, docs); err != nil {
			return nil, err
		}
		return getThrough(ctx, docs)
	})
	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)

	first, second := <-gw.calls, <-gw.calls
	if first.WorkContext == "" || second.WorkContext == "" {
		t.Fatal("a module call arrived with no capability at all")
	}
	if first.WorkContext != second.WorkContext {
		t.Error("the 409 retired the cached capability: a module's conflict is not a statement this runtime can read as supersession, and acting on it costs an audited mint per business conflict")
	}
	if got := gw.mintCount(); got != 1 {
		t.Errorf("minted %d capabilities, want 1: one ask mints once, and a 409 from a callee does not change that", got)
	}
}

// TestPlatformTrafficIsNeverProxiedAndPresentsThisWorkload keeps the viewer's
// credentials and this workload's own off an arbitrary egress host, and makes
// the outbound hop authenticated rather than merely https.
//
// Every platform target is composition-local, and these requests carry the
// viewer's bearer, the capability minted for them, and — on a mint — the
// projected token that attests which workload this process is. An https URL
// alone says only that the scheme is https: without a trust anchor the far end
// is verified against whatever the image's system roots happen to hold, and
// without a client certificate it cannot tell this workload from anything else
// that reached it.
func TestPlatformTrafficIsNeverProxiedAndPresentsThisWorkload(t *testing.T) {
	if unauthenticatedTransport.Proxy != nil {
		t.Error("the platform transport carries a proxy: with HTTP(S)_PROXY set and a NO_PROXY that misses the in-cluster gateway, the viewer's bearer and capability would be dialled to an arbitrary egress host")
	}

	certFile, keyFile, bundleFile, _, _ := workloadIdentity(t, testPrincipal)
	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
		mintPeersFile:    identitiesFile(t, testGatewayPrincipal),
		gatewayPeersFile: identitiesFile(t, testGatewayPrincipal),
		// This test inspects the transport rather than dialling, so any
		// resolved destination will do.
		mintURL: "https://mint.cell:443" + credentialMintPath}
	server.principal = testPrincipal
	client, err := server.outboundClient(nil)
	if err != nil {
		t.Fatalf("outboundClient: %v", err)
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("outbound transport is %T, want *http.Transport", client.Transport)
	}
	switch {
	case transport.Proxy != nil:
		t.Error("the outbound client carries a proxy")
	case transport.DialTLSContext == nil:
		t.Fatal("the outbound client has no per-connection dialler, so its trust is whatever was snapshotted at boot")
	case transport.TLSClientConfig != nil:
		t.Error("the outbound transport carries a snapshotted TLS configuration: peer trust must be built per connection, or a removed root keeps authenticating the platform")
	case transport.IdleConnTimeout == 0 || transport.IdleConnTimeout > outboundTrustReloadBound:
		t.Errorf("idle connections live for %s, so per-dial reloading bounds nothing: want at most %s", transport.IdleConnTimeout, outboundTrustReloadBound)
	}
	if client.CheckRedirect == nil {
		t.Error("the outbound client follows redirects: net/http copies every header but three across hosts, so a Location would be handed this workload's credentials")
	}
	// A pair that rotated to another workload's identity must not be presented
	// to the platform, which the default path never checked: the listener's
	// leaf was held to the principal and this second reloader over the same
	// files was not.
	rival, rivalKey, _, _, _ := workloadIdentity(t, "spiffe://codefly.test/ns/solutions/sa/another-workload")
	writeFile(t, certFile, readFile(t, rival))
	writeFile(t, keyFile, readFile(t, rivalKey))
	if _, err := server.outboundClient(nil); err == nil {
		t.Error("an outbound client was built presenting a leaf issued for another workload")
	}
	// A boot with no trust anchor cannot build one at all, which is the same
	// refusal the listener makes.
	server.cfg.trustBundleFile = ""
	if _, err := server.outboundClient(nil); err == nil {
		t.Error("an outbound client was built with no projected anchor to verify the platform against")
	}
}

// TestAHandlersGatewayDialsThroughTheBootsAuthenticatedTransport is the leg the
// test above was missing, and a reviewer showed it: everything there inspects
// the client outboundClient *returns*, and the defect this file's comments are
// about was the gateway handed to a handler not carrying it. Deleting
// gatewayFor's one assignment left every assertion above passing while a
// handler's reads went out over the unauthenticated fallback.
//
// So this drives the production gateway client at a platform host that requires
// a caller's certificate, and asks the host who called. The answer has to be
// this workload.
func TestAHandlersGatewayDialsThroughTheBootsAuthenticatedTransport(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)
	host := newPlatformHost(t, c, testGatewayPrincipal)

	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
		mintPeersFile:    identitiesFile(t, testGatewayPrincipal),
		gatewayPeersFile: identitiesFile(t, testGatewayPrincipal), gatewayURL: host.URL}
	server.principal = testPrincipal
	outbound, err := server.outboundClient(nil)
	if err != nil {
		t.Fatalf("outboundClient: %v", err)
	}
	server.outbound = outbound

	gateway := server.gatewayFor(http.Header{"authorization": {viewerBearer()}})
	resp, err := gateway.HTTPClient().Get(host.URL + "/v1/things/search")
	if err != nil {
		t.Fatalf("a handler's gateway could not reach a platform host that requires this workload's certificate: %v\n"+
			"a gateway that does not carry the boot's transport dials the platform as an anonymous client", err)
	}
	_ = resp.Body.Close()
	called := host.called()
	if len(called) == 0 {
		t.Fatal("the platform host recorded no caller")
	}
	if called[0] != testPrincipal {
		t.Errorf("the platform saw a request from %q, want this workload's own %q", called[0], testPrincipal)
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
	_, err := newGateway(gw.URL, viewerBearer(), "", viewerSession).
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
	if call.Bearer != viewerBearer() {
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
	_, err := newGateway(gw.URL, viewerBearer(), viewerOrg, "").
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
	req.Header.Set("authorization", viewerBearer())
	req.Header.Set(orgHeader, viewerOrg)
	req.Header.Set(sessionHeader, viewerSession)
	req.Header.Set(workcontext.InstallationIDHeaderName, testInstallation)
	req.Header.Set(workcontext.HeaderName, capability("forged"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("call solution: %v", err)
	}
	defer drainAndClose(resp)

	if mint := <-gw.mints; mint.WorkContext == capability("forged") {
		t.Error("the mint presented the capability the browser sent: a caller-supplied capability must not authenticate anything")
	}
	if call := <-gw.calls; call.WorkContext != capability("context-documents.1") {
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
			req.Header.Set("authorization", viewerBearer())
			req.Header.Set(orgHeader, tt.org)
			req.Header.Set(sessionHeader, tt.session)
			req.Header.Set(workcontext.InstallationIDHeaderName, testInstallation)
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

// TestManifestURLIsNeverAnAbsoluteOrigin pins where the served manifestUrl
// points. It used to be absolute: on PUBLIC_URL when one was set, and otherwise
// on "http://localhost:<port>", this process's own loopback address — so every
// deployed solution published a manifest no browser could load and the product
// showed it as failed to load. It is now the path on this backend and nothing
// else, which the host resolves against the route its presence document names;
// PUBLIC_URL is gone with the registration that was the only reason to build an
// origin here.
func TestManifestURLIsNeverAnAbsoluteOrigin(t *testing.T) {
	t.Setenv("PUBLIC_URL", "https://solutions.example.com/widgets")
	t.Setenv("PORT", "8080")
	s := New(Manifest{ID: testSolutionID})
	s.cfg = loadConfig(context.Background(), testSolutionID, nil)
	frontend, _ := s.manifestMap()["frontend"].(map[string]any)
	if got := frontend["manifestUrl"]; got != federationManifestPath {
		t.Errorf("manifestUrl = %v, want %q: no environment variable may make it absolute again", got, federationManifestPath)
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

// optionalIdentitiesFile is identitiesFile, or no path at all for an empty set
// — the distinction a boot-refusal table needs, since "the platform never
// provisioned a path" and "the path is there and names nobody" are two
// different refusals and each has its own row.
func optionalIdentitiesFile(t *testing.T, identities string) string {
	t.Helper()
	if identities == "" {
		return ""
	}
	return identitiesFile(t, identities)
}

// TestABootWithoutAResolvedMintURLIsRefused: the previous revision derived the
// mint address from the resolved gateway and labelled the result a guess — the
// field was literally named mintURLGuessed, the code said the endpoint was "NOT
// settled" and that "neither endpoint exists yet", and the README and the boot
// log both said "settled". Both could not be true.
//
// This is the address the projected service-account token goes to, which is the
// strongest statement this process can make about which workload it is. A
// guessed address for that is what fail-closed forbids, and this package
// already refuses rather than guesses when it cannot pair a token-exchange URL.
func TestABootWithoutAResolvedMintURLIsRefused(t *testing.T) {
	cfg := config{port: "8080", gatewayURL: "https://gateway:42152", profile: localProfile}
	err := cfg.validate()
	if err == nil {
		t.Fatal("the boot accepted a configuration with no mint URL, so this runtime would POST its projected token to an address nobody resolved")
	}
	if !strings.Contains(err.Error(), CredentialMintURLEnvironmentVariable) {
		t.Errorf("the refusal %q does not name %s, the variable that sets it", err, CredentialMintURLEnvironmentVariable)
	}
	// And the refusal must not read as a provisioning gap in the gateway,
	// which resolved perfectly well.
	if strings.Contains(err.Error(), "unresolved gateway") {
		t.Errorf("the refusal %q blames the gateway, which resolved: that sends an operator to inspect endpoint resolution over a value that is simply not set", err)
	}
}

// TestNoProductionCodeDerivesTheMintAddress pins the absence. A default address
// is the thing this repository's rules single out, and the previous one came
// back as a "labelled stopgap" that the README then described as settled.
func TestNoProductionCodeDerivesTheMintAddress(t *testing.T) {
	for _, name := range moduleSources(t) {
		source, err := os.ReadFile(name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		body := string(source)
		for _, derived := range []string{"gatewayURL + credentialMintPath", "gatewayURL+credentialMintPath"} {
			if strings.Contains(body, derived) {
				t.Errorf("%s derives the credential mint address from the resolved gateway: the gateway's address says where the gateway is, not where this host mints a credential, and the projected token this runtime sends there is not something to address by assumption", name)
			}
		}
		if strings.Contains(body, "mintURLGuessed") {
			t.Errorf("%s still carries mintURLGuessed: a guessed address for the endpoint this runtime attests itself to is refused now, so there is nothing to label", name)
		}
	}
}

// TestTwoAdmissionSourcesAreRefusedRatherThanRanked: an admission set answered
// by both an operator override and the platform's provisioning is two sources
// for one authorization fact. The previous revision logged which one won, which
// reports the conflict without resolving it — whichever this process picked, the
// other is a decision somebody made that is not in force, and for admission
// being wrong admits a caller.
//
// It is the stance the SDK already takes on the same question: a value
// delivered inline and by file carrier is refused as two sources for one fact.
func TestTwoAdmissionSourcesAreRefusedRatherThanRanked(t *testing.T) {
	base := func(t *testing.T) config {
		t.Helper()
		return config{
			port: "8080", gatewayURL: "https://gateway:42152",
			mintURL: "https://gateway:42152" + credentialMintPath,
			profile: localProfile,
		}
	}

	t.Run("an override alone is accepted", func(t *testing.T) {
		cfg := base(t)
		cfg.allowedCallersFile = identitiesFile(t, testGatewayPrincipal)
		if err := cfg.validate(); err != nil {
			t.Fatalf("an override with no provisioning behind it was refused: %v", err)
		}
	})

	// Driven through the real resolver, not injected. The comment that used to
	// stand here said a test cannot make the SDK's workspace configuration
	// answer, and that was simply false — authorityValues does it for the
	// authority group, the same way. So the conflict rule had no behavioural
	// test at all and three mutants of it survived.
	t.Run("both answering is refused, through the resolver", func(t *testing.T) {
		provisionedWorkloadValue(t, WorkloadIdentityAllowedCallersFileKey, "/provisioned/callers")
		t.Setenv(IdentityAllowedCallersFileEnvironmentVariable, "/override/callers")
		conflict := conflictingAdmissionSources(context.Background(), nil)
		if conflict == nil {
			t.Fatal("the resolver saw no conflict while both the override and the platform answered for the caller set")
		}
		for _, named := range []string{"/override/callers", "/provisioned/callers"} {
			if !strings.Contains(conflict.Error(), named) {
				t.Errorf("the refusal %q does not name %s, so an operator cannot tell which two answers are in play", conflict, named)
			}
		}

		cfg := base(t)
		cfg.admissionConflict = conflict
		err := cfg.validate()
		if err == nil {
			t.Fatal("a boot accepted an admission set answered by two sources: ranking them silently is how a caller set gets widened with nothing recording that the platform's decision was not in force")
		}
		if !strings.Contains(err.Error(), "answered twice") {
			t.Errorf("the refusal %q does not say the set has two answers", err)
		}
		// And it is reported before every other provisioning message, or it
		// reads as ordinary advice next to them.
		cfg.port = "not-a-port"
		if again := cfg.validate(); again == nil || !strings.Contains(again.Error(), "answered twice") {
			t.Errorf("with another refusal also pending, validate reported %v: the conflicting-authorization refusal is the one that says a decision is not in force", again)
		}
	})

	t.Run("the resolver finds no conflict with no override set", func(t *testing.T) {
		provisionedWorkloadValue(t, WorkloadIdentityAllowedCallersFileKey, "/provisioned/callers")
		if err := conflictingAdmissionSources(context.Background(), nil); err != nil {
			t.Errorf("a conflict was reported with no override set: %v", err)
		}
	})

	// And an override against provisioning this process cannot READ is a
	// conflict too. The resolver discarded the SDK's error, saw no second
	// answer, and put the override in force — against provisioning it simply
	// could not see.
	t.Run("an unreadable platform answer is a conflict, not an absent one", func(t *testing.T) {
		t.Setenv(IdentityAllowedCallersFileEnvironmentVariable, "/override/wide")
		// No workspace configuration loaded at all, so the SDK errors rather
		// than answering empty.
		withoutWorkloadValues(t)
		// With a failed environment load, which is the one signal that
		// separates "never provisioned" from "could not be read": the SDK
		// answers both with the same error.
		err := conflictingAdmissionSources(context.Background(), errors.New("loading the injected environment failed"))
		if err == nil {
			t.Fatal("an override was put in force while the platform's own answer could not be read: an unreadable answer is still an answer somebody provisioned, and choosing between two is exactly what this rule refuses")
		}
		if !strings.Contains(err.Error(), "cannot be read") {
			t.Errorf("the refusal %q does not say the platform's answer was unreadable", err)
		}
	})
}

// TestAnAdmissionFileIsReadWholeOrRefused: each entry has to be a complete
// line, which is the part that is not obvious.
//
// The previous reader split whatever it was handed, so a file caught mid-write
// — a platform rewriting it without an atomic swap, an operator's `>` redirect
// — truncated an entry and the truncation was admitted as an identity of its
// own. The executed review showed ".../sa/gateway-internal" read as
// ".../sa/gateway", admitting a caller the set never named.
func TestAnAdmissionFileIsReadWholeOrRefused(t *testing.T) {
	const gateway = "spiffe://codefly.test/ns/platform/sa/gateway"
	const internal = "spiffe://codefly.test/ns/platform/sa/gateway-internal"

	read := func(t *testing.T, content string) ([]string, error) {
		t.Helper()
		path := filepath.Join(t.TempDir(), "identities")
		writeFile(t, path, content)
		return resolvedIdentities(path, "unresolved")()
	}

	t.Run("a truncated last line is refused, not admitted", func(t *testing.T) {
		// What a reader sees partway through a non-atomic rewrite of a file
		// whose only entry is the -internal identity.
		got, err := read(t, internal[:len(internal)-len("-internal")])
		if err == nil {
			t.Fatalf("a file caught mid-write resolved to %v: the fragment %q is a different identity from the one being written, and admitting it lets in a caller the set never named", got, gateway)
		}
		if !strings.Contains(err.Error(), "newline") {
			t.Errorf("the refusal %q does not say why the file is not whole", err)
		}
	})

	t.Run("a terminated file is read", func(t *testing.T) {
		got, err := read(t, gateway+"\n"+internal+"\n")
		if err != nil {
			t.Fatalf("a complete file was refused: %v", err)
		}
		if len(got) != 2 || got[0] != gateway || got[1] != internal {
			t.Errorf("resolved %v, want both identities", got)
		}
	})

	t.Run("entries that can never match are refused at the file", func(t *testing.T) {
		for _, tc := range []struct{ name, content string }{
			{"a byte-order mark", "\ufeff" + gateway + "\n"},
			{"a NUL in an entry", "spiffe://codefly.test/ns/platform/sa/gate\x00way\n"},
			{"not a URI at all", "gateway\n"},
			{"another scheme", "https://codefly.test/ns/platform/sa/gateway\n"},
			{"no path", "spiffe://codefly.test\n"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				if got, err := read(t, tc.content); err == nil {
					t.Errorf("resolved %v: an entry that cannot match any peer is a provisioning mistake, and carrying it silently turns into a caller nobody admits at a handshake far from the cause", got)
				}
			})
		}
	})

	t.Run("a file too large to re-read every second is refused", func(t *testing.T) {
		big := strings.Repeat(gateway+"\n", (admissionFileLimit/(len(gateway)+1))+16)
		got, err := read(t, big)
		if err == nil {
			t.Fatalf("resolved %d identities from a file over the limit: this is read on every handshake, every dial, and once a second per established connection in each direction", len(got))
		}
		// And refused BY THE CAP. Without this the case passes for the wrong
		// reason: the reader stops at the limit, so the last line it sees is a
		// fragment and the whole-line rule refuses it — which means removing
		// the cap entirely left this green.
		if !strings.Contains(err.Error(), "larger than") {
			t.Errorf("the refusal %q is not about the file's size, so this case does not cover the cap", err)
		}
	})

	t.Run("comments, CRLF and commas still work", func(t *testing.T) {
		got, err := read(t, "# the gateway\r\n"+gateway+", "+internal+"\r\n")
		if err != nil {
			t.Fatalf("a conforming file was refused: %v", err)
		}
		if len(got) != 2 {
			t.Errorf("resolved %v, want two identities", got)
		}
	})
}

// TestACredentialBearingURLCarriesNothingButADestination: userinfo, a query and
// a fragment were all accepted on both credential-bearing destinations, and the
// first two were written to the boot log verbatim — a secret that is disclosed
// and, in the userinfo case, that net/http strips before the request is even
// sent, so it is never used for anything except being logged.
func TestACredentialBearingURLCarriesNothingButADestination(t *testing.T) {
	for _, tc := range []struct{ name, mint, names string }{
		{"userinfo", "https://ops:s3cr3t@mint.cell/platform/_credential", "userinfo"},
		{"a query", "https://mint.cell/platform/_credential?token=s3cr3t", "query"},
		{"a fragment", "https://mint.cell/platform/_credential#part", "fragment"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config{port: "8080", gatewayURL: "https://gateway:42152", mintURL: tc.mint, profile: localProfile}
			err := cfg.validate()
			if err == nil {
				t.Fatalf("a credential mint URL carrying %s was accepted", tc.names)
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Errorf("the refusal %q does not say the URL carries %s", err, tc.names)
			}
		})
	}

	for _, tc := range []struct{ raw, hidden string }{
		{"https://ops:s3cr3t@mint.cell/x", "s3cr3t"},
		{"https://mint.cell/x?token=s3cr3t", "s3cr3t"},
	} {
		if got := redactedURL(tc.raw); strings.Contains(got, tc.hidden) {
			t.Errorf("redactedURL(%q) = %q, which still carries the secret", tc.raw, got)
		}
	}

	// And the boot log actually uses it. Asserting on the helper alone left
	// the *call site* free to pass the raw URL, which is where the secret was
	// being written — the helper being correct is not the property.
	t.Run("the boot log carries no secret", func(t *testing.T) {
		var captured bytes.Buffer
		log.SetOutput(&captured)
		t.Cleanup(func() { log.SetOutput(os.Stderr) })

		cfg := config{port: "8080", gatewayURL: "https://gateway:42152", profile: localProfile,
			mintURL: "https://ops:s3cr3t-password@mint.cell/platform/_credential"}
		// validate() refuses this URL, and the log line still must not carry
		// the secret: the refusal and the logging are independent, which is
		// the whole reason the log redacts regardless.
		_ = cfg.validate()
		cfg.mintURL = "https://mint.cell/platform/_credential"
		if err := cfg.validate(); err != nil {
			t.Fatalf("a conforming configuration was refused: %v", err)
		}
		cfg.mintURL = "https://ops:s3cr3t-password@mint.cell/platform/_credential"
		cfg.logResolved()
		if got := captured.String(); strings.Contains(got, "s3cr3t-password") {
			t.Errorf("the boot log carries the secret from the mint URL:\n%s", got)
		}
	})
}

// TestTheEnvironmentLoadErrorReachesTheRefusals: three refusals and a boot log
// exist to tell "the SDK resolved nothing" apart from "loading the injected
// environment failed first", and a signature refactor dropped the value they
// read, so all of them reported the former.
//
// That is the exact mistake validate() was written to stop making: its own
// comment records that a single generic message sent an operator to inspect
// endpoint resolution over a variable they had broken themselves.
func TestTheEnvironmentLoadErrorReachesTheRefusals(t *testing.T) {
	loadErr := errors.New("the injected carriers could not be read")

	t.Run("loadConfig carries it onto the configuration", func(t *testing.T) {
		cfg := loadConfig(context.Background(), testSolutionID, loadErr)
		if cfg.environmentLoadErr == nil {
			t.Fatal("loadConfig dropped the environment-load error, so every refusal below reads as absent provisioning rather than as an environment that never loaded")
		}
	})

	t.Run("an unresolved destination says which it is", func(t *testing.T) {
		cfg := config{port: "8080", profile: localProfile, environmentLoadErr: loadErr}
		err := cfg.validate()
		if err == nil {
			t.Fatal("a configuration with no gateway was accepted")
		}
		if !strings.Contains(err.Error(), "injected environment failed first") {
			t.Errorf("the refusal %q does not say the environment never loaded, so it sends an operator to inspect provisioning that may well be in place", err)
		}
	})

	t.Run("a missing path says which it is", func(t *testing.T) {
		cfg := config{environmentLoadErr: loadErr}
		err := cfg.requirePath("workload identity certificate", "", "OVERRIDE", "CERT_FILE")
		if err == nil {
			t.Fatal("an unresolved path was accepted")
		}
		if !strings.Contains(err.Error(), "environment failed first") {
			t.Errorf("the refusal %q does not distinguish an unprovisioned path from an environment that never loaded", err)
		}
	})
}

// TestAUsernameCredentialIsNotLogged: url.Redacted() masks the password and
// keeps the username, so a token carried as a username — which is how a great
// many of them are carried — came through the redaction intact.
func TestAUsernameCredentialIsNotLogged(t *testing.T) {
	for _, raw := range []string{
		"https://s3cr3t-token@mint.cell/platform/_credential",
		"https://s3cr3t-token:@mint.cell/platform/_credential",
		"https://user:s3cr3t-token@mint.cell/platform/_credential",
	} {
		if got := redactedURL(raw); strings.Contains(got, "s3cr3t-token") {
			t.Errorf("redactedURL(%q) = %q, which still carries the secret: Redacted() only masks the password", raw, got)
		}
		// And it still says where, or it is useless in a log.
		if got := redactedURL(raw); !strings.Contains(got, "mint.cell") {
			t.Errorf("redactedURL(%q) = %q, which no longer names the destination", raw, got)
		}
	}
}

// clearSelfEnvironment unsets every carrier the configuration tests key on, so
// a variable exported in the shell running the suite cannot decide an
// assertion.
//
// It lived in deployed_registration_test.go, which went with the
// registrations. The MCP configuration tests that arrived on main need it, and
// the reason it exists outlives what it was written for: these assertions are
// about what the SDK resolves, and an exported variable answering instead is a
// green run that proves nothing.
func clearSelfEnvironment(t *testing.T) {
	t.Helper()
	for _, key := range []string{"SELF_UPSTREAM", "PUBLIC_URL", "CODEFLY__RUNTIME_CONTEXT",
		"CODEFLY__MODULE", "CODEFLY__SERVICE", "CODEFLY__ENVIRONMENT"} {
		t.Setenv(key, "")
	}
	// Every self-endpoint carrier, by prefix rather than by name.
	//
	// The restored version named one deployment's:
	// CODEFLY__SELF_ENDPOINT__LASTLOGIN_GO__BACKEND__HTTP__HTTP. A carrier's
	// name is built from the module and service it belongs to, so naming one
	// puts a particular deployment in a runtime that is generic by rule — and
	// it clears exactly that deployment's variable and no other, which is the
	// weaker half of the problem: an operator running the suite with any other
	// service's carrier exported still has it answering these assertions.
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if strings.HasPrefix(key, resources.SelfEndpointPrefix) {
			t.Setenv(key, "")
		}
	}
}

// TestAnAskCannotBeEditedAfterItsCeilingIsChecked is round fourteen's B2.
//
// workContextScopes converted Scope to its wire form, which copies the struct
// and leaves both pointing at the CALLER's backing arrays. The ask is retained
// on the delegation and its JSON is the cache key, computed once — so a caller
// could hand over Actions: []string{"read"}, take the delegated gateway, write
// "delete" into that array, and wait for the cached capability to expire. The
// next mint serialized "delete", under the key computed for "read", with the
// ceiling having been checked against "read". No concurrency, no second call
// to ForModule, and nothing in the published contract to stop it.
func TestAnAskCannotBeEditedAfterItsCeilingIsChecked(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	mint := newHostMint(t, &hostMint{})
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected")
	module := passthroughModule()
	module.Scopes = []Scope{{ResourceKind: "things", Actions: []string{"read"}}}
	module.Methods = nil
	server := New(Manifest{ID: testSolutionID}).Consumes(module).
		Credential(mintClientFor(t, mint, tokenFile)).
		Contract(ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
		}})
	server.cfg = config{gatewayURL: gw.URL, profile: localProfile, consumes: newProjection(consumesThings)}
	server.principal = testPrincipal
	contract, err := server.resolveContract()
	if err != nil {
		t.Fatalf("resolve the published contract: %v", err)
	}
	server.contract, server.contractResolved = contract, true

	header := http.Header{}
	header.Set("authorization", viewerBearer())
	header.Set(orgHeader, viewerOrg)
	header.Set(sessionHeader, viewerSession)
	header.Set(workcontext.InstallationIDHeaderName, testInstallation)
	gateway := server.gatewayFor(header)

	// The ask the ceiling is checked against, in a slice the caller keeps.
	actions := []string{"read"}
	acting, err := gateway.ForModule(context.Background(), "things", Scope{ResourceKind: "things", Actions: actions})
	if err != nil {
		t.Fatalf("the declared ask was refused: %v", err)
	}
	first := <-gw.mints
	if len(first.AuthorityScopes) != 1 || len(first.AuthorityScopes[0].Actions) != 1 ||
		first.AuthorityScopes[0].Actions[0] != "read" {
		t.Fatalf("the first mint asked for %+v, want read", first.AuthorityScopes)
	}

	// The caller edits the array it still holds, and the capability it was
	// handed is retired — which is what expiry does, with no second call to
	// ForModule and no concurrency.
	actions[0] = "delete"
	if _, err := acting.workContext(context.Background()); err != nil {
		t.Fatalf("read the delegated capability: %v", err)
	}
	// Expire the held capability, which is what forces the next read to mint.
	// This used the cache's supersede primitive, which existed only to serve
	// the 409 inference and went with it; expiring the entry directly says
	// what the test means — a LATER mint must not carry the edited slice —
	// without a production method nothing calls.
	acting.contexts.mu.Lock()
	delete(acting.contexts.minted, acting.delegation.key)
	acting.contexts.mu.Unlock()

	// A refusal here is also a correct answer. What must not happen is a
	// silent mint for "delete".
	if _, err := acting.workContext(context.Background()); err != nil {
		t.Logf("the renewal was refused, which is the other acceptable answer: %v", err)
		return
	}
	second := <-gw.mints
	for _, scope := range second.AuthorityScopes {
		for _, action := range scope.Actions {
			if action == "delete" {
				t.Fatalf("a mint asked the issuer for %q after the ceiling had been checked against read: the ask was retained with the caller's own backing array, so editing it changed what was minted under a cache key computed for something else — and the published ceiling is the guarantee that cannot hold", action)
			}
		}
	}
}

// TestAnOrdinaryConflictDoesNotRetireAValidCapability is round sixteen's first
// major.
//
// supersededCapability accepted ANY 409 carrying a non-empty installation
// header, and a 409 is an ordinary business answer: a duplicate, a lost
// update, a version conflict. A module answering one with installation
// metadata beside it therefore evicted a perfectly valid cached capability,
// and the next call minted again — needless mints and needless audit traffic
// on the one path whose whole purpose is one mint per execution.
//
// The header is matched against the installation the capability THAT WAS
// PRESENTED is sealed to now, so a conflict about somebody else's
// installation says nothing about this one.
func TestAnOrdinaryConflictDoesNotRetireAValidCapability(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{conflictFirstCall: true})
	solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
		docs, err := g.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
		if err != nil {
			return nil, err
		}
		// Two reads: the first gets the ordinary 409, the second must present
		// the SAME capability rather than a freshly minted one.
		if _, err := getThrough(ctx, docs); err != nil {
			return nil, err
		}
		status, err := getThrough(ctx, docs)
		if err != nil {
			return nil, err
		}
		return map[string]int{"status": status}, nil
	})

	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the handler answered %d, want 200", resp.StatusCode)
	}

	// ONE mint. An ordinary conflict that retired the capability would show up
	// here as two.
	if got := gw.mintCount(); got != 1 {
		t.Errorf("the issuer minted %d capabilities for one ask, want 1: an ordinary 409 retired a valid capability, so every business conflict a module answers costs this solution a fresh audited mint", got)
	}
	// And the second call presented the same capability.
	first, second := <-gw.calls, <-gw.calls
	if first.WorkContext == "" || second.WorkContext == "" {
		t.Fatal("a module call arrived with no capability at all")
	}
	if first.WorkContext != second.WorkContext {
		t.Error("the second call presented a different capability than the first: the ordinary conflict evicted the cached one, which is the re-mint this check exists to prevent")
	}
}
