package solution

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	corework "github.com/codefly-dev/core/workcontext"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

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
		cfg := loadConfig(context.Background())
		if cfg.gatewayURL != addr {
			t.Fatalf("gatewayURL = %q, want %q resolved from the current role without an override", cfg.gatewayURL, addr)
		}
		if want := addr + credentialMintPath; cfg.mintURL != want {
			t.Errorf("mintURL = %q, want %q derived from the resolved gateway", cfg.mintURL, want)
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
// the current saas (auth-gateway service), the pre-rename saas-starter
// (auth-sidecar), or any other name a solution composes it under (codefly-dev/core#382).
func TestLoadConfigResolvesHostByRole(t *testing.T) {
	const gatewayAddr = "https://gateway:42152"
	cases := []struct {
		name    string
		module  string
		gateway string
	}{
		{"a host module named saas", "SAAS", "AUTH_GATEWAY"},
		{"a host module named saas-starter", "SAAS_STARTER", "AUTH_GATEWAY"},
		{"any other name a solution composes it under", "SOME_OTHER_HOST", "AUTH_GATEWAY"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setEndpoint(t, "CODEFLY__ENDPOINT__"+tc.module+"__"+tc.gateway+"__REST__REST", gatewayAddr)

			cfg := loadConfig(context.Background())
			if cfg.gatewayURL != gatewayAddr {
				t.Errorf("gatewayURL = %q, want %q resolved without a CODEFLY_HOST_MODULE override", cfg.gatewayURL, gatewayAddr)
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

// consumesDocuments is the api.consumes projection core surfaces to a running
// backend for the notes→documents federation. The literal key is
// manifest.APIConsumesEnvironmentVariable (a wire contract).
const consumesDocuments = `[{"id":"docstore.documents","module":"docstore","service":"documents","endpoint":"rest","protocol":"rest","as":"documents"}]`

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
	// supersedeFirstCall answers the first module call the way a far end
	// answers a capability sealed to state it has moved past: 409, with the
	// installation headers the carrier put beside it.
	supersedeFirstCall bool

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
		g.mu.Unlock()
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
	if call.WorkContext != capability("context-documents.1") {
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
		if mint.Bearer != "Bearer viewer-token" {
			t.Errorf("mint for %q carried bearer %q, want the viewer's", mint.Audience, mint.Bearer)
		}
	}
}

// TestASupersededCapabilityIsDroppedNotReused closes the other half of
// classifying a refusal as ErrRevoked.
//
// That sentinel means the capability was sound when it was minted and the state
// moved under it, so the holder's answer is to mint again. Classifying the
// error and keeping the capability until its own clock ran out would answer
// every call in that window with the same refusal — the cache handing back a
// credential the issuer had already stopped honouring, and a caller that
// re-asked getting it straight back.
func TestASupersededCapabilityIsDroppedNotReused(t *testing.T) {
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
	if first.WorkContext == second.WorkContext {
		t.Error("the second read presented the capability the far end said was superseded: the cache reused a credential the issuer had stopped honouring")
	}
	if got := gw.mintCount(); got != 2 {
		t.Errorf("minted %d capabilities, want 2: a superseded one costs exactly one re-mint", got)
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
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile}
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
	case transport.TLSClientConfig == nil:
		t.Fatal("the outbound client has no TLS configuration: it would verify the platform against the image's system roots")
	case transport.TLSClientConfig.RootCAs == nil:
		t.Error("the outbound client verifies the platform against no projected anchor")
	case transport.TLSClientConfig.GetClientCertificate == nil:
		t.Error("the outbound client presents no identity, so the platform cannot tell this workload from anything else that reached it")
	case transport.TLSClientConfig.MinVersion != tls.VersionTLS13:
		t.Errorf("the outbound client's floor is 0x%04x, want TLS 1.3", transport.TLSClientConfig.MinVersion)
	}
	if client.CheckRedirect == nil {
		t.Error("the outbound client follows redirects: net/http copies every header but three across hosts, so a Location would be handed this workload's credentials")
	}
	// A boot with no trust anchor cannot build one at all, which is the same
	// refusal the listener makes.
	server.cfg.trustBundleFile = ""
	if _, err := server.outboundClient(nil); err == nil {
		t.Error("an outbound client was built with no projected anchor to verify the platform against")
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
	s.cfg = loadConfig(context.Background())
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
