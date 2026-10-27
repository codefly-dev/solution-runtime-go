package solution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/codefly-dev/core/solutionhost"
	"gopkg.in/yaml.v3"
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

// frontendYAML is a declared frontend file (FrontendFileName) with extra YAML
// — a dashboard, surfaces — under the required fields.
func frontendYAML(extra string) []byte {
	return []byte("title: Notes\norder: 3\nexposed_module: ./Page\nhost_contract: 1\n" + extra)
}

// declaredFrontend is the fixture above as a boot decodes it.
func declaredFrontend(t *testing.T, extra string) frontendDeclaration {
	t.Helper()
	frontend, err := parseFrontend(frontendYAML(extra))
	if err != nil {
		t.Fatalf("parse the declared frontend: %v", err)
	}
	return frontend
}

// footnoteSurface is the surface shape the notes solution declares for a Word
// document: the whole set of slots a client reads, so a test can assert on all
// of them.
const footnoteSurface = `surfaces:
  - id: footnote
    client: word
    title: Footnote
    description: Cite a claim from the notes solution.
    module: /surfaces/word/footnote.js
    contract: 1
    applies: always
    events: [documents.entry]
`

// The served manifest must carry a declared dashboard data-graph verbatim
// through JSON, so the host receives exactly what the solution declared.
func TestServedManifestCarriesDashboardVerbatim(t *testing.T) {
	graph := sampleDataGraph()
	declared, err := yaml.Marshal(map[string]any{"dashboard": graph})
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{manifest: Manifest{ID: testSolutionID}, frontend: declaredFrontend(t, string(declared))}

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
	s := &Server{manifest: Manifest{ID: testSolutionID}, frontend: declaredFrontend(t, "")}
	if _, ok := s.manifestMap()["dashboard"]; ok {
		t.Errorf("emitted a dashboard key with no dashboard declared")
	}
}

// A client discovers what a solution offers it from the served manifest alone,
// so every declared slot must survive the trip through JSON.
func TestServedManifestCarriesDeclaredSurfaces(t *testing.T) {
	s := &Server{manifest: Manifest{ID: "notes"}, frontend: declaredFrontend(t, footnoteSurface)}

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
		"events":      []any{"documents.entry"},
	}}
	if !reflect.DeepEqual(got["surfaces"], want) {
		t.Errorf("served surfaces = %#v, want %#v", got["surfaces"], want)
	}
}

// A tagged selector is a structure, not a keyword, and the runtime must hand it
// to the client exactly as declared rather than flattening it.
func TestServedSurfaceCarriesTaggedAppliesVerbatim(t *testing.T) {
	declared := strings.Replace(footnoteSurface, "applies: always", "applies: {tagged: [legal, finance]}", 1)
	s := &Server{manifest: Manifest{ID: "notes"}, frontend: declaredFrontend(t, declared)}

	var got map[string]any
	body, _ := json.Marshal(s.manifestMap())
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("unmarshal manifest: %v", err)
	}
	entry := got["surfaces"].([]any)[0].(map[string]any)
	if want := map[string]any{"tagged": []any{"legal", "finance"}}; !reflect.DeepEqual(entry["applies"], want) {
		t.Errorf("served applies = %#v, want %#v", entry["applies"], want)
	}
}

// A solution that offers nothing inside a client must not gain the key at all,
// and a surface's optional slots say what they mean by being absent: nothing
// to show and nothing to reconcile on are different from a null the client
// still has to interpret. The selector is not optional — core carries no
// default — so the minimal surface spells it.
func TestManifestOmitsAbsentSurfacesAndTheirEmptySlots(t *testing.T) {
	bare := &Server{manifest: Manifest{ID: testSolutionID}, frontend: declaredFrontend(t, "")}
	if _, ok := bare.manifestMap()["surfaces"]; ok {
		t.Errorf("emitted a surfaces key with no surface declared")
	}
	minimal := "surfaces:\n  - id: footnote\n    client: word\n    title: Footnote\n    module: /surfaces/word/footnote.js\n    contract: 1\n    applies: always\n"
	s := &Server{manifest: Manifest{ID: "notes"}, frontend: declaredFrontend(t, minimal)}
	entry := s.manifestMap()["surfaces"].([]any)[0].(map[string]any)
	if got := entry["applies"]; got != "always" {
		t.Errorf("applies = %#v, want %q as declared", got, "always")
	}
	if _, ok := entry["description"]; ok {
		t.Errorf("emitted a description key with no description declared")
	}
	if _, ok := entry["events"]; ok {
		t.Errorf("emitted an events key with no namespaces declared")
	}
}

// wordFootnote is the declared surface as the file decodes it.
func wordFootnote() frontendSurface {
	return frontendSurface{
		ID:          "footnote",
		Client:      "word",
		Title:       "Footnote",
		Description: "Cite a claim from the notes solution.",
		Module:      "/surfaces/word/footnote.js",
		Contract:    1,
		Applies:     "always",
		Events:      []string{"documents.entry"},
	}
}

// A surface no client could load must fail the boot, not register quietly and
// show up as a solution that simply never appears in the add-in.
func TestSurfaceValidationRejectsUnusableDeclarations(t *testing.T) {
	with := func(edit func(*frontendSurface)) []frontendSurface {
		s := wordFootnote()
		edit(&s)
		return []frontendSurface{s}
	}
	cases := []struct {
		name     string
		surfaces []frontendSurface
		want     string
	}{
		{"no id", with(func(s *frontendSurface) { s.ID = "" }), "no id"},
		{"id with uppercase", with(func(s *frontendSurface) { s.ID = "Footnote" }), "id must be"},
		{"id with a slash", with(func(s *frontendSurface) { s.ID = "word/footnote" }), "id must be"},
		{"id with a leading dash", with(func(s *frontendSurface) { s.ID = "-footnote" }), "id must be"},
		{"id with a trailing dash", with(func(s *frontendSurface) { s.ID = "footnote-" }), "id must be"},
		{"id of one dash", with(func(s *frontendSurface) { s.ID = "-" }), "id must be"},
		{"duplicate id in one client", []frontendSurface{wordFootnote(), wordFootnote()}, "declared twice"},
		{"no title", with(func(s *frontendSurface) { s.Title = "" }), "no title"},
		{"invalid client", with(func(s *frontendSurface) { s.Client = "bad/client" }), "client"},
		{"no client", with(func(s *frontendSurface) { s.Client = "" }), "unknown client kind"},
		{"undeclared contract", with(func(s *frontendSurface) { s.Contract = 0 }), "contract"},
		// The selector is declared, in one of the two shapes the host client
		// reads; core signs no default and refuses every other shape.
		{"no applies", with(func(s *frontendSurface) { s.Applies = nil }), "no applies"},
		{"an applies keyword that is not always", with(func(s *frontendSurface) { s.Applies = "sometimes" }), "applies"},
		{"a tagged selector naming no tag", with(func(s *frontendSurface) { s.Applies = map[string]any{"tagged": []any{}} }), "one or more tags"},
		{"a tagged selector with an empty tag", with(func(s *frontendSurface) { s.Applies = map[string]any{"tagged": []any{""}} }), "empty tag"},
		{"a selector mapping with another key", with(func(s *frontendSurface) { s.Applies = map[string]any{"tagged": []any{"legal"}, "also": true} }), "one key tagged"},
		{"a selector of another type", with(func(s *frontendSurface) { s.Applies = 7 }), "applies"},
		// Events are journal namespaces as core signs them.
		{"an event with a wildcard", with(func(s *frontendSurface) { s.Events = []string{"documents.entry.*"} }), "journal namespace"},
		{"an event with uppercase", with(func(s *frontendSurface) { s.Events = []string{"Documents.entry"} }), "journal namespace"},
		{"an event named twice", with(func(s *frontendSurface) { s.Events = []string{"documents.entry", "documents.entry"} }), "named twice"},
		{"absolute module URL", with(func(s *frontendSurface) { s.Module = "https://evil.example/footnote.js" }), "own origin"},
		{"protocol-relative module", with(func(s *frontendSurface) { s.Module = "//evil.example/footnote.js" }), "own origin"},
		// A browser reads the backslash beside the leading slash as a slash and
		// what follows as a host, so each of these loads third-party code even
		// though net/url reports no host in any of them.
		{"backslash authority module", with(func(s *frontendSurface) { s.Module = `/\evil.example/footnote.js` }), "own origin"},
		{"backslash-slash authority module", with(func(s *frontendSurface) { s.Module = `/\/evil.example/footnote.js` }), "own origin"},
		{"tab-smuggled authority module", with(func(s *frontendSurface) { s.Module = "/\t/evil.example/footnote.js" }), "own origin"},
		{"newline-smuggled authority module", with(func(s *frontendSurface) { s.Module = "/\n//evil.example/footnote.js" }), "own origin"},
		{"relative module", with(func(s *frontendSurface) { s.Module = "surfaces/footnote.js" }), "own origin"},
		{"no module", with(func(s *frontendSurface) { s.Module = "" }), "own origin"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSurfaces(tc.surfaces)
			if err == nil {
				t.Fatalf("validateSurfaces accepted %s", tc.name)
			}
			if !errors.Is(err, solutionhost.ErrInvalid) {
				t.Errorf("invalid surface did not retain Core's refusal: %v", err)
			}
		})
	}
}

// The same offering in two clients carries the same id — the notes solution's
// footnote is "footnote" in Word and in PowerPoint — and neither client can see
// the other's, so that is not a collision. Only two surfaces of one client are
// ambiguous.
func TestSurfaceIDsAreUniquePerClientNotPerSolution(t *testing.T) {
	powerpoint := wordFootnote()
	powerpoint.Client = "powerpoint"
	powerpoint.Module = "/surfaces/powerpoint/footnote.js"
	if err := validateSurfaces([]frontendSurface{wordFootnote(), powerpoint}); err != nil {
		t.Errorf("validateSurfaces refused one id shared across two clients: %v", err)
	}

	second := wordFootnote()
	second.Title = "Footnote, again"
	second.Module = "/surfaces/word/footnote-2.js"
	err := validateSurfaces([]frontendSurface{wordFootnote(), second})
	if err == nil {
		t.Fatal("validateSurfaces accepted two surfaces sharing an id within one client")
	}
	if !strings.Contains(err.Error(), "declared twice") {
		t.Errorf("error %q does not say the id was declared twice", err)
	}
}

// Serve must refuse a declaration whose surface no client could load, and name
// the surface — the mistake is in the author's file, and it is the same
// mistake in every environment, so it must not wait on the environment
// resolving first.
func TestServeRejectsUnusableSurface(t *testing.T) {
	declared := frontendYAML(strings.Replace(footnoteSurface, "/surfaces/word/footnote.js", `"/\\evil.example/footnote.js"`, 1))
	s := New(Manifest{ID: "notes", Frontend: declared})
	err := s.Serve()
	if err == nil {
		t.Fatal("Serve returned nil for an off-origin surface module; expected a boot error and no bind")
	}
	if !strings.Contains(err.Error(), "footnote") {
		t.Errorf("boot error should name the surface, got: %v", err)
	}
}

// TestTheDeclaredFrontendIsStrictAndNamed: the file is the one source of what
// the host lists a solution under, and the author writes it by hand, so every
// way of getting it wrong is refused at boot naming the file — and a file the
// CLI would read differently (an unknown key, a second document) is refused
// rather than read as whatever this runtime makes of it.
func TestTheDeclaredFrontendIsStrictAndNamed(t *testing.T) {
	complete := "title: Notes\norder: 3\nexposed_module: ./Page\nhost_contract: 1\n"
	for _, tc := range []struct{ name, file, want string }{
		{"no file", "", FrontendFileName},
		{"whitespace only", "\n  \n", FrontendFileName},
		{"an unknown key", complete + "nav_order: 3\n", "nav_order"},
		{"no title", strings.Replace(complete, "title: Notes\n", "", 1), "frontend.title"},
		{"an empty title", strings.Replace(complete, "title: Notes\n", "title: ''\n", 1), "title"},
		{"a title of two lines", strings.Replace(complete, "title: Notes\n", "title: \"Notes\\nmore\"\n", 1), "title"},
		{"no order", strings.Replace(complete, "order: 3\n", "", 1), "frontend.order"},
		{"no exposed module", strings.Replace(complete, "exposed_module: ./Page\n", "", 1), "frontend.exposed_module"},
		{"no host contract", strings.Replace(complete, "host_contract: 1\n", "", 1), "frontend.host_contract"},
		{"a host contract of zero", strings.Replace(complete, "host_contract: 1\n", "host_contract: 0\n", 1), "host_contract"},
		{"a negative host contract", strings.Replace(complete, "host_contract: 1\n", "host_contract: -1\n", 1), "host_contract"},
		{"a dashboard with a non-string key", complete + "dashboard:\n  1: widget\n", "dashboard"},
		{"a dashboard that is not a mapping", complete + "dashboard: [1, 2]\n", "dashboard"},
		{"a dashboard carrying a fraction", complete + "dashboard:\n  ratio: 0.5\n", "dashboard"},
		{"a dashboard over the bound", complete + "dashboard:\n  pad: " + strings.Repeat("a", frontendDashboardMaxBytes) + "\n", "dashboard"},
		{"a surface with no contract", complete + strings.Replace(footnoteSurface, "    contract: 1\n", "", 1), "contract"},
		{"two documents", complete + "---\ntitle: Other\n", "more than one"},
		{"not a mapping", "- title: Notes\n", "frontend declaration"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseFrontend([]byte(tc.file))
			if err == nil {
				t.Fatalf("a frontend file with %s was accepted", tc.name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("the refusal %q does not say %q", err, tc.want)
			}
			if !strings.Contains(err.Error(), FrontendFileName) {
				t.Errorf("the refusal %q does not name the file the author has to fix", err)
			}
		})
	}
	t.Run("a complete declaration decodes as written", func(t *testing.T) {
		frontend, err := parseFrontend([]byte("title: Notes\norder: 0\nexposed_module: ./Entry\nhost_contract: 2\n"))
		if err != nil {
			t.Fatal(err)
		}
		if frontend.Title != "Notes" || frontend.Order != 0 || frontend.HostContract != 2 || frontend.ExposedModule != "./Entry" {
			t.Errorf("decoded %+v, want the declared title, order, exposed module and host contract", frontend)
		}
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestManifestURLIsNeverAnAbsoluteOrigin pins where the served manifestUrl
// points. It used to be absolute: on PUBLIC_URL when one was set, and otherwise
// on "http://localhost:<port>", this process's own loopback address — so every
// deployed solution published a manifest no browser could load. It is now the
// path on this backend and nothing else, which the host resolves against the
// route its presence document names.
func TestManifestURLIsNeverAnAbsoluteOrigin(t *testing.T) {
	t.Setenv("PUBLIC_URL", "https://solutions.example.com/widgets")
	t.Setenv("PORT", "8080")
	s := New(Manifest{ID: testSolutionID})
	s.cfg = loadConfig(context.Background(), nil)
	frontend, _ := s.manifestMap()["frontend"].(map[string]any)
	if got := frontend["manifestUrl"]; got != federationManifestPath {
		t.Errorf("manifestUrl = %v, want %q: no environment variable may make it absolute again", got, federationManifestPath)
	}
}

// TestTheEnvironmentLoadErrorReachesTheRefusals: when loading Codefly's
// injected carriers fails, every SDK-resolved value is empty for that reason,
// and the refusal has to say so rather than send an operator to inspect
// provisioning that may well be in place.
func TestTheEnvironmentLoadErrorReachesTheRefusals(t *testing.T) {
	loadErr := errors.New("the injected carriers could not be read")
	if cfg := loadConfig(context.Background(), loadErr); cfg.environmentLoadErr == nil {
		t.Fatal("loadConfig dropped the environment-load error, so every refusal below reads as absent provisioning")
	}
	cfg := config{port: "8080", profile: localProfile, projectedTokenPath: "t", environmentLoadErr: loadErr}
	err := cfg.validate()
	if err == nil {
		t.Fatal("a configuration naming no authority was accepted")
	}
	if !strings.Contains(err.Error(), "injected environment failed first") {
		t.Errorf("the refusal %q does not say the environment never loaded", err)
	}
}

// TestAConfigurationIsRefusedForWhatItLacks: the authority and the projected
// credential the authority takes as actor are each required, and each refusal
// names what fixes it.
func TestAConfigurationIsRefusedForWhatItLacks(t *testing.T) {
	complete := config{port: "8080", profile: localProfile, authorityEndpoint: "127.0.0.1:1", projectedTokenPath: "t"}
	if err := complete.validate(); err != nil {
		t.Fatalf("a complete configuration was refused: %v", err)
	}
	for name, c := range map[string]struct {
		edit func(*config)
		want string
	}{
		"no authority":            {func(c *config) { c.authorityEndpoint = "" }, AuthorityInterfaceGroup + "/" + AuthorityEndpointKey},
		"no projected credential": {func(c *config) { c.projectedTokenPath = "" }, ProjectedTokenFileEnvironmentVariable},
		"no port":                 {func(c *config) { c.port = "" }, "PORT"},
	} {
		cfg := complete
		c.edit(&cfg)
		if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a refusal naming %s", name, err, c.want)
		}
	}
}

// The surface assertions exercise the production file reader rather than a
// second surface validator kept by this runtime.
func validateSurfaces(surfaces []frontendSurface) error {
	raw, err := yaml.Marshal(frontendDeclaration{Title: "Example", Order: 0, ExposedModule: "./Page", HostContract: 1, Surfaces: surfaces})
	if err != nil {
		return err
	}
	_, err = parseFrontend(raw)
	return err
}

func TestFrontendReaderRetainsCoreLimitsAndExtensibleClientKinds(t *testing.T) {
	surface := wordFootnote()
	surface.Client = "new-client"
	if err := validateSurfaces([]frontendSurface{surface}); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{
		"title: " + strings.Repeat("x", solutionhost.FrontendTextMaxBytes+1) + "\norder: 0\nexposed_module: ./Page\nhost_contract: 1\n",
		string(frontendYAML(strings.Replace(footnoteSurface, "contract: 1", "contract: -1", 1))),
	} {
		if _, err := parseFrontend([]byte(extra)); !errors.Is(err, solutionhost.ErrInvalid) {
			t.Fatalf("invalid file was not refused by Core: %v", err)
		}
	}
}
