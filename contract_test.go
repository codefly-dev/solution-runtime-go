package solution

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/codefly-dev/core/solution/manifest"
)

// contractServer is a solution consuming one module, with the declaration and
// the contract a test varies.
func contractServer(t *testing.T, profile string, contract ModuleContract, modules ...ConsumedModule) *Server {
	t.Helper()
	if len(modules) == 0 {
		modules = []ConsumedModule{passthroughModule()}
	}
	server := New(Manifest{ID: testSolutionID}).Consumes(modules...).Contract(contract)
	server.cfg = config{profile: profile, apiConsumes: consumesThings}
	server.principal = testPrincipal
	return server
}

// TestAContractWithoutThisProfileIsRefusedByName is the profile gap, closed. A
// deployed environment reads its own profile — core v0.7.1 stopped it rendering
// under the local one (codefly-dev/core#687) — so a contract that declares only
// "local" is refused in a deployment rather than read as if the deployment were
// somebody's laptop.
func TestAContractWithoutThisProfileIsRefusedByName(t *testing.T) {
	server := contractServer(t, "staging", ModuleContract{Ceilings: map[string]map[string][]Scope{
		localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
	}})
	_, err := server.resolveContract()
	if err == nil {
		t.Fatal("a contract declaring only the local profile was accepted in staging")
	}
	for _, want := range []string{"staging", localProfile, ContractProfileEnvironmentVariable} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
}

// TestAnAskOutsideItsCeilingIsRefusedNamingTheScope: the ceiling is declared,
// so a declaration that asks for more is a boot failure rather than a ceiling
// that silently widened to fit it.
func TestAnAskOutsideItsCeilingIsRefusedNamingTheScope(t *testing.T) {
	module := passthroughModule()
	module.Methods[0].Scopes = []Scope{{ResourceKind: "things", Actions: []string{"delete"}}}
	server := contractServer(t, localProfile, ModuleContract{Ceilings: map[string]map[string][]Scope{
		localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
	}}, module)
	_, err := server.resolveContract()
	if err == nil {
		t.Fatal("a method asking for an action outside the ceiling was accepted")
	}
	for _, want := range []string{"delete", "things", localProfile} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
}

// TestACeilingNamingResourceIdsRefusesAnAskAcrossTheKind: "every thing" is not
// inside "these two things", and reading it as the narrower ask would mint
// authority the declaration never wrote.
func TestACeilingNamingResourceIdsRefusesAnAskAcrossTheKind(t *testing.T) {
	server := contractServer(t, localProfile, ModuleContract{Ceilings: map[string]map[string][]Scope{
		localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}, ResourceIDs: []string{"a", "b"}}}},
	}})
	_, err := server.resolveContract()
	if err == nil {
		t.Fatal("an ask across the whole resource kind was accepted under a ceiling naming two resources")
	}
	if !strings.Contains(err.Error(), "whole resource kind") {
		t.Errorf("refusal %q does not say the ask covers the whole resource kind", err)
	}
}

// TestAMissingCeilingAndASuperfluousOneAreBothRefused: every audience that
// mints authority needs a ceiling, and a ceiling for an audience nothing
// consumes is authority the renderer would grant for a call that cannot happen.
func TestAMissingCeilingAndASuperfluousOneAreBothRefused(t *testing.T) {
	t.Run("an audience with no ceiling", func(t *testing.T) {
		server := contractServer(t, localProfile, ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {"other": {{ResourceKind: "other", Actions: []string{"read"}}}},
		}})
		_, err := server.resolveContract()
		if err == nil || !strings.Contains(err.Error(), "things") {
			t.Fatalf("resolveContract = %v, want a refusal naming the audience with no ceiling", err)
		}
	})
	t.Run("a ceiling for an audience nothing consumes", func(t *testing.T) {
		server := contractServer(t, localProfile, ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {
				"things": {{ResourceKind: "things", Actions: []string{"read"}}},
				"ghost":  {{ResourceKind: "ghost", Actions: []string{"read"}}},
			},
		}})
		_, err := server.resolveContract()
		if err == nil || !strings.Contains(err.Error(), "ghost") {
			t.Fatalf("resolveContract = %v, want a refusal naming the audience nothing consumes", err)
		}
	})
}

// TestAViewerBearerModuleTakesNoCeiling: it mints nothing, so a ceiling
// declared for it governs nothing — and a reviewer who wrote one down believes
// it does.
func TestAViewerBearerModuleTakesNoCeiling(t *testing.T) {
	module := ConsumedModule{As: "things", ViewerBearer: true, Methods: []ConsumedMethod{{
		Name: "/things.v1.Things/Search", Response: MustFieldMask(thingMessage("Thing"), "entry_id"),
	}}}
	t.Run("a ceiling on it is refused", func(t *testing.T) {
		server := contractServer(t, localProfile, ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
		}}, module)
		_, err := server.resolveContract()
		if err == nil || !strings.Contains(err.Error(), "ViewerBearer") {
			t.Fatalf("resolveContract = %v, want a refusal naming the ViewerBearer declaration", err)
		}
	})
	t.Run("no profile is needed for it", func(t *testing.T) {
		server := contractServer(t, "staging", ModuleContract{}, module)
		contract, err := server.resolveContract()
		if err != nil {
			t.Fatalf("resolveContract = %v, want no refusal: a solution that mints nothing has no authority to cap", err)
		}
		if len(contract.Bindings) != 1 || len(contract.Bindings[0].Ceiling) != 0 {
			t.Errorf("published bindings = %+v, want the audience with no ceiling", contract.Bindings)
		}
	})
}

// TestACeilingIsASetNotAnOrderedList: the verdict used to depend on which
// entry of the matching kind came first, so reordering a ceiling changed
// whether a declaration booted. A reviewer who writes a ceiling does not also
// choose a traversal order.
func TestACeilingIsASetNotAnOrderedList(t *testing.T) {
	module := passthroughModule()
	module.Scopes = []Scope{{ResourceKind: "things", Actions: []string{"read"}, ResourceIDs: []string{"b"}}}
	entries := [][]Scope{
		{{ResourceKind: "things", Actions: []string{"read"}, ResourceIDs: []string{"a"}}, {ResourceKind: "things", Actions: []string{"read"}, ResourceIDs: []string{"b"}}},
		{{ResourceKind: "things", Actions: []string{"read"}, ResourceIDs: []string{"b"}}, {ResourceKind: "things", Actions: []string{"read"}, ResourceIDs: []string{"a"}}},
	}
	for i, ceiling := range entries {
		server := contractServer(t, localProfile, ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {"things": ceiling},
		}}, module)
		if _, err := server.resolveContract(); err != nil {
			t.Errorf("ceiling order %d refused an ask a later entry covers: %v", i, err)
		}
	}

	// And the refusal, when no single entry covers the ask, says so rather
	// than reporting whichever entry happened to be first.
	module.Scopes = []Scope{{ResourceKind: "things", Actions: []string{"read", "list"}}}
	server := contractServer(t, localProfile, ModuleContract{Ceilings: map[string]map[string][]Scope{
		localProfile: {"things": {
			{ResourceKind: "things", Actions: []string{"read"}},
			{ResourceKind: "things", Actions: []string{"list"}},
		}},
	}}, module)
	_, err := server.resolveContract()
	if err == nil {
		t.Fatal("two entries each covering half an ask were treated as covering it: that is authority nobody declared")
	}
	if !strings.Contains(err.Error(), "no single ceiling entry") {
		t.Errorf("refusal %q does not say that no single entry covers the ask", err)
	}
}

// TestTheArtifactRefusesWhatTheBootWouldRefuse: the artifact is the document
// authority is derived from, so a rule enforced on the running process and not
// on the published document governs the half nobody reads.
func TestTheArtifactRefusesWhatTheBootWouldRefuse(t *testing.T) {
	module := passthroughModule()
	for _, tc := range []struct {
		name     string
		ceilings map[string]map[string][]Scope
		says     string
	}{
		{
			name:     "a surplus audience",
			ceilings: map[string]map[string][]Scope{localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}, "ghost": {{ResourceKind: "ghost", Actions: []string{"read"}}}}},
			says:     "ghost",
		},
		{
			name:     "an audience with no ceiling",
			ceilings: map[string]map[string][]Scope{localProfile: {"ghost": {{ResourceKind: "ghost", Actions: []string{"read"}}}}},
			says:     "things",
		},
		{
			name:     "an ask outside its ceiling",
			ceilings: map[string]map[string][]Scope{localProfile: {"things": {{ResourceKind: "things", Actions: []string{"list"}}}}},
			says:     "outside the ceiling",
		},
		{
			name: "a profile that is fine beside one that is not",
			ceilings: map[string]map[string][]Scope{
				localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
				"staging":    {"things": {{ResourceKind: "things", Actions: []string{"list"}}}},
			},
			says: "staging",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := ContractArtifact(testSolutionID, ModuleContract{Ceilings: tc.ceilings}, module)
			if err == nil {
				t.Fatal("the artifact published a contract the boot would refuse")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("refusal %q does not name %q", err, tc.says)
			}
		})
	}
}

// TestTheContractArtifactCarriesEveryProfileAndNoPrincipal: the build-time
// document carries the binding set and the per-profile ceilings, and no
// principal — that is a value only the deployment knows.
//
// It was called "…IsWhatTheRendererReads" until cli#855 answered that the
// renderer reads RendererContractFile instead, in a different shape. The name
// was the only thing asserting that, and a test name is where a refuted claim
// survives longest: nothing here ever exercised a renderer, so nothing failed
// when it stopped being true.
func TestTheContractArtifactCarriesEveryProfileAndNoPrincipal(t *testing.T) {
	raw, err := ContractArtifact(testSolutionID, ModuleContract{Ceilings: map[string]map[string][]Scope{
		localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
		"staging":    {"things": {{ResourceKind: "things", Actions: []string{"read", "list"}}}},
	}}, passthroughModule())
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Schema   string                        `json:"schema"`
		Solution string                        `json:"solution"`
		Bindings []artifactBinding             `json:"bindings"`
		Profiles map[string]map[string][]Scope `json:"profiles"`
	}
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	if document.Schema != ContractSchema || document.Solution != testSolutionID {
		t.Errorf("artifact names %q/%q, want %q/%q", document.Schema, document.Solution, ContractSchema, testSolutionID)
	}
	if len(document.Bindings) != 1 || document.Bindings[0].Audience != "things" {
		t.Errorf("artifact bindings = %+v, want the one audience the declaration consumes", document.Bindings)
	}
	if _, ok := document.Profiles["staging"]; !ok {
		t.Error("artifact has no staging profile: a deployed process would have none to resolve its ceiling from")
	}
	if strings.Contains(string(raw), testPrincipal) {
		t.Error("the artifact carries a principal: that is a value only the deployment knows")
	}

	if _, err := ContractArtifact(testSolutionID, ModuleContract{}, passthroughModule()); err == nil {
		t.Error("a contract declaring no profile at all was rendered for a solution that mints authority")
	}
	if _, err := ContractArtifact("", ModuleContract{}); err == nil {
		t.Error("an artifact naming no solution was rendered")
	}
}

// TestAnUnusableProfileNameIsRefused: a profile name selects a directory on
// disk wherever one is read, so Core's own rule applies here too.
func TestAnUnusableProfileNameIsRefused(t *testing.T) {
	if _, err := ContractArtifact(testSolutionID, ModuleContract{Ceilings: map[string]map[string][]Scope{
		"../local": {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
	}}, passthroughModule()); err == nil {
		t.Error("a traversing profile name was rendered")
	}
	cfg := config{
		port: "8080", gatewayURL: "https://gateway:42152", mintURL: "https://gateway:42152" + credentialMintPath,
		identityCertFile: "c", identityKeyFile: "k", projectedTokenPath: "t", trustBundleFile: "b", profile: "../local",
	}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), ContractProfileEnvironmentVariable) {
		t.Errorf("validate = %v, want a refusal naming %s", err, ContractProfileEnvironmentVariable)
	}
}

var _ = manifest.APIConsumesEnvironmentVariable

// TestThisRuntimesContractDoesNotClaimTheRenderersSchema pins a cross-repo fact
// that is invisible from inside this package.
//
// The renderer reads one file — RendererContractFile, YAML, strict-decoded, at
// the module directory the composition resolved — under
// RendererContractSchema, in a shape carrying `{from: <group>/<key>}` slots a
// composition resolves per environment (codefly-dev/cli#855). This runtime
// publishes a different document, in JSON, keyed by profile, answering what a
// process holds itself to.
//
// Both surfaces of this package once claimed the renderer's schema string for
// that different shape, which is strictly worse than a mismatch: strict
// decoding refuses the unknown fields, and because the string matched, the
// renderer reports a *malformed* module-contract rather than a document meant
// for someone else — a version skew that is not one, pointing at the wrong
// owner. Two shapes under one schema string is the one case a reader branching
// on that string cannot survive.
//
// So this test fails if the strings ever converge again, whichever side moves.
func TestThisRuntimesContractDoesNotClaimTheRenderersSchema(t *testing.T) {
	if ContractSchema == RendererContractSchema {
		t.Fatalf("this runtime publishes %q, the schema string the renderer's own document uses: the renderer strict-decodes %s and would report these bytes as a malformed module contract rather than another document",
			ContractSchema, RendererContractFile)
	}

	// And it is claimed on both surfaces, so neither can drift back on its own:
	// the build-time artifact...
	raw, err := ContractArtifact(testSolutionID, ModuleContract{Ceilings: map[string]map[string][]Scope{
		localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
	}}, ConsumedModule{As: "things", Scopes: []Scope{{ResourceKind: "things", Actions: []string{"read"}}}})
	if err != nil {
		t.Fatal(err)
	}
	var artifact struct{ Schema string }
	if err := json.Unmarshal(raw, &artifact); err != nil {
		t.Fatal(err)
	}
	if artifact.Schema != ContractSchema {
		t.Errorf("the build-time artifact names schema %q, want %q", artifact.Schema, ContractSchema)
	}

	// ...and the document a running process answers with.
	server := New(Manifest{ID: testSolutionID}).Consumes(ConsumedModule{
		As: "things", Scopes: []Scope{{ResourceKind: "things", Actions: []string{"read"}}},
	}).Contract(ModuleContract{Ceilings: map[string]map[string][]Scope{
		localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
	}})
	server.cfg.profile = localProfile
	effective, err := server.resolveContract()
	if err != nil {
		t.Fatal(err)
	}
	if effective.Schema != ContractSchema {
		t.Errorf("the served contract names schema %q, want %q", effective.Schema, ContractSchema)
	}
}

// TestABootedRuntimeHoldsForModuleToThePublishedCeiling is the authority bypass
// a second reviewer found, and it defeats the point of publishing a ceiling at
// all.
//
// checkContract governs the Consumes *declaration*. ForModule is public, takes
// any audience and any scopes, and went straight to the mint — so the document
// saying "the most authority this solution may ever ask for" was a statement
// about a declaration the handlers did not have to use. Worse at the other end:
// a solution whose handlers only call ForModule consumes nothing, so
// mintsAuthority was false, so it needed no profile and published an empty
// contract while minting whatever it liked.
//
// This boots a real runtime with a declared ceiling and drives all three cases
// through its handler, counting what the host was asked — a refusal that still
// minted would be no refusal.
func TestABootedRuntimeHoldsForModuleToThePublishedCeiling(t *testing.T) {
	type ask struct {
		audience string
		scope    Scope
	}
	for _, tc := range []struct {
		name     string
		ask      ask
		wantMint bool
		says     string
	}{
		{
			"inside the ceiling", ask{"things", Scope{ResourceKind: "things", Actions: []string{"read"}}},
			true, "",
		},
		{
			"an action the ceiling does not allow", ask{"things", Scope{ResourceKind: "things", Actions: []string{"delete"}}},
			false, "outside the ceiling its contract publishes",
		},
		{
			"an audience the contract names no binding for", ask{"ghost", Scope{ResourceKind: "things", Actions: []string{"read"}}},
			false, "names no binding for that audience",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(manifest.APIConsumesEnvironmentVariable, consumesThings)
			mint := newHostMint(t, &hostMint{})
			var mintErr error
			solution := boot(t, New(Manifest{ID: testSolutionID}).
				Consumes(passthroughModule()).
				Contract(ModuleContract{Ceilings: map[string]map[string][]Scope{
					localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
				}}).
				Handle("/thing", func(ctx context.Context, gw *Gateway) (any, error) {
					_, mintErr = gw.ForModule(ctx, tc.ask.audience, tc.ask.scope)
					return map[string]string{"ok": "yes"}, nil
				}), mint)

			request, err := http.NewRequest(http.MethodGet, solution.base+"/thing", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("authorization", "Bearer viewer")
			request.Header.Set(orgHeader, "org-1")
			request.Header.Set(sessionHeader, "session-1")
			resp, err := solution.client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()

			// The mint the boot itself ran is request-independent; what matters
			// is whether the viewer's mint was attempted on top of it.
			viewerMints := len(mint.observedStartTasks())
			switch {
			case tc.wantMint && mintErr != nil:
				t.Fatalf("an ask inside the published ceiling was refused: %v", mintErr)
			case tc.wantMint && viewerMints != 1:
				t.Errorf("an ask inside the ceiling produced %d viewer mints, want 1", viewerMints)
			case !tc.wantMint:
				if mintErr == nil {
					t.Fatalf("ForModule minted %s for %q, which the published contract does not allow",
						scopeText([]Scope{tc.ask.scope}), tc.ask.audience)
				}
				if !strings.Contains(mintErr.Error(), tc.says) {
					t.Errorf("refusal %q does not say %q", mintErr, tc.says)
				}
				if viewerMints != 0 {
					t.Errorf("the host was asked for %d viewer mint(s) on an ask outside the contract, want 0: a refusal that still mints is not a refusal", viewerMints)
				}
				// The viewer sees their own 403-shaped answer, not this
				// solution's 502.
				var clientErr *ClientError
				if !errors.As(mintErr, &clientErr) || clientErr.StatusCode != http.StatusForbidden {
					t.Errorf("refusal carries %T, want a ClientError with 403 so the page is told the solution asked for too much", mintErr)
				}
			}
		})
	}
}

// TestTheCeilingRefusesAsksThatStateNoAuthority closes three ways past the
// ceiling that a third reviewer found: the check governed what was asked for
// and not whether anything was asked for.
//
//   - ForModule with no scopes, and a Scope naming a kind with no actions, both
//     satisfied every ceiling by construction, because the loop had nothing to
//     check. What accounts does with an empty authorityScopes is its decision,
//     and leaving it there is this runtime declining to govern the one thing
//     its contract claims to govern.
//   - a ViewerBearer audience carries a nil ceiling and still sat in the map,
//     so a declared lookup succeeded and ForModule minted real authority for
//     the one kind of module the contract publishes as minting none.
func TestTheCeilingRefusesAsksThatStateNoAuthority(t *testing.T) {
	t.Setenv(manifest.APIConsumesEnvironmentVariable, consumesThings)
	mint := newHostMint(t, &hostMint{})
	type ask struct {
		audience string
		scopes   []Scope
	}
	var attempted ask
	var mintErr error
	solution := boot(t, New(Manifest{ID: testSolutionID}).
		Consumes(passthroughModule()).
		Contract(ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
		}}).
		Handle("/thing", func(ctx context.Context, gw *Gateway) (any, error) {
			_, mintErr = gw.ForModule(ctx, attempted.audience, attempted.scopes...)
			return map[string]string{"ok": "yes"}, nil
		}), mint)

	for _, tc := range []struct {
		name string
		ask  ask
		says string
	}{
		{"no scopes at all", ask{"things", nil}, "no scopes at all"},
		{"a scope with no actions", ask{"things", []Scope{{ResourceKind: "things"}}}, "no actions"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			attempted, mintErr = tc.ask, nil
			before := len(mint.observedStartTasks())

			request, err := http.NewRequest(http.MethodGet, solution.base+"/thing", nil)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("authorization", "Bearer viewer")
			request.Header.Set(orgHeader, "org-1")
			request.Header.Set(sessionHeader, "session-1")
			resp, err := solution.client.Do(request)
			if err != nil {
				t.Fatal(err)
			}
			_ = resp.Body.Close()

			if mintErr == nil {
				t.Fatalf("ForModule(%q, %+v) minted: an ask the published ceiling cannot govern must be refused locally", tc.ask.audience, tc.ask.scopes)
			}
			if !strings.Contains(mintErr.Error(), tc.says) {
				t.Errorf("refusal %q does not say %q", mintErr, tc.says)
			}
			if got := len(mint.observedStartTasks()) - before; got != 0 {
				t.Errorf("the host was asked for %d viewer mint(s), want 0", got)
			}
			var clientErr *ClientError
			if !errors.As(mintErr, &clientErr) || clientErr.StatusCode != http.StatusForbidden {
				t.Errorf("refusal carries %T, want a ClientError with 403", mintErr)
			}
		})
	}
}

// TestAViewerBearerAudienceCannotBeMintedFor is the third way past the ceiling,
// tested where the shape is reachable: a ViewerBearer binding carries a nil
// ceiling and still sat in the map a gateway is given, so the `declared` lookup
// succeeded and ForModule minted real authority for the one kind of module the
// published contract says mints none.
//
// Driven through resolveContract and gatewayFor rather than a boot, because the
// passthrough validator has its own requirements for a declared module's
// methods and they are not what is under test here.
func TestAViewerBearerAudienceCannotBeMintedFor(t *testing.T) {
	gw := newModuleGateway(t, http.StatusOK, `{"entry_id":"e1"}`)
	server := New(Manifest{ID: testSolutionID}).
		Consumes(passthroughModule(), ConsumedModule{As: "pages", ViewerBearer: true}).
		Contract(ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
		}})
	server.cfg.profile = localProfile
	server.cfg.gatewayURL = gw.URL
	contract, err := server.resolveContract()
	if err != nil {
		t.Fatalf("resolveContract: %v", err)
	}
	server.contract = contract
	// Said explicitly, because the ceiling is governing only for a contract a
	// boot resolved. It used to be inferred from the contract carrying a
	// solution id, which is why an empty Manifest.ID switched the ceiling off.
	server.contractResolved = true
	// The binding is published, with the flag and no ceiling.
	var published bool
	for _, binding := range contract.Bindings {
		if binding.Audience == "pages" {
			published = true
			if len(binding.Ceiling) != 0 {
				t.Errorf("the ViewerBearer binding publishes a ceiling of %+v, want none", binding.Ceiling)
			}
		}
	}
	if !published {
		t.Fatal("the ViewerBearer module is not in the published contract at all")
	}

	header := http.Header{}
	header.Set("authorization", "Bearer viewer")
	header.Set(orgHeader, "org-1")
	header.Set(sessionHeader, "session-1")
	_, err = server.gatewayFor(header).ForModule(context.Background(), "pages",
		Scope{ResourceKind: "pages", Actions: []string{"read"}})
	if err == nil {
		t.Fatal("ForModule minted authority for a module the contract publishes as minting none")
	}
	if !strings.Contains(err.Error(), "no ceiling at all") {
		t.Errorf("refusal %q does not say the module has no ceiling", err)
	}
	if got := len(gw.observedMints()); got != 0 {
		t.Errorf("observed %d mints for a ViewerBearer audience, want 0", got)
	}
}
