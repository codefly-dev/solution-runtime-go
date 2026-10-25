package solution

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// contractServer is a solution consuming one module, with the declaration and
// the contract a test varies.
func contractServer(t *testing.T, profile string, contract ModuleContract, modules ...ConsumedModule) *Server {
	t.Helper()
	if len(modules) == 0 {
		modules = []ConsumedModule{passthroughModule()}
	}
	server := New(Manifest{ID: testSolutionID}).Consumes(modules...).Contract(contract)
	server.cfg = config{profile: profile}
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
	if strings.Contains(string(raw), "principal") {
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
	cfg := config{port: "8080", authorityEndpoint: "127.0.0.1:1", projectedTokenPath: "t", profile: "../local"}
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), ContractProfileEnvironmentVariable) {
		t.Errorf("validate = %v, want a refusal naming %s", err, ContractProfileEnvironmentVariable)
	}
}

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

// TestAnEmptyManifestIdIsRefused: the id is what the presence document names
// this solution by, the audience the authority addresses its Work Contexts to,
// what the published contract reports and what every refusal here identifies
// this process as.
func TestAnEmptyManifestIdIsRefused(t *testing.T) {
	err := Manifest{ID: ""}.validateID()
	if err == nil {
		t.Fatal("a manifest with no id was accepted")
	}
	if !strings.Contains(err.Error(), "Manifest.ID") {
		t.Errorf("the refusal %q does not name the field that fixes it", err)
	}
	if err := (Manifest{ID: "   "}).validateID(); err == nil {
		t.Error("a manifest whose id is whitespace was accepted")
	}
}

// TestTheDeclaredCeilingIsFrozenAtDeclaration: Contract() stored the caller's
// maps and backing arrays, so a caller writing through its own slice after
// boot changed the contract this process publishes. Both operands of the
// ceiling comparison are frozen at declaration.
func TestTheDeclaredCeilingIsFrozenAtDeclaration(t *testing.T) {
	ceilingActions := []string{"read"}
	askedActions := []string{"read"}
	module := passthroughModule()
	module.Methods = nil
	module.Scopes = []Scope{{ResourceKind: "things", Actions: askedActions}}

	server := New(Manifest{ID: testSolutionID}).Consumes(module).
		Contract(ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {"things": {{ResourceKind: "things", Actions: ceilingActions}}},
		}})
	server.cfg = config{profile: localProfile}
	contract, err := server.resolveContract()
	if err != nil {
		t.Fatalf("resolve the published contract: %v", err)
	}
	server.contract = contract

	ceilingActions[0] = "delete"
	askedActions[0] = "delete"

	published, err := json.Marshal(server.contract)
	if err != nil {
		t.Fatalf("render the published contract: %v", err)
	}
	if strings.Contains(string(published), "delete") {
		t.Errorf("the published contract names an action the declaration never contained: %s", published)
	}
	if again, err := server.resolveContract(); err != nil || strings.Contains(fmt.Sprint(again), "delete") {
		t.Errorf("a contract resolved after the caller's edit names %v (%v): the declaration was not frozen", again, err)
	}
}
