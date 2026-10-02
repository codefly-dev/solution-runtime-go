package solution

import (
	"encoding/json"
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

// TestTheContractArtifactIsWhatTheRendererReads: the build-time document
// carries the binding set and the per-profile ceilings, and no principal — that
// is a value only the deployment knows.
func TestTheContractArtifactIsWhatTheRendererReads(t *testing.T) {
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
		t.Error("artifact has no staging profile: a deployed render would have none to read")
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
