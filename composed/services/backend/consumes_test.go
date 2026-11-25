package main

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"gopkg.in/yaml.v3"
)

// solutionManifestPath is the solution's own manifest: api.consumes lives
// there, one directory above services/, where `codefly add solution` writes it
// and where the platform's gates read it.
const solutionManifestPath = "../../solution.codefly.yaml"

// serviceManifestPath is this service's manifest, beside this file.
const serviceManifestPath = "service.codefly.yaml"

// TestTheGeneratedConsumptionMatchesTheManifest is THE DRIFT CHECK, and the
// reason consumption is generated rather than written twice.
//
// consumed_gen.go is generated from api.consumes by `codefly sync`. It must
// name exactly what the manifest names: a module added to api.consumes reaches
// nothing until `codefly sync` has run, and that is invisible until the page
// calls it. This fails until it has run.
//
// It is the GENERATED file that is compared, not consumed() — see the two
// tests below for why those are different sets.
func TestTheGeneratedConsumptionMatchesTheManifest(t *testing.T) {
	generated := append([]string{}, consumedAsAll...)
	slices.Sort(generated)

	wanted := append([]string{}, manifestAliases(t)...)
	slices.Sort(wanted)

	if !slices.Equal(generated, wanted) {
		t.Fatalf("consumed_gen.go names %v; %s declares %v.\n"+
			"consumed_gen.go is generated from api.consumes: run `codefly sync` and commit it.",
			generated, solutionManifestPath, wanted)
	}
}

// TestThisBackendRelaysOnlyWhatTheManifestDeclares is the direction that must
// hold absolutely: a module this backend relays but the manifest does not
// declare has no delivered binding, so the runtime refuses the boot naming it.
//
// THE REVERSE IS NOT A FAILURE, and that is the point of having two tests.
// api.consumes names every module the solution reaches ANYWHERE — the page
// reaches modules at the authority's edge with their own clients, and those
// are never relayed through this backend. The reference solution declares six
// consumed modules and relays two. An entry this backend does not relay is
// also the state of every entry in a freshly scaffolded solution, until
// someone composes its methods in consumes.go.
func TestThisBackendRelaysOnlyWhatTheManifestDeclares(t *testing.T) {
	declared := map[string]bool{}
	for _, as := range consumedAsAll {
		declared[as] = true
	}
	for _, module := range consumed() {
		if !declared[module.As] {
			t.Errorf("this backend relays %q, which %s does not declare: the composition delivers no binding for it and the runtime refuses the boot naming it",
				module.As, solutionManifestPath)
		}
	}
}

// TestEveryRelayedModuleDeclaresAMethod: the runtime refuses a consumed module
// that declares no method, and that refusal stops the boot. consumed() leaves
// an uncomposed module out for exactly that reason, so this fails only if that
// filter is ever removed — here, in `go test`, rather than at a boot.
func TestEveryRelayedModuleDeclaresAMethod(t *testing.T) {
	for _, module := range consumed() {
		if len(module.Methods) == 0 {
			t.Errorf("%q is relayed but declares no method: the runtime refuses a consumed module with none and the boot fails", module.As)
		}
	}
}

// TestEveryConsumedModuleIsReachedThroughTheHop pins that every module call
// goes to the authority's hop at an address and a binding THE COMPOSITION
// supplies, never to an address this repository names. A declaration missing
// either slot is a boot that fails naming it, so this is the same refusal one
// step earlier.
func TestEveryConsumedModuleIsReachedThroughTheHop(t *testing.T) {
	for _, module := range consumed() {
		relay := module.Authority
		if relay.Group == "" || relay.EndpointKey == "" || relay.BindingKey == "" {
			t.Errorf("%q names no hop slots (group=%q endpoint=%q binding=%q): the composition says where a module is and which binding reaches it",
				module.As, relay.Group, relay.EndpointKey, relay.BindingKey)
		}
	}
}

// TestNoModuleEdgeIsDeclared is SP-SOL-04 in this solution's own words: a
// solution reaches every module through the authority's hop, which checks the
// call, and a `service-dependencies` edge on a module renders into a mesh
// allow rule straight to that module's service, PAST the check.
//
// The only edges this service may hold are the host's own door: the authority
// interface it requires by `interface:` alone, and `authority/hop`. The
// consumer repository's check-solution-mesh gate refuses anything else; this
// fails here first, in `go test`, where whoever added the edge is standing.
func TestNoModuleEdgeIsDeclared(t *testing.T) {
	var document struct {
		Dependencies []struct {
			Interface string `yaml:"interface"`
			Name      string `yaml:"name"`
			Module    string `yaml:"module"`
		} `yaml:"service-dependencies"`
	}
	content, err := os.ReadFile(serviceManifestPath)
	if err != nil {
		t.Fatalf("cannot read %s: %v", serviceManifestPath, err)
	}
	if err := yaml.Unmarshal(content, &document); err != nil {
		t.Fatalf("cannot read %s: %v", serviceManifestPath, err)
	}
	for _, dependency := range document.Dependencies {
		switch {
		case dependency.Module == "":
			// An interface requirement, or a dependency on this solution's own
			// service. Neither names a module service.
		case dependency.Module == "authority" && dependency.Name == "hop":
			// The authority's door: it lets through only a call the authority
			// checked.
		default:
			t.Errorf("%s declares a direct path to %s/%s. A solution reaches a module through the authority's hop, which checks the call; this edge renders into a mesh allow rule past it (SP-SOL-04). Declare the module under api.consumes instead.",
				serviceManifestPath, dependency.Module, dependency.Name)
		}
	}
}

// manifestAliases reads the `as` of every api.consumes entry. A missing
// manifest fails rather than reading as "consumes nothing": this service is a
// solution's entry service, and a solution without a manifest is not installed
// by anything.
func manifestAliases(t *testing.T) []string {
	t.Helper()
	content, err := os.ReadFile(filepath.FromSlash(solutionManifestPath))
	if err != nil {
		t.Fatalf("cannot read %s, which every reader of this solution reads: %v", solutionManifestPath, err)
	}
	var document struct {
		API struct {
			Consumes []struct {
				ID string `yaml:"id"`
				As string `yaml:"as"`
			} `yaml:"consumes"`
		} `yaml:"api"`
	}
	if err := yaml.Unmarshal(content, &document); err != nil {
		t.Fatalf("cannot read %s: %v", solutionManifestPath, err)
	}
	aliases := []string{}
	for _, consumed := range document.API.Consumes {
		alias := consumed.As
		if alias == "" {
			alias = consumed.ID
		}
		aliases = append(aliases, alias)
	}
	return aliases
}
