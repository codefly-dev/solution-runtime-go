package main

import (
	"strings"

	solution "github.com/codefly-dev/solution-runtime-go"
	"github.com/obin-ai/module-document-store/clients/go/gen/documents/v1/documentsv1connect"
)

// consumed is every module call this solution's page may make through this
// backend, and nothing else of any module is reachable from it. Each call is
// relayed by the runtime's passthrough to the authority's hop in front of the
// module, AS THE VIEWER — a child of the person's Work Context, issued through
// this solution's binding for that module (module.contract.codefly.yaml) — and
// the module authorizes it. This declaration only narrows what may be asked
// and what comes back.
//
// THE MODULES ARE NOT NAMED HERE. They come from consumedAsAll, which is
// generated from api.consumes in the solution's solution.codefly.yaml: that
// manifest is the one place this solution says what it may reach, and a second
// list here is a second declaration that drifts. What this file adds is the
// part no manifest can carry — the authority each call asks for, and the
// module methods it may call, which are constants of that module's generated
// Go client.
//
// A MODULE WITH NO COMPOSED METHOD IS NOT DECLARED HERE AT ALL, and the
// difference is not cosmetic: the runtime refuses a consumed module that
// declares no method ("consumed module %q declares no methods") and that
// refusal stops the boot. Declaring an uncomposed entry as an empty module
// would therefore not mean "nothing of it is reachable" — it would mean the
// solution does not start.
//
// Skipping it says the same thing the empty declaration was reaching for:
// nothing of that module is reachable through this backend. Two different
// things arrive here that way, and both are meant to:
//
//   - a module whose methods nobody has composed YET. It is in api.consumes,
//     so the composition delivers its binding; it reaches nothing until
//     someone fills `composition` in below. A freshly scaffolded solution is
//     entirely in this state, and starts.
//   - a module this backend never relays. api.consumes names every module the
//     solution reaches ANYWHERE, and a module the page calls at the
//     authority's edge is not relayed through here. The reference solution
//     declares six and relays two.
func consumed() []solution.ConsumedModule {
	modules := make([]solution.ConsumedModule, 0, len(consumedAsAll))
	for _, as := range consumedAsAll {
		declared := composition[as]
		if len(declared.Methods) == 0 {
			continue
		}
		modules = append(modules, solution.ConsumedModule{
			As:        as,
			Scopes:    declared.Scopes,
			Methods:   declared.Methods,
			Authority: relayFor(as),
		})
	}
	return modules
}

// consumedComposition is what this solution asks for at one module: the
// authority it asks the authority to issue for the viewer, and the methods it
// may call. A method that declares its own Scopes asks only for those.
type consumedComposition struct {
	Scopes  []solution.Scope
	Methods []solution.ConsumedMethod
}

// composition is that, per module, keyed by the `as` api.consumes gives it.
// Add the module's Go client to go.mod and name its procedures from the
// generated package, never as string literals — a renamed procedure must fail
// to compile here rather than 404 at the hop:
//
//	var composition = map[string]consumedComposition{
//		consumedAs.Documents: {
//			Scopes: []solution.Scope{
//				{ResourceKind: "documents", Actions: []string{"read"}},
//				{ResourceKind: "documents.collection", Actions: []string{"read"}},
//			},
//			Methods: []solution.ConsumedMethod{
//				{Name: documentsv1connect.DocumentsServiceListCollectionProcedure,
//					Response: solution.MustFieldMask(&documentsv1.ListCollectionResponse{}, "documents.entry.entry_id", "documents.entry.path")},
//			},
//		},
//	}
//
// Response is an ALLOWLIST, named leaf by leaf, so a field the module adds
// later is dropped until someone names it. Omitting it sends the whole
// message to the page.
var composition = map[string]consumedComposition{
	// FILLED IN, as the comment above says to: one read and one write of the
	// document store, each asking only what its own method needs.
	consumedAs.Documents: {
		Methods: []solution.ConsumedMethod{
			{Name: documentsv1connect.DocumentsServiceGetDocumentProcedure, WholeResponse: true,
				Scopes: []solution.Scope{
					{ResourceKind: "documents", Actions: []string{"read"}},
					{ResourceKind: "documents.collection", Actions: []string{"read"}},
				}},
			{Name: documentsv1connect.DocumentsServiceCreateDocumentProcedure, WholeResponse: true,
				Scopes: []solution.Scope{
					{ResourceKind: "documents", Actions: []string{"read", "write"}},
					{ResourceKind: "documents.collection", Actions: []string{"read", "create"}},
				}},
		},
	},
}

// slotsGroup is this solution's own workspace configuration group: where the
// composition says, per consumed module, where it is and which of this
// solution's bindings the viewer's calls are issued through.
const slotsGroup = solutionID

// relayFor is those two slots for one consumed module.
//
// They are the COMPOSITION's to fill, never this repository's: `<AS>_ENDPOINT`
// holds the grpc address of the hop in front of the module (an
// ${endpoint:authority/hop/grpc} reference the run resolves) and `<AS>_BINDING`
// the id the composition installs this solution's binding for that module
// under. The runtime opens a relay for every declared module at boot and
// refuses the boot, by name, while either is empty — which is the right
// moment to find out.
func relayFor(as string) solution.AuthorityRelay {
	return solution.AuthorityRelay{
		Group:       slotsGroup,
		EndpointKey: slotKey(as, "ENDPOINT"),
		BindingKey:  slotKey(as, "BINDING"),
	}
}

// slotKey is the configuration key an `as` yields: "document-store" and
// "ENDPOINT" give DOCUMENT_STORE_ENDPOINT.
func slotKey(as, suffix string) string {
	return strings.ToUpper(strings.NewReplacer("-", "_", ".", "_").Replace(as)) + "_" + suffix
}
