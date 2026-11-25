// Command backend is the server for the "Codefly Base" solution.
//
// Everything a solution needs identically is the solution runtime's: it
// presents what this solution is, answers the health probe the endpoint
// declares, serves the page's calls, and relays the page's module calls to
// the authority's hop AS THE VIEWER, where each module authorizes the call.
//
// What is left here is this solution's own composition: what it is (below),
// which routes it serves itself (operations.go), and which module operations
// its page may call (consumes.go).
package main

import (
	_ "embed"
	"log"

	solution "github.com/codefly-dev/solution-runtime-go"
)

// The runtime and the CLI read ONE declared frontend block: the runtime serves
// it at /.well-known/solution.json and the CLI delivers it in the presence
// document it signs. Keeping it beside this service — and embedding it rather
// than restating it — is what keeps the served manifest and the signed
// presence from becoming two files that disagree.
//
//go:embed solution.frontend.codefly.yaml
var frontendDeclaration []byte

// solutionID is this solution's ONE name: the id the host's presence document
// names it by, the alias the authority's edge routes it at (/v1/codefly-base),
// the principal the authority issues to, and the Codefly module name.
const solutionID = "codefly-base"

// manifest is what this solution is.
//
// Capabilities are the feature ids the host's capability handshake reports
// (/.well-known/capabilities). Name one per thing this solution can actually
// do — "documents.read" once its page reads the document store, "read-only"
// when it writes nothing anywhere — and nothing it cannot: a host lists a
// solution by what it claims here.
var manifest = solution.Manifest{
	ID:       solutionID,
	Contract: solutionID,
	Frontend: frontendDeclaration,
}

func main() {
	// A composition that names no authority is refused at boot, by name:
	// there is no other way from here to a module.
	if err := server().Serve(); err != nil {
		log.Fatal(err)
	}
}

// server is this solution on the authority interface: the routes it serves
// itself, and the modules it consumes relayed by the runtime's passthrough.
//
// ONE declaration both serves the solution and renders its interface document
// (openapi.go), so a route cannot be served without publishing the policy a
// call to it must hold, nor published without being served.
func server() *solution.Server {
	return solution.New(manifest).Consumes(consumed()...).Operations(operations()...)
}
