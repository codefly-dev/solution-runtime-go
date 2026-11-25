package main

import solution "github.com/codefly-dev/solution-runtime-go"

//go:generate go test -run TestInterfaceArtifactIsCurrent -update .

// interfaceArtifactPath is this backend's interface document: every route it
// serves under the authority interface, each with the policy a call to it must
// hold, rendered by the solution runtime from the server itself at the version
// service.codefly.yaml declares.
//
// It is the document `codefly generate contracts` publishes as the http
// endpoint's contract, and the CLI derives the route rows the authority's
// Check applies from it — so a backend without one publishes no contract, and
// a route served without being in it is a route the authority has no row for.
// `go generate ./...` rewrites it and openapi_test.go fails on a diff.
const interfaceArtifactPath = "openapi/api.swagger.json"

// renderInterfaceArtifact renders the document for the backend rooted at dir.
func renderInterfaceArtifact(dir string) ([]byte, error) {
	return server().InterfaceArtifact(dir, solution.InterfaceInfo{
		Title:       "codefly-base solution backend",
		Description: "The codefly-base solution's backend under the authority interface, at the route the authority's edge forwards it on: the routes it serves itself, and the module calls the solution runtime relays as the viewer. A relayed call is any checked caller's, because the child the authority issues through this solution's binding for that module, and the module's own method policy, gate it.",
		// No base path: every route already carries /v1/codefly-base, as served.
		OperationPrefix: "CodeflyBase",
		Tag:             solutionID,
	})
}
