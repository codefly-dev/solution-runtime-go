package main

import (
	"context"
	"net/http"

	solution "github.com/codefly-dev/solution-runtime-go"
)

// route is where the authority's edge routes this solution and forwards its
// requests unchanged: /v1/<id>, the solution's alias. EVERY operation carries
// it, because the runtime asks the authority about the route as served — a
// path declared without it is a row no request matches.
const route = "/v1/" + solutionID

// operations is what this backend serves itself, beside the runtime's
// passthrough.
//
// A freshly scaffolded solution serves none of its own: the host lists it,
// mounts its page, and the page reads what it reads through the modules this
// solution consumes (consumes.go). Add one per route this solution answers
// with work that is its own.
//
// Policy is REQUIRED on every operation. The authority applies it to each
// call, and an absent declaration and "nothing in particular is required"
// must not look the same — so a route that needs nothing beyond a checked
// caller says so with solution.AnyCheckedCaller():
//
//	solution.Operation{
//		Path: route + "/notes", Method: http.MethodGet,
//		Summary:  "list the notes the viewer may read",
//		Callers:  "The page's Notes view.",
//		Behavior: "Answers the viewer's own notes, newest first, 50 at a time.",
//		Response: notesResponse{},
//		Policy:   solution.Requires("codefly-base.note", "read"),
//		Handler:  listNotes,
//	}
//
// The resource kind a policy names is this solution's OWN vocabulary, which
// module.contract.codefly.yaml declares under scope_ceilings. A kind the
// contract does not declare is a scope the authority never issues, so the
// route would refuse every call.
func operations() []solution.Operation {
	return []solution.Operation{overviewOperation()}
}

// overviewOperation is the one route a scaffolded solution serves, and the
// one its page reads.
//
// It exists so a freshly scaffolded solution is RUNNABLE AND OBSERVABLE
// rather than correct-looking and inert. Everything between a host and this
// backend has to work for its answer to appear on the page: the host mounts
// the remote, the edge routes /v1/<id>, the authority checks the viewer's
// Work Context against the policy below, and the runtime dispatches. A page
// that renders this has proven that path; a page that renders a fixed string
// has proven nothing, which is why the answer is derived rather than typed.
//
// Replace it with the solution's own first route. Keep the shape: a policy,
// the three prose fields, and a typed Response.
func overviewOperation() solution.Operation {
	return solution.Operation{
		Path:     route + "/overview",
		Method:   http.MethodGet,
		Summary:  "report what this solution is and which modules it can reach",
		Callers:  "This solution's own page, to show that it is installed and reachable as the viewer",
		Behavior: "Answers the solution's id and the `as` name of every module this backend relays, in the order they are declared. Takes no parameters and reads nothing outside this backend",
		Response: overviewResponse{},
		// The viewer must hold a read on this solution's own page. The kind is
		// the solution's OWN vocabulary, which module.contract.codefly.yaml
		// declares under scope_ceilings and grants through the installer role
		// — both written by `codefly add solution` for exactly this name
		// (cli#1216). A kind the contract does not declare is a scope the
		// authority never issues, so the route would refuse every call.
		Policy:  solution.Requires(solutionID+".page", "read"),
		Handler: overview,
	}
}

// overviewResponse is what the page reads to show that this solution is
// reachable, and what it can reach.
type overviewResponse struct {
	// Solution is this solution's id, as the host lists it and the authority
	// issues to.
	Solution string `json:"solution"`
	// Consumes is the `as` route name of every module this backend relays,
	// which is what consumes.go declares and the runtime opened a relay for.
	// Empty on a freshly scaffolded solution, which composes none yet.
	Consumes []string `json:"consumes"`
}

// overview answers from the DECLARATIONS the runtime booted with, not from
// constants: the list is the one consumed() built, so a module that failed to
// declare a method is absent here too, and the page shows what is actually
// reachable.
func overview(_ context.Context, _ *solution.Gateway) (any, error) {
	relayed := consumed()
	names := make([]string, 0, len(relayed))
	for index := range relayed {
		names = append(names, relayed[index].As)
	}
	return overviewResponse{Solution: solutionID, Consumes: names}, nil
}
