package solution

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/api/annotations"
)

type documentedTree struct {
	ID       string                          `json:"id"`
	Rule     Message[*annotations.HttpRule]  `json:"rule"`
	Optional *Message[*annotations.HttpRule] `json:"optional,omitempty"`
	Children []*documentedTree               `json:"children"`
	Facets   map[string]any                  `json:"facets"`
}

type documentedResponse struct {
	Nodes []*documentedTree `json:"nodes"`
}

func documentedOperations() []Operation {
	return []Operation{{
		Path:     "/nodes/tree",
		Summary:  "List the nodes",
		Callers:  "Signed-in viewers.",
		Behavior: "Returns every node.",
		Query:    []QueryParameter{{Name: "pageToken"}},
		Response: documentedResponse{},
		Policy:   Requires("example.node", "read"),
		Handler:  func(context.Context, *Gateway) (any, error) { return documentedResponse{}, nil },
	}}
}

func TestInterfaceDocumentDescribesGeneratedMessagesFromTheirDescriptor(t *testing.T) {
	raw, err := InterfaceDocument(InterfaceInfo{Title: "example backend", Version: "1.2.3", BasePath: "/solutions/example", OperationPrefix: "Example", Tag: "example"}, documentedOperations())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), "}\n") {
		t.Fatalf("the artifact has no trailing newline")
	}
	var doc struct {
		BasePath    string                               `json:"basePath"`
		Paths       map[string]map[string]map[string]any `json:"paths"`
		Definitions map[string]struct {
			Properties map[string]map[string]any `json:"properties"`
		} `json:"definitions"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BasePath != "/solutions/example" || doc.Paths["/nodes/tree"]["get"]["operationId"] != "Example_Get_Nodes_Tree" {
		t.Fatalf("document = %s", raw)
	}
	rule, ok := doc.Definitions["GoogleApiHttpRule"]
	if !ok {
		t.Fatalf("the generated message has no definition: %v", doc.Definitions)
	}
	// Protobuf JSON names, not Go struct tags.
	if _, ok := rule.Properties["responseBody"]; !ok {
		t.Fatalf("definition does not use JSON names: %v", rule.Properties)
	}
	if items := rule.Properties["additionalBindings"]["items"].(map[string]any); items["$ref"] != "#/definitions/GoogleApiHttpRule" {
		t.Fatalf("a self-referencing message does not terminate in a $ref: %v", items)
	}
	tree, ok := doc.Definitions["DocumentedTree"]
	if !ok {
		t.Fatalf("struct definitions are missing: %v", doc.Definitions)
	}
	if tree.Properties["optional"]["$ref"] != "#/definitions/GoogleApiHttpRule" {
		t.Fatalf("a pointer to a generated message is not described by it: %v", tree.Properties["optional"])
	}
}

func TestInterfaceDocumentRefusesAnUndocumentedOperation(t *testing.T) {
	for _, broken := range []func(*Operation){
		func(o *Operation) { o.Summary = "" },
		func(o *Operation) { o.Callers = "" },
		func(o *Operation) { o.Behavior = "" },
		func(o *Operation) { o.Response = nil },
		func(o *Operation) { o.Handler = nil },
		func(o *Operation) { o.Path = "nodes" },
		func(o *Operation) { o.Policy = nil },
		func(o *Operation) {
			o.RequestHandler = func(*http.Request, *Gateway) (any, error) { return nil, nil }
		},
	} {
		ops := documentedOperations()
		broken(&ops[0])
		if _, err := InterfaceDocument(InterfaceInfo{}, ops); err == nil {
			t.Fatalf("an invalid operation rendered: %+v", ops[0])
		}
	}
}

func TestOperationsServesEachDeclaredRoute(t *testing.T) {
	s, _ := authorityServer(t)
	s.Operations(documentedOperations()...)
	mux := http.NewServeMux()
	if err := s.mountOperations(mux); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(mux)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/nodes/tree", nil)
	req.Header.Set(WorkContextHeader, edgeContext)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

// authorityOperations is a backend served under the authority: its routes
// carry the /v1/<id> the edge forwards them on, and one serves a subtree.
func authorityOperations() []Operation {
	handler := func(context.Context, *Gateway) (any, error) { return nil, nil }
	return []Operation{
		{Path: "/v1/example/upload-access", Summary: "s", Callers: "c", Behavior: "b", Response: map[string]string{},
			Policy: Requires("example.page", "read"), Handler: handler},
		{Path: "/v1/example/modules/robin/", Method: http.MethodPost, Summary: "s", Callers: "c", Behavior: "b", Response: map[string]string{},
			Policy: AnyCheckedCaller(), Handler: handler},
	}
}

// TestInterfaceDocumentWritesEachOperationsPolicyAtTheRouteAsServed: the row
// the CLI derives is "<VERB> <basePath><path>" with the operation's
// x-codefly-authority-policy, and the runtime asks the authority's Check for
// "<VERB> <path>" as served, so an authority-served document has no base path,
// every route its full served path, a subtree its "{path=**}" template, and
// each policy in the authority.hop.v1.Policy JSON the CLI decodes.
func TestInterfaceDocumentWritesEachOperationsPolicyAtTheRouteAsServed(t *testing.T) {
	raw, err := InterfaceDocument(InterfaceInfo{Title: "t", Version: "1", OperationPrefix: "Example", Tag: "example"}, authorityOperations())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		BasePath *string                                          `json:"basePath"`
		Paths    map[string]map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.BasePath != nil {
		t.Fatalf("an authority-served document names a base path %q: its routes are already as served", *doc.BasePath)
	}
	for route, want := range map[string]string{
		"get /v1/example/upload-access":            `{"requires":[{"resource_kind":"example.page","actions":["read"]}]}`,
		"post /v1/example/modules/robin/{path=**}": `{"any_checked_caller":true}`,
	} {
		verb, path, _ := strings.Cut(route, " ")
		got, ok := doc.Paths[path][verb][PolicyExtension]
		if !ok {
			t.Fatalf("%s carries no %s: %s", route, PolicyExtension, raw)
		}
		var compact bytes.Buffer
		if err := json.Compact(&compact, got); err != nil {
			t.Fatal(err)
		}
		if compact.String() != want {
			t.Fatalf("%s declares %s, want %s", route, compact.String(), want)
		}
	}
}

// TestInterfaceDocumentRefusesAServedRouteWithNoPolicyByName: a route with
// nothing to be held to would reach the authority as a row it refuses every
// call to, or as no row at all; generation refuses it first, naming it.
func TestInterfaceDocumentRefusesAServedRouteWithNoPolicyByName(t *testing.T) {
	for name, policy := range map[string]*Policy{
		"none":     nil,
		"empty":    {},
		"both":     {AnyCheckedCaller: true, Requires: []Requirement{{ResourceKind: "example.page", Actions: []string{"read"}}}},
		"no kind":  {Requires: []Requirement{{Actions: []string{"read"}}}},
		"no verbs": {Requires: []Requirement{{ResourceKind: "example.page"}}},
	} {
		ops := authorityOperations()
		ops[1].Policy = policy
		_, err := InterfaceDocument(InterfaceInfo{}, ops)
		if err == nil || !strings.Contains(err.Error(), "POST /v1/example/modules/robin/") {
			t.Fatalf("%s: a served route with policy %+v rendered, or was not named: %v", name, policy, err)
		}
	}
}

// TestInterfaceDocumentKeepsEveryMethodOfOnePath: two operations on one path
// are two routes; one declared twice is refused rather than one overwriting
// the other's policy.
func TestInterfaceDocumentKeepsEveryMethodOfOnePath(t *testing.T) {
	ops := authorityOperations()
	write := ops[0]
	write.Method, write.Policy = "post", Requires("example.page", "write")
	raw, err := InterfaceDocument(InterfaceInfo{}, append(ops, write))
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Paths["/v1/example/upload-access"]) != 2 {
		t.Fatalf("one path's two methods: %v", doc.Paths["/v1/example/upload-access"])
	}
	if _, err := InterfaceDocument(InterfaceInfo{}, append(ops, ops[0])); err == nil || !strings.Contains(err.Error(), "declared twice") {
		t.Fatalf("a route declared twice rendered: %v", err)
	}
}

// TestInterfaceDocumentGivesEveryOperationItsOwnID: an operationId names one
// operation, so each method on one path has its own, and two operations the
// derivation would give one id are refused rather than written ambiguous.
func TestInterfaceDocumentGivesEveryOperationItsOwnID(t *testing.T) {
	refused := authorityOperations()[0]
	var ops []Operation
	for _, method := range []string{"get", "head", "post", "put", "patch", "delete"} {
		op := refused
		op.Method = method
		ops = append(ops, op)
	}
	raw, err := InterfaceDocument(InterfaceInfo{OperationPrefix: "Example"}, ops)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Paths map[string]map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for path, operations := range doc.Paths {
		for method, operation := range operations {
			id, _ := operation["operationId"].(string)
			if other, taken := seen[id]; taken {
				t.Errorf("%s %s and %s share the operationId %q", method, path, other, id)
			}
			seen[id] = method + " " + path
		}
	}
	if len(seen) != len(ops) {
		t.Fatalf("%d operations, %d distinct ids: %v", len(ops), len(seen), seen)
	}
	if id := doc.Paths["/v1/example/upload-access"]["post"]["operationId"]; id != "Example_Post_V1_Example_Upload-access" {
		t.Fatalf("POST /v1/example/upload-access is %v", id)
	}

	// A path and the subtree under it are two operations, with two ids.
	path, subtree := refused, refused
	path.Path, subtree.Path = "/v1/example/mcp", "/v1/example/mcp/"
	raw, err = InterfaceDocument(InterfaceInfo{OperationPrefix: "Example"}, []Operation{path, subtree})
	if err != nil {
		t.Fatalf("a path and its subtree: %v", err)
	}
	if !strings.Contains(string(raw), `"Example_Get_V1_Example_Mcp"`) || !strings.Contains(string(raw), `"Example_Get_V1_Example_Mcp_Path"`) {
		t.Fatalf("a path and its subtree are not two ids: %s", raw)
	}

	// "/A/b" and "/a/b" are two routes the derivation spells alike.
	upper, lower := refused, refused
	upper.Path, lower.Path = "/A/b", "/a/b"
	if _, err := InterfaceDocument(InterfaceInfo{OperationPrefix: "Example"}, []Operation{upper, lower}); err == nil || !strings.Contains(err.Error(), "share the operationId") {
		t.Fatalf("two operations with one operationId rendered: %v", err)
	}
}

// TestServedRouteSpellsMuxPatternsAsTheAuthorityMatchesThem pins the pattern
// forms the runtime's mux serves.
func TestServedRouteSpellsMuxPatternsAsTheAuthorityMatchesThem(t *testing.T) {
	for path, want := range map[string]string{
		"/v1/x/upload":           "/v1/x/upload",
		"/v1/x/modules/robin/":   "/v1/x/modules/robin/{path=**}",
		"/v1/x/files/{rest...}":  "/v1/x/files/{rest=**}",
		"/v1/x/{$}":              "/v1/x/",
		"/v1/x/items/{id}/parts": "/v1/x/items/{id}/parts",
	} {
		if got := servedRoute(path); got != want {
			t.Fatalf("servedRoute(%q) = %q, want %q", path, got, want)
		}
	}
}
