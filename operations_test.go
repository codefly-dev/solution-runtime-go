package solution

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/api/annotations"
)

type documentedTree struct {
	ID       string                         `json:"id"`
	Rule     Message[*annotations.HttpRule] `json:"rule"`
	Children []*documentedTree              `json:"children"`
	Facets   map[string]any                 `json:"facets"`
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
	if doc.BasePath != "/solutions/example" || doc.Paths["/nodes/tree"]["get"]["operationId"] != "Example_Nodes_Tree" {
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
	if _, ok := doc.Definitions["DocumentedTree"]; !ok {
		t.Fatalf("struct definitions are missing: %v", doc.Definitions)
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
	s := New(Manifest{ID: "example"}).Operations(documentedOperations()...)
	handler, ok := s.handlers["/nodes/tree"]
	if !ok {
		t.Fatalf("the declared route was not registered: %v", s.handlers)
	}
	srv := httptest.NewServer(s.wrapRequest(handler))
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/nodes/tree", nil)
	req.Header.Set("authorization", "Bearer viewer")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}
