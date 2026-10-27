package solution

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	basev0 "github.com/codefly-dev/core/generated/go/codefly/base/v0"
	runnablev0 "github.com/codefly-dev/core/generated/go/codefly/runnable/v0"
	"github.com/codefly-dev/core/resources"
	corerunnable "github.com/codefly-dev/core/runnable"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type recordedComponent struct {
	Name   string `json:"name"`
	Pinned string `json:"pinned,omitempty"`
}

type recordedBoard struct {
	ObservedAt string              `json:"observedAt"`
	Components []recordedComponent `json:"components"`
}

type recordResult struct {
	Tags int `json:"tags"`
}

// releasesServer serves the shape of the releases solution: two reads that
// require only records read, a write, a link that invokes a datasource, a
// status any checked caller may ask for, a stream, a relayed module and MCP.
func releasesServer() *Server {
	answer := func(context.Context, *Gateway) (any, error) { return nil, nil }
	reads := Requires("records.records", "read")
	return New(Manifest{ID: "releases"}).Operations(
		Operation{Path: "/v1/releases/recorded", Summary: "Read the board as records holds it, without asking GitHub",
			Callers: "Any member who may read records", Behavior: "The newest recorded pin of every component",
			Response: recordedBoard{}, Policy: reads, Handler: answer},
		Operation{Path: "/v1/releases/history", Summary: "Read the recorded tags of one repository and the recorded pins of one component",
			Callers: "Any member who may read records", Behavior: "Newest first",
			Query:    []QueryParameter{{Name: "repo", Required: true}, {Name: "component"}},
			Response: recordedBoard{}, Policy: reads, Handler: answer},
		Operation{Path: "/v1/releases/record", Method: http.MethodPost, Summary: "Record every tag and pin the board shows",
			Callers: "A member who may write records", Behavior: "How many events were recorded",
			Response: recordResult{}, Policy: Requires("records.records", "read", "write"), Handler: answer},
		Operation{Path: "/v1/releases/link/begin", Method: http.MethodPost, Summary: "Connect the viewer's GitHub source",
			Callers: "An organization administrator", Behavior: "Where to send the browser",
			Response: recordResult{}, Policy: Requires("datasource", "invoke"), Handler: answer},
		Operation{Path: "/v1/releases/status", Summary: "Report whether the viewer's GitHub source is connected",
			Callers: "Any member", Behavior: "One object",
			Response: recordResult{}, Policy: AnyCheckedCaller(), Handler: answer},
		Operation{Path: "/v1/releases/watch", Summary: "Watch the board", Callers: "Any member who may read records", Behavior: "A stream",
			Streaming: true, Response: recordedBoard{}, Policy: reads, Handler: answer},
	).Consumes(passthroughModule()).ServeMCP("tools", "v1", reads, func(*mcp.Server) {})
}

func releasesArtifact(t *testing.T) []byte {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "service.codefly.yaml"), []byte("kind: service\nname: backend\nversion: 0.3.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := releasesServer().InterfaceArtifact(dir, InterfaceInfo{Title: "releases", OperationPrefix: "Releases", Tag: "releases"})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

// TestTheArtifactMarksEveryReadAsARunnableOperation: every read route the
// backend serves carries x-codefly-operation beside its policy, and core
// derives each from the artifact exactly as `codefly generate runnables` will
// — a GET read whose query is its input, presented as a read-only tool named
// by its operationId and described by its Summary. Nothing else is marked: a
// write and a datasource invocation are mutations whose receipt this runtime
// does not serve, a status any checked caller may ask for requires nothing to
// mint from, and a stream, MCP and a relayed subtree are not one finite call
// on one fixed path.
func TestTheArtifactMarksEveryReadAsARunnableOperation(t *testing.T) {
	doc := releasesArtifact(t)
	var parsed struct {
		Paths map[string]map[string]map[string]json.RawMessage `json:"paths"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatal(err)
	}
	marked := map[string]bool{}
	for path, methods := range parsed.Paths {
		for method, operation := range methods {
			if _, ok := operation[OperationExtension]; ok {
				marked[method+" "+path] = true
			}
		}
	}
	want := map[string]bool{"get /v1/releases/recorded": true, "get /v1/releases/history": true}
	if len(marked) != len(want) || !marked["get /v1/releases/recorded"] || !marked["get /v1/releases/history"] {
		t.Fatalf("marked %v, want exactly %v", marked, want)
	}

	owner := corerunnable.ServiceOwner{Module: "releases", Service: "backend", Endpoint: "http",
		Agent: &basev0.Agent{Kind: basev0.Agent_SERVICE, Name: "go", Version: "0.0.48", Publisher: "codefly.dev"}}
	location := func(name string) *resources.RunnableLocation {
		return &resources.RunnableLocation{
			Identity:      &resources.RunnableIdentity{Name: name, Module: "releases", Workspace: "core-solutions", Version: "0.3.0"},
			WorkspacePath: "/workspaces/core-solutions", RelativeToWorkspace: "solutions/releases",
		}
	}
	pkg, spec, err := corerunnable.PackageFromOpenAPIOperation(doc, location("backend-http-history"), owner, http.MethodGet, "/v1/releases/history")
	if err != nil {
		t.Fatalf("core does not derive the published read: %v", err)
	}
	if spec.Audience != "releases" || spec.Tool.GetEffect() != runnablev0.ToolExposure_EFFECT_READ_ONLY ||
		spec.Tool.GetName() != "Releases_Get_V1_Releases_History" ||
		spec.Tool.GetDescription() != "Read the recorded tags of one repository and the recorded pins of one component" {
		t.Fatalf("the derived operation is %+v", spec)
	}
	if pkg.GetExecution().GetRecovery() != basev0.RunnableExecution_RECOVERY_RECOMPUTE {
		t.Fatalf("a read is not recomputed: %v", pkg.GetExecution())
	}
	fields := pkg.GetContract().GetInput().GetFields()
	if len(fields) != 2 || fields[0].GetName() != "repo" || fields[0].GetOptional() || fields[1].GetName() != "component" || !fields[1].GetOptional() {
		t.Fatalf("the query is not the input: %v", fields)
	}
	if _, _, err = corerunnable.PackageFromOpenAPIOperation(doc, location("backend-http-recorded"), owner, http.MethodGet, "/v1/releases/recorded"); err != nil {
		t.Fatalf("core does not derive the published read: %v", err)
	}
	for _, route := range [][2]string{{http.MethodPost, "/v1/releases/record"}, {http.MethodPost, "/v1/releases/link/begin"}, {http.MethodGet, "/v1/releases/status"}} {
		if _, _, err = corerunnable.PackageFromOpenAPIOperation(doc, location("backend-http-unmarked"), owner, route[0], route[1]); !errors.Is(err, corerunnable.ErrNotAnOperation) {
			t.Errorf("%s %s: %v, want no operation", route[0], route[1], err)
		}
	}
}

// TestInterfaceDocumentMarksNothing: the marker names the audience the serving
// runtime's hop admits, which only the Server knows, so the free function marks
// no operation rather than guess one.
func TestInterfaceDocumentMarksNothing(t *testing.T) {
	doc, err := InterfaceDocument(InterfaceInfo{Title: "t", Version: "1", OperationPrefix: "Example", Tag: "example"}, documentedOperations())
	if err != nil {
		t.Fatal(err)
	}
	if json.Valid(doc) && containsKey(t, doc, OperationExtension) {
		t.Fatalf("InterfaceDocument marked an operation: %s", doc)
	}
}

// TestEveryDescribedObjectIsClosed: a struct marshals exactly its fields and
// protojson refuses an undeclared one, so each object the artifact defines
// says so — which is what lets a Runnable contract describe it at all.
func TestEveryDescribedObjectIsClosed(t *testing.T) {
	var parsed struct {
		Definitions map[string]map[string]any `json:"definitions"`
	}
	if err := json.Unmarshal(releasesArtifact(t), &parsed); err != nil {
		t.Fatal(err)
	}
	raw, err := InterfaceDocument(InterfaceInfo{}, documentedOperations())
	if err != nil {
		t.Fatal(err)
	}
	var generated struct {
		Definitions map[string]map[string]any `json:"definitions"`
	}
	if err = json.Unmarshal(raw, &generated); err != nil {
		t.Fatal(err)
	}
	for _, definitions := range []map[string]map[string]any{parsed.Definitions, generated.Definitions} {
		for name, schema := range definitions {
			if schema["additionalProperties"] != false {
				t.Errorf("definition %s does not close additionalProperties: %v", name, schema)
			}
		}
	}
}

func containsKey(t *testing.T, doc []byte, key string) bool {
	t.Helper()
	var walk func(any) bool
	walk = func(v any) bool {
		switch v := v.(type) {
		case map[string]any:
			if _, ok := v[key]; ok {
				return true
			}
			for _, child := range v {
				if walk(child) {
					return true
				}
			}
		case []any:
			for _, child := range v {
				if walk(child) {
					return true
				}
			}
		}
		return false
	}
	var parsed any
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatal(err)
	}
	return walk(parsed)
}

// TestAnExcludedReadIsNoOperation: an owner keeps a read from every agent the
// way a module keeps a method, and the artifact then marks it as nothing.
func TestAnExcludedReadIsNoOperation(t *testing.T) {
	ops := []Operation{{Path: "/v1/releases/recorded", Summary: "Read the board", Callers: "c", Behavior: "b",
		Response: recordedBoard{}, Policy: Requires("records.records", "read"), Exclude: true,
		Handler: func(context.Context, *Gateway) (any, error) { return nil, nil }}}
	doc, err := interfaceDocument(InterfaceInfo{OperationPrefix: "Releases"}, ops, "releases")
	if err != nil {
		t.Fatal(err)
	}
	if containsKey(t, doc, OperationExtension) {
		t.Fatalf("an excluded read was marked: %s", doc)
	}
	ops[0].Exclude = false
	if doc, err = interfaceDocument(InterfaceInfo{OperationPrefix: "Releases"}, ops, "releases"); err != nil || !containsKey(t, doc, OperationExtension) {
		t.Fatalf("the same read, not excluded, was not marked (%v): %s", err, doc)
	}
}
