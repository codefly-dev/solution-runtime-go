package solution

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
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
			Tool:     "read_recorded_board",
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

// TestAnOperationNamesTheToolItIsOfferedAs: the one part of the marker a model
// actually reads is the one part the owner says. Left empty it falls back to
// the operationId, which identifies the route and describes nothing, and the
// operationId itself never moves — generated clients are named from it.
func TestAnOperationNamesTheToolItIsOfferedAs(t *testing.T) {
	doc := releasesArtifact(t)
	var parsed struct {
		Paths map[string]map[string]struct {
			OperationID string `json:"operationId"`
			Marker      *struct {
				// The marker is proto3 JSON; decoded here as the plain
				// document a reader sees, not through the proto type, whose
				// enum does not round-trip encoding/json.
				Tool struct {
					Name   string `json:"name"`
					Effect string `json:"effect"`
				} `json:"tool"`
			} `json:"x-codefly-operation"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatal(err)
	}
	named := parsed.Paths["/v1/releases/recorded"]["get"]
	if named.Marker == nil {
		t.Fatal("the named read is marked as a Runnable operation")
	}
	if got := named.Marker.Tool.Name; got != "read_recorded_board" {
		t.Errorf("the tool is offered as %q, not the name its owner gave it", got)
	}
	if named.OperationID != "Releases_Get_V1_Releases_Recorded" {
		t.Errorf("naming the tool moved the operationId to %q, which renames every generated client", named.OperationID)
	}

	fallback := parsed.Paths["/v1/releases/history"]["get"]
	if fallback.Marker == nil {
		t.Fatal("the unnamed read is still marked")
	}
	if got := fallback.Marker.Tool.Name; got != fallback.OperationID {
		t.Errorf("an operation that names no tool falls back to its operationId, got %q", got)
	}
}

// TestAToolNameIsOneSpelling: core's own sanitiser keeps whatever it is given,
// so a name typed with a capital or a hyphen would reach a model as typed. An
// owner naming its own tool is told what a name is, at the one place that can
// still refuse it.
func TestAToolNameIsOneSpelling(t *testing.T) {
	for _, name := range []string{"Read_Board", "read-board", "9read", "", "read board", "read_board_"} {
		op := Operation{
			Path: "/v1/releases/recorded", Summary: "Read the board", Callers: "Anyone", Behavior: "One object",
			Tool: name, Response: recordedBoard{}, Policy: Requires("records.records", "read"),
			Handler: func(context.Context, *Gateway) (any, error) { return nil, nil },
		}
		err := op.validate()
		if name == "" {
			if err != nil {
				t.Errorf("an operation that names no tool is valid, got %v", err)
			}
			continue
		}
		if err == nil {
			t.Errorf("the tool name %q was accepted; a model-facing name is one spelling", name)
		}
	}
}

// TestOneToolNameNamesOneOperation: a tool name is the identity a model
// addresses, so it names exactly one operation, as an operationId names
// exactly one route. Two reads claiming one name would publish two tools a
// model cannot tell apart, and nothing downstream collapses them — a derived
// package is keyed by the operationId, and Robin's catalogue dedupes on the
// operation, the contract digest and the policy, never on the word.
func TestOneToolNameNamesOneOperation(t *testing.T) {
	answer := func(context.Context, *Gateway) (any, error) { return nil, nil }
	reads := Requires("records.records", "read")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "service.codefly.yaml"), []byte("kind: service\nname: backend\nversion: 0.3.0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	server := New(Manifest{ID: "releases"}).Operations(
		Operation{Path: "/v1/releases/one", Summary: "One", Callers: "Any member", Behavior: "One object",
			Tool: "read_board", Response: recordResult{}, Policy: reads, Handler: answer},
		Operation{Path: "/v1/releases/two", Summary: "Two", Callers: "Any member", Behavior: "One object",
			Tool: "read_board", Response: recordResult{}, Policy: reads, Handler: answer},
	)
	_, err := server.InterfaceArtifact(dir, InterfaceInfo{Title: "releases", OperationPrefix: "Releases", Tag: "releases"})
	if err == nil {
		t.Fatal("two operations offered one tool name and the artifact rendered")
	}
	if !strings.Contains(err.Error(), "both offer the tool") || !strings.Contains(err.Error(), "read_board") {
		t.Errorf("the refusal must name the tool and both routes, got %v", err)
	}
}

// TestANameOnWhatIsNeverATool: only a read is marked, so only a read is named.
// A name on anything else is a declaration that does nothing and reads as the
// opposite — the owner believes they exposed a tool.
func TestANameOnWhatIsNeverATool(t *testing.T) {
	answer := func(context.Context, *Gateway) (any, error) { return nil, nil }
	base := func() Operation {
		return Operation{Path: "/v1/releases/thing", Summary: "Thing", Callers: "Any member",
			Behavior: "One object", Tool: "read_thing", Response: recordResult{},
			Policy: Requires("records.records", "read"), Handler: answer}
	}
	for _, c := range []struct {
		why   string
		of    func(Operation) Operation
		names string
	}{
		{"a mutation", func(o Operation) Operation {
			o.Method, o.Policy = "post", Requires("records.records", "read", "write")
			return o
		}, "only a read"},
		{"an excluded route", func(o Operation) Operation { o.Exclude = true; return o }, "excludes itself"},
		{"a stream", func(o Operation) Operation { o.Streaming = true; return o }, "streams"},
		{"any checked caller", func(o Operation) Operation { o.Policy = AnyCheckedCaller(); return o }, "only a read"},
	} {
		err := c.of(base()).validate()
		if err == nil {
			t.Errorf("%s named a tool and was accepted", c.why)
			continue
		}
		if !strings.Contains(err.Error(), c.names) {
			t.Errorf("%s: the refusal must say why it is never a tool, got %v", c.why, err)
		}
	}
	// The same operation without a name is valid: this refuses the name, not
	// the operation.
	for _, of := range []func(Operation) Operation{
		func(o Operation) Operation { o.Tool, o.Exclude = "", true; return o },
		func(o Operation) Operation { o.Tool, o.Streaming = "", true; return o },
		func(o Operation) Operation { o.Tool, o.Policy = "", AnyCheckedCaller(); return o },
	} {
		if err := of(base()).validate(); err != nil {
			t.Errorf("an unnamed operation must stay valid, got %v", err)
		}
	}
}
