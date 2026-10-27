package solution

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// publishedRows is what the CLI derives from a solution's interface artifact:
// one "<VERB> <template>" row for each operation that publishes a policy.
func publishedRows(t *testing.T, artifact []byte) []string {
	t.Helper()
	var doc struct {
		Paths map[string]map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(artifact, &doc); err != nil {
		t.Fatal(err)
	}
	rows := []string{}
	for path, methods := range doc.Paths {
		for method, op := range methods {
			if _, ok := op[PolicyExtension]; ok {
				rows = append(rows, strings.ToUpper(method)+" "+path)
			}
		}
	}
	slices.Sort(rows)
	return rows
}

// Under an enforcing authority holding only the rows the interface artifact
// publishes, every route the runtime serves is admitted for what it declares:
// its own operation, the MCP route (F3), and each relayed module route (F4),
// which the authority is asked about as served. Take a route's row away and
// the authority refuses it, before any tool or module runs: the row is what
// admits it, so a route with none would be refused.
func TestUnderEnforcementEveryServedRouteIsAdmittedByItsPublishedRow(t *testing.T) {
	module := &relayedModule{streamed: 1}
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__PAGE__THINGS_ENDPOINT", "grpc://"+module.serve(t))
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__PAGE__THINGS_BINDING", "things-binding")
	tools := 0
	server := New(Manifest{ID: "page", Frontend: []byte(testFrontend)}).
		Operations(served("get", "/v1/page/types", func(context.Context, *Gateway) (any, error) { return map[string]string{"ok": "yes"}, nil })).
		Consumes(watchModule(ConsumedMethod{})).
		ServeMCP("page", "v1", Requires("page.tools", "call"), func(srv *mcp.Server) {
			mcp.AddTool(srv, &mcp.Tool{Name: "ask", Description: "asks"},
				func(context.Context, *mcp.CallToolRequest, askInput) (*mcp.CallToolResult, askOutput, error) {
					tools++
					return nil, askOutput{Owner: "answered"}, nil
				})
		})
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "service.codefly.yaml"), []byte("version: 0.0.1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	artifact, err := server.InterfaceArtifact(dir, InterfaceInfo{Title: "page", OperationPrefix: "Page", Tag: "page"})
	if err != nil {
		t.Fatal(err)
	}
	rows := publishedRows(t, artifact)
	want := []string{
		"GET /v1/page/types",
		"POST /v1/page/mcp",
		"POST /v1/page/modules/things/relayed.v1.Things/Search",
		"POST /v1/page/modules/things/relayed.v1.Things/Watch",
	}
	slices.Sort(want)
	if !slices.Equal(rows, want) {
		t.Fatalf("the artifact publishes rows %v, want %v", rows, want)
	}

	b := boot(t, server)
	hold := func(rows []string) {
		b.authority.mu.Lock()
		b.authority.held = rows
		b.authority.mu.Unlock()
	}
	hold(rows)
	if status := getStatusWith(t, b, "/v1/page/types"); status != http.StatusOK {
		t.Fatalf("the operation answered %d under its own row", status)
	}
	session, err := connectMCP(t, b.base, edgeContext)
	if err != nil {
		t.Fatalf("the MCP route was refused under its published row: %v", err)
	}
	if result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "ask", Arguments: map[string]any{"question": "why"}}); err != nil || result.IsError || tools != 1 {
		t.Fatalf("the tool call under its published row: %v %+v (ran %d)", err, result, tools)
	}
	if code, answer := connectCall(t, b.base+relayedSearchPath, edgeContext, `{"entryId":"e1"}`); code != http.StatusOK {
		t.Fatalf("the relayed call answered %d %v under its published row", code, answer)
	}
	if got, err := watch(t, b.base, edgeContext); err != nil || len(got) != 1 {
		t.Fatalf("the relayed stream under its published row: %d messages, %v", len(got), err)
	}
	asked := map[string]bool{}
	for _, check := range b.authority.checks() {
		asked[check.GetMethod()] = true
		if check.GetAdvisory() {
			t.Fatalf("an enforcing run asked an advisory check: %v", check)
		}
	}
	for _, row := range want {
		if !asked[row] {
			t.Errorf("the authority was never asked about %s: %v", row, asked)
		}
	}

	// Without the MCP and Search rows, both are refused at the authority.
	hold([]string{"GET /v1/page/types", "POST /v1/page/modules/things/relayed.v1.Things/Watch"})
	calls := len(module.observed())
	if _, err := connectMCP(t, b.base, edgeContext); err == nil {
		t.Fatal("the MCP route was admitted with no row")
	}
	if code, answer := connectCall(t, b.base+relayedSearchPath, edgeContext, `{"entryId":"e1"}`); code != http.StatusForbidden || answer["code"] != "permission_denied" ||
		!strings.Contains(answer["message"].(string), "/v1/page/modules/things/relayed.v1.Things/Search") {
		t.Fatalf("a relayed call with no row answered %d %v", code, answer)
	}
	if tools != 1 || len(module.observed()) != calls {
		t.Fatalf("a refused route reached a tool (%d) or the module (%d calls)", tools, len(module.observed()))
	}
}

// getStatusWith GETs path on a booted solution with the edge's Work Context.
func getStatusWith(t *testing.T, b *booted, path string) int {
	t.Helper()
	request, _ := http.NewRequest(http.MethodGet, b.base+path, nil)
	request.Header.Set(WorkContextHeader, edgeContext)
	response, err := b.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	return response.StatusCode
}

// An authority that cannot be reached refused nobody: the page is told the
// authority is unavailable (503, by name), never asked to sign in, and the
// handler does not run.
func TestAnAuthorityOutageIsNamedNotAnsweredAsASignIn(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	gone := l.Addr().String()
	_ = l.Close()
	host, err := dialAuthority("grpc://"+gone, meshTransport{local: true}, filepath.Join(t.TempDir(), "token"), "page", false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	s := &Server{manifest: Manifest{ID: "page"}, host: host}
	ran := false
	request := httptest.NewRequest(http.MethodGet, "/v1/page/types", nil)
	request.Header.Set(WorkContextHeader, edgeContext)
	answer := httptest.NewRecorder()
	s.wrapRequest("GET /v1/page/types", func(*http.Request, *Gateway) (any, error) { ran = true; return nil, nil })(answer, request)
	if answer.Code != http.StatusServiceUnavailable || ran || !strings.Contains(answer.Body.String(), ErrAuthorityUnavailable.Error()) || strings.Contains(answer.Body.String(), gone) {
		t.Fatalf("an outage answered %d %s (handler ran: %v)", answer.Code, answer.Body.String(), ran)
	}
}
