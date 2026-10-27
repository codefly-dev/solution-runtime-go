package solution

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// edgeTransport is the authority's edge as an MCP request arrives from it: it
// sends the request on with the Work Context it carries for the solution.
type edgeTransport struct{ workContext string }

func (e edgeTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Del(WorkContextHeader)
	if e.workContext != "" {
		r.Header.Set(WorkContextHeader, e.workContext)
	}
	return http.DefaultTransport.RoundTrip(r)
}

type askInput struct {
	Question string `json:"question"`
}

type askOutput struct {
	Owner string `json:"owner"`
	Token string `json:"token"`
}

// mcpPage is a solution under the stand-in authority serving register's tools,
// mounted as serve mounts it.
func mcpPage(t *testing.T, register func(*mcp.Server)) (*httptest.Server, *Server, *interfaceAuthority) {
	t.Helper()
	s, stand := authorityServer(t)
	s.ServeMCP("page", "v1", AnyCheckedCaller(), register)
	mux := http.NewServeMux()
	if err := s.mountMCP(mux); err != nil {
		t.Fatal(err)
	}
	page := httptest.NewServer(mux)
	t.Cleanup(page.Close)
	return page, s, stand
}

func connectMCP(t *testing.T, base string, workContext string) (*mcp.ClientSession, error) {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "v0"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   base + "/v1/page" + MCPPath,
		HTTPClient: &http.Client{Transport: edgeTransport{workContext: workContext}},
	}, nil)
	if err == nil {
		t.Cleanup(func() { _ = session.Close() })
	}
	return session, err
}

// A tool call runs as the person the authority says the request is for: the
// viewer is the authority's Check of the Work Context the edge sent, naming
// the MCP route, and a tool reaches a module through a child of it.
func TestAnMCPToolCallRunsAsTheViewer(t *testing.T) {
	page, _, stand := mcpPage(t, func(srv *mcp.Server) {
		mcp.AddTool(srv, &mcp.Tool{Name: "ask", Description: "asks a module as the viewer"},
			func(ctx context.Context, _ *mcp.CallToolRequest, _ askInput) (*mcp.CallToolResult, askOutput, error) {
				gw, err := ViewerFromContext(ctx)
				if err != nil {
					return nil, askOutput{}, err
				}
				principals, err := gw.WorkContextPrincipals(ctx)
				if err != nil {
					return nil, askOutput{}, err
				}
				docs, err := gw.ForParent(ctx, "documents-read", Scope{ResourceKind: "documents", Actions: []string{"read"}})
				if err != nil {
					return nil, askOutput{}, err
				}
				token, err := docs.WorkContext(ctx)
				return nil, askOutput{Owner: principals.OwnerPrincipalID, Token: token}, err
			})
	})
	session, err := connectMCP(t, page.URL, edgeContext)
	if err != nil {
		t.Fatal(err)
	}
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "ask", Arguments: map[string]any{"question": "why"}})
	if err != nil || result.IsError {
		t.Fatalf("tools/call: %v %+v", err, result)
	}
	out, _ := result.StructuredContent.(map[string]any)
	if out["owner"] != "person-1" || out["token"] != "issued-documents-read" {
		t.Fatalf("the tool answered %v", result.StructuredContent)
	}
	checks := stand.checks()
	if len(checks) == 0 || checks[len(checks)-1].GetMethod() != "POST /v1/page/mcp" || checks[len(checks)-1].GetAudience() != "page" {
		t.Fatalf("the authority was asked %v", checks)
	}
	if asked := stand.asked(); len(asked) != 1 || asked[0].GetParentToken() != edgeContext {
		t.Fatalf("the child was asked %v", asked)
	}
}

// A request with no Work Context did not come through the edge and is
// answered 401 before the MCP handler reads it; one the authority does not
// check runs no tool.
func TestAnMCPCallTheAuthorityDoesNotAdmitRunsNoTool(t *testing.T) {
	ran := 0
	page, _, _ := mcpPage(t, func(srv *mcp.Server) {
		mcp.AddTool(srv, &mcp.Tool{Name: "ask", Description: "asks"},
			func(context.Context, *mcp.CallToolRequest, askInput) (*mcp.CallToolResult, askOutput, error) {
				ran++
				return nil, askOutput{}, nil
			})
	})
	response, err := http.Post(page.URL+"/v1/page"+MCPPath, "application/json", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a request with no Work Context answered %d", response.StatusCode)
	}
	if session, err := connectMCP(t, page.URL, "forged"); err == nil {
		if _, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "ask", Arguments: map[string]any{}}); err == nil {
			t.Fatal("a forged Work Context reached a tool")
		}
	}
	if ran != 0 {
		t.Fatalf("a tool ran %d times for a call the authority did not admit", ran)
	}
}

// A tool's error result that names an address this runtime dialled is
// replaced, and the original goes to the log; one naming nothing of the
// runtime's is the tool's own to word.
func TestAnMCPErrorResultNeverNamesAnAddressThisRuntimeDialled(t *testing.T) {
	page, s, _ := mcpPage(t, func(srv *mcp.Server) {
		mcp.AddTool(srv, &mcp.Tool{Name: "ask", Description: "asks"},
			func(_ context.Context, _ *mcp.CallToolRequest, in askInput) (*mcp.CallToolResult, askOutput, error) {
				return nil, askOutput{}, errors.New(in.Question)
			})
	})
	s.cfg.dialled = dialledAddresses("hop.internal:9090")
	session, err := connectMCP(t, page.URL, edgeContext)
	if err != nil {
		t.Fatal(err)
	}
	for question, leaked := range map[string]bool{"dial hop.internal:9090: refused": true, "no such page": false} {
		result, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: "ask", Arguments: map[string]any{"question": question}})
		if err != nil || !result.IsError || len(result.Content) != 1 {
			t.Fatalf("tools/call %q: %v %+v", question, err, result)
		}
		text := result.Content[0].(*mcp.TextContent).Text
		if strings.Contains(text, "hop.internal") || (!leaked && !strings.Contains(text, question)) {
			t.Errorf("an error result for %q reached the client as %q", question, text)
		}
	}
}

// ServeMCP is declared once, completely, and on a route no handler holds.
func TestAnMCPDeclarationIsRefusedForWhatItLacks(t *testing.T) {
	register := func(*mcp.Server) {}
	for name, s := range map[string]*Server{
		"twice":        New(Manifest{ID: "page"}).ServeMCP("page", "v1", AnyCheckedCaller(), register).ServeMCP("page", "v1", AnyCheckedCaller(), register),
		"no name":      New(Manifest{ID: "page"}).ServeMCP("", "v1", AnyCheckedCaller(), register),
		"no version":   New(Manifest{ID: "page"}).ServeMCP("page", "", AnyCheckedCaller(), register),
		"no tools":     New(Manifest{ID: "page"}).ServeMCP("page", "v1", AnyCheckedCaller(), nil),
		"no policy":    New(Manifest{ID: "page"}).ServeMCP("page", "v1", nil, register),
		"empty policy": New(Manifest{ID: "page"}).ServeMCP("page", "v1", &Policy{}, register),
		"an operation on its route": New(Manifest{ID: "page"}).ServeMCP("page", "v1", AnyCheckedCaller(), register).
			Operations(served("get", "/v1/page/mcp", func(context.Context, *Gateway) (any, error) { return nil, nil })),
	} {
		if err := s.validateMCPDeclaration(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}
