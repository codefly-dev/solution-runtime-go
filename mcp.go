package solution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- MCP ---
//
// A solution exposes its experience to an agent client the way it exposes it to
// a browser: as the person the authority says the request is for, with the
// same authority. The solution owns its tool surface; this runtime owns serving
// it.
//
// The surface is the MCP transport — the official SDK's stateless Streamable
// HTTP handler at MCPPath under the solution's route, and the receiving
// middleware that binds each call to its viewer — and nothing else. A tool
// call is admitted exactly as a handler route is: the authority's Check of the
// Work Context the request carries, addressed to this module, naming the route
// ("POST /v1/<id>/mcp") so the solution's delivered route policy applies. The
// policy is declared with the surface (ServeMCP) and published in the
// interface artifact like every operation's (Server.InterfaceArtifact), so the
// CLI derives the route's row from the same document. No
// token is verified here, no identity header is read, and the OAuth discovery
// the saas host's gateway used to authenticate agent clients against is gone
// with that host: how an agent client obtains a Work Context for a solution
// through the authority — robin calling a solution's tools, for the person or
// as itself — is the authority's to answer, and this transport serves whatever
// context arrives.

// MCPPath is where the MCP endpoint serves, relative to the solution's route:
// through the edge that is /v1/<id>/mcp, the route the edge already forwards.
const MCPPath = "/mcp"

// mcpSurface is the MCP server a solution declared with ServeMCP.
type mcpSurface struct {
	name, version string
	// policy is what a call to the MCP route must hold, as every operation
	// declares it.
	policy   *Policy
	register func(*mcp.Server)
}

// validate rejects a declaration that cannot serve anything. Both mistakes are
// the author's and are the same in every environment, so they are refused
// before the environment is consulted, as a mis-declared surface is.
func (m *mcpSurface) validate() error {
	if strings.TrimSpace(m.name) == "" {
		return fmt.Errorf("ServeMCP was given no server name: it is what an MCP client displays for this server")
	}
	if strings.TrimSpace(m.version) == "" {
		return fmt.Errorf("ServeMCP server %q was given no version: a client negotiates and caches against it", m.name)
	}
	if m.register == nil {
		return fmt.Errorf("ServeMCP server %q was given no register function: the solution owns its tool surface, and a server with no tools answers tools/list with nothing", m.name)
	}
	if err := m.policy.validate(); err != nil {
		return fmt.Errorf("ServeMCP server %q %w", m.name, err)
	}
	return nil
}

// ServeMCP exposes the solution as an MCP server over stateless Streamable HTTP
// at MCPPath under the solution's route. Chainable, like Operations.
//
// name and version identify the server to a client. policy is what a call to
// the route must hold, which the authority applies to every MCP request as it
// does to every operation's, and which the interface artifact publishes for
// the route (POST /v1/<id>/mcp). register adds the tools,
// prompts and resources the solution offers, on the official SDK's own
// *mcp.Server — the solution's tool surface is its own, and this runtime adds
// nothing to it.
//
// Every tool call runs as the viewer who made the request: ViewerFromContext
// returns the same viewer-bound Gateway a Handler is given, so a tool reaches a
// module through ForParent exactly as the page does, under a child of the
// viewer's own Work Context and no more authority than it asks for.
//
// Sessions are stateless because the edge is a reverse proxy with no sticky
// routing: a session held in one replica's memory is unreachable from the next
// request, so the MCP session would break under any rollout or scale-out. Each
// request carries its own Work Context, which is all a tool call needs.
func (s *Server) ServeMCP(name, version string, policy *Policy, register func(*mcp.Server)) *Server {
	// A second call is not a second server — there is one MCP endpoint — so it
	// replaces the first. Recorded rather than applied silently, and refused at
	// boot by validateMCPDeclaration: a solution assembled from two places,
	// each declaring its own tools, would otherwise serve only the tools of
	// whichever ran last, with tools/list answering as if that were all there
	// is. ServeMCP cannot return the error itself, being chainable.
	if s.mcp != nil {
		s.mcpRedeclared = true
	}
	s.mcp = &mcpSurface{name: name, version: version, policy: policy, register: register}
	return s
}

// mcpOperation is the MCP route as the interface artifact publishes it: one
// operation, POST at the route, with the declared policy. The MCP transport,
// not an operation's handler, serves it (mountMCP).
func (s *Server) mcpOperation() Operation {
	return Operation{
		Path:    s.mcpRoute(),
		Method:  "post",
		Summary: fmt.Sprintf("Call the %s MCP server's tools as the viewer", s.mcp.name),
		Callers: "Agent clients, through the authority's edge, as the person whose Work Context the request carries; " +
			"every call is held to this route's policy.",
		Behavior: "The MCP Streamable HTTP transport, stateless: one JSON-RPC message per POST, answered with its result. " +
			"Each tool runs as the viewer and reaches a module only through a child the authority issues through one of this solution's bindings. " +
			"Any other method is refused.",
		Request:  json.RawMessage{},
		Response: json.RawMessage{},
		Policy:   s.mcp.policy,
		// The body is a JSON-RPC message for any of the server's tools, not
		// one operation's input: each tool is its own surface.
		Exclude: true,
		Handler: func(context.Context, *Gateway) (any, error) { return nil, errors.New("served by the MCP transport") },
	}
}

// mcpRoute is where the MCP endpoint is served: under the route the edge
// forwards this solution's requests on, which is also what the authority's
// Check is asked to hold the call to.
func (s *Server) mcpRoute() string { return s.authorityRoute() + MCPPath }

// validateMCPDeclaration refuses what the author declared, before any address
// is resolved and before the listener opens: these are the same in every
// environment. It is also what keeps a route collision from reaching net/http,
// which panics on a duplicate pattern — inside serve(), with http's own message
// and after the listener is open.
func (s *Server) validateMCPDeclaration() error {
	if s.mcp == nil {
		return nil
	}
	if s.mcpRedeclared {
		return fmt.Errorf("ServeMCP was called more than once: there is one MCP endpoint, so the last call would be the only surface served and the tools registered by the others would simply not exist. Register every tool in one ServeMCP")
	}
	if err := s.mcp.validate(); err != nil {
		return err
	}
	for _, op := range s.operations {
		if op.Path == s.mcpRoute() {
			return fmt.Errorf("an operation is declared at %q, which ServeMCP serves: one of the two would have to win, and the solution would serve either its own handler with no MCP endpoint or an MCP endpoint with the handler unreachable. Move the operation to another path", s.mcpRoute())
		}
	}
	return nil
}

// mountMCP serves the MCP endpoint on mux, or does nothing when the solution
// declared no MCP surface.
func (s *Server) mountMCP(mux *http.ServeMux) error {
	if s.mcp == nil {
		return nil
	}
	if err := s.validateMCPDeclaration(); err != nil {
		return fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: s.mcp.name, Version: s.mcp.version}, nil)
	s.mcp.register(srv)
	// Receiving middleware rather than the HTTP context, because this is the
	// seam the SDK documents for carrying per-request state into a handler: it
	// sees the request's own headers (RequestExtra.Header) and the context it
	// passes on is the one the tool handler runs under.
	srv.AddReceivingMiddleware(s.mcpViewer)
	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return srv },
		&mcp.StreamableHTTPOptions{Stateless: true},
	)
	// No CORS on the MCP endpoint: an MCP client is not a browser page, and the
	// runtime's permissive policy (any origin) would be handing a page the one
	// route that acts with the viewer's full authority. POST is the one method
	// published for the route, so it is the one served: the stateless
	// transport answers nothing else, and any other method is refused by name
	// before the transport reads it.
	mux.Handle(s.mcpRoute(), byMethod(s.mcpRoute(), map[string]http.HandlerFunc{
		http.MethodPost: s.requireWorkContext(handler).ServeHTTP,
	}))
	return nil
}

// --- the viewer a tool call runs as ---

type mcpViewerKey struct{}

// ViewerFromContext returns the Gateway bound to the viewer whose MCP request
// this tool call belongs to: the same viewer-bound Gateway a Handler is given,
// so ForParent issues a child of the viewer's own Work Context.
//
// It is the one line a tool handler writes:
//
//	gw, err := solution.ViewerFromContext(ctx)
//	if err != nil {
//	    return nil, out, err
//	}
//	docs, err := gw.ForParent(ctx, "documents", solution.Scope{...})
//
// The error is for a handler invoked outside a request this runtime served —
// a tool called from a test harness of its own, or an *mcp.Server mounted
// without ServeMCP. It never happens on a served request: the middleware
// refuses a call the authority does not admit before any tool runs.
func ViewerFromContext(ctx context.Context) (*Gateway, error) {
	gw, _ := ctx.Value(mcpViewerKey{}).(*Gateway)
	if gw == nil {
		return nil, fmt.Errorf("no viewer in this context: only a request served through ServeMCP supplies a viewer-bound gateway")
	}
	return gw, nil
}

// requireWorkContext answers a request that carries no Work Context at all
// with a plain 401, before the MCP handler reads it: such a request did not
// come through the edge, and a JSON-RPC error would tell a misrouted caller
// nothing about why.
func (s *Server) requireWorkContext(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get(WorkContextHeader) == "" {
			http.Error(w, "no Work Context: this MCP endpoint is reached through the authority's edge, which sends each request on with the person's Work Context for this solution", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// mcpViewer binds each incoming MCP call to the viewer it arrived as, so a tool
// handler reaches modules on their behalf and not as the solution.
//
// The viewer is the authority's Check of the Work Context the request carries,
// naming this endpoint's route so the solution's delivered policy for it
// applies — exactly what wrapRequest asks for a handler route. It is never
// read from the MCP payload: a tool's arguments are written by the model, and
// an identity taken from them would let a client ask for another viewer's
// authority. Every method is checked, the handshake included, because a method
// that acts for nobody costs one Check and a method a future SDK adds is then
// checked rather than exempt.
func (s *Server) mcpViewer(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		header := http.Header{}
		if extra := req.GetExtra(); extra != nil && extra.Header != nil {
			header = extra.Header
		}
		gw, err := s.viewerGateway(ctx, header.Get(WorkContextHeader), http.MethodPost+" "+s.mcpRoute())
		if err != nil {
			log.Printf("solution %q: mcp %s refused: %v", s.manifest.ID, method, err)
			_, message := handlerErrorResponse(err)
			return nil, errors.New(message)
		}
		// The one thing a tool call leaves nowhere else: the authority's audit
		// names the viewer and the module, but not which tool asked, so an
		// operator reading it cannot tell an "ask the wiki" from a bulk export.
		// The name only: arguments are the viewer's content.
		if call, ok := req.(*mcp.CallToolRequest); ok && call.Params != nil {
			log.Printf("solution %q: mcp tool %q", s.manifest.ID, call.Params.Name)
		}
		// A tool's error becomes content the client reads, below this
		// middleware, so the runtime's own errors are sanitized before the
		// author ever holds one. See Gateway.surfaced.
		gw.sanitizeErrors = true

		result, err := next(context.WithValue(ctx, mcpViewerKey{}, gw), method, req)
		// An error RESULT, which is not an error at all as far as this
		// middleware is concerned: the SDK's typed AddTool wrapper turns a
		// tool's returned error into CallToolResult{IsError: true} and returns a
		// NIL err, so the text travels as content. The runtime's own errors are
		// sanitized where they leave its hands (Gateway.surfaced), which removes
		// the authority's words — but a client library prepends the address it
		// dialled to whatever a transport returned, and the author did not
		// author that. This is a net over that one thing: if what a tool is
		// about to tell a client contains an address THIS RUNTIME dialled, the
		// content is replaced wholesale and the original goes to the log.
		if err == nil {
			result = s.withoutRuntimeAddresses(result, method)
		}
		if err != nil {
			// Sanitized on the way out, through the same function the handler
			// routes use: a tool's error is written for a model and read by
			// whoever is driving it.
			_, message := handlerErrorResponse(err)
			log.Printf("solution %q: mcp %s failed: %v", s.manifest.ID, method, err)
			return result, errors.New(message)
		}
		return result, nil
	}
}

// namedInJSON decodes one JSON document and reports the first string value or
// key inside it that names something the given test matches.
//
// Decoded rather than textual, because JSON escaping means the serialized form
// and the form a client reads are not the same string: `https:\/\/host` and
// `https://host` are one value with two spellings, and a search over the bytes
// sees only the one it was given. A document this runtime cannot decode is
// reported as offending for the same reason an unmarshalable value is — it
// cannot be cleared if it cannot be read.
func namedInJSON(document []byte, named func(string) (string, bool)) (string, bool) {
	var decoded any
	if err := json.Unmarshal(document, &decoded); err != nil {
		return "undecodable structured content: " + err.Error(), true
	}
	var walk func(any) (string, bool)
	walk = func(value any) (string, bool) {
		switch typed := value.(type) {
		case string:
			if _, found := named(typed); found {
				return typed, true
			}
		case []any:
			for _, item := range typed {
				if offending, found := walk(item); found {
					return offending, true
				}
			}
		case map[string]any:
			for key, item := range typed {
				// The KEY as well: a map keyed by the address discloses it
				// just as a value does.
				if _, found := named(key); found {
					return key, true
				}
				if offending, found := walk(item); found {
					return offending, true
				}
			}
		}
		return "", false
	}
	return walk(decoded)
}

// withoutRuntimeAddresses replaces an error result that names an address this
// runtime dialled: the authority, or a relayed module's hop.
//
// Only an IsError result, and only when the text contains one of those
// addresses: a tool's own refusal is its own to word, and rewriting every error
// result would take that away.
func (s *Server) withoutRuntimeAddresses(result mcp.Result, method string) mcp.Result {
	call, ok := result.(*mcp.CallToolResult)
	if !ok || call == nil || !call.IsError {
		return result
	}
	// The TEXT content, and the STRUCTURED content: the SDK serializes both,
	// and structured content is arbitrary JSON, so it is rendered once and
	// searched as a whole rather than walked field by field.
	named := func(text string) (string, bool) {
		for _, dialled := range s.cfg.dialled {
			if dialled != "" && strings.Contains(text, dialled) {
				return dialled, true
			}
		}
		return "", false
	}
	replaced := func(where, offending string) mcp.Result {
		log.Printf("solution %q: an MCP %s error result named an address this runtime dialled (in its %s); replaced: %s",
			s.manifest.ID, method, where, offending)
		return &mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{
				Text: "this solution could not complete the call",
			}},
		}
	}
	// SERIALIZE EVERYTHING FIRST, THEN INSPECT, THEN PUBLISH AN OWNED SNAPSHOT.
	//
	// The order is the whole fix. A MarshalJSON answering differently the
	// second time disclosed on the second call; a structured value holding a
	// pointer to the result's own *mcp.TextContent rewrote the text, from inside
	// MarshalJSON, after it had passed inspection. So every marshaller runs
	// first, nothing is inspected that is not about to be published, and what
	// is published is a value built here from strings and bytes this runtime
	// owns. Nothing the caller still holds a pointer to can change it, and no
	// marshaller is asked twice.
	var rendered []byte
	if call.StructuredContent != nil {
		// Marshalling failure is itself a reason to replace: a structured
		// value this runtime cannot read is one it cannot clear either, and
		// the SDK is about to serialize it.
		var err error
		if rendered, err = json.Marshal(call.StructuredContent); err != nil {
			return replaced("structured content", "unreadable structured content: "+err.Error())
		}
	}
	// Only now are the texts read, and they are COPIED as they are read, so
	// what is inspected below and what is published are the same strings.
	snapshot := make([]mcp.Content, 0, len(call.Content))
	for _, content := range call.Content {
		text, isText := content.(*mcp.TextContent)
		if !isText {
			// Content this runtime cannot read is content it cannot clear.
			// Replacing is the fail-closed answer: the alternative is
			// publishing a type whose serialization nothing here inspected.
			return replaced("non-text content", fmt.Sprintf("%T", content))
		}
		snapshot = append(snapshot, &mcp.TextContent{
			Text:        text.Text,
			Annotations: text.Annotations,
			Meta:        text.Meta,
		})
	}
	for _, content := range snapshot {
		text := content.(*mcp.TextContent)
		if _, found := named(text.Text); found {
			return replaced("text content", text.Text)
		}
	}
	if rendered != nil {
		// The DECODED strings, not the serialization: JSON has more than one
		// spelling for the same string, and the client decodes the address
		// back out of whichever one was used.
		if offending, found := namedInJSON(rendered, named); found {
			return replaced("structured content", offending)
		}
	}
	clean := &mcp.CallToolResult{
		IsError: true,
		Content: snapshot,
		Meta:    call.Meta,
	}
	if rendered != nil {
		clean.StructuredContent = json.RawMessage(rendered)
	}
	return clean
}
