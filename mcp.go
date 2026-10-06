package solution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	codefly "github.com/codefly-dev/sdk-go"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
	"golang.org/x/net/idna"
)

// --- MCP ---
//
// A solution exposes its experience to an agent client the way it exposes it to
// a browser: as the signed-in person, through the host's gateway, with the same
// authority. The solution owns its tool surface; this runtime owns serving it.
//
// Nothing MCP-specific lives in the host's gateway, and no token verification
// lives here: the gateway strips caller identity headers, authenticates the
// bearer and stamps the viewer's identity, exactly as it does for every other
// request this runtime serves. The MCP surface reads that stamped identity and
// refuses a request that arrives without it — it never inspects the bearer.

const (
	// MCPPath is where the MCP endpoint serves, relative to the solution's own
	// backend. Through the gateway that is /solutions/<id>/mcp, the route the
	// gateway already fronts.
	MCPPath = "/mcp"

	// ProtectedResourceMetadataPath is where the OAuth 2.0 Protected Resource
	// Metadata document (RFC 9728) serves, at the well-known location a client
	// discovers it at. It is the document a 401 challenge points to, so a
	// client that cannot reach it cannot learn which authorization server to
	// use: it is served without authentication, and the gateway must admit it
	// unauthenticated for discovery to work at all. Through the gateway that
	// challenge is the gateway's own — see requireStampedViewer — and this is
	// the document it has to name.
	ProtectedResourceMetadataPath = "/.well-known/oauth-protected-resource"
)

// userHeader carries the viewer's user id, and credentialKindHeader the kind of
// credential the gateway authenticated. They are the other half of the identity
// the gateway stamps from verified claims (see orgHeader and sessionHeader,
// which the Work Context mint is built on) and replace anything the caller sent.
//
// Only the MCP surface reads them, for one refusal each: nothing stamped at all
// means the request did not come through the gateway, and a credential kind that
// authenticates without a session cannot act for a viewer at all.
const (
	userHeader           = "x-user-id"
	credentialKindHeader = "x-credential-kind"
)

// mcpSurface is the MCP server a solution declared with ServeMCP.
type mcpSurface struct {
	name, version string
	register      func(*mcp.Server)
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
	return nil
}

// ServeMCP exposes the solution as an MCP server over stateless Streamable HTTP
// at MCPPath, with the RFC 9728 Protected Resource Metadata document that lets a
// client discover how to authenticate. Chainable, like Handle.
//
// name and version identify the server to a client. register adds the tools,
// prompts and resources the solution offers, on the official SDK's own
// *mcp.Server — the solution's tool surface is its own, and this runtime adds
// nothing to it.
//
// Every tool call runs as the viewer who made the request: ViewerFromContext
// returns the same caller-bound Gateway a Handler is given, so a tool reads a
// composed module through ForModule exactly as the page does, under the viewer's
// own Work Context and no more authority than it asks for.
//
// Sessions are stateless because the gateway is a reverse proxy with no sticky
// routing: a session held in one replica's memory is unreachable from the next
// request, so the MCP session would break under any rollout or scale-out. Each
// request carries its own identity, which is all a tool call needs.
func (s *Server) ServeMCP(name, version string, register func(*mcp.Server)) *Server {
	// A second call is not a second server — there is one MCP endpoint — so it
	// replaces the first. Recorded rather than applied silently, and refused at
	// boot by validateMCPDeclaration: a solution assembled from two places,
	// each declaring its own tools, would otherwise serve only the tools of
	// whichever ran last, with tools/list answering as if that were all there
	// is. ServeMCP cannot return the error itself, being chainable.
	if s.mcp != nil {
		s.mcpRedeclared = true
	}
	s.mcp = &mcpSurface{name: name, version: version, register: register}
	return s
}

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
	for _, path := range []string{MCPPath, ProtectedResourceMetadataPath} {
		if _, taken := s.handlers[path]; taken {
			return fmt.Errorf("a handler is registered at %q, which ServeMCP serves: one of the two would have to win, and the solution would serve either its own handler with no MCP endpoint or an MCP endpoint with the handler unreachable. Move the handler to another path", path)
		}
	}
	return nil
}

// mountMCP serves the MCP endpoint and its metadata document on mux, or does
// nothing when the solution declared no MCP surface.
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
	// runtime's permissive policy (any origin, with the authorization header)
	// would be handing a page the one route that acts with the viewer's full
	// authority. The metadata document does carry CORS — discovery is public
	// (RFC 9728 §3.1) — and the SDK's own handler sets it.
	mux.Handle(MCPPath, s.requireStampedViewer(handler))
	mux.Handle(ProtectedResourceMetadataPath, http.HandlerFunc(s.handleProtectedResourceMetadata))
	if s.cfg.mcpPublicURL == "" {
		// The one signal that this is happening. The resource identifier a
		// client binds its token to must be the URL the client dialled; with
		// no PUBLIC_URL to derive it from and no override declared, the runtime
		// can only reconstruct it from what the proxy forwards, and a gateway
		// that forwards no prefix yields an identifier missing the path it
		// stripped — which a conforming client rejects and a tolerant one
		// silently binds to the wrong resource.
		log.Printf("solution %q: MCP resource identifier derived per request from forwarded headers (no PUBLIC_URL and no %s): set PUBLIC_URL to the origin clients reach this product at, so the identifier is %q",
			s.manifest.ID, mcpConfigurationValue(MCPPublicURLKey), hostSolutionPublicMCPURL("https://<host>", s.manifest.ID))
	}
	return nil
}

// MCPEnvironment is what Serve resolves from the composition for the MCP
// surface, supplied instead by a caller of mcpHandler.
type MCPEnvironment struct {
	// GatewayURL is the host gateway a tool call's Work Context is minted
	// through and its composed-module reads go to.
	GatewayURL string
	// IssuerURL is the host's OAuth issuer, published as the authorization
	// server in the metadata document.
	IssuerURL string
	// PublicURL is the canonical public MCP URL, which Serve derives from the
	// resolved PUBLIC_URL and this solution's id. Empty derives it from each
	// request's forwarded headers, as it does when Serve has neither.
	PublicURL string
}

// mcpHandler is the MCP surface exactly as Serve serves it, for a test in this
// package.
//
// NOT exported, and it must not become so. It was `MCPHandler`, and its only
// callers are tests: an exported method that hands back a servable handler is
// the PassthroughHandler defect again — whoever mounts it serves the viewer's
// bearer and this workload's credential over whatever they mounted it on,
// having skipped validate(), the mTLS boot, the caller allow-list, the ceiling
// and authenticated outbound. This one also writes boot configuration from
// values its caller supplies, which is the one thing loadConfig exists to be
// the only source of.
//
// It is the same endpoint, the same metadata document, the same refusals,
// mounted by the same code, against an environment the caller supplies instead
// of the one Serve resolves. Nothing else of the solution is served, and
// nothing registers anywhere.
//
// TestNoExportedPathHandsOutAServableHandler fails if an exported path
// reappears; it is what caught this.
//
// It exists for tests: a solution drives its own tools under the runtime's
// identity handling, with a fake host standing in for the gateway. A solution
// serves with Serve, which overwrites the environment set here when it resolves
// its own.
func (s *Server) mcpHandler(env MCPEnvironment) (http.Handler, error) {
	if s.mcp == nil {
		return nil, fmt.Errorf("solution %q declares no MCP server (ServeMCP)", s.manifest.ID)
	}
	s.cfg.gatewayURL, s.cfg.mcpIssuerURL, s.cfg.mcpPublicURL = env.GatewayURL, env.IssuerURL, env.PublicURL
	// And the derived set, because this overwrites what it was derived FROM.
	//
	// cfg.dialled is assembled in loadConfig; assigning the gateway URL here
	// without rebuilding it left the set empty on exactly the seam a consumer
	// runs, so the net that stops a tool naming an address this runtime
	// dialled was silently off there. A derived field whose sources are
	// reassigned is stale until it is not.
	s.cfg.dialled = dialledAddresses(s.cfg.gatewayURL, s.cfg.mintURL)
	// The caller named both, so they are as explicit as the composition's
	// declared values: what validate() refuses is an issuer nobody chose, and
	// what a refusal has to name for a public URL is whoever set it.
	s.cfg.mcpIssuerExplicit = env.IssuerURL != ""
	s.cfg.mcpPublicExplicit = env.PublicURL != ""
	s.cfg.mcp = true
	if err := s.cfg.validateMCP(); err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	mux := http.NewServeMux()
	if err := s.mountMCP(mux); err != nil {
		return nil, err
	}
	return mux, nil
}

// --- the viewer a tool call runs as ---

type mcpViewerKey struct{}

// ViewerFromContext returns the Gateway bound to the viewer whose MCP request
// this tool call belongs to: the same caller-bound Gateway a Handler is given,
// carrying the viewer's bearer and the organization and session the gateway
// stamped, so ForModule mints the viewer's own Work Context.
//
// It is the one line a tool handler writes:
//
//	gw, err := solution.ViewerFromContext(ctx)
//	if err != nil {
//	    return nil, out, err
//	}
//	docs, err := gw.ForModule(ctx, "documents", solution.Scope{...})
//
// The error is for a handler invoked outside a request this runtime served —
// a tool called from a test harness of its own, or an *mcp.Server mounted
// without ServeMCP. It never happens on a served request: the endpoint refuses
// one without a stamped identity before any tool runs.
func ViewerFromContext(ctx context.Context) (*Gateway, error) {
	gw, _ := ctx.Value(mcpViewerKey{}).(*Gateway)
	if gw == nil {
		return nil, fmt.Errorf("no viewer in this context: a tool handler receives one only on a request served through ServeMCP, which reads the identity the host gateway stamped")
	}
	return gw, nil
}

// actsForNobody reports whether an MCP method runs nothing on a viewer's
// behalf: the handshake, the keepalive, and the listings that describe what
// this solution declares.
//
// Everything else is held to this execution's credential. The list is what a
// method must be ON to skip that check, so a method nobody here has heard of is
// checked.
func actsForNobody(method string) bool {
	switch method {
	// The handshake, the keepalive and the listings that describe what this
	// solution declares.
	case "initialize", "ping",
		"tools/list", "prompts/list", "resources/list", "resources/templates/list",
		// The notifications the SDK itself sends, named one by one.
		//
		// This was strings.HasPrefix(method, "notifications/"), which is a
		// DENYLIST wearing an allowlist's clothes: the namespace is open, the
		// SDK's extension API lets author code register methods under it, and
		// one registered there would have run with a viewer's gateway and no
		// credential check — the round-nine defect, still reachable. An exact
		// list cannot be widened by someone else's naming.
		"notifications/initialized", "notifications/cancelled",
		"notifications/progress", "notifications/roots/list_changed":
		return true
	}
	return false
}

// mcpCredentialUnavailableCode is what an MCP client is told when this process
// will not act for a viewer: -32001, in JSON-RPC's implementation-defined
// server range, beside the SDK's own CodeResourceNotFound (-32002).
//
// I claimed this could not be set because the SDK's wire-error type was
// internal. That was wrong, and wrong because I grepped for the type and
// stopped: package jsonrpc exports it as an alias
// (jsonrpc.Error = jsonrpc2.WireError) precisely so a server can set a code. A
// client that only gets a generic protocol error cannot tell "this solution
// cannot act right now" from a broken tool, so it cannot back off.
const mcpCredentialUnavailableCode = -32001

// mcpViewer binds each incoming MCP request to the viewer it arrived as, so a
// tool handler reads composed modules on their behalf and not as the solution.
//
// The identity comes from the headers the gateway stamped from verified claims,
// never from the MCP payload: a tool's arguments are written by the model, and a
// session id taken from them would let a client ask for another viewer's
// authority. A request that reached here has already been refused if it carried
// no stamped identity (see requireStampedViewer).
func (s *Server) mcpViewer(next mcp.MethodHandler) mcp.MethodHandler {
	return func(ctx context.Context, method string, req mcp.Request) (mcp.Result, error) {
		header := http.Header{}
		if extra := req.GetExtra(); extra != nil && extra.Header != nil {
			header = extra.Header
		}
		// The one thing a tool call leaves nowhere else. Minting is audited on
		// accounts and names the viewer and the module, but not which tool
		// asked — so an operator reading that audit cannot tell a single
		// lookup from a bulk export. The name only: arguments are the viewer's
		// content and the headers carry their credentials.
		if call, ok := req.(*mcp.CallToolRequest); ok && call.Params != nil {
			log.Printf("solution %q: mcp tool %q", s.manifest.ID, call.Params.Name)
		}
		// Through gatewayFor, not newGateway. A raw gateway carries the
		// viewer's headers and nothing else: no credential acquirer, so a tool
		// call could not attest which module was asking; no attestation report
		// and no terminal hook; and — the one that matters most — none of the
		// published contract's ceilings, so a mint from an MCP tool call was
		// held to nothing the contract claims. Every other path a viewer
		// reaches this runtime on is built here, and this one has to be too.
		gw := s.gatewayFor(header)
		// A tool's error becomes content the client reads, below this
		// middleware, so the runtime's own errors are sanitized before the
		// author ever holds one. See Gateway.surfaced.
		gw.sanitizeErrors = true
		// The credential gate, before anything author-written runs.
		//
		// This is R4-3 on the MCP path, and it arrived with the surface rather
		// than being missed in it: a plain handler and a ViewerBearer
		// passthrough are both held here, and a tool call was not. A tool
		// receives a gateway carrying the viewer's bearer, so running one while
		// the issuer has withdrawn this execution's credential is acting for a
		// viewer without authority — and a tool that mints nothing still sends
		// that bearer wherever it dials.
		//
		// An ALLOWLIST of the methods that act for nobody, not a denylist of
		// the ones that act. A denylist over a method set this package does not
		// own is the mistake the TLS posture made three times: whatever it does
		// not name, the far side keeps. A method the SDK adds tomorrow is gated
		// here by default, and the cost of that being wrong is a refusal rather
		// than an ungated viewer action.
		if !actsForNobody(method) {
			if err := s.actingForAViewer(ctx); err != nil {
				// The sanitized sentence, not the error: it wraps whatever the
				// source said — a mint URL, an issuer's own text, a dial
				// failure naming an internal address — and an MCP client is as
				// much a viewer's channel as a browser is.
				log.Printf("solution %q: refusing an MCP %s for a viewer: %v", s.manifest.ID, method, err)
				return nil, &jsonrpc.Error{
					Code:    mcpCredentialUnavailableCode,
					Message: credentialRefusalForAViewer(err),
				}
			}
		}
		result, err := next(context.WithValue(ctx, mcpViewerKey{}, gw), method, req)
		// An error RESULT, which is not an error at all as far as this
		// middleware is concerned.
		//
		// The SDK's typed AddTool wrapper turns a tool's returned error into
		// CallToolResult{IsError: true} and returns a NIL err, so the branch
		// below never runs on that path and the text travels as content. The
		// runtime's own errors are sanitized where they leave its hands now
		// (Gateway.surfaced, bearerTransport), which removes the issuer's
		// words — but http.Client.Do prepends the URL it dialled to whatever
		// the transport returned, and the author did not author that.
		//
		// So this is a net over the one thing left: if what a tool is about to
		// tell a client contains an address THIS RUNTIME configured, the
		// content is replaced wholesale and the original goes to the log. It
		// matches on exact values the runtime knows — its gateway and mint
		// URLs — not on a pattern, so a tool's own message about its own
		// domain is untouched.
		//
		// It is a net and not the boundary. The boundary is surfaced; this
		// catches what net/http adds after it.
		if err == nil {
			result = s.withoutRuntimeAddresses(result, method)
		}
		if err != nil {
			// Sanitized on the way out, through the same function the handler
			// routes use. A tool that called ForModule and was refused handed
			// the viewer's agent client the whole chain: "mint returned HTTP
			// 503", and with the issuer unreachable the mint's own URL and
			// dial address. The gate above stops a tool running without a
			// credential; this stops what a tool learned about the issuer
			// reaching the client when one fails mid-call.
			//
			// The author's own errors are sanitized by the same rule as a
			// handler's, which is what that rule is for: a tool's error is
			// written for a model and read by whoever is driving it.
			_, message := handlerErrorResponse(err)
			log.Printf("solution %q: mcp %s failed: %v", s.manifest.ID, method, err)
			return result, errors.New(message)
		}
		return result, nil
	}
}

// --- the identity the gateway stamps ---

// mcpIdentity is one MCP request's caller, as the gateway presented it.
type mcpIdentity struct {
	bearer, userID, orgID, sessionID, credentialKind string
}

func stampedIdentity(h http.Header) mcpIdentity {
	return mcpIdentity{
		bearer:         h.Get("authorization"),
		userID:         h.Get(userHeader),
		orgID:          h.Get(orgHeader),
		sessionID:      h.Get(sessionHeader),
		credentialKind: h.Get(credentialKindHeader),
	}
}

// stamped reports whether the gateway named this caller at all. Any one of the
// three is enough: the question this answers is whether the request came through
// the gateway, and which of them a given credential gets stamped with is the
// gateway's business — an org-less API key is stamped a principal and no org.
func (i mcpIdentity) stamped() bool {
	return i.userID != "" || i.orgID != "" || i.sessionID != ""
}

// apiKeyCredentialKind is the credential kind the gateway stamps for a caller
// that authenticated with an organization API key: a principal and no session.
const apiKeyCredentialKind = "api_key"

// requireStampedViewer refuses an MCP request the gateway did not authenticate,
// and one whose credential cannot act for a viewer.
//
// This is the whole of the runtime's authentication for MCP: the gateway runs
// ext_authz on the bearer and stamps the result, so verifying the token again
// here would be a second, divergent implementation of the host's admission
// rules — with its own JWKS fetch, its own audience logic, and its own bugs.
// What is enforced here is that the gateway did it.
func (s *Server) requireStampedViewer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := stampedIdentity(r.Header)
		switch {
		case id.bearer == "":
			// Not the request an MCP client makes through the gateway: the
			// gateway runs ext_authz before it proxies, so an unauthenticated
			// request is denied there and never arrives. What reaches here
			// without a bearer is a caller dialling this solution directly — a
			// local run, a port-forward — and the challenge is both the only
			// answer that tells such a caller where to authenticate and the
			// shape the gateway's own has to match.
			s.challenge(w, r, "no bearer token: this MCP server is a protected resource")
			return
		case !id.stamped():
			// A bearer arrived but no identity did, so either this request did
			// not come through the host gateway — nothing else may reach this
			// endpoint, and no header a caller sends is trusted here — or the
			// gateway did not authenticate it. Answering the challenge rather
			// than a bare 401 leaves a caller that reached the wrong address
			// something to act on.
			s.challenge(w, r, fmt.Sprintf("no stamped identity: the host gateway authenticates the bearer and stamps %s, %s and %s, and none of them arrived",
				userHeader, orgHeader, sessionHeader))
			return
		case id.sessionID == "":
			// Not fixable by getting another token, so not a challenge: this
			// credential authenticates without a session, and every tool call
			// that acts for the viewer mints a Work Context rooted in one
			// (accounts requires a Task to name a session). Named by kind,
			// because the kind is what the caller has to change.
			// The kind is named as the gateway stamped it, and nothing is
			// asserted about which kind it is: told about an API key, a caller
			// whose credential is of some other kind goes looking for an API
			// key it does not have, and the one fact that would have helped —
			// what the gateway actually stamped — is the one the message
			// replaced with a guess.
			stamped := fmt.Sprintf("%s=%q", credentialKindHeader, id.credentialKind)
			if id.credentialKind == "" {
				stamped = credentialKindHeader + " empty"
			}
			detail := ""
			if id.credentialKind == apiKeyCredentialKind {
				detail = " — an organization API key names a principal and no session"
			}
			http.Error(w, fmt.Sprintf("MCP requires a user session: the gateway stamped %s and %s empty%s. A credential that authenticates without a session cannot act for a viewer: every tool call that does mints a Work Context rooted in one. Connect as a signed-in person.",
				stamped, sessionHeader, detail), http.StatusForbidden)
			return
		}
		// And this execution's own credential, at the HTTP boundary.
		//
		// The method-layer gate in mcpViewer refuses the same thing, and both
		// are here on purpose. This one answers a real HTTP 503, which
		// JSON-RPC has no equivalent for at all, and it holds anything that
		// reaches this handler without going through the method middleware.
		//
		// The method layer is not codeless: it carries -32001 through
		// jsonrpc.Error. This comment said the SDK's wire-error type was
		// internal and a code could not be set, which was my own false claim —
		// I grepped for the type, found internal/jsonrpc2, and stopped looking
		// for the exported alias. Corrected in the code one commit and left
		// standing here.
		if err := s.actingForAViewer(r.Context()); err != nil {
			// The sanitized sentence, never the source's error: it wraps
			// whatever the issuer said, which is a mint URL and sometimes a
			// dial failure naming an internal address. An agent client is a
			// viewer's channel like a browser is, and this was the disclosure
			// executed round eight reproduced.
			log.Printf("solution %q: refusing an MCP request for a viewer: %v", s.manifest.ID, err)
			http.Error(w, credentialRefusalForAViewer(err), http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// challenge answers 401 with the RFC 9728 pointer to this resource's metadata
// document, the way a protected resource says which authorization server to
// authenticate against (RFC 9728 §5.1). The URL is absolute and names the
// resource as the caller reached it, so one following it arrives back here
// rather than at an address only the cluster can dial.
//
// Through the gateway nothing unauthenticated gets this far, so this is the
// direct and local caller's answer, and the shape the gateway's own challenge
// has to match (codefly-dev/module-saas-starter#1003). It is kept here rather
// than dropped because a solution reached directly would otherwise answer a
// bare 401 that names nothing.
func (s *Server) challenge(w http.ResponseWriter, r *http.Request, message string) {
	metadata := siblingURL(s.mcpResource(r), MCPPath, ProtectedResourceMetadataPath)
	if metadata != "" {
		w.Header().Add("WWW-Authenticate", fmt.Sprintf("Bearer resource_metadata=%q", metadata))
	}
	http.Error(w, message, http.StatusUnauthorized)
}

// handleProtectedResourceMetadata serves the RFC 9728 document for this MCP
// resource: the identifier a client binds its token to, and the authorization
// server it gets that token from.
//
// The document is built per request because the resource identifier can only be
// derived from the request when no canonical URL is configured. The
// authorization server never is: it is the host issuer resolved at boot, so a
// crafted Host header cannot point a client at an issuer of someone's choosing.
func (s *Server) handleProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	auth.ProtectedResourceMetadataHandler(&oauthex.ProtectedResourceMetadata{
		Resource:               s.mcpResource(r),
		AuthorizationServers:   []string{s.cfg.mcpIssuerURL},
		BearerMethodsSupported: []string{"header"},
		ResourceName:           s.manifest.Title,
	}).ServeHTTP(w, r)
}

// mcpResource is this endpoint's resource identifier: the absolute URL an MCP
// client dialled to get here.
//
// It is what the client asks the authorization server for a token for (RFC 8707)
// and what the metadata document must name, so it has to be the public URL — not
// this process's listen address and not the in-cluster address the gateway dials.
// So it is the public MCP URL resolved at boot: derived from PUBLIC_URL and this
// solution's id, or the override the composition declared (see
// resolveMCPPublicURL). With neither it is reconstructed from what the proxy in
// front of this solution forwarded, which validate() refuses in a deployment.
func (s *Server) mcpResource(r *http.Request) string {
	if s.cfg.mcpPublicURL != "" {
		return s.cfg.mcpPublicURL
	}
	return forwardedOrigin(r) + forwardedPrefix(r) + MCPPath
}

const (
	forwardedProtoHeader  = "x-forwarded-proto"
	forwardedHostHeader   = "x-forwarded-host"
	forwardedPrefixHeader = "x-forwarded-prefix"
)

// forwardedOrigin is the scheme and host the client used, as the proxy in front
// of this solution reported them, falling back to the request's own. These
// headers are only worth reading because the one route to this endpoint is the
// host gateway; what a caller could do by crafting them is misname the resource
// identifier in its own 401 and its own metadata document, never redirect
// anyone to an authorization server of its choosing.
func forwardedOrigin(r *http.Request) string {
	// Only the two schemes an HTTP resource can be dialled over. A forwarded
	// proto is a hop's claim about the client's connection, and anything else
	// would be spliced in front of "://" — "javascript" included, which is a
	// URL a client might hand to something that executes it.
	scheme := strings.ToLower(firstForwarded(r, forwardedProtoHeader))
	if scheme != "http" && scheme != "https" {
		scheme = "http"
		if r.TLS != nil {
			scheme = "https"
		}
	}
	host := firstForwarded(r, forwardedHostHeader)
	// A forwarded host that is not a host is not usable: it would be spliced
	// into the middle of the identifier, where a space or a slash makes the
	// rest of the URL mean something else. The request's own host is what the
	// identifier is built from then.
	if !validHost(host) {
		host = r.Host
	}
	return scheme + "://" + host
}

// validHost reports whether raw is a plain host[:port] — enough to be
// concatenated into an origin without changing where the URL points.
func validHost(raw string) bool {
	if raw == "" || len(raw) > 253+6 {
		return false
	}
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c <= ' ', c >= 0x7f, c == '/', c == '?', c == '#', c == '@', c == '\\':
			return false
		}
	}
	return true
}

// forwardedPrefix is the path the proxy stripped before this solution saw the
// request — "/solutions/<id>" at the host gateway. Empty when nothing forwarded
// one, which is why the identifier is derived at boot rather than per request
// wherever PUBLIC_URL resolves: a gateway that forwards no prefix leaves this
// the only input, and it has none.
func forwardedPrefix(r *http.Request) string {
	prefix := strings.TrimRight(firstForwarded(r, forwardedPrefixHeader), "/")
	// A prefix that is not a plain absolute path is not a prefix: "//evil.test"
	// is a protocol-relative URL, and anything with a query, a fragment or a
	// space does not belong in a URL path. None of them can be repaired, so the
	// identifier is built without the prefix and is refused by the client for
	// not matching what it dialled — loud, where a sanitized guess would be a
	// resource identifier that looks right and names something else.
	if !pathPrefix(prefix) {
		return ""
	}
	return prefix
}

// pathPrefix reports whether raw is a plain absolute URL path: one that can be
// concatenated in front of MCPPath and still address this resource.
func pathPrefix(raw string) bool {
	if !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") {
		return false
	}
	for i := 0; i < len(raw); i++ {
		switch c := raw[i]; {
		case c <= ' ', c >= 0x7f, c == '?', c == '#', c == '\\':
			return false
		}
	}
	return true
}

// firstForwarded is the first value of a forwarded header, which a chain of
// proxies appends to: the client-most hop, comma-separated or repeated.
func firstForwarded(r *http.Request, name string) string {
	raw := r.Header.Get(name)
	if comma := strings.IndexByte(raw, ','); comma >= 0 {
		raw = raw[:comma]
	}
	return strings.TrimSpace(raw)
}

// --- boot configuration ---

// MCPConfigurationGroup names the workspace-configuration group a composition
// declares for a solution that serves MCP, and MCPIssuerURLKey and
// MCPPublicURLKey the two values in it. They are resolved through the SDK
// because a Codefly composition has no way to set a bare environment variable
// on a service: every value a service receives is either an endpoint the SDK
// resolves or a declared configuration the render projects. Both were read as
// bare environment variables when ServeMCP landed, which named a provisioning
// path that does not exist.
//
// This used to say "the way the registration secret is", naming
// SolutionRegistrationSecretGroup. That group and the registrations it fed are
// deleted; the comparison outlived the thing it compared to.
//
// MCPIssuerURLKey is the origin MCP clients authenticate against — the host as
// an authorization server. A deployment must supply it: what the SDK resolves
// is the address this composition dials the host at, in-cluster and reachable
// by no client. It is the one value a composition has to declare for MCP, and
// it stops being one when module-saas-starter#1003 settles what `iss` is.
//
// MCPPublicURLKey is the public MCP URL. A deployed MCP surface must declare
// it: the runtime can derive one from PUBLIC_URL, but the derivation builds
// <PUBLIC_URL>/api/solutions/<id>/proxy/mcp, which encodes the route the HOST
// serves this solution on — a layout this runtime does not know. The derivation
// stands for a local run, where whoever made the guess can check it.
//
// A declared value is published verbatim. It is the resource identifier, which
// RFC 9728 §3.3 has a client compare code point for code point against the URL
// it dialled, so "…/mcp/" and "…/mcp" are two different identifiers and only
// one of them can be the one a client reached. Trimming the trailing slash
// turned the first into the second and published an identifier nobody declared
// and no client dialled, which is a 401 on a document that validates.
//
// It must end in MCPPath, because the metadata document's own URL is derived
// from it by swapping that suffix, and a value that cannot be paired is
// refused at boot rather than guessed at. The pairing is siblingURL, which the
// deleted registration token URLs used for the same reason — it is the only
// caller left.
const (
	MCPConfigurationGroup = "mcp"
	MCPIssuerURLKey       = "issuer-url"
	MCPPublicURLKey       = "public-url"
)

// hostSolutionProxyRoute and hostSolutionProxySuffix bracket the host's PUBLIC
// route to a solution's backend, "/api/solutions/<id>/proxy" — the one piece of
// the host's route layout this runtime does encode, and only for the resource
// identifier.
//
// It is the PUBLIC route, not the gateway's internal one. The host's gateway
// fronts a solution under "/solutions/<id>" in-cluster, but that prefix is not
// reachable from outside: on the host's public origin it is a page of the
// host's frontend, so a client dialling it does not arrive here. This runtime
// derived that in-cluster prefix and published it, and the published identifier
// is the one thing a client cannot work around — RFC 9728 §3.3 has it compare
// the identifier in this document against the URL it dialled, so discovery
// stopped there. Both the derivation and the value this package SUGGESTS to an
// operator were the unreachable route; the suggestion is worse, because it
// reads as the answer and provisions the same failure by hand.
//
// Everywhere else it deliberately encodes nothing: the manifest URL is
// registered root-relative and the host resolves it against the route it
// reached the solution by (see frontendManifestURL). An MCP client cannot do
// that — it has only this document. The resource identifier is what its token
// is audience-bound to (RFC 8707), so it has to be byte-exact with the URL the
// client dialled, and a client handed any other identifier rejects it.
//
// These are compiled constants, so the identifier tracks PUBLIC_URL but not a
// change to the host's route shape. That gap is why a DEPLOYED surface must
// declare MCPPublicURLKey rather than derive anything (see validateMCP): the
// route is the host's to resolve and this runtime does not know it. What
// remains derived is the local run, where whoever made the guess can check it,
// and the suggestion in that boot log. Nothing projects the route to a composed
// solution's backend today — the SDK resolves endpoints as
// resources.NetworkInstance (host, hostname, port, address; no path), a
// basev0.Endpoint carries no public URL or route template, and core's one
// public-route concept, resources.EnvironmentIngressRoute, binds hosts to a
// service endpoint, is CLI-side and is not serialized to proto. Closing it
// belongs to the host that serves "/api/solutions/<id>/proxy", projecting that
// route as resolved configuration for this runtime to consume and refuse by its
// provisioning key. TestMCPIdentifierNamesTheHostsPublicProxyRoute pins these
// against a literal so nobody changes them here unnoticed — and that is all it
// can do: this module has no dependency on the host, so if the HOST changes its
// route, this repository stays green and a client's discovery breaks.
//
// NO automated alarm covers that case today. The test for it has to compare the
// host's OWN rendered solution-proxy route against the identifier this runtime
// advertises, and fail when either side moves — which it can only do where the
// host is visible, so it belongs in module-saas-starter and not here. Until it
// exists, a host route change is caught by whoever notices that discovery
// stopped working.
//
// What bounds the exposure meanwhile is the refusal below, and it — not a test
// — is the mitigation: a DEPLOYED surface DECLARES the identifier, so no cell
// depends on these constants at all. What they govern is a local run, where the
// person who made the guess can check it, and the value the boot log suggests.
// Carried as an ACCEPTED limitation; the specification for closing it is in
// README's resource-identifier section.
const (
	hostSolutionProxyRoute  = "/api/solutions/"
	hostSolutionProxySuffix = "/proxy"
)

// hostSolutionPublicMCPURL is the identifier a client dials for the solution
// id, on the given origin: the host's public proxy route plus MCPPath.
func hostSolutionPublicMCPURL(origin, id string) string {
	return strings.TrimRight(origin, "/") + hostSolutionProxyRoute + id +
		hostSolutionProxySuffix + MCPPath
}

// mcpConfigurationValue names one value in the group above, as a refusal and
// the README both name it: group/key, never an environment variable.
func mcpConfigurationValue(key string) string {
	return MCPConfigurationGroup + "/" + key
}

// resolveMCPPublicURL is the canonical public MCP URL: the URL an MCP client
// dials, which is the resource identifier its token is bound to.
//
// It is derived by construction from the origin this product is reachable at
// and this solution's id — PUBLIC_URL + the host's public proxy route + MCPPath —
// so a composition that renders a solution serving MCP declares nothing for
// it. Empty when PUBLIC_URL resolved nothing and no override was declared,
// which validate() refuses in a deployed runtime context: the identifier would
// then be reconstructed per request from the forwarded headers.
//
// The declared override wins, for a host whose gateway routes solutions
// elsewhere. It is read through the SDK rather than from the environment for
// the reason the group's doc comment gives, and it is returned exactly as
// declared: only surrounding whitespace is dropped, which a URL cannot contain
// and a carrier can pick up. Nothing inside the string is normalised, for the
// reason MCPPublicURLKey's comment gives — validateMCP refuses what cannot be
// paired instead, naming the declaration.
func resolveMCPPublicURL(ctx context.Context, publicURL, id string) (string, bool) {
	if declared, err := codefly.For(ctx).WorkspaceConfiguration(MCPConfigurationGroup, MCPPublicURLKey); err == nil {
		if declared = strings.TrimSpace(declared); declared != "" {
			return declared, true
		}
	}
	if publicURL == "" || id == "" {
		return "", false
	}
	return hostSolutionPublicMCPURL(publicURL, id), false
}

// resolveMCPIssuer is the host's OAuth issuer, published as this resource's
// authorization server, and whether the composition declared it. The declared
// value wins over the resolved host frontend origin; the boolean is what tells
// a deployment that was told the origin clients authenticate against from one
// that resolved the host's in-cluster address, which validate() refuses.
//
// The SDK's error is dropped for the reason solutionRegistrationSecret drops
// it: it is the same "no workspace configuration value" whether the group was
// never declared or its carriers never loaded, and the one signal that
// distinguishes them is config.environmentLoadErr.
func resolveMCPIssuer(ctx context.Context, frontendURL string) (string, bool) {
	if declared, err := codefly.For(ctx).WorkspaceConfiguration(MCPConfigurationGroup, MCPIssuerURLKey); err == nil {
		if declared = strings.TrimRight(strings.TrimSpace(declared), "/"); declared != "" {
			return declared, true
		}
	}
	return strings.TrimRight(frontendURL, "/"), false
}

// validateMCP refuses a configuration whose MCP surface would serve a metadata
// document no client can act on. It runs only when the solution declared one:
// a solution that serves no MCP has never needed the host's issuer, and must
// not start failing to boot because this runtime now resolves one.
//
// Both refusals are silent damage otherwise. An empty issuer publishes
// `authorization_servers: [""]`, which a client reads as "there is nowhere to
// authenticate" — on a document that is otherwise well-formed, served with a
// 200, by a solution that looks healthy. An unpairable public URL leaves the
// 401 challenge with no metadata URL at all, so a client that could have
// discovered the authorization server simply does not.
func (c config) validateMCP() error {
	if !c.mcp {
		return nil
	}
	if u, err := url.Parse(c.mcpIssuerURL); err != nil || !u.IsAbs() || u.Host == "" {
		if c.environmentLoadErr != nil {
			return fmt.Errorf("unresolved host issuer %q, and loading Codefly's injected environment failed first: %w — nothing the SDK resolves can be trusted to be absent until that is fixed",
				redactedURL(c.mcpIssuerURL), c.environmentLoadErr)
		}
		return fmt.Errorf("unresolved host issuer %q: ServeMCP publishes it as the authorization server of this MCP resource, so a client has nowhere to authenticate without it. Provision the workspace configuration %s with the origin MCP clients authenticate against and declare that group as a workspace-configuration dependency of this backend, or ensure the SDK resolves the host frontend's http endpoint",
			redactedURL(c.mcpIssuerURL), mcpConfigurationValue(MCPIssuerURLKey))
	}
	// In a deployment neither value below can be resolved from inside the
	// cluster, for the reason the loopback refusals above exist: the runtime
	// cannot tell that what it resolved is unreachable, and serves a
	// well-formed document naming it with a 200, from a solution that
	// registered and looks healthy. A boot log line was the only signal, and a
	// log line nobody reads is how a solution is absent while every gate is
	// green.
	if deployedRuntimeContext(c.runtimeContext) {
		if c.mcpPublicURL == "" {
			// Only reachable with PUBLIC_URL unresolved and no override
			// declared: the identifier is otherwise derived by construction.
			//
			// And this must NOT offer PUBLIC_URL as the remedy. It did, and
			// setting it in a deployment reaches the very next refusal below —
			// a derived identifier is refused in a deployed context, because
			// the derivation encodes the route the host serves this solution
			// on. So the diagnostic sent an operator one step further and then
			// failed the boot again, which is worse than the first refusal
			// because it reads as progress. There is one remedy in a
			// deployment and this names only that one.
			return fmt.Errorf("no public MCP URL in the deployed runtime context %q: the identifier an MCP client binds its token to has to be the one it dialled, and nothing here knows that — PUBLIC_URL resolved nothing, so it would be reconstructed per request from the forwarded headers, missing the route the gateway strips and naming the scheme of the hop rather than the client's. Provision the workspace configuration %s with the URL clients dial, ending in %s, and declare the %s group as a workspace-configuration dependency of this backend. Setting PUBLIC_URL does not answer this in a deployment: a derived identifier is refused here too, because the derivation encodes the route the HOST serves this solution on",
				c.runtimeContext, mcpConfigurationValue(MCPPublicURLKey), MCPPath, MCPConfigurationGroup)
		}
		if !c.mcpIssuerExplicit {
			return fmt.Errorf("no %s provisioned in the deployed runtime context %q: the issuer resolved from the SDK (%q) is the address this composition dials the host at, which no MCP client can reach, and it would be published as this resource's authorization server. Provision that workspace configuration with the origin clients authenticate against and declare the %s group as a workspace-configuration dependency of this backend",
				mcpConfigurationValue(MCPIssuerURLKey), c.runtimeContext, redactedURL(c.mcpIssuerURL), MCPConfigurationGroup)
		}
		// Declared, not derived. The derived identifier satisfied a check for
		// "a public URL is set", so this refusal never fired in the one case
		// it matters: a deployment with PUBLIC_URL resolved, where
		// <PUBLIC_URL>/solutions/<id>/mcp is this runtime encoding the HOST's
		// route layout. That is what the manifest URL was changed to stop
		// doing in this cutover — the route a client reaches a solution
		// through is the host's to resolve, and a runtime guessing it was
		// wrong in every deployment but the author's machine. Locally the
		// derivation stands, because there the guess is checkable by the
		// person making it.
		if c.mcpPublicURL != "" && !c.mcpPublicExplicit {
			return fmt.Errorf("the public MCP URL in the deployed runtime context %q is derived (%q), not declared: it is built as <PUBLIC_URL>%s<id>%s%s, which encodes the route the HOST serves this solution on — a layout this runtime does not know and must not assume. Provision the workspace configuration %s with the URL clients actually dial, ending in %s",
				c.runtimeContext, redactedURL(c.mcpPublicURL), hostSolutionProxyRoute, hostSolutionProxySuffix, MCPPath,
				mcpConfigurationValue(MCPPublicURLKey), MCPPath)
		}
	}
	// After the deployed block, whose refusals name the specific value an
	// operator has not provisioned; this one reports a defect in a value they
	// did. Put first, it answered "not https" for an in-cluster address whose
	// real problem is that no MCP client can reach it at all.
	if err := usablePublishedURL("host issuer", c.mcpIssuerURL,
		mcpConfigurationValue(MCPIssuerURLKey), deployedRuntimeContext(c.runtimeContext)); err != nil {
		return err
	}
	// The issuer's host, through the one decision point. It is published as
	// this resource's authorization server, so a host no client can read or
	// reach sends every client nowhere — on a document that is well-formed and
	// served with a 200. The issuer is the one value a deployment must declare,
	// which is why declaring a reachable-LOOKING one is not enough.
	if err := publishedHostError(c.mcpIssuerURL, deployedRuntimeContext(c.runtimeContext)); err != nil {
		return fmt.Errorf("unusable %s (%q): its host is %w. It is published as this MCP resource's authorization server, so it has to be a URL a client can read and dial. Provision that workspace configuration with the origin clients authenticate against",
			mcpConfigurationValue(MCPIssuerURLKey), redactedURL(c.mcpIssuerURL), err)
	}
	if c.mcpPublicURL == "" {
		return nil
	}
	if u, err := url.Parse(c.mcpPublicURL); err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("unusable %s (%q): it is the resource identifier an MCP client binds its token to, so it must be the absolute URL clients dial",
			c.mcpPublicURLSource(), redactedURL(c.mcpPublicURL))
	}
	// Before the pairing check, because a URL carrying a query or a fragment
	// cannot pair either — and the pairing refusal would then report the wrong
	// defect while printing the value verbatim. It did exactly that: an
	// identifier ending "/mcp?token=s3cr3t" was refused as "unpairable", with
	// the token in the message and so in the boot log.
	//
	// Both URLs are held to what the mint and gateway URLs are held to. They
	// are published rather than dialled — the issuer as this resource's
	// authorization server, the public URL as the identifier a client binds a
	// token to — which makes the same three defects worse rather than milder:
	// userinfo is a credential this runtime publishes to every client that
	// reads the document, a query travels with the identifier, and a fragment
	// is never sent so the identifier is not the one it appears to be.
	deployed := deployedRuntimeContext(c.runtimeContext)
	if err := usablePublishedURL(c.mcpPublicURLSource(), c.mcpPublicURL,
		mcpConfigurationValue(MCPPublicURLKey), deployed); err != nil {
		return err
	}
	// The identifier's host, through the same decision point, and before the
	// trailing-slash and pairing checks: a host a client cannot read or reach
	// cannot be dialled at all, and those two would report a suffix defect in a
	// URL whose authority is the problem.
	if err := publishedHostError(c.mcpPublicURL, deployed); err != nil {
		return fmt.Errorf("unusable %s (%q): its host is %w. It is the resource identifier an MCP client binds its token to, so it has to be a URL a client can read and dial. Provision %s with the URL they dial",
			c.mcpPublicURLSource(), redactedURL(c.mcpPublicURL), err,
			mcpConfigurationValue(MCPPublicURLKey))
	}
	// A trailing slash is a different identifier, not a cosmetic variant: RFC
	// 9728 §3.3 has the client compare the `resource` in this document against
	// the URL it dialled, code point for code point. Refused on its own rather
	// than falling through to the pairing refusal below, which would tell an
	// operator that a value ending in "/mcp/" has to end in "/mcp".
	if strings.HasSuffix(c.mcpPublicURL, "/") {
		return fmt.Errorf("unusable %s (%q): the trailing slash makes it a different identifier from %q, and only one of the two can be the URL a client dialled — it compares the one published here against that URL code point for code point. Declare it ending in %s, with no trailing slash",
			c.mcpPublicURLSource(), redactedURL(c.mcpPublicURL),
			redactedURL(strings.TrimRight(c.mcpPublicURL, "/")), MCPPath)
	}
	if siblingURL(c.mcpPublicURL, MCPPath, ProtectedResourceMetadataPath) == "" {
		return fmt.Errorf("unpairable %s (%q): it must end in %s, because the metadata document a 401 points a client to is derived from it by swapping that suffix",
			c.mcpPublicURLSource(), redactedURL(c.mcpPublicURL), MCPPath)
	}
	return nil
}

// hostKind is what a published URL's host turns out to be once it is read the
// way the client that dials it reads it. There are exactly three outcomes, and
// the defect this type exists to prevent is the third being treated as the
// second: a host nothing can read is not a domain, and admitting it as one is
// how an address-shaped authority reached a cell unclassified, three rounds
// running. Every caller goes through hostOf, and hostOf is the only place the
// three are decided.
type hostKind int

const (
	// hostIsUnreadable is neither a name nor an address. Always refused, naming
	// the configuration that supplied it.
	hostIsUnreadable hostKind = iota
	// hostIsName is a domain. Admitted, unless the name is one reserved for this
	// machine.
	hostIsName
	// hostIsAddress is an IP literal or a numeric host, in any notation a URL
	// consumer reads as one. Classified.
	hostIsAddress
)

// publishedHostError is why a URL this runtime publishes cannot be published,
// or nil. It is the one decision point: both published URLs — the resource
// identifier and the issuer — go through it, so neither can grow a predicate
// of its own that disagrees about what a host is.
//
// deployed selects what is merely local rather than broken. A loopback address
// and a name reserved for loopback are both right on a developer's machine and
// reachable by nobody from a cell. A host that does not read at all is broken
// in either.
func publishedHostError(raw string, deployed bool) error {
	u, err := url.Parse(raw)
	if err != nil {
		// Reported by the absolute-URL refusal, which names the whole value
		// rather than its authority.
		return nil
	}
	kind, name, ip, why := hostOf(u.Hostname())
	switch kind {
	case hostIsUnreadable:
		return why
	case hostIsAddress:
		if deployed && (ip.IsLoopback() || ip.IsUnspecified()) {
			return fmt.Errorf("the loopback address %s, which no client but this machine's can dial", ip)
		}
	case hostIsName:
		if deployed && (name == "localhost" || strings.HasSuffix(name, ".localhost")) {
			return fmt.Errorf("%q, a name reserved for this machine's loopback interface, which no client but this machine's can dial", name)
		}
	}
	return nil
}

// hostOf reads a URL's host the way a URL consumer does and reports which of
// the three outcomes it is. The error is set only for hostIsUnreadable, and it
// says what about the host could not be read.
//
// It is UTS-46 through x/net/idna and then WHATWG's host rules: the mapping
// table is Unicode's and the rules are the specification a client's URL library
// implements, so one address classifies the same however it is written without
// this package enumerating notations.
func hostOf(hostname string) (hostKind, string, net.IP, error) {
	if hostname == "" {
		// A URL's authority can be non-empty while naming no host: "https://:443/"
		// has the authority ":443". Admitting that as a name let it through
		// every check, and a client dialling a URL with no host reaches its own
		// machine.
		return hostIsUnreadable, "", nil, errors.New("absent: the authority names a port and no host")
	}
	// An IPv6 literal, which url.Hostname returns without its brackets. A zone
	// selects the interface an address is reached on, not which address it is,
	// so it is dropped before parsing.
	if strings.Contains(hostname, ":") {
		literal := hostname
		if zone := strings.IndexByte(literal, '%'); zone >= 0 {
			literal = literal[:zone]
		}
		if parsed := net.ParseIP(literal); parsed != nil {
			return hostIsAddress, hostname, parsed, nil
		}
		return hostIsUnreadable, "", nil, fmt.Errorf("%q, bracketed like an IPv6 address and not one", hostname)
	}
	mapped, err := urlHostProfile.ToASCII(hostname)
	if err != nil || mapped == "" {
		return hostIsUnreadable, "", nil, fmt.Errorf("%q, which UTS-46 mapping cannot read: %v", hostname, err)
	}
	if bad := forbiddenDomainRune(mapped); bad >= 0 {
		return hostIsUnreadable, "", nil, fmt.Errorf("%q, which contains %q — a code point a URL consumer forbids in a host", hostname, bad)
	}
	if !hostEndsInNumber(mapped) {
		return hostIsName, strings.TrimSuffix(mapped, "."), nil, nil
	}
	parsed, ok := ipv4FromHost(mapped)
	if !ok {
		// WHATWG makes a host whose last label is a number an invalid URL when
		// it does not parse as an address. Treating it as a name is what let a
		// malformed authority through.
		return hostIsUnreadable, "", nil, fmt.Errorf("%q, which ends in a number and so has to be an address, and is not a valid one", hostname)
	}
	return hostIsAddress, mapped, parsed, nil
}

// forbiddenDomainRune is the first code point WHATWG forbids in a domain, or
// -1. That is the forbidden host code points, the C0 controls, DELETE and "%".
//
// "%" is the one that has to be checked here rather than assumed away. Go's URL
// parsing decodes "%25" to "%" before url.Hostname is read, and a UTS-46
// profile with STD3 rules off permits the result — so a percent-encoded
// separator would otherwise survive mapping and read as an ordinary label.
func forbiddenDomainRune(host string) rune {
	for _, r := range host {
		if r <= 0x20 || r == 0x7f || strings.ContainsRune("#/:<>?@[\\]^|%", r) {
			return r
		}
	}
	return -1
}

// urlHostProfile maps a host the way a URL consumer does before dialling it:
// UTS-46, with the options WHATWG's "domain to ASCII" uses outside strict mode.
// It is x/net/idna's table rather than one written here: the mapping is
// Unicode's, a classifier that reads only ASCII is not reading the host the
// client dialled, and re-deriving the table is not a thing this runtime should
// be doing.
var urlHostProfile = idna.New(
	idna.MapForLookup(),
	idna.BidiRule(),
	idna.StrictDomainName(false),
)

// hostEndsInNumber is WHATWG's "ends in a number": the test that decides
// whether a host has to be an address rather than a name. A trailing empty
// label is the root dot, which does not change the answer.
//
// It asks whether the last label IS a number, not whether it is a number this
// platform can hold. Those came apart once: a label was recognised by a 64-bit
// conversion succeeding, so one that overflowed read as a name.
func hostEndsInNumber(host string) bool {
	parts := strings.Split(host, ".")
	if len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	last := parts[len(parts)-1]
	if last == "" {
		return false
	}
	if strings.IndexFunc(last, func(r rune) bool { return r < '0' || r > '9' }) < 0 {
		return true
	}
	_, numeric, _ := ipv4Number(last)
	return numeric
}

// ipv4FromHost is WHATWG's IPv4 parser: one to four parts, every part before
// the last naming one byte and the last spanning the bytes that are left. So
// "127.1", "2130706433", "0x7f000001" and "017700000001" are all 127.0.0.1.
func ipv4FromHost(host string) (net.IP, bool) {
	parts := strings.Split(host, ".")
	if len(parts) > 1 && parts[len(parts)-1] == "" {
		parts = parts[:len(parts)-1]
	}
	if len(parts) > 4 {
		return nil, false
	}
	numbers := make([]uint64, len(parts))
	for i, part := range parts {
		value, numeric, inRange := ipv4Number(part)
		if !numeric || !inRange {
			return nil, false
		}
		numbers[i] = value
	}
	last := numbers[len(numbers)-1]
	if last >= 1<<(8*uint(5-len(numbers))) {
		return nil, false
	}
	packed := last
	for i, value := range numbers[:len(numbers)-1] {
		if value > 0xff {
			return nil, false
		}
		packed |= value << (8 * uint(3-i))
	}
	return net.IPv4(byte(packed>>24), byte(packed>>16), byte(packed>>8), byte(packed)), true
}

// ipv4Number reads one part of a numeric address, in the base its prefix names:
// "0x" hexadecimal, a leading "0" octal, otherwise decimal. A prefix with no
// digits after it is zero rather than a failure, which is easy to read past and
// load-bearing — a bare "0x" component is a zero byte.
//
// It reports whether the part is a NUMBER at all, separately from whether that
// number is in range, because those are different answers: a part that is
// numeric and too large makes the host malformed, where one that is not numeric
// at all makes it a name.
func ipv4Number(part string) (uint64, bool, bool) {
	if part == "" {
		return 0, false, false
	}
	base, digits := 10, part
	switch {
	case len(part) >= 2 && part[0] == '0' && (part[1] == 'x' || part[1] == 'X'):
		base, digits = 16, part[2:]
	case len(part) >= 2 && part[0] == '0':
		base, digits = 8, part[1:]
	}
	if digits == "" {
		return 0, true, true
	}
	value, err := strconv.ParseUint(digits, base, 64)
	switch {
	case err == nil:
		return value, true, true
	case errors.Is(err, strconv.ErrRange):
		return 0, true, false
	}
	return 0, false, false
}

// mcpPublicURLSource names where the public MCP URL came from, so a refusal
// sends an operator to the value they can change. A derived identifier is
// unusable because PUBLIC_URL is, and naming the override instead would send
// them to provision a value whose absence is not the problem.
func (c config) mcpPublicURLSource() string {
	if c.mcpPublicExplicit {
		return "workspace configuration " + mcpConfigurationValue(MCPPublicURLKey)
	}
	return "public MCP URL derived from PUBLIC_URL"
}

// usablePublishedURL holds a URL this runtime publishes to what validate()
// holds the addresses it dials to.
//
// The same three refusals, for a reason that is stronger here: a dialled URL
// carrying userinfo is a secret this process logs and net/http then strips, and
// a published one is a secret handed to every client that reads the document.
// https is required only in a deployment, because http://localhost is what a
// developer machine serves and refusing it there would refuse the local run
// this runtime is also meant to support.
func usablePublishedURL(name, value, fixWith string, deployed bool) error {
	u, err := url.Parse(value)
	if err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("unusable %s (%q): it is published to MCP clients, so it must be an absolute URL. Provision %s", name, redactedURL(value), fixWith)
	}
	if deployed && u.Scheme != "https" {
		return fmt.Errorf("%s (%q) is not https in a deployed runtime context: MCP clients authenticate against it and dial it, so a plaintext hop hands their credentials to anything on the path. Provision %s with an https URL",
			name, redactedURL(value), fixWith)
	}
	switch {
	case u.User != nil:
		return fmt.Errorf("%s carries userinfo (%q): this URL is published in a document clients read, so credentials in it are disclosed to every one of them. Provision %s with the origin and path and nothing else",
			name, redactedURL(value), fixWith)
	case u.RawQuery != "":
		return fmt.Errorf("%s carries a query string (%q): clients bind a token to this identifier and dial it, and anything secret in a query is logged by every hop that sees it. Provision %s with the origin and path and nothing else",
			name, redactedURL(value), fixWith)
	case u.Fragment != "":
		return fmt.Errorf("%s carries a fragment (%q): a fragment is never sent, so this is not the identifier it appears to be. Provision %s with the URL clients actually dial",
			name, redactedURL(value), fixWith)
	}
	return nil
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
// runtime dialled.
//
// Only an IsError result, and only when the text contains the gateway or mint
// URL this process was configured with: a tool's own refusal is its own to
// word, and rewriting every error result would take that away.
func (s *Server) withoutRuntimeAddresses(result mcp.Result, method string) mcp.Result {
	call, ok := result.(*mcp.CallToolResult)
	if !ok || call == nil || !call.IsError {
		return result
	}
	// The TEXT content, and the STRUCTURED content.
	//
	// This read only Content. The pinned SDK serializes StructuredContent as
	// well, so a result with generic text and
	// StructuredContent{"error": err.Error()} went to the agent client with
	// the mint's address in it — the net was installed for exactly that
	// disclosure and looked in one of the two places the SDK sends.
	//
	// Structured content is arbitrary JSON, so it is rendered once and
	// searched as a whole rather than walked field by field: a rule that
	// inspected a field named "error" would be a rule about this round's
	// example.
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
	// The order is the whole fix, and getting it wrong twice is why it is
	// spelled out. First this inspected the object and returned it for the SDK
	// to serialize later, so a MarshalJSON answering differently the second
	// time disclosed on the second call. Then the structured half was frozen
	// and the text half was not — and the text was read BEFORE the structured
	// marshalling ran, so a structured value holding a pointer to the result's
	// own *mcp.TextContent could rewrite the text, from inside MarshalJSON,
	// after it had passed inspection. `{}` is a clean serialization of a value
	// whose side effect put the mint's address in a sibling field.
	//
	// So: every marshaller runs first, then nothing is inspected that is not
	// about to be published, and what is published is a value built here from
	// strings and bytes this runtime owns. Nothing the caller still holds a
	// pointer to can change it, and no marshaller is asked twice.
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
		// The DECODED strings, not the serialization.
		//
		// This searched the marshalled bytes for the configured URL, and JSON
		// has more than one spelling for the same string: a json.RawMessage
		// holding {"error":"https:\/\/mint…"} keeps those escapes through
		// Marshal, the search for "https://mint…" misses, and the client
		// decodes the address back out. So the bytes are decoded and every
		// string inside them — and every key — is checked, which is the
		// representation the client actually sees.
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
