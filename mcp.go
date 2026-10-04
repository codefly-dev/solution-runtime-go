package solution

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"

	codefly "github.com/codefly-dev/sdk-go"
	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/oauthex"
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
			s.manifest.ID, mcpConfigurationValue(MCPPublicURLKey), "https://<host>"+gatewaySolutionsRoute+s.manifest.ID+MCPPath)
	}
	return nil
}

// MCPEnvironment is what Serve resolves from the composition for the MCP
// surface, supplied instead by a caller of MCPHandler.
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

// MCPHandler is the MCP surface exactly as Serve serves it — the same endpoint,
// the same metadata document, the same refusals, mounted by the same code —
// against an environment the caller supplies instead of the one Serve resolves.
// Nothing else of the solution is served, and nothing registers anywhere.
//
// It exists for tests: a solution drives its own tools under the runtime's
// identity handling, with a fake host standing in for the gateway. A solution
// serves with Serve, which overwrites the environment set here when it resolves
// its own.
func (s *Server) MCPHandler(env MCPEnvironment) (http.Handler, error) {
	if s.mcp == nil {
		return nil, fmt.Errorf("solution %q declares no MCP server (ServeMCP)", s.manifest.ID)
	}
	s.cfg.gatewayURL, s.cfg.mcpIssuerURL, s.cfg.mcpPublicURL = env.GatewayURL, env.IssuerURL, env.PublicURL
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
		// asked — so an operator reading that audit cannot tell an "ask the
		// wiki" from a bulk export. The name only: arguments are the viewer's
		// content and the headers carry their credentials.
		if call, ok := req.(*mcp.CallToolRequest); ok && call.Params != nil {
			log.Printf("solution %q: mcp tool %q", s.manifest.ID, call.Params.Name)
		}
		id := stampedIdentity(header)
		gw := newGateway(s.cfg.gatewayURL, id.bearer, id.orgID, id.sessionID)
		return next(context.WithValue(ctx, mcpViewerKey{}, gw), method, req)
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
// MCPPublicURLKey the two values in it. They are resolved through the SDK the
// way the registration secret is (see SolutionRegistrationSecretGroup), because
// a Codefly composition has no way to set a bare environment variable on a
// service: every value a service receives is either an endpoint the SDK
// resolves or a declared configuration the render projects. Both were read as
// bare environment variables when ServeMCP landed, which named a provisioning
// path that does not exist.
//
// MCPIssuerURLKey is the origin MCP clients authenticate against — the host as
// an authorization server. A deployment must supply it: what the SDK resolves
// is the address this composition dials the host at, in-cluster and reachable
// by no client. It is the one value a composition has to declare for MCP, and
// it stops being one when module-saas-starter#1003 settles what `iss` is.
//
// MCPPublicURLKey overrides the public MCP URL, which the runtime otherwise
// derives by construction (see resolveMCPPublicURL). It exists for a host whose
// gateway fronts solutions under some other route; it must end in MCPPath,
// because the metadata document's own URL is derived from it by swapping that
// suffix — the same pairing the registration token URLs use, and refused at
// boot for the same reason when it cannot be made.
const (
	MCPConfigurationGroup = "mcp"
	MCPIssuerURLKey       = "issuer-url"
	MCPPublicURLKey       = "public-url"
)

// gatewaySolutionsRoute is the route prefix the host gateway fronts a solution
// under, "/solutions/<id>" — the one piece of the host's route layout this
// runtime does encode, and only for the resource identifier.
//
// Everywhere else it deliberately does not: the manifest URL is registered
// root-relative and the host resolves it against the route it reached the
// solution by (see frontendManifestURL). An MCP client cannot do that. The
// resource identifier is what its token is audience-bound to (RFC 8707), so it
// has to be byte-exact with the URL the client dialled, and a client that is
// handed any other identifier rejects it. Deriving it is what makes a
// composition supply nothing; MCPPublicURLKey is the way out for a host that
// routes differently.
const gatewaySolutionsRoute = "/solutions/"

// mcpConfigurationValue names one value in the group above, as a refusal and
// the README both name it: group/key, never an environment variable.
func mcpConfigurationValue(key string) string {
	return MCPConfigurationGroup + "/" + key
}

// resolveMCPPublicURL is the canonical public MCP URL: the URL an MCP client
// dials, which is the resource identifier its token is bound to.
//
// It is derived by construction from the origin this product is reachable at
// and this solution's id — PUBLIC_URL + gatewaySolutionsRoute + id + MCPPath —
// so a composition that renders a solution serving MCP declares nothing for
// it. Empty when PUBLIC_URL resolved nothing and no override was declared,
// which validate() refuses in a deployed runtime context: the identifier would
// then be reconstructed per request from the forwarded headers.
//
// The declared override wins, for a host whose gateway routes solutions
// elsewhere. It is read through the SDK rather than from the environment for
// the reason the group's doc comment gives.
func resolveMCPPublicURL(ctx context.Context, publicURL, id string) (string, bool) {
	if declared, err := codefly.For(ctx).WorkspaceConfiguration(MCPConfigurationGroup, MCPPublicURLKey); err == nil {
		if declared = strings.TrimRight(strings.TrimSpace(declared), "/"); declared != "" {
			return declared, true
		}
	}
	if publicURL == "" || id == "" {
		return "", false
	}
	return strings.TrimRight(publicURL, "/") + gatewaySolutionsRoute + id + MCPPath, false
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
				c.mcpIssuerURL, c.environmentLoadErr)
		}
		return fmt.Errorf("unresolved host issuer %q: ServeMCP publishes it as the authorization server of this MCP resource, so a client has nowhere to authenticate without it. Provision the workspace configuration %s with the origin MCP clients authenticate against and declare that group as a workspace-configuration dependency of this backend, or ensure the SDK resolves the host frontend's http endpoint",
			c.mcpIssuerURL, mcpConfigurationValue(MCPIssuerURLKey))
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
			return fmt.Errorf("no public MCP URL in the deployed runtime context %q: it is derived as <PUBLIC_URL>%s<id>%s, and PUBLIC_URL resolved nothing — so the identifier would be reconstructed per request from the forwarded headers, missing the route the gateway strips (and naming the scheme of the hop, not the client's), and an MCP client binds its token to the identifier it dialled and rejects any other. Set PUBLIC_URL to the origin clients reach this product at, or provision the workspace configuration %s with the URL they dial, ending in %s",
				c.runtimeContext, gatewaySolutionsRoute, MCPPath, mcpConfigurationValue(MCPPublicURLKey), MCPPath)
		}
		if !c.mcpIssuerExplicit {
			return fmt.Errorf("no %s provisioned in the deployed runtime context %q: the issuer resolved from the SDK (%q) is the address this composition dials the host at, which no MCP client can reach, and it would be published as this resource's authorization server. Provision that workspace configuration with the origin clients authenticate against and declare the %s group as a workspace-configuration dependency of this backend",
				mcpConfigurationValue(MCPIssuerURLKey), c.runtimeContext, c.mcpIssuerURL, MCPConfigurationGroup)
		}
	}
	if c.mcpPublicURL == "" {
		return nil
	}
	if u, err := url.Parse(c.mcpPublicURL); err != nil || !u.IsAbs() || u.Host == "" {
		return fmt.Errorf("unusable %s (%q): it is the resource identifier an MCP client binds its token to, so it must be the absolute URL clients dial",
			c.mcpPublicURLSource(), c.mcpPublicURL)
	}
	if siblingURL(c.mcpPublicURL, MCPPath, ProtectedResourceMetadataPath) == "" {
		return fmt.Errorf("unpairable %s (%q): it must end in %s, because the metadata document a 401 points a client to is derived from it by swapping that suffix",
			c.mcpPublicURLSource(), c.mcpPublicURL, MCPPath)
	}
	return nil
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
