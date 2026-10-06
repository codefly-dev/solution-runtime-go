package solution

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workcontext"
	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// --- the host gateway, as an MCP request arrives from it ---

// stampedTransport is the host gateway's half of an MCP request: it authenticates
// the client's bearer and replaces the identity headers with what it resolved.
// Everything the runtime's MCP surface knows about the caller comes from here.
type stampedTransport struct {
	bearer, userID, orgID, sessionID, credentialKind string
	// installation is what the gateway stamps as x-codefly-installation-id,
	// which every mint the runtime runs names.
	installation string
	// prefix is the path the gateway strips before the solution sees the
	// request, forwarded as x-forwarded-prefix.
	prefix string
}

func (s stampedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.Header.Del(userHeader)
	r.Header.Del(orgHeader)
	r.Header.Del(sessionHeader)
	r.Header.Del(credentialKindHeader)
	r.Header.Del(workcontext.InstallationIDHeaderName)
	if s.bearer != "" {
		r.Header.Set("authorization", s.bearer)
	}
	for name, value := range map[string]string{
		userHeader:                           s.userID,
		orgHeader:                            s.orgID,
		sessionHeader:                        s.sessionID,
		credentialKindHeader:                 s.credentialKind,
		workcontext.InstallationIDHeaderName: s.installation,
		forwardedPrefixHeader:                s.prefix,
	} {
		if value != "" {
			r.Header.Set(name, value)
		}
	}
	return http.DefaultTransport.RoundTrip(r)
}

// viewerStamp is the identity the gateway stamps for a signed-in person: the
// same org and session every other test's viewer acts under.
func viewerStamp() stampedTransport {
	return stampedTransport{
		bearer:         viewerBearer(),
		userID:         "viewer-principal",
		orgID:          viewerOrg,
		sessionID:      viewerSession,
		credentialKind: "user_session",
		installation:   testInstallation,
	}
}

const (
	testIssuer    = "https://host.test"
	mcpToolName   = "read_collection"
	mcpServerName = "example"
)

type askInput struct {
	Question string `json:"question"`
}

type askOutput struct {
	Status int `json:"status"`
}

// serveMCP mounts a solution's MCP surface the way Serve does, against a fake
// host. register adds the tools the test drives.
func serveMCP(t *testing.T, env MCPEnvironment, register func(*mcp.Server)) *httptest.Server {
	t.Helper()
	// A credential for this workload, because a tool call attests which module
	// is asking and this runtime refuses to send a mint it cannot attest for.
	// Before the cutover nothing here held one; the refusal is the point, and
	// a test seam that skipped it would be testing a path no deployment has.
	mint := newHostMint(t, &hostMint{})
	s := New(Manifest{ID: mcpServerName, Title: "Example"}).
		ServeMCP(mcpServerName, "v1.2.3", register).
		Credential(stubCredentialSource{credential: mintedCredential(t, mint, testProjectionAudience)})
	handler, err := s.mcpHandler(env)
	if err != nil {
		t.Fatalf("mount MCP: %v", err)
	}
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	return server
}

// readCollectionTool is the tool a solution writes: it asks the runtime who the
// viewer is and reads a composed module on their behalf.
func readCollectionTool(srv *mcp.Server) {
	mcp.AddTool(srv, &mcp.Tool{Name: mcpToolName, Description: "read the collection"},
		func(ctx context.Context, _ *mcp.CallToolRequest, _ askInput) (*mcp.CallToolResult, askOutput, error) {
			gw, err := ViewerFromContext(ctx)
			if err != nil {
				return nil, askOutput{}, err
			}
			status, err := readModule(ctx, gw, "documents")
			return nil, askOutput{Status: status}, err
		})
}

// connectMCP drives the endpoint with a real MCP client through the gateway
// double, as Claude Code would.
func connectMCP(t *testing.T, server *httptest.Server, gateway stampedTransport) *mcp.ClientSession {
	t.Helper()
	client := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "v0"}, nil)
	session, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{
		Endpoint:   server.URL + MCPPath,
		HTTPClient: &http.Client{Transport: gateway},
	}, nil)
	if err != nil {
		t.Fatalf("connect to %s: %v", server.URL+MCPPath, err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

// TestMCPToolCallRunsAsTheViewer is the whole point of the surface: a tool call
// arriving from an agent client mints the Work Context of the person who signed
// in, so the module read it makes is the one the browser would have made. The
// module refuses a bearer alone, so a 200 is only possible because the viewer's
// own capability was minted and presented.
func TestMCPToolCallRunsAsTheViewer(t *testing.T) {
	host := newWorkContextGateway(t, &workContextGateway{})
	server := serveMCP(t, MCPEnvironment{GatewayURL: host.URL, IssuerURL: testIssuer}, readCollectionTool)
	session := connectMCP(t, server, viewerStamp())

	tools, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	if len(tools.Tools) != 1 || tools.Tools[0].Name != mcpToolName {
		t.Fatalf("tools/list = %+v, want the solution's own tool %q", tools.Tools, mcpToolName)
	}

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      mcpToolName,
		Arguments: map[string]any{"question": "what is the handbook"},
	})
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	if result.IsError {
		t.Fatalf("tools/call failed: %v", toolErrorText(result))
	}
	var out askOutput
	if err := remarshal(result.StructuredContent, &out); err != nil {
		t.Fatalf("decode tool output %v: %v", result.StructuredContent, err)
	}
	if out.Status != http.StatusOK {
		t.Fatalf("module answered %d, want 200 — the read was not authenticated as the viewer", out.Status)
	}

	mint := <-host.mints
	if mint.Bearer != viewerBearer() {
		t.Errorf("mint presented bearer %q, want the viewer's — accounts must resolve the viewer as owner", mint.Bearer)
	}
	if mint.OrgID != viewerOrg {
		t.Errorf("mint org = %q, want the org the gateway stamped", mint.OrgID)
	}
	if mint.SessionID != viewerSession {
		t.Errorf("mint session = %q, want the viewer's %q: a tool call is rooted in the session the gateway stamped, never one the runtime invents", mint.SessionID, viewerSession)
	}
	if call := <-host.calls; call.WorkContext == "" {
		t.Errorf("module read carried no work context: the tool acted as the solution, not as the viewer")
	}
}

// remarshal reads a tool's structured output into the type the tool returned.
func remarshal(from any, into any) error {
	raw, err := json.Marshal(from)
	if err != nil {
		return err
	}
	return json.Unmarshal(raw, into)
}

// toolErrorText is whatever a failed tool call said, for a test failure message.
func toolErrorText(result *mcp.CallToolResult) string {
	var parts []string
	for _, content := range result.Content {
		if text, ok := content.(*mcp.TextContent); ok {
			parts = append(parts, text.Text)
		}
	}
	return strings.Join(parts, " ")
}

// post issues one raw MCP POST, which is how the refusals are observed: the
// client library cannot complete a handshake the endpoint refuses.
func post(t *testing.T, server *httptest.Server, header http.Header) *http.Response {
	t.Helper()
	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"agent","version":"v0"}}}`
	req, err := http.NewRequest(http.MethodPost, server.URL+MCPPath, strings.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json, text/event-stream")
	for name, values := range header {
		req.Header[name] = values
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", MCPPath, err)
	}
	t.Cleanup(func() { drainAndClose(resp) })
	return resp
}

// TestMCPChallengesARequestWithNoBearer pins the direct caller's answer and the
// shape the gateway's own challenge has to match. Through the gateway an
// unauthenticated request is denied by ext_authz before it is proxied, so what
// arrives here with no bearer reached this solution directly — a local run, a
// port-forward — and without the challenge it would have nothing to go on but a
// status code.
func TestMCPChallengesARequestWithNoBearer(t *testing.T) {
	server := serveMCP(t, MCPEnvironment{IssuerURL: testIssuer}, readCollectionTool)

	resp := post(t, server, http.Header{"x-forwarded-proto": {"https"}, "x-forwarded-host": {"host.test"}, "x-forwarded-prefix": {"/solutions/example"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("answered %d, want 401", resp.StatusCode)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	want := `Bearer resource_metadata="https://host.test/solutions/example` + ProtectedResourceMetadataPath + `"`
	if challenge != want {
		t.Errorf("challenge = %q, want %q", challenge, want)
	}
}

// TestMCPChallengesARequestTheGatewayDidNotStamp covers the request that carries
// a bearer the runtime never looks at. Nothing but the gateway may reach this
// endpoint, so a bearer with no stamped identity is not a caller this runtime can
// serve — and it is answered with the challenge rather than a bare 401 so that a
// caller which reached the wrong address has something to act on.
func TestMCPChallengesARequestTheGatewayDidNotStamp(t *testing.T) {
	server := serveMCP(t, MCPEnvironment{IssuerURL: testIssuer, PublicURL: "https://host.test/solutions/example" + MCPPath}, readCollectionTool)

	resp := post(t, server, http.Header{"authorization": {"Bearer whatever"}})
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("answered %d, want 401", resp.StatusCode)
	}
	if got := resp.Header.Get("WWW-Authenticate"); !strings.Contains(got, ProtectedResourceMetadataPath) {
		t.Errorf("challenge = %q, want the metadata document", got)
	}
	body := readBody(t, resp)
	for _, header := range []string{userHeader, orgHeader, sessionHeader} {
		if !strings.Contains(body, header) {
			t.Errorf("refusal %q does not name %s: a refusal must name what is missing", body, header)
		}
	}
}

// TestMCPRefusesACredentialWithNoSession pins the one credential kind MCP cannot
// serve, named by its kind. An organization API key authenticates a principal and
// no session, and every tool call that acts for a viewer mints a Work Context
// rooted in a session — so this is refused at the boundary rather than once per
// tool call, where the same refusal would read as the tool being broken.
func TestMCPRefusesACredentialWithNoSession(t *testing.T) {
	server := serveMCP(t, MCPEnvironment{IssuerURL: testIssuer}, readCollectionTool)

	resp := post(t, server, http.Header{
		"authorization":      {"Bearer org-api-key"},
		userHeader:           {"service-principal"},
		credentialKindHeader: {apiKeyCredentialKind},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("answered %d, want 403: another token cannot fix the kind of credential this is", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") != "" {
		t.Errorf("challenge = %q, want none: re-authenticating with the same kind of credential would be refused again", resp.Header.Get("WWW-Authenticate"))
	}
	body := readBody(t, resp)
	if !strings.Contains(body, apiKeyCredentialKind) || !strings.Contains(body, credentialKindHeader) {
		t.Errorf("refusal %q names neither %s nor %q", body, credentialKindHeader, apiKeyCredentialKind)
	}
}

// TestMCPNoSessionRefusalNamesTheStampedKind: told about an API key, a caller
// whose credential is of another kind goes looking for an API key it does not
// have — while the one fact that would have helped, what the gateway stamped, is
// what the message replaced with a guess.
func TestMCPNoSessionRefusalNamesTheStampedKind(t *testing.T) {
	server := serveMCP(t, MCPEnvironment{IssuerURL: testIssuer}, readCollectionTool)

	resp := post(t, server, http.Header{
		"authorization":      {"Bearer token"},
		userHeader:           {"viewer-principal"},
		orgHeader:            {viewerOrg},
		credentialKindHeader: {"service_account"},
	})
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("answered %d, want 403", resp.StatusCode)
	}
	body := readBody(t, resp)
	if !strings.Contains(body, "service_account") {
		t.Errorf("refusal %q does not name the stamped kind", body)
	}
	if strings.Contains(body, apiKeyCredentialKind) {
		t.Errorf("refusal %q names %q, which is not what the gateway stamped", body, apiKeyCredentialKind)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}

// --- RFC 9728 Protected Resource Metadata ---

func metadata(t *testing.T, server *httptest.Server, header http.Header) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, server.URL+ProtectedResourceMetadataPath, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for name, values := range header {
		req.Header[name] = values
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", ProtectedResourceMetadataPath, err)
	}
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("metadata answered %d, want 200: a client that cannot read it cannot authenticate", resp.StatusCode)
	}
	if origin := resp.Header.Get("Access-Control-Allow-Origin"); origin != "*" {
		t.Errorf("metadata CORS origin = %q, want *: discovery is public (RFC 9728 §3.1)", origin)
	}
	var document map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&document); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	return document
}

// TestMCPMetadataNamesTheResolvedIssuer pins both halves of the document a client
// acts on: the resource it binds its token to, and the authorization server it
// gets that token from. The resource is reconstructed from what the proxy
// forwarded — the URL the client actually dialled — while the issuer is the one
// resolved at boot and never anything the request carried.
func TestMCPMetadataNamesTheResolvedIssuer(t *testing.T) {
	server := serveMCP(t, MCPEnvironment{IssuerURL: testIssuer}, readCollectionTool)

	document := metadata(t, server, http.Header{
		"x-forwarded-proto":  {"https"},
		"x-forwarded-host":   {"host.test"},
		"x-forwarded-prefix": {"/solutions/example"},
	})
	if got, want := document["resource"], "https://host.test/solutions/example"+MCPPath; got != want {
		t.Errorf("resource = %v, want %q — the identifier a client binds its token to must be the URL it dialled", got, want)
	}
	if got, want := document["authorization_servers"], []any{testIssuer}; len(document["authorization_servers"].([]any)) != 1 || got.([]any)[0] != want[0] {
		t.Errorf("authorization_servers = %v, want %v", got, want)
	}
	if got := document["bearer_methods_supported"]; len(got.([]any)) != 1 || got.([]any)[0] != "header" {
		t.Errorf("bearer_methods_supported = %v, want [header]", got)
	}
	if got := document["resource_name"]; got != "Example" {
		t.Errorf("resource_name = %v, want the solution's title", got)
	}
}

// TestMCPMetadataIssuerIsNotRequestDerived is the security property of the
// document: `resource` is reconstructed from headers a caller could craft, and
// `authorization_servers` — the field that decides where a client sends its
// credentials — is not derivable from a request at all.
func TestMCPMetadataIssuerIsNotRequestDerived(t *testing.T) {
	server := serveMCP(t, MCPEnvironment{IssuerURL: testIssuer}, readCollectionTool)

	document := metadata(t, server, http.Header{
		"x-forwarded-proto": {"https"},
		"x-forwarded-host":  {"evil.test"},
	})
	if got := document["authorization_servers"].([]any)[0]; got != testIssuer {
		t.Errorf("authorization_servers = %v, want the resolved issuer %q: a crafted host must not point a client at another issuer", got, testIssuer)
	}
}

// TestMCPMetadataPrefersTheConfiguredPublicURL: a deployment whose proxy forwards
// no prefix has no way for the runtime to reconstruct the path it stripped, so
// the configured URL is what the document and the challenge name — whatever the
// request carried.
func TestMCPMetadataPrefersTheConfiguredPublicURL(t *testing.T) {
	const public = "https://app.example.com/solutions/example" + MCPPath
	server := serveMCP(t, MCPEnvironment{IssuerURL: testIssuer, PublicURL: public}, readCollectionTool)

	document := metadata(t, server, http.Header{"x-forwarded-host": {"evil.test"}, "x-forwarded-prefix": {"/elsewhere"}})
	if got := document["resource"]; got != public {
		t.Errorf("resource = %v, want the configured %q", got, public)
	}
}

// TestMCPMetadataDropsAnUnusablePrefix: a forwarded prefix that is not a plain
// absolute path cannot be concatenated in front of the MCP path. The identifier
// is built without it — which a client rejects for not matching what it
// dialled — rather than sanitized into one that looks right and names something
// else.
func TestMCPMetadataDropsAnUnusablePrefix(t *testing.T) {
	server := serveMCP(t, MCPEnvironment{IssuerURL: testIssuer}, readCollectionTool)

	for _, prefix := range []string{"//evil.test", "/solutions/example?x=1", "/solutions/example#f", "solutions/example"} {
		document := metadata(t, server, http.Header{
			"x-forwarded-proto":  {"https"},
			"x-forwarded-host":   {"host.test"},
			"x-forwarded-prefix": {prefix},
		})
		if got, want := document["resource"], "https://host.test"+MCPPath; got != want {
			t.Errorf("with forwarded prefix %q, resource = %v, want %q", prefix, got, want)
		}
	}
}

// TestMCPMetadataDropsAnUnusableForwardedHost: a forwarded host that is not a
// host would be spliced into the middle of the identifier, where a space or a
// slash makes the rest of the URL mean something else. The request's own host is
// what the identifier is built from then.
func TestMCPMetadataDropsAnUnusableForwardedHost(t *testing.T) {
	server := serveMCP(t, MCPEnvironment{IssuerURL: testIssuer}, readCollectionTool)
	own := strings.TrimPrefix(server.URL, "http://")

	for _, host := range []string{"host.test/../elsewhere", "host.test other.test", "user@host.test", "host.test?x=1"} {
		document := metadata(t, server, http.Header{"x-forwarded-host": {host}})
		if got, want := document["resource"], "http://"+own+MCPPath; got != want {
			t.Errorf("with forwarded host %q, resource = %v, want the request's own host %q", host, got, want)
		}
	}
}

// TestMCPMetadataDropsAnUnusableForwardedScheme: a forwarded proto is a hop's
// claim about the client's connection, and only the two schemes an HTTP resource
// can be dialled over are usable. "javascript" would otherwise be spliced in
// front of "://" and handed to a client as the URL of this resource.
func TestMCPMetadataDropsAnUnusableForwardedScheme(t *testing.T) {
	server := serveMCP(t, MCPEnvironment{IssuerURL: testIssuer}, readCollectionTool)

	for _, scheme := range []string{"javascript", "file", "ws", "httpss", "data"} {
		document := metadata(t, server, http.Header{
			"x-forwarded-proto": {scheme},
			"x-forwarded-host":  {"host.test"},
		})
		if got, want := document["resource"], "http://host.test"+MCPPath; got != want {
			t.Errorf("with forwarded proto %q, resource = %v, want the request's own scheme in %q", scheme, got, want)
		}
	}
	// The one a proxy actually forwards is used.
	document := metadata(t, server, http.Header{"x-forwarded-proto": {"HTTPS"}, "x-forwarded-host": {"host.test"}})
	if got, want := document["resource"], "https://host.test"+MCPPath; got != want {
		t.Errorf("resource = %v, want %q: https is the scheme a proxy in front of TLS forwards", got, want)
	}
}

// TestMCPToolCallIsRecordedByName is the only trace a tool call leaves here:
// minting is audited on accounts and names the viewer and the module, but not
// which tool asked, so an operator reading that audit cannot tell one tool from
// another. The name only — arguments are the viewer's content, and the headers
// carry their credentials.
func TestMCPToolCallIsRecordedByName(t *testing.T) {
	host := newWorkContextGateway(t, &workContextGateway{})
	server := serveMCP(t, MCPEnvironment{GatewayURL: host.URL, IssuerURL: testIssuer}, readCollectionTool)
	session := connectMCP(t, server, viewerStamp())

	recorded := captureLog(t)
	if _, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      mcpToolName,
		Arguments: map[string]any{"question": "a secret question"},
	}); err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	logged := recorded.String()
	if !strings.Contains(logged, mcpToolName) {
		t.Errorf("the log %q does not name the tool that ran", logged)
	}
	if strings.Contains(logged, "a secret question") || strings.Contains(logged, "viewer-token") {
		t.Errorf("the log %q carries the call's arguments or the viewer's credential", logged)
	}
}

// captureLog collects what the runtime logs for the rest of the test. It is
// locked because the heartbeat goroutines of tests that have finished are still
// writing to the same logger.
func captureLog(t *testing.T) *lockedBuffer {
	t.Helper()
	buffer := &lockedBuffer{}
	flags := log.Flags()
	log.SetOutput(buffer)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(os.Stderr)
		log.SetFlags(flags)
	})
	return buffer
}

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// --- transport shape ---

// TestMCPIsStateless pins the transport the gateway can actually proxy: a
// session held in one replica's memory is unreachable from the next request
// through a reverse proxy with no sticky routing, so no session is issued and
// the methods that only exist to serve one are not offered.
func TestMCPIsStateless(t *testing.T) {
	host := newWorkContextGateway(t, &workContextGateway{})
	server := serveMCP(t, MCPEnvironment{GatewayURL: host.URL, IssuerURL: testIssuer}, readCollectionTool)

	stamp := viewerStamp()
	resp := post(t, server, http.Header{
		"authorization":      {stamp.bearer},
		userHeader:           {stamp.userID},
		orgHeader:            {stamp.orgID},
		sessionHeader:        {stamp.sessionID},
		credentialKindHeader: {stamp.credentialKind},
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initialize answered %d (%s), want 200", resp.StatusCode, readBody(t, resp))
	}
	if id := resp.Header.Get("Mcp-Session-Id"); id != "" {
		t.Errorf("initialize issued session %q: a stateless server must not, or the next request is routed to a replica that never saw it", id)
	}

	req, err := http.NewRequest(http.MethodGet, server.URL+MCPPath, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("authorization", stamp.bearer)
	req.Header.Set(sessionHeader, stamp.sessionID)
	req.Header.Set(workcontext.InstallationIDHeaderName, testInstallation)
	stream, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", MCPPath, err)
	}
	defer drainAndClose(stream)
	if stream.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("GET answered %d, want 405: there is no server-initiated stream without a session", stream.StatusCode)
	}
}

// TestMCPEndpointServesNoCORS: the one route that acts with the viewer's full
// authority is not offered to a browser page. The runtime's CORS policy admits
// any origin with an authorization header, which is the right answer for the
// solution's own API and the wrong one here; an MCP client is not a page.
func TestMCPEndpointServesNoCORS(t *testing.T) {
	server := serveMCP(t, MCPEnvironment{IssuerURL: testIssuer}, readCollectionTool)

	resp := post(t, server, http.Header{"origin": {"https://evil.test"}})
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Errorf("MCP endpoint answered CORS origin %q, want none", got)
	}
}

// --- declaration and configuration refusals ---

// TestServeMCPRefusesAMisDeclaredSurface: each of these is the author's mistake
// and is the same in every environment, so it is refused before any address is
// resolved — as a mis-declared surface is.
func TestServeMCPRefusesAMisDeclaredSurface(t *testing.T) {
	for name, surface := range map[string]*mcpSurface{
		"no name":     {version: "v1", register: readCollectionTool},
		"no version":  {name: "example", register: readCollectionTool},
		"no register": {name: "example", version: "v1"},
	} {
		if err := surface.validate(); err == nil {
			t.Errorf("%s: declaration accepted, want a refusal", name)
		}
	}
}

// TestTheMCPSeamRefusesWithoutAServeMCPDeclaration keeps the test seam honest:
// it serves the surface Serve serves, and there is none to serve here.
func TestTheMCPSeamRefusesWithoutAServeMCPDeclaration(t *testing.T) {
	if _, err := New(Manifest{ID: "example"}).mcpHandler(MCPEnvironment{IssuerURL: testIssuer}); err == nil {
		t.Error("mcpHandler accepted a solution that declares no MCP server")
	}
}

// TestValidateRefusesAnUnresolvedIssuerOnlyWhenMCPIsServed: an empty issuer
// publishes `authorization_servers: [""]` on a 200, from a solution that looks
// healthy — so it is refused at boot. A solution serving no MCP has never needed
// the host's issuer and must not start failing to boot because this runtime now
// resolves one.
func TestValidateRefusesAnUnresolvedIssuerOnlyWhenMCPIsServed(t *testing.T) {
	cfg := config{mcp: true}
	err := cfg.validateMCP()
	if err == nil {
		t.Fatal("an unresolved issuer was accepted while serving MCP")
	}
	if !strings.Contains(err.Error(), mcpConfigurationValue(MCPIssuerURLKey)) {
		t.Errorf("refusal %q does not name %s, the configuration that fixes it", err, mcpConfigurationValue(MCPIssuerURLKey))
	}
	if err := (config{}).validateMCP(); err != nil {
		t.Errorf("a solution serving no MCP was refused: %v", err)
	}
}

// TestValidateRefusesAnUnpairablePublicURL: the metadata document's URL is
// derived from the public MCP URL by swapping the path suffix, exactly as the
// registration token URLs are derived from their register URLs. An override that
// drops the suffix cannot be paired, so it is refused at boot naming the suffix,
// rather than leaving every 401 challenge without the one URL a client needs.
//
// The refusal names where the value came from, because the two sources are
// fixed in different places: a declared override is the composition's, and a
// derived identifier is unusable only because PUBLIC_URL is.
func TestValidateRefusesAnUnpairablePublicURL(t *testing.T) {
	for _, public := range []string{"https://host.test/solutions/example", "https://host.test/mcp/", "/solutions/example/mcp"} {
		cfg := config{mcp: true, mcpIssuerURL: testIssuer, mcpPublicURL: public, mcpPublicExplicit: true}
		err := cfg.validateMCP()
		if err == nil {
			t.Errorf("%s %q was accepted, want a refusal", mcpConfigurationValue(MCPPublicURLKey), public)
			continue
		}
		if !strings.Contains(err.Error(), mcpConfigurationValue(MCPPublicURLKey)) {
			t.Errorf("refusal %q for a declared override does not name %s", err, mcpConfigurationValue(MCPPublicURLKey))
		}
		derived := cfg
		derived.mcpPublicExplicit = false
		err = derived.validateMCP()
		if err == nil {
			t.Errorf("derived public URL %q was accepted, want a refusal", public)
			continue
		}
		if !strings.Contains(err.Error(), "PUBLIC_URL") || strings.Contains(err.Error(), mcpConfigurationValue(MCPPublicURLKey)) {
			t.Errorf("refusal %q for a derived identifier does not send the operator to PUBLIC_URL", err)
		}
	}
	cfg := config{mcp: true, mcpIssuerURL: testIssuer, mcpPublicURL: "https://host.test/solutions/example" + MCPPath}
	if err := cfg.validateMCP(); err != nil {
		t.Errorf("a pairable public URL was refused: %v", err)
	}
}

// TestServeMCPRefusesARedeclaredSurface: there is one MCP endpoint, so a second
// ServeMCP would be the only one served and the tools registered by the first
// would simply not exist — with tools/list answering as if that were all there
// is. Refused at boot rather than resolved by call order.
func TestServeMCPRefusesARedeclaredSurface(t *testing.T) {
	s := New(Manifest{ID: "example"}).
		ServeMCP("example", "v1", readCollectionTool).
		ServeMCP("example", "v1", readCollectionTool)
	err := s.validateMCPDeclaration()
	if err == nil {
		t.Fatal("two ServeMCP calls were accepted")
	}
	if !strings.Contains(err.Error(), "ServeMCP") {
		t.Errorf("refusal %q does not name ServeMCP", err)
	}
	if _, err := s.mcpHandler(MCPEnvironment{IssuerURL: testIssuer}); err == nil {
		t.Error("mcpHandler served a redeclared surface")
	}
}

// TestServeMCPRefusesAHandlerOnItsOwnPath: net/http panics on a duplicate
// pattern, which in serve() happens with http's own message and after the
// listener is open. One of the two would have to win, so the boot names them
// both instead.
func TestServeMCPRefusesAHandlerOnItsOwnPath(t *testing.T) {
	for _, path := range []string{MCPPath, ProtectedResourceMetadataPath} {
		s := New(Manifest{ID: "example"}).ServeMCP("example", "v1", readCollectionTool)
		s.Handle(path, func(context.Context, *Gateway) (any, error) { return nil, nil })
		err := s.validateMCPDeclaration()
		if err == nil {
			t.Errorf("a handler at %q was accepted alongside ServeMCP", path)
			continue
		}
		if !strings.Contains(err.Error(), path) {
			t.Errorf("refusal %q does not name %q", err, path)
		}
	}
	// The same solution without the collision is served.
	if err := New(Manifest{ID: "example"}).ServeMCP("example", "v1", readCollectionTool).
		Handle("/search", func(context.Context, *Gateway) (any, error) { return nil, nil }).
		validateMCPDeclaration(); err != nil {
		t.Errorf("a handler on its own path was refused: %v", err)
	}
}

// TestValidateRefusesADeployedMCPThatNobodyAddressed is the F2 refusal: in a
// deployment the runtime cannot tell that what it resolved is unreachable. The
// identifier reconstructed from forwarded headers is missing the route prefix
// the gateway stripped, and the resolved issuer is the address this composition
// dials the host at — both served with a 200, from a solution that registered
// and looks healthy, with a boot log line as the only signal. It is the same
// silent damage the loopback refusals above already refuse, so it is refused the
// same way.
func TestValidateRefusesADeployedMCPThatNobodyAddressed(t *testing.T) {
	const inCluster = "http://frontend.saas.svc.cluster.local:3000"
	const public = "https://app.example.com/solutions/example" + MCPPath

	deployed := config{mcp: true, runtimeContext: "kubernetes", mcpIssuerURL: inCluster}
	err := deployed.validateMCP()
	if err == nil {
		t.Fatal("a deployed MCP surface with no public URL was accepted")
	}
	if !strings.Contains(err.Error(), "PUBLIC_URL") || !strings.Contains(err.Error(), mcpConfigurationValue(MCPPublicURLKey)) {
		t.Errorf("refusal %q names neither the origin it derives from nor %s", err, mcpConfigurationValue(MCPPublicURLKey))
	}

	addressed := deployed
	addressed.mcpPublicURL = public
	err = addressed.validateMCP()
	if err == nil {
		t.Fatal("a deployed MCP surface with an issuer nobody chose was accepted")
	}
	if !strings.Contains(err.Error(), mcpConfigurationValue(MCPIssuerURLKey)) {
		t.Errorf("refusal %q does not name %s", err, mcpConfigurationValue(MCPIssuerURLKey))
	}

	// An operator who declared the issuer but let the identifier be derived is
	// still refused, and this is the case that used to pass.
	//
	// The derived value is <PUBLIC_URL>/solutions/<id>/mcp: this runtime
	// encoding the route the HOST serves it on. That assumption is what the
	// Module Federation manifest URL was changed to stop making in this
	// cutover, for the same reason — the route a client reaches a solution
	// through is the host's to resolve, and a runtime guessing it is right
	// only on the machine of whoever wrote the guess. A derived value also
	// satisfied the "a public URL is set" check above, so nothing refused it.
	halfTold := addressed
	halfTold.mcpIssuerExplicit = true
	halfTold.mcpIssuerURL = "https://app.example.com"
	err = halfTold.validateMCP()
	if err == nil {
		t.Fatal("a deployed MCP surface was accepted with an identifier derived from PUBLIC_URL: a client binds its token to the URL it dialled, and this one is this runtime's guess about the host's route")
	}
	if !strings.Contains(err.Error(), mcpConfigurationValue(MCPPublicURLKey)) {
		t.Errorf("refusal %q does not name %s, the configuration that fixes it", err, mcpConfigurationValue(MCPPublicURLKey))
	}

	told := halfTold
	told.mcpPublicExplicit = true
	if err := told.validateMCP(); err != nil {
		t.Errorf("a deployed MCP surface an operator addressed in full was refused: %v", err)
	}

	// A local run resolves a host it can actually reach and is unaffected: the
	// refusal is about a deployment, never about the environment's name.
	for _, local := range []string{"", "native", "nix", "container", "free"} {
		cfg := config{mcp: true, runtimeContext: local, mcpIssuerURL: "http://localhost:3000"}
		if err := cfg.validateMCP(); err != nil {
			t.Errorf("runtime context %q was refused: %v", local, err)
		}
	}
}

// TestViewerFromContextOutsideAServedRequest: a tool handler invoked by a
// harness of its own gets a refusal that says where the viewer comes from,
// rather than a nil gateway that fails later inside a module read.
func TestViewerFromContextOutsideAServedRequest(t *testing.T) {
	gw, err := ViewerFromContext(context.Background())
	if gw != nil || err == nil {
		t.Fatalf("ViewerFromContext = (%v, %v), want a refusal", gw, err)
	}
	if !strings.Contains(err.Error(), "ServeMCP") {
		t.Errorf("refusal %q does not name ServeMCP", err)
	}
}

// TestAnMCPToolCallIsHeldToThePublishedCeiling is the gap integrating this
// surface with the cutover exposed.
//
// The MCP middleware built its viewer gateway with newGateway, which carries
// the caller's headers and nothing else. Every other path a viewer reaches this
// runtime on is built by gatewayFor, which attaches the credential controller,
// the attestation report, the terminal hook and — the one that matters here —
// the ceilings of the contract this process published. So a mint driven from an
// MCP tool call was held to nothing the contract claims, while the identical
// mint from a handler or the passthrough was refused.
//
// The ceiling is declared, not derived, for the reason AGENTS.md gives: one
// computed from what the code asks for is satisfied by construction. A surface
// that bypasses it is the same defect by another route.
//
// Driven through the real middleware, by a tool reading its own viewer with
// ViewerFromContext. The first version of this test called gatewayFor directly
// and passed against the broken code, which is the mistake it exists to catch.
func TestAnMCPToolCallIsHeldToThePublishedCeiling(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	var (
		seen      atomic.Bool
		ceilings  atomic.Bool
		audience  atomic.Bool
		acquirer  atomic.Bool
		reporting atomic.Bool
		terminal  atomic.Bool
	)
	register := func(srv *mcp.Server) {
		mcp.AddTool(srv, &mcp.Tool{Name: "inspect", Description: "reports its own viewer"},
			func(ctx context.Context, _ *mcp.CallToolRequest, _ askInput) (*mcp.CallToolResult, askOutput, error) {
				gw, err := ViewerFromContext(ctx)
				if err != nil {
					return nil, askOutput{}, err
				}
				seen.Store(true)
				ceilings.Store(gw.ceilings != nil)
				_, declared := gw.ceilings["example-api"]
				audience.Store(declared)
				acquirer.Store(gw.workload != nil)
				reporting.Store(gw.report != nil)
				terminal.Store(gw.terminal != nil)
				return nil, askOutput{Status: 200}, nil
			})
	}

	server := New(Manifest{ID: mcpServerName, Title: "Example"}).
		ServeMCP(mcpServerName, "v1.2.3", register).
		Credential(stubCredentialSource{credential: mintedCredential(t, mint, testProjectionAudience)})
	// A resolved contract with one audience, which is what the ceiling is read
	// off; contractResolved is the flag that makes it governing.
	server.contract = effectiveContract{
		Solution: mcpServerName,
		Bindings: []contractBinding{{Audience: "example-api", Ceiling: []Scope{{ResourceKind: "collection", Actions: []string{"read"}}}}},
	}
	server.contractResolved = true

	handler, err := server.mcpHandler(MCPEnvironment{IssuerURL: testIssuer})
	if err != nil {
		t.Fatalf("mount MCP: %v", err)
	}
	host := httptest.NewServer(handler)
	t.Cleanup(host.Close)
	session := connectMCP(t, host, viewerStamp())
	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "inspect",
		Arguments: map[string]any{"question": "anything"},
	})
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	if result.IsError {
		t.Fatalf("tools/call failed: %v", toolErrorText(result))
	}

	if !seen.Load() {
		t.Fatal("the tool never ran, so this test asserted nothing about the gateway it would have been given")
	}
	if !ceilings.Load() {
		t.Error("the gateway an MCP tool call receives carries no ceilings: a mint driven from a tool call is held to nothing the published contract claims, while the identical mint from a handler is refused")
	}
	if !audience.Load() {
		t.Error("the gateway's ceilings do not name the declared audience")
	}
	if !acquirer.Load() {
		t.Error("the gateway has no credential acquirer, so a tool call cannot attest which module is asking")
	}
	if !reporting.Load() {
		t.Error("the gateway has no attestation report, so a refused mint is reported by nothing")
	}
	if !terminal.Load() {
		t.Error("the gateway has no terminal hook, so a refusal that should end the process does not")
	}
}

// --- the composition's half: a derived identifier and one declared value ---

// mcpConfigurationCarrier is the environment variable Codefly's render projects
// one value of the `mcp` workspace-configuration group into. The runtime never
// reads it: it resolves the value through the SDK, exactly as it resolves the
// registration secret. The tests below write the carrier so the SDK's real
// accessor is what answers — a fake in its place would prove the runtime agrees
// with the fake about an encoding that is the SDK's to own.
func mcpConfigurationCarrier(key string) string {
	return resources.WorkspaceConfigurationPrefix + "__" +
		strings.ToUpper(MCPConfigurationGroup) + "__" +
		strings.ToUpper(strings.ReplaceAll(key, "-", "_"))
}

// declareMCPConfiguration projects one value of the group the way a composition
// does, and reloads the SDK's process-wide snapshot of the injected carriers.
func declareMCPConfiguration(t *testing.T, key, value string) {
	t.Helper()
	// Registered before Setenv so it runs after the environment is restored,
	// leaving no declared value behind for the boot tests that follow.
	t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })
	t.Setenv(mcpConfigurationCarrier(key), value)
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
}

// TestMCPPublicURLIsDerivedFromTheProductOrigin is the whole point of issue #48:
// a composition has no way to set a bare environment variable on a service, so
// the URL an MCP client dials cannot be one an operator exports. It is built
// from the origin this product is reachable at and this solution's id — the two
// things the runtime already has — and a composition declares nothing for it.
// A deployment declares it anyway (validateMCP refuses a derived identifier
// there), so what this covers is the local run and the value the boot log
// suggests to an operator.
//
// It derives the host's PUBLIC route to a solution, "/api/solutions/<id>/proxy".
// The gateway's internal "/solutions/<id>" is not reachable from outside, and an
// identifier naming it is one no client can dial — which RFC 9728 §3.3 has the
// client detect and reject, ending discovery.
func TestMCPPublicURLIsDerivedFromTheProductOrigin(t *testing.T) {
	clearSelfEnvironment(t)
	t.Setenv("PORT", "8080")
	t.Setenv("PUBLIC_URL", "https://app.example.com/")

	cfg := loadConfig(context.Background(), "example", nil)
	if want := "https://app.example.com/api/solutions/example/proxy" + MCPPath; cfg.mcpPublicURL != want {
		t.Fatalf("mcpPublicURL = %q, want the derived %q", cfg.mcpPublicURL, want)
	}
	if cfg.mcpPublicExplicit {
		t.Error("a derived public URL reads as explicitly declared, so a refusal would name an override nobody set")
	}
	// Derived, it is pairable by construction: the metadata document a 401
	// points a client at is this URL with MCPPath swapped for the well-known
	// path, so the derivation can never produce the shape validate() refuses.
	paired := siblingURL(cfg.mcpPublicURL, MCPPath, ProtectedResourceMetadataPath)
	if want := "https://app.example.com/api/solutions/example/proxy" + ProtectedResourceMetadataPath; paired != want {
		t.Errorf("metadata URL = %q, want %q", paired, want)
	}
	// It is also what the served document names, with no request-derived part:
	// mcpResource returns the configured identifier before it looks at any
	// forwarded header.
	s := New(Manifest{ID: "example"})
	s.cfg = cfg
	request := httptest.NewRequest(http.MethodPost, MCPPath, nil)
	request.Header.Set(forwardedHostHeader, "attacker.test")
	if got := s.mcpResource(request); got != cfg.mcpPublicURL {
		t.Errorf("mcpResource = %q, want the resolved %q", got, cfg.mcpPublicURL)
	}

	// No origin to derive from: the identifier falls back to the forwarded
	// headers, which validate() refuses in a deployment.
	t.Setenv("PUBLIC_URL", "")
	if got := loadConfig(context.Background(), "example", nil).mcpPublicURL; got != "" {
		t.Errorf("with no PUBLIC_URL, mcpPublicURL = %q, want empty", got)
	}
}

// TestMCPPublicURLOverrideIsADeclaredConfiguration: the override survives, for
// a host whose gateway fronts solutions under some other route — but only as a
// value the composition declares and the SDK resolves, never as a bare
// environment variable, which is what a render cannot project.
func TestMCPPublicURLOverrideIsADeclaredConfiguration(t *testing.T) {
	clearSelfEnvironment(t)
	t.Setenv("PORT", "8080")
	t.Setenv("PUBLIC_URL", "https://app.example.com")
	const declared = "https://mcp.example.com/elsewhere" + MCPPath
	// Declared with the surrounding whitespace a carrier can pick up, which a
	// URL cannot contain. Nothing inside the string is touched — see
	// TestDeclaredMCPPublicURLIsTheIdentifierVerbatim.
	declareMCPConfiguration(t, MCPPublicURLKey, "  "+declared+"\n")

	cfg := loadConfig(context.Background(), "example", nil)
	if cfg.mcpPublicURL != declared {
		t.Fatalf("mcpPublicURL = %q, want the declared %q", cfg.mcpPublicURL, declared)
	}
	if !cfg.mcpPublicExplicit {
		t.Error("a declared public URL does not read as explicit, so a refusal would send the operator to PUBLIC_URL instead of the value they set")
	}
	// The bare environment variable is gone: an operator who exports the name
	// the runtime used to read gets the derived URL, not theirs.
	t.Setenv("MCP_PUBLIC_URL", "https://exported.example.com/mcp")
	if got := loadConfig(context.Background(), "example", nil).mcpPublicURL; got != declared {
		t.Errorf("mcpPublicURL = %q, want the declared %q — a bare MCP_PUBLIC_URL must have no effect", got, declared)
	}
}

// TestMCPIssuerIsADeclaredConfiguration: the issuer is the one value a
// composition must supply for MCP, and it supplies it as a declared workspace
// configuration. Resolved from the host frontend's endpoint otherwise, which is
// right for a local run — and refused in a deployment, where it is the
// in-cluster address this composition dials the host at.
func TestMCPIssuerIsADeclaredConfiguration(t *testing.T) {
	clearSelfEnvironment(t)
	t.Setenv("PORT", "8080")
	t.Setenv("CODEFLY_HOST_FRONTEND", "frontend")
	const declared = "https://login.example.com"
	declareMCPConfiguration(t, MCPIssuerURLKey, declared+"/")

	cfg := loadConfig(context.Background(), "example", nil)
	if cfg.mcpIssuerURL != declared {
		t.Fatalf("mcpIssuerURL = %q, want the declared %q", cfg.mcpIssuerURL, declared)
	}
	if !cfg.mcpIssuerExplicit {
		t.Fatal("a declared issuer does not read as explicit, so a deployment that supplied one would still be refused")
	}
	// The bare environment variable is gone here too.
	t.Setenv("HOST_ISSUER_URL", "https://exported.example.com")
	if got := loadConfig(context.Background(), "example", nil).mcpIssuerURL; got != declared {
		t.Errorf("mcpIssuerURL = %q, want the declared %q — a bare HOST_ISSUER_URL must have no effect", got, declared)
	}
}

// TestDeployedMCPRefusalsNameTheConfigurationThroughTheSDK drives both F2
// refusals the way a deployed cell reaches them: a rendered environment, the
// SDK's own accessors, and nothing else. It is the test that would have caught
// what #48 reports — the refusals naming variables a composition cannot set.
func TestDeployedMCPRefusalsNameTheConfigurationThroughTheSDK(t *testing.T) {
	deployed := func(t *testing.T) config {
		t.Helper()
		clearSelfEnvironment(t)
		t.Setenv("PORT", "8080")
		t.Setenv("CODEFLY__RUNTIME_CONTEXT", "kubernetes")
		t.Setenv("GATEWAY_URL", "http://auth-gateway.saas.svc.cluster.local:8080")
		cfg := loadConfig(context.Background(), "example", nil)
		cfg.mcp = true
		return cfg
	}

	t.Run("no origin to derive the identifier from", func(t *testing.T) {
		declareMCPConfiguration(t, MCPIssuerURLKey, "https://login.example.com")
		cfg := deployed(t)
		if cfg.mcpPublicURL != "" {
			t.Fatalf("mcpPublicURL = %q, want empty with no PUBLIC_URL", cfg.mcpPublicURL)
		}
		err := cfg.validateMCP()
		if err == nil {
			t.Fatal("a deployed MCP surface with no identifier to publish was accepted")
		}
		if !strings.Contains(err.Error(), "PUBLIC_URL") {
			t.Errorf("refusal %q does not name PUBLIC_URL, which the identifier is derived from", err)
		}
		if !strings.Contains(err.Error(), mcpConfigurationValue(MCPPublicURLKey)) {
			t.Errorf("refusal %q does not name %s, the declared override", err, mcpConfigurationValue(MCPPublicURLKey))
		}
		for _, gone := range []string{"MCP_PUBLIC_URL", "HOST_ISSUER_URL"} {
			if strings.Contains(err.Error(), gone) {
				t.Errorf("refusal %q names %s, an environment variable a composition cannot set", err, gone)
			}
		}
	})

	t.Run("no issuer the composition declared", func(t *testing.T) {
		// For the deployed environment it sets, not the config it returns:
		// PUBLIC_URL lands after it, so the config has to be loaded again.
		deployed(t)
		t.Setenv("PUBLIC_URL", "https://app.example.com")
		cfg := loadConfig(context.Background(), "example", nil)
		cfg.mcp = true
		if cfg.mcpIssuerExplicit {
			t.Fatal("an issuer nobody declared reads as explicit")
		}
		err := cfg.validateMCP()
		if err == nil {
			t.Fatal("a deployed MCP surface with an issuer nobody declared was accepted")
		}
		if !strings.Contains(err.Error(), mcpConfigurationValue(MCPIssuerURLKey)) {
			t.Errorf("refusal %q does not name %s, the configuration that fixes it", err, mcpConfigurationValue(MCPIssuerURLKey))
		}
		if strings.Contains(err.Error(), "HOST_ISSUER_URL") {
			t.Errorf("refusal %q names HOST_ISSUER_URL, an environment variable a composition cannot set", err)
		}
	})

	t.Run("a derived identifier is refused however well PUBLIC_URL resolved", func(t *testing.T) {
		// This test asserted the opposite: that declaring the issuer alone was
		// enough, because the identifier is "derived by construction" from
		// PUBLIC_URL. The derivation builds <PUBLIC_URL>/solutions/<id>/mcp,
		// which is this runtime encoding the route the HOST serves it on — the
		// same assumption the Module Federation manifest URL was changed to
		// stop making in this cutover, for the same reason: the route a client
		// reaches a solution through is the host's to resolve, and a runtime
		// guessing it is right only on the machine of whoever wrote the guess.
		//
		// A derived value satisfied the old "a public URL is set" check, so the
		// deployed refusal never fired in the one case that matters.
		declareMCPConfiguration(t, MCPIssuerURLKey, "https://login.example.com")
		deployed(t)
		t.Setenv("PUBLIC_URL", "https://app.example.com")
		cfg := loadConfig(context.Background(), "example", nil)
		cfg.mcp = true
		err := cfg.validateMCP()
		if err == nil {
			t.Fatal("a deployed MCP surface was accepted with an identifier derived from PUBLIC_URL: a client binds its token to the URL it dialled, and this one is a guess about the host's route layout")
		}
		if !strings.Contains(err.Error(), mcpConfigurationValue(MCPPublicURLKey)) {
			t.Errorf("the refusal %q does not name %s, the configuration that fixes it", err, mcpConfigurationValue(MCPPublicURLKey))
		}
	})

	t.Run("both declared values are enough", func(t *testing.T) {
		declareMCPConfiguration(t, MCPIssuerURLKey, "https://login.example.com")
		declareMCPConfiguration(t, MCPPublicURLKey, "https://app.example.com/example"+MCPPath)
		deployed(t)
		cfg := loadConfig(context.Background(), "example", nil)
		cfg.mcp = true
		if err := cfg.validateMCP(); err != nil {
			t.Fatalf("a deployed MCP surface with both values declared was refused: %v", err)
		}
		if want := "https://app.example.com/example" + MCPPath; cfg.mcpPublicURL != want {
			t.Errorf("mcpPublicURL = %q, want the declared %q", cfg.mcpPublicURL, want)
		}
	})

	t.Run("a published URL is held to what a dialled one is", func(t *testing.T) {
		for _, tc := range []struct{ name, value, names string }{
			{"userinfo", "https://ops:s3cr3t@app.example.com/example" + MCPPath, "userinfo"},
			{"a query string", "https://app.example.com/example" + MCPPath + "?token=s3cr3t", "query"},
			{"a fragment", "https://app.example.com/example" + MCPPath + "#frag", "fragment"},
			{"plaintext", "http://app.example.com/example" + MCPPath, "https"},
		} {
			t.Run(tc.name, func(t *testing.T) {
				declareMCPConfiguration(t, MCPIssuerURLKey, "https://login.example.com")
				declareMCPConfiguration(t, MCPPublicURLKey, tc.value)
				deployed(t)
				cfg := loadConfig(context.Background(), "example", nil)
				cfg.mcp = true
				err := cfg.validateMCP()
				if err == nil {
					t.Fatalf("a deployed MCP surface published %q: it is the identifier clients bind a token to and dial, so it is held to what the addresses this runtime dials are held to", tc.value)
				}
				if !strings.Contains(err.Error(), tc.names) {
					t.Errorf("the refusal %q does not say what is wrong (%s)", err, tc.names)
				}
				if strings.Contains(err.Error(), "s3cr3t") {
					t.Errorf("the refusal %q repeats the secret it is refusing", err)
				}
			})
		}
	})
}

// TestAnMCPToolDoesNotRunWhileThisExecutionHoldsNoCredential is R4-3 on the
// MCP path, which the integration of main reopened.
//
// A plain handler and a ViewerBearer passthrough are both refused while the
// issuer has withdrawn this execution's credential — "fail closed, with no
// exception for a counterpart's current state". A tool call was not: executed
// round eight reproduced one being SERVED over mTLS with a real MCP client,
// with the viewer's bearer reaching the gateway.
//
// Refused at the HTTP boundary, which answers a real 503. An earlier version of
// this gated only at the method layer so that tools/list could still answer,
// on the grounds that refusing it would make a withdrawn credential look like
// a solution serving no MCP at all. That reasoning was weak: a 503 carrying
// the sanitized sentence says "temporarily cannot act", which is accurate,
// where a 404 would be the indistinguishable answer. And a client that
// connects and lists tools it can never call is worse served than one told to
// back off. The method-layer gate stays as well, for anything reaching the
// method middleware another way.
func TestAnMCPToolDoesNotRunWhileThisExecutionHoldsNoCredential(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"a terminal refusal", workcontext.ErrMintRefused},
		{"a transient unavailability", workcontext.ErrMintUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var ran atomic.Bool
			register := func(srv *mcp.Server) {
				mcp.AddTool(srv, &mcp.Tool{Name: "act", Description: "must not run"},
					func(ctx context.Context, _ *mcp.CallToolRequest, _ askInput) (*mcp.CallToolResult, askOutput, error) {
						ran.Store(true)
						return nil, askOutput{Status: 200}, nil
					})
			}
			server := New(Manifest{ID: mcpServerName, Title: "Example"}).
				ServeMCP(mcpServerName, "v1.2.3", register).
				Credential(refusingSource{err: fmt.Errorf("%w: the issuer said so, at https://mint.internal.example/platform/_credential (dial tcp 10.4.1.9:8443: connection refused)", tc.err)})

			handler, err := server.mcpHandler(MCPEnvironment{IssuerURL: testIssuer})
			if err != nil {
				t.Fatalf("mount MCP: %v", err)
			}
			host := httptest.NewServer(handler)
			t.Cleanup(host.Close)

			// A tools/call the way a client sends it, by hand: the SDK's
			// client cannot complete its handshake against a surface that is
			// refusing, which is the point.
			body := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"act","arguments":{"question":"anything"}}}`
			req, err := http.NewRequest(http.MethodPost, host.URL+MCPPath, strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			req.Header.Set("content-type", "application/json")
			stamp := viewerStamp()
			req.Header.Set("authorization", stamp.bearer)
			req.Header.Set(userHeader, stamp.userID)
			req.Header.Set(orgHeader, stamp.orgID)
			req.Header.Set(sessionHeader, stamp.sessionID)
			req.Header.Set(workcontext.InstallationIDHeaderName, testInstallation)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("post a tool call: %v", err)
			}
			defer drainAndClose(resp)

			if resp.StatusCode != http.StatusServiceUnavailable {
				t.Errorf("a tool call answered %d while this execution held no usable credential, want 503: the viewer's bearer would otherwise reach author code under authority this process does not have", resp.StatusCode)
			}
			if ran.Load() {
				t.Error("the tool ran: the gate has to refuse before anything author-written executes")
			}
			said, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatal(err)
			}
			for _, leak := range []string{"mint.internal.example", "_credential", "10.4.1.9", "connection refused"} {
				if strings.Contains(string(said), leak) {
					t.Errorf("the refusal discloses %q to an MCP client: %s", leak, said)
				}
			}
		})
	}

	t.Run("the refusal is 503 and not 404", func(t *testing.T) {
		// A withdrawn credential must not read as "this solution serves no
		// MCP": one is a back-off, the other sends a client looking for an
		// endpoint that does not exist.
		server := New(Manifest{ID: mcpServerName, Title: "Example"}).
			ServeMCP(mcpServerName, "v1.2.3", readCollectionTool).
			Credential(refusingSource{err: workcontext.ErrMintRefused})
		handler, err := server.mcpHandler(MCPEnvironment{IssuerURL: testIssuer})
		if err != nil {
			t.Fatalf("mount MCP: %v", err)
		}
		host := httptest.NewServer(handler)
		t.Cleanup(host.Close)

		req, err := http.NewRequest(http.MethodPost, host.URL+MCPPath, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`))
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("content-type", "application/json")
		stamp := viewerStamp()
		req.Header.Set("authorization", stamp.bearer)
		req.Header.Set(orgHeader, stamp.orgID)
		req.Header.Set(sessionHeader, stamp.sessionID)
		req.Header.Set(workcontext.InstallationIDHeaderName, testInstallation)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer drainAndClose(resp)
		if resp.StatusCode == http.StatusNotFound {
			t.Error("a withdrawn credential answered 404: an MCP client cannot tell that from a solution that serves no MCP at all")
		}
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", resp.StatusCode)
		}
	})

	t.Run("every method that is not allowlisted is gated at the method layer too", func(t *testing.T) {
		// The method-layer gate's property, not an enumeration: a method this
		// file has never heard of is held to the credential. A denylist over
		// the SDK's method set is the mistake the TLS posture made three times.
		for _, method := range []string{"tools/call", "resources/read", "prompts/get", "completion/complete", "some/method-added-next-release",
			// The namespace that used to be exempted by prefix. It is open —
			// the SDK's extension API lets author code register under it — so
			// a method nobody here named must be gated, not waved through for
			// looking like a notification.
			"notifications/anything-an-author-registers", "notifications/tools/call"} {
			if actsForNobody(method) {
				t.Errorf("%q is treated as acting for nobody, so a viewer action on it would skip the credential gate", method)
			}
		}
		for _, method := range []string{"initialize", "ping", "tools/list", "prompts/list", "resources/list",
			"notifications/initialized", "notifications/cancelled", "notifications/progress", "notifications/roots/list_changed"} {
			if !actsForNobody(method) {
				t.Errorf("%q is gated at the method layer though it runs nothing for a viewer", method)
			}
		}
	})
}

// TestAToolsOwnFailureIsSanitizedOnTheWayOut is the other half of R8-1, and
// the half my first answer to it did not test.
//
// The gate refuses a tool when this execution holds no credential. This is the
// case the gate lets through: the credential is fine when the call starts and
// the viewer's mint fails during it. A tool that called ForModule and was
// refused handed the agent client the whole chain — "mint returned HTTP 503",
// and with the issuer unreachable the mint's own URL and dial address.
//
// A tool's error is written for a model and read by whoever is driving it, so
// it is sanitized by the same rule a handler's is. The mutation that relays
// err.Error() verbatim survived until this test existed, because the gate test
// refuses before any tool runs and never reaches the out-path.
func TestAToolsOwnFailureIsSanitizedOnTheWayOut(t *testing.T) {
	// A gateway whose mint refuses, and a workload credential that is
	// perfectly good — so the gate passes and the failure happens inside the
	// tool.
	gw := newWorkContextGateway(t, &workContextGateway{mintStatus: http.StatusServiceUnavailable})
	register := func(srv *mcp.Server) {
		mcp.AddTool(srv, &mcp.Tool{Name: "read", Description: "reads a module as the viewer"},
			func(ctx context.Context, _ *mcp.CallToolRequest, _ askInput) (*mcp.CallToolResult, askOutput, error) {
				viewer, err := ViewerFromContext(ctx)
				if err != nil {
					return nil, askOutput{}, err
				}
				// The real shape: a tool minting for the viewer, refused.
				if _, err := viewer.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}}); err != nil {
					return nil, askOutput{}, err
				}
				return nil, askOutput{Status: 200}, nil
			})
	}
	server := New(Manifest{ID: mcpServerName, Title: "Example"}).
		ServeMCP(mcpServerName, "v1.2.3", register).
		Credential(attestingSource(t))
	server.cfg.gatewayURL = gw.URL

	handler, err := server.mcpHandler(MCPEnvironment{GatewayURL: gw.URL, IssuerURL: testIssuer})
	if err != nil {
		t.Fatalf("mount MCP: %v", err)
	}
	host := httptest.NewServer(handler)
	t.Cleanup(host.Close)
	session := connectMCP(t, host, viewerStamp())

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "read",
		Arguments: map[string]any{"question": "anything"},
	})
	// Either shape is a failure the client sees; what matters is what it says.
	said := ""
	switch {
	case err != nil:
		said = err.Error()
	case result != nil && result.IsError:
		said = toolErrorText(result)
	default:
		t.Fatal("a tool whose viewer mint was refused answered as though it had succeeded")
	}
	for _, leak := range []string{gw.URL, "StartTask", "503", "mint returned"} {
		if strings.Contains(said, leak) {
			t.Errorf("the tool's failure discloses %q to the MCP client: %s", leak, said)
		}
	}
	if said == "" {
		t.Error("the client was told nothing at all")
	}
}

// TestTheMethodLayerGateRefusesOnItsOwn exercises the MCP method middleware
// directly, without the HTTP boundary in front of it.
//
// Both gates refuse a viewer action while this execution holds no credential,
// and after the HTTP one was added the method one had nothing holding it: the
// mutation that removes it survived, because every test reaching a tool goes
// through requireStampedViewer first and is refused there. Adding the better
// check orphaned the one behind it.
//
// It is not redundant. It is what holds a method dispatched without passing
// through that handler — and it is the layer that knows the method name, so it
// is where the allowlist lives.
func TestTheMethodLayerGateRefusesOnItsOwn(t *testing.T) {
	server := New(Manifest{ID: mcpServerName, Title: "Example"}).
		ServeMCP(mcpServerName, "v1.2.3", readCollectionTool).
		Credential(refusingSource{err: fmt.Errorf("%w: at https://mint.internal.example/platform/_credential", workcontext.ErrMintUnavailable)})

	var reached atomic.Bool
	next := func(context.Context, string, mcp.Request) (mcp.Result, error) {
		reached.Store(true)
		return nil, nil
	}
	gated := server.mcpViewer(next)

	t.Run("a method that acts for a viewer is refused", func(t *testing.T) {
		reached.Store(false)
		_, err := gated(context.Background(), "tools/call", &mcp.CallToolRequest{})
		if err == nil {
			t.Fatal("the method middleware admitted a tool call while this execution held no usable credential: it is what holds a method dispatched without the HTTP handler in front of it")
		}
		if reached.Load() {
			t.Error("the call reached the next handler, so nothing was gated")
		}
		for _, leak := range []string{"mint.internal.example", "_credential"} {
			if strings.Contains(err.Error(), leak) {
				t.Errorf("the refusal discloses %q: %s", leak, err)
			}
		}
		// And it carries the CODE, which is the whole point of item 8: a
		// client that gets a generic protocol error cannot tell "this solution
		// cannot act right now" from a broken tool, so it cannot back off.
		// The mutation that drops the typed error survived until this.
		var wire *jsonrpc.Error
		if !errors.As(err, &wire) {
			t.Fatalf("the refusal is %T, not a *jsonrpc.Error: without a code an MCP client cannot distinguish this from any other server error", err)
		}
		if wire.Code != mcpCredentialUnavailableCode {
			t.Errorf("the refusal carries code %d, want %d", wire.Code, mcpCredentialUnavailableCode)
		}
	})

	t.Run("a method that acts for nobody passes", func(t *testing.T) {
		reached.Store(false)
		if _, err := gated(context.Background(), "tools/list", &mcp.ListToolsRequest{}); err != nil {
			t.Errorf("the method middleware refused tools/list, which runs nothing for a viewer: %v", err)
		}
		if !reached.Load() {
			t.Error("tools/list never reached the next handler")
		}
	})
}

// TestNoMCPRefusalEverPrintsASecret is item 4, as a property rather than an
// audit.
//
// Every refusal that quotes a URL goes through redactedURL, which drops
// userinfo, the query and the fragment — url.Redacted() masks the password and
// keeps the username, which is how a great many tokens are carried. I had
// redacted two paths and missed six, so this drives every refusal validateMCP
// can produce with a secret in each position and asserts none of them comes
// back out.
func TestNoMCPRefusalEverPrintsASecret(t *testing.T) {
	const secret = "s3cr3tvalue"
	// Every shape that reaches a refusal: unresolved, in-cluster, derived,
	// unpairable, plaintext, and a secret in each of the three positions a URL
	// can hide one.
	withSecret := []string{
		"https://ops:" + secret + "@app.example.com/example" + MCPPath,
		"https://app.example.com/example" + MCPPath + "?token=" + secret,
		"https://app.example.com/example" + MCPPath + "#" + secret,
		"http://app.example.com/example" + MCPPath + "?token=" + secret,
		"https://" + secret + ":x@app.example.com/not-the-suffix",
		"not-a-url-at-all?token=" + secret,
		// Scheme-less and opaque forms. url.Parse accepts
		// "ops:SECRET@host/path" as scheme "ops" with everything after the
		// colon opaque, so User is nil and RawQuery empty and the ordinary
		// strips touch nothing — the secret came through redactedURL intact.
		"ops:" + secret + "@app.example.com/example" + MCPPath,
		"mailto:ops:" + secret + "@app.example.com",
		"app.example.com:8443/example" + MCPPath + "?token=" + secret,
		"https://app.example.com/example?token=" + secret,
	}
	for _, runtimeContext := range []string{"", "kubernetes"} {
		for _, value := range withSecret {
			for _, which := range []string{"issuer", "public"} {
				cfg := config{mcp: true, runtimeContext: runtimeContext,
					mcpIssuerURL: "https://login.example.com", mcpIssuerExplicit: true,
					mcpPublicURL: "https://app.example.com/example" + MCPPath, mcpPublicExplicit: true}
				switch which {
				case "issuer":
					cfg.mcpIssuerURL = value
				case "public":
					cfg.mcpPublicURL = value
				}
				err := cfg.validateMCP()
				if err == nil {
					continue // accepted; nothing was printed
				}
				if strings.Contains(err.Error(), secret) {
					t.Errorf("a refusal printed the secret in %s=%q (runtime context %q): %v",
						which, value, runtimeContext, err)
				}
			}
		}
	}
}

// A transport failure through gw.HTTPClient() is deliberately NOT sanitized,
// and a test asserting otherwise was deleted rather than weakened.
//
// Two reasons, found by writing it. http.Client.Do wraps whatever the
// transport returns in its own *url.Error carrying the URL, so a transport
// wrapper cannot remove the address. And the author built that request from
// BaseURL(), so the address is already theirs — the error discloses nothing
// they did not have. What the runtime owes them is not handing over what they
// could not otherwise see, which is Gateway.surfaced's job and is covered by
// TestAToolsOwnFailureIsSanitizedOnTheWayOut.

// TestNoExportedGatewayMethodRelaysTheRuntimesError is round eleven's item 3,
// and it is a gate rather than one more case.
//
// ForModule's mint errors were sanitized and its exported SIBLING's were not:
// WorkContextPrincipals reaches the same mint, produced the same errors — the
// status, the issuer's code, its message — and handed them straight back. A
// tool relayed the whole chain to an agent client. Two callers of one mint,
// one of them sanitized.
//
// So this drives every exported Gateway method that can return a runtime
// error, on a gateway that asked for sanitizing, and asserts none of them
// carries the issuer's words. A method added later is one line here, and the
// one-by-one version of this test is how the second path was missed.
func TestNoExportedGatewayMethodRelaysTheRuntimesError(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	server := New(Manifest{ID: testSolutionID}).Credential(attestingSource(t))
	server.cfg = config{gatewayURL: gw.URL}

	header := http.Header{}
	header.Set("authorization", viewerBearer())
	header.Set(orgHeader, viewerOrg)
	header.Set(sessionHeader, viewerSession)
	header.Set(workcontext.InstallationIDHeaderName, testInstallation)

	viewer := server.gatewayFor(header)
	// The MCP path, where a tool's error becomes content a client reads and
	// nothing downstream can tell it from the author's own.
	viewer.sanitizeErrors = true

	// A derived gateway first, so the delegation exists; then the host starts
	// refusing and the held capability lapses, which is what a tool holding a
	// gateway hits mid-call.
	acting, err := viewer.ForModule(context.Background(), "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
	if err != nil {
		t.Fatalf("the first derive failed, so nothing below is about sanitizing: %v", err)
	}
	gw.mintStatus = http.StatusServiceUnavailable
	lapseCachedCapabilities(acting)

	for _, probe := range []struct {
		name string
		call func() error
	}{
		{"ForModule", func() error {
			_, err := viewer.ForModule(context.Background(), "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
			return err
		}},
		{"WorkContextPrincipals", func() error {
			_, err := acting.WorkContextPrincipals(context.Background())
			return err
		}},
	} {
		t.Run(probe.name, func(t *testing.T) {
			err := probe.call()
			if err == nil {
				t.Fatal("the refusing host was not reached, so this probe asserted nothing")
			}
			// The issuer's own words, the status it answered with, and the
			// address this runtime dialled.
			for _, leak := range []string{gw.URL, "StartTask", "503", "permission_denied", "no such authority", "rejected"} {
				if strings.Contains(err.Error(), leak) {
					t.Errorf("%s relays %q to whoever the author hands this to: %v", probe.name, leak, err)
				}
			}
		})
	}
}

// TestAToolResultNeverCarriesTheRuntimesInternals is B1: the path where the
// middleware sees no error at all.
//
// The SDK's typed AddTool wrapper turns a tool's returned error into
// CallToolResult{IsError: true} and returns a NIL error, so the middleware's
// error branch never runs and whatever the tool was handed travels as content.
// The shape that exposed it: a tool derives a gateway, the held capability
// lapses, and the re-mint happens INSIDE the round trip — so the refusal
// carries the issuer's status, its code and its words, and http.Client.Do
// prepends the address it dialled.
//
// Measured before the fix, the client was told:
//
//	Get "http://127.0.0.1:50122/v1/documents/collection": work context mint
//	for "documents" rejected (status 503, "permission_denied"): caller holds
//	no such authority
//
// Two layers answer it, because one was not enough. bearerTransport sanitizes
// the mint error where it leaves this runtime, which removes the issuer's
// words; and the middleware replaces an error result that still names an
// address this runtime dialled, which is what net/http added after the author
// had no further say.
//
// My earlier reasoning is what let this through: I argued a transport error
// only names an address the author already holds from BaseURL(), which is true
// of a dial failure and false of a renewal that happens inside the transport.
func TestAToolResultNeverCarriesTheRuntimesInternals(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	register := func(srv *mcp.Server) {
		mcp.AddTool(srv, &mcp.Tool{Name: "read", Description: "reads a module as the viewer"},
			func(ctx context.Context, _ *mcp.CallToolRequest, _ askInput) (*mcp.CallToolResult, askOutput, error) {
				viewer, err := ViewerFromContext(ctx)
				if err != nil {
					return nil, askOutput{}, err
				}
				acting, err := viewer.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
				if err != nil {
					return nil, askOutput{}, err
				}
				// The host starts refusing and the capability lapses, so the
				// re-mint lands inside the round trip below.
				gw.mintStatus = http.StatusServiceUnavailable
				lapseCachedCapabilities(acting)
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, acting.BaseURL()+modulePath, nil)
				if err != nil {
					return nil, askOutput{}, err
				}
				resp, err := acting.HTTPClient().Do(request)
				if err != nil {
					// Relayed verbatim, which is what an author does.
					return nil, askOutput{}, err
				}
				drainAndClose(resp)
				return nil, askOutput{Status: resp.StatusCode}, nil
			})
	}
	server := New(Manifest{ID: mcpServerName, Title: "Example"}).
		ServeMCP(mcpServerName, "v1.2.3", register).
		Credential(attestingSource(t))
	server.cfg.gatewayURL = gw.URL

	handler, err := server.mcpHandler(MCPEnvironment{GatewayURL: gw.URL, IssuerURL: testIssuer})
	if err != nil {
		t.Fatalf("mount MCP: %v", err)
	}
	host := httptest.NewServer(handler)
	t.Cleanup(host.Close)
	session := connectMCP(t, host, viewerStamp())

	result, callErr := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "read",
		Arguments: map[string]any{"question": "anything"},
	})
	said := ""
	switch {
	case callErr != nil:
		said = callErr.Error()
	case result != nil && result.IsError:
		said = toolErrorText(result)
	default:
		t.Fatal("the tool reported success though its module read could not be authenticated")
	}
	for _, leak := range []string{gw.URL, "127.0.0.1", modulePath, "StartTask", "503", "permission_denied", "no such authority", "work context mint"} {
		if strings.Contains(said, leak) {
			t.Errorf("the tool result discloses %q to the MCP client: %s", leak, said)
		}
	}
	if said == "" {
		t.Error("the client was told nothing at all")
	}
}

// TestAToolsOwnRefusalIsLeftAlone is the other half of B1's fix: the net must
// not rewrite what an author actually wrote.
//
// Replacing every error result would take a tool's own vocabulary away, and a
// model driving it reads that text. The replacement fires only when the
// content names an address this runtime dialled.
func TestAToolsOwnRefusalIsLeftAlone(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	register := func(srv *mcp.Server) {
		mcp.AddTool(srv, &mcp.Tool{Name: "ask", Description: "refuses in its own words"},
			func(context.Context, *mcp.CallToolRequest, askInput) (*mcp.CallToolResult, askOutput, error) {
				return nil, askOutput{}, errors.New("no such collection in this solution")
			})
	}
	server := New(Manifest{ID: mcpServerName, Title: "Example"}).
		ServeMCP(mcpServerName, "v1.2.3", register).
		Credential(attestingSource(t))
	server.cfg.gatewayURL = gw.URL
	handler, err := server.mcpHandler(MCPEnvironment{GatewayURL: gw.URL, IssuerURL: testIssuer})
	if err != nil {
		t.Fatalf("mount MCP: %v", err)
	}
	host := httptest.NewServer(handler)
	t.Cleanup(host.Close)
	session := connectMCP(t, host, viewerStamp())

	result, err := session.CallTool(context.Background(), &mcp.CallToolParams{
		Name:      "ask",
		Arguments: map[string]any{"question": "anything"},
	})
	if err != nil {
		t.Fatalf("tools/call: %v", err)
	}
	if !strings.Contains(toolErrorText(result), "no such collection in this solution") {
		t.Errorf("the tool's own refusal was rewritten: %q — a tool's vocabulary is its own, and a model driving it reads that text", toolErrorText(result))
	}
}

// TestAStructuredToolResultNeverCarriesTheRuntimesInternals is round fifteen's
// minor, and it narrows a closure claim I made.
//
// withoutRuntimeAddresses read only Content. The pinned SDK serializes
// StructuredContent too, so a result with generic text and
// StructuredContent{"error": err.Error()} reached the agent client with the
// mint's address in it. The net was installed for exactly that disclosure and
// was looking in one of the two places the SDK sends.
func TestAStructuredToolResultNeverCarriesTheRuntimesInternals(t *testing.T) {
	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{
		gatewayURL: "https://gateway.internal.test",
		mintURL:    "https://mint.internal.test/platform/_credential",
	}
	server.cfg.dialled = dialledAddresses(server.cfg.gatewayURL, server.cfg.mintURL)

	t.Run("the address is in the structured content alone", func(t *testing.T) {
		result := server.withoutRuntimeAddresses(&mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.TextContent{Text: "the call did not complete"}},
			StructuredContent: map[string]any{
				"error": `Post "https://mint.internal.test/platform/_credential": dial tcp 127.0.0.1:1 connect: connection refused`,
			},
		}, "tools/call")
		call, ok := result.(*mcp.CallToolResult)
		if !ok {
			t.Fatalf("the filter returned %T", result)
		}
		if call.StructuredContent != nil {
			t.Errorf("the replaced result still carries structured content: %v", call.StructuredContent)
		}
		rendered, err := json.Marshal(call)
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{"mint.internal.test", "gateway.internal.test"} {
			if strings.Contains(string(rendered), secret) {
				t.Errorf("the serialized result names %q, which is an address this runtime dialled and nothing a viewer's agent client may be told: %s", secret, rendered)
			}
		}
	})

	t.Run("a tool's own structured refusal is left alone", func(t *testing.T) {
		// The net matches on exact configured values, so an author's own
		// structured error about their own domain is untouched.
		own := &mcp.CallToolResult{
			IsError:           true,
			Content:           []mcp.Content{&mcp.TextContent{Text: "the backend rejected that page title"}},
			StructuredContent: map[string]any{"error": "title must not be empty", "field": "title"},
		}
		// The CONTENT survives, which is what "left alone" means. Pointer
		// identity used to stand in for it and no longer can: the filter
		// returns the bytes it checked, so what a client reads is exactly
		// what was inspected rather than a re-serialization of a value this
		// runtime does not own.
		got, ok := server.withoutRuntimeAddresses(own, "tools/call").(*mcp.CallToolResult)
		if !ok {
			t.Fatalf("the filter returned %T", got)
		}
		if !got.IsError || len(got.Content) != 1 {
			t.Fatalf("the filter reshaped a tool's own refusal: %+v", got)
		}
		if text, isText := got.Content[0].(*mcp.TextContent); !isText || text.Text != "the backend rejected that page title" {
			t.Errorf("the filter replaced a tool's own message: %+v", got.Content[0])
		}
		rendered, err := json.Marshal(got.StructuredContent)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []string{"title must not be empty", "title"} {
			if !strings.Contains(string(rendered), want) {
				t.Errorf("a tool's own structured refusal lost %q: %s", want, rendered)
			}
		}
	})

	t.Run("the address is JSON-escaped, which is the same string to a client", func(t *testing.T) {
		// Round sixteen's escape: json.RawMessage keeps `https:\/\/host`
		// through Marshal, so a search over the serialized bytes for
		// "https://host" misses — and the client decodes the address straight
		// back out. The decoded strings are what get checked now.
		escaped := json.RawMessage(`{"error":"https:\/\/mint.internal.test\/platform\/_credential failed"}`)
		result := server.withoutRuntimeAddresses(&mcp.CallToolResult{
			IsError:           true,
			Content:           []mcp.Content{&mcp.TextContent{Text: "the call did not complete"}},
			StructuredContent: escaped,
		}, "tools/call")
		call, ok := result.(*mcp.CallToolResult)
		if !ok {
			t.Fatalf("the filter returned %T", result)
		}
		if call.StructuredContent != nil {
			t.Errorf("the escaped address survived the filter: %v", call.StructuredContent)
		}
		// And what a client would actually read must not contain it either.
		rendered, err := json.Marshal(call)
		if err != nil {
			t.Fatal(err)
		}
		var asAClientSeesIt any
		if err := json.Unmarshal(rendered, &asAClientSeesIt); err != nil {
			t.Fatal(err)
		}
		again, _ := json.Marshal(asAClientSeesIt)
		if strings.Contains(string(again), "mint.internal.test") {
			t.Errorf("a client decoding this result reads the mint's address: %s", again)
		}
	})

	t.Run("an address used as a structured KEY is caught too", func(t *testing.T) {
		result := server.withoutRuntimeAddresses(&mcp.CallToolResult{
			IsError:           true,
			Content:           []mcp.Content{&mcp.TextContent{Text: "the call did not complete"}},
			StructuredContent: map[string]any{"https://mint.internal.test/platform/_credential": "refused"},
		}, "tools/call")
		if call, ok := result.(*mcp.CallToolResult); !ok || call.StructuredContent != nil {
			t.Errorf("an address in a structured KEY survived the filter: %+v", result)
		}
	})

	t.Run("a marshaler that answers differently the second time cannot disclose", func(t *testing.T) {
		// The confirming round's finding: the filter inspected ONE
		// serialization and returned the original object, which the SDK then
		// serialized again. A MarshalJSON that answers `{}` first and the
		// mint's address afterwards passed the check and disclosed on the
		// second call. No concurrency needed — marshalling is not a pure
		// function of a value this runtime did not write.
		shifty := &shiftingMarshaler{later: `{"error":"https://mint.internal.test/platform/_credential"}`}
		result := server.withoutRuntimeAddresses(&mcp.CallToolResult{
			IsError:           true,
			Content:           []mcp.Content{&mcp.TextContent{Text: "the call did not complete"}},
			StructuredContent: shifty,
		}, "tools/call")
		// What a client reads is the SDK's serialization of what came back.
		published, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(published), "mint.internal.test") {
			t.Errorf("the published result names the mint's address, which the filter had approved on an earlier serialization: %s", published)
		}
		if shifty.calls > 1 {
			t.Errorf("the value was marshalled %d times, so the bytes that were checked are not the bytes that were published", shifty.calls)
		}
	})

	t.Run("a marshaler that rewrites sibling text cannot disclose", func(t *testing.T) {
		// The confirming round's minor, and the sharper half of it: the text
		// was inspected BEFORE the structured content was marshalled, so a
		// structured value holding a pointer to the result's own TextContent
		// could rewrite the text from inside MarshalJSON — after it had
		// passed inspection — and serialize as a clean `{}` itself. No second
		// marshaller call and no concurrency.
		text := &mcp.TextContent{Text: "the call did not complete"}
		result := server.withoutRuntimeAddresses(&mcp.CallToolResult{
			IsError:           true,
			Content:           []mcp.Content{text},
			StructuredContent: sabotagingMarshaler{text: text, to: "https://mint.internal.test/platform/_credential"},
		}, "tools/call")
		published, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(published), "mint.internal.test") {
			t.Errorf("the published result names the mint's address: a marshaler rewrote text that had already passed inspection: %s", published)
		}
	})

	t.Run("content this runtime cannot read is replaced", func(t *testing.T) {
		// Fail closed: content whose serialization nothing here inspected is
		// not published.
		result := server.withoutRuntimeAddresses(&mcp.CallToolResult{
			IsError: true,
			Content: []mcp.Content{&mcp.ImageContent{Data: []byte("x"), MIMEType: "image/png"}},
		}, "tools/call")
		call, ok := result.(*mcp.CallToolResult)
		if !ok {
			t.Fatalf("the filter returned %T", result)
		}
		if len(call.Content) != 1 {
			t.Fatalf("want the single replacement message, got %+v", call.Content)
		}
		if text, isText := call.Content[0].(*mcp.TextContent); !isText || !strings.Contains(text.Text, "could not complete") {
			t.Errorf("content the filter cannot inspect was published as-is: %+v", call.Content[0])
		}
	})

	t.Run("structured content this runtime cannot read is replaced", func(t *testing.T) {
		// It cannot be cleared if it cannot be read, and the SDK is about to
		// serialize it either way.
		result := server.withoutRuntimeAddresses(&mcp.CallToolResult{
			IsError:           true,
			Content:           []mcp.Content{&mcp.TextContent{Text: "the call did not complete"}},
			StructuredContent: map[string]any{"error": func() {}},
		}, "tools/call")
		call, ok := result.(*mcp.CallToolResult)
		if !ok || call.StructuredContent != nil {
			t.Errorf("unreadable structured content survived the filter: %+v", result)
		}
	})
}

// shiftingMarshaler answers `{}` the first time and something else after, which
// is the shape that defeats checking one serialization and publishing another.
type shiftingMarshaler struct {
	calls int
	later string
}

func (s *shiftingMarshaler) MarshalJSON() ([]byte, error) {
	s.calls++
	if s.calls == 1 {
		return []byte(`{}`), nil
	}
	return []byte(s.later), nil
}

// sabotagingMarshaler serializes as `{}` and, as a side effect, rewrites a
// sibling TextContent the result still carries.
type sabotagingMarshaler struct {
	text *mcp.TextContent
	to   string
}

func (v sabotagingMarshaler) MarshalJSON() ([]byte, error) {
	v.text.Text = v.to
	return []byte(`{}`), nil
}

// --- the identifier is the host's public route, exactly, and reachable ---

// deployedMCPConfig is a deployed runtime context with both MCP values declared
// — what a cell actually provisions, since validateMCP refuses a derived
// identifier there. The caller overrides whichever value it is testing.
func deployedMCPConfig(t *testing.T, publicURL string) config {
	t.Helper()
	clearSelfEnvironment(t)
	t.Setenv("PORT", "8080")
	t.Setenv("CODEFLY__RUNTIME_CONTEXT", "kubernetes")
	declareMCPConfiguration(t, MCPIssuerURLKey, "https://login.example.com")
	declareMCPConfiguration(t, MCPPublicURLKey, publicURL)
	cfg := loadConfig(context.Background(), "example", nil)
	cfg.mcp = true
	return cfg
}

// TestMCPIdentifierNamesTheHostsPublicProxyRoute pins the one piece of the
// host's route layout this runtime encodes, against a literal written out here
// rather than built from the constants — so changing either constant turns this
// red instead of silently re-pointing what a local run publishes and what the
// boot log tells an operator to provision.
//
// It is pinned by a literal because nothing projects it. The host owns
// "/api/solutions/<id>/proxy" and there is no contract by which it reaches a
// composed solution's backend: the SDK resolves endpoints as
// resources.NetworkInstance (host, hostname, port, address — no path), a
// basev0.Endpoint carries no public URL or route template, and core's only
// public-route concept, resources.EnvironmentIngressRoute, binds hosts to a
// service endpoint, is CLI-side and is not serialized to proto.
//
// What this pins, exactly: nobody changes the runtime's route constants without
// a red suite. It does NOT detect the host changing its route — this module has
// no dependency on the host and nothing here observes the host's routing, so
// that case leaves this suite green and breaks a client's discovery. The test
// for that drives the host's own source and lives where the host is visible.
// What limits the damage meanwhile is that a DEPLOYED surface must declare the
// identifier; the derivation is the local run's.
func TestMCPIdentifierNamesTheHostsPublicProxyRoute(t *testing.T) {
	clearSelfEnvironment(t)
	t.Setenv("PORT", "8080")
	t.Setenv("PUBLIC_URL", "https://app.example.com")

	cfg := loadConfig(context.Background(), "example", nil)
	const identifier = "https://app.example.com/api/solutions/example/proxy/mcp"
	if cfg.mcpPublicURL != identifier {
		t.Fatalf("resource identifier = %q, want the host's public proxy route %q", cfg.mcpPublicURL, identifier)
	}
	// The gateway's in-cluster route is a page of the host's frontend on the
	// public origin, so an identifier naming it is one no client can dial.
	if strings.Contains(cfg.mcpPublicURL, "https://app.example.com/solutions/") {
		t.Errorf("resource identifier %q names the gateway's in-cluster route, which is not reachable from outside the cell", cfg.mcpPublicURL)
	}
	// The metadata document a 401 points at is this URL with the suffix
	// swapped, so it must land on the same public route.
	const metadata = "https://app.example.com/api/solutions/example/proxy/.well-known/oauth-protected-resource"
	if got := siblingURL(cfg.mcpPublicURL, MCPPath, ProtectedResourceMetadataPath); got != metadata {
		t.Errorf("metadata URL = %q, want %q", got, metadata)
	}
	// And the value this package SUGGESTS to an operator is the same route. It
	// named the in-cluster one, which is the worse half of the bug: a
	// derivation an operator never sees is a default, but a suggestion is read
	// as the answer and provisions the same unreachable identifier by hand.
	if got := hostSolutionPublicMCPURL("https://<host>", "example"); got != "https://<host>/api/solutions/example/proxy/mcp" {
		t.Errorf("suggested identifier = %q, want the public proxy route", got)
	}
}

// TestDeclaredMCPPublicURLIsTheIdentifierVerbatim: a declared identifier is
// published exactly as declared. RFC 9728 §3.3 has the client compare the
// `resource` in this document against the URL it dialled code point for code
// point, so ".../mcp/" and ".../mcp" are two different identifiers — trimming
// the slash published one nobody declared and no client dialled, and the 401
// that followed was on a document that validates.
//
// It goes through loadConfig, which is where the trimming was: a test that
// builds config directly never reaches the SDK path that normalized the value.
func TestDeclaredMCPPublicURLIsTheIdentifierVerbatim(t *testing.T) {
	const declared = "https://mcp.example.com/elsewhere" + MCPPath
	for _, raw := range []string{declared, declared + "/"} {
		t.Run(raw, func(t *testing.T) {
			cfg := deployedMCPConfig(t, raw)
			if cfg.mcpPublicURL != raw {
				t.Fatalf("mcpPublicURL = %q, want the declared %q unchanged", cfg.mcpPublicURL, raw)
			}
			err := cfg.validateMCP()
			if raw == declared {
				if err != nil {
					t.Fatalf("the declared identifier was refused: %v", err)
				}
				return
			}
			// Not silently corrected into the other identifier: refused, and
			// the refusal names the declaration an operator can change.
			if err == nil {
				t.Fatal("a declared identifier ending in a trailing slash was accepted")
			}
			if !strings.Contains(err.Error(), mcpConfigurationValue(MCPPublicURLKey)) {
				t.Errorf("refusal %q does not name %s, the declaration that fixes it", err, mcpConfigurationValue(MCPPublicURLKey))
			}
			if !strings.Contains(err.Error(), "trailing slash") {
				t.Errorf("refusal %q does not say the trailing slash is the problem, so it reads as a value that must end in %s already ending in it", err, MCPPath)
			}
		})
	}
}

// TestDeployedMCPPublicURLRefusesALoopbackAddress: a declared identifier passes
// every other check and can still name this machine. The registration that
// refused a loopback PUBLIC_URL and self upstream is gone, and with it the only
// address classifier this package had — so nothing refused a loopback
// identifier provisioned into a cell, and https does not launder one.
//
// Every spelling, because a spelling the predicate misses is an address that
// passes. An IPv6 zone is the one that defeats net.ParseIP: url.Hostname keeps
// the zone and ParseIP rejects any address carrying one, so the same loopback
// written with a zone read as a name that is not an IP at all.
func TestDeployedMCPPublicURLRefusesALoopbackAddress(t *testing.T) {
	for _, declared := range []string{
		"https://localhost:8443" + MCPPath,
		"https://app.localhost:8443" + MCPPath,
		"https://127.0.0.1:8443" + MCPPath,
		"https://127.9.9.9:8443" + MCPPath,
		"https://[::1]:8443" + MCPPath,
		"https://0.0.0.0:8443" + MCPPath,
		"https://[::1%25eth0]:8443" + MCPPath,
		"https://[::1%25lo0]:8443" + MCPPath,
		"https://[0:0:0:0:0:0:0:1%25lo0]:8443" + MCPPath,
		"https://[::%25lo0]:8443" + MCPPath,
	} {
		t.Run(declared, func(t *testing.T) {
			cfg := deployedMCPConfig(t, declared)
			if cfg.mcpPublicURL != declared {
				t.Fatalf("mcpPublicURL = %q, want the declared %q", cfg.mcpPublicURL, declared)
			}
			err := cfg.validateMCP()
			if err == nil {
				t.Fatal("a deployed MCP surface publishing a loopback identifier was accepted")
			}
			if !strings.Contains(err.Error(), mcpConfigurationValue(MCPPublicURLKey)) {
				t.Errorf("refusal %q does not name %s, the declaration that supplied the address", err, mcpConfigurationValue(MCPPublicURLKey))
			}
			if !strings.Contains(err.Error(), "loopback") {
				t.Errorf("refusal %q does not say the address is a loopback one", err)
			}
		})
	}
	// A reachable declaration is accepted in the same context, and a zone on an
	// address that is neither loopback nor unspecified is not itself the
	// refusal: dropping the zone must classify the address, not condemn the
	// spelling.
	for _, declared := range []string{
		"https://mcp.example.com/elsewhere" + MCPPath,
		"https://[fe80::1%25lo0]:8443" + MCPPath,
	} {
		t.Run("reachable "+declared, func(t *testing.T) {
			if err := deployedMCPConfig(t, declared).validateMCP(); err != nil {
				t.Fatalf("a reachable declared identifier was refused in a deployment: %v", err)
			}
		})
	}
	// Locally it stands: a developer's machine is where a loopback identifier
	// is the right one, and refusing it there would refuse the local run this
	// runtime also serves.
	t.Run("local", func(t *testing.T) {
		clearSelfEnvironment(t)
		t.Setenv("PORT", "8080")
		declareMCPConfiguration(t, MCPIssuerURLKey, "http://localhost:3000")
		declareMCPConfiguration(t, MCPPublicURLKey, "http://localhost:8080"+MCPPath)
		cfg := loadConfig(context.Background(), "example", nil)
		cfg.mcp = true
		if err := cfg.validateMCP(); err != nil {
			t.Fatalf("a local loopback identifier was refused: %v", err)
		}
	})
}
