package solution

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codefly-dev/core/solution/manifest"
	codefly "github.com/codefly-dev/sdk-go"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// passthroughModule is the "things" module of transcodeTestFile as a solution
// declares it: Search passes through, with only entry_id and big returned.
func passthroughModule() ConsumedModule {
	return ConsumedModule{
		As:     "things",
		Scopes: []Scope{{ResourceKind: "things", Actions: []string{"read"}}},
		Methods: []ConsumedMethod{{
			Name:     "/things.v1.Things/Search",
			Response: MustFieldMask(thingMessage("Thing"), "entry_id", "big"),
		}},
	}
}

// moduleGateway stands in for the host gateway: the accounts mint, and the
// module behind /v1/things.
type moduleGateway struct {
	*httptest.Server
	status int
	reply  string

	mu    sync.Mutex
	mints []mintRequest
	calls []*http.Request
	bodys []string
}

func newModuleGateway(t *testing.T, status int, reply string) *moduleGateway {
	t.Helper()
	g := &moduleGateway{status: status, reply: reply}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == workContextStartTaskProcedure {
			var mint mintRequest
			_ = json.Unmarshal(body, &mint)
			mint.Bearer = r.Header.Get("authorization")
			g.mints = append(g.mints, mint)
			writeJSON(w, http.StatusOK, map[string]any{
				"token": "context-" + mint.Audience + ".1", "orgId": mint.OrgID,
				"ownerPrincipalId": "viewer", "currentActorPrincipalId": "viewer",
				"expiresAt": time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano),
			})
			return
		}
		g.calls = append(g.calls, r.Clone(r.Context()))
		g.bodys = append(g.bodys, string(body))
		w.WriteHeader(g.status)
		_, _ = io.WriteString(w, g.reply)
	}))
	t.Cleanup(g.Close)
	return g
}

// call sends one Connect unary JSON request, as connect-es does, to the
// solution's passthrough and returns the status and decoded body.
func call(t *testing.T, s *Server, path, bearer, body string) (int, map[string]any) {
	t.Helper()
	routes, err := resolvePassthrough(s.consumed)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("content-type", "application/json")
	req.Header.Set("connect-protocol-version", "1")
	if bearer != "" {
		req.Header.Set("authorization", bearer)
	}
	req.Header.Set(orgHeader, "org-1")
	req.Header.Set(sessionHeader, "session-1")
	rec := httptest.NewRecorder()
	s.passthroughHandler(routes).ServeHTTP(rec, req)
	var out map[string]any
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("status %d, body %q: %v", rec.Code, rec.Body.String(), err)
		}
	}
	return rec.Code, out
}

func passthroughServer(gatewayURL string, modules ...ConsumedModule) *Server {
	s := New(Manifest{ID: "test"}).Consumes(modules...)
	s.cfg.gatewayURL = gatewayURL
	return s
}

const searchPath = "/modules/things/things.v1.Things/Search"

func TestPassthroughAnswersADeclaredMethodAsTheViewer(t *testing.T) {
	gw := newModuleGateway(t, http.StatusOK, `{"entryId":"e1","big":"7","secret":"s3cret","sub":{"name":"x"}}`)
	s := passthroughServer(gw.URL, passthroughModule())

	status, body := call(t, s, searchPath, "Bearer viewer", `{"entryId":"e1","pageSize":3}`)
	if status != http.StatusOK {
		t.Fatalf("status %d: %v", status, body)
	}
	// Only the declared response fields reach the page.
	if body["entryId"] != "e1" || body["big"] != "7" || body["secret"] != nil || body["sub"] != nil {
		t.Fatalf("response = %v, want only entryId and big", body)
	}
	// The module was called over its binding, with the viewer's capability.
	if len(gw.calls) != 1 || gw.calls[0].Method != http.MethodPost || gw.calls[0].URL.Path != "/v1/things/search" {
		t.Fatalf("module calls = %v", gw.calls)
	}
	var sent map[string]any
	if err := json.Unmarshal([]byte(gw.bodys[0]), &sent); err != nil || sent["entryId"] != "e1" || sent["pageSize"] != float64(3) {
		t.Fatalf("module received %q", gw.bodys[0])
	}
	if got := gw.calls[0].Header.Get(codefly.WorkContextHeaderName); got != "context-things.1" {
		t.Fatalf("work context = %q, want the one minted for the module", got)
	}
	if gw.calls[0].Header.Get("authorization") != "Bearer viewer" {
		t.Fatal("the viewer's bearer was not forwarded")
	}
	if len(gw.mints) != 1 || gw.mints[0].Audience != "things" || gw.mints[0].OrgID != "org-1" || gw.mints[0].SessionID != "session-1" ||
		len(gw.mints[0].AuthorityScopes) != 1 || gw.mints[0].AuthorityScopes[0].ResourceKind != "things" {
		t.Fatalf("mints = %+v, want one for the declared audience and scope, in the viewer's org and session", gw.mints)
	}
}

func TestPassthroughForwardsOnlyTheBearerToAModuleThatAuthenticatesTheViewer(t *testing.T) {
	gw := newModuleGateway(t, http.StatusOK, `{"entryId":"e1"}`)
	module := passthroughModule()
	module.Scopes, module.ViewerBearer = nil, true
	s := passthroughServer(gw.URL, module)

	if status, body := call(t, s, searchPath, "Bearer viewer", `{"entryId":"e1"}`); status != http.StatusOK {
		t.Fatalf("status %d: %v", status, body)
	}
	if len(gw.mints) != 0 {
		t.Fatalf("minted %d capabilities for a module that reads the bearer", len(gw.mints))
	}
	if gw.calls[0].Header.Get(codefly.WorkContextHeaderName) != "" || gw.calls[0].Header.Get("authorization") != "Bearer viewer" {
		t.Fatal("want the viewer's bearer and no capability")
	}
}

func TestPassthroughServesOnlyWhatIsDeclared(t *testing.T) {
	gw := newModuleGateway(t, http.StatusOK, `{}`)
	s := passthroughServer(gw.URL, passthroughModule())
	for _, path := range []string{
		"/modules/things/things.v1.Things/Get",     // the module's, but not declared
		"/modules/other/things.v1.Things/Search",   // not a consumed module
		"/modules/things/../things/x",              // not a procedure
		"/modules/things/things.v1.Things/Search/", // not the procedure
	} {
		status, body := call(t, s, path, "Bearer viewer", `{}`)
		if status != http.StatusNotFound || body["code"] != "not_found" {
			t.Errorf("%s: status %d %v, want not_found", path, status, body)
		}
	}
	if len(gw.calls) != 0 || len(gw.mints) != 0 {
		t.Fatalf("an undeclared call reached the gateway: %d calls, %d mints", len(gw.calls), len(gw.mints))
	}
}

func TestPassthroughRequiresTheViewersBearer(t *testing.T) {
	gw := newModuleGateway(t, http.StatusOK, `{}`)
	s := passthroughServer(gw.URL, passthroughModule())
	status, body := call(t, s, searchPath, "", `{}`)
	if status != http.StatusUnauthorized || body["code"] != "unauthenticated" {
		t.Fatalf("status %d %v", status, body)
	}
	if len(gw.calls)+len(gw.mints) != 0 {
		t.Fatal("an anonymous call reached the gateway")
	}
}

func TestPassthroughForwardsOnlyTheMethodsOwnFields(t *testing.T) {
	gw := newModuleGateway(t, http.StatusOK, `{}`)
	s := passthroughServer(gw.URL, passthroughModule())
	// A field the method's request does not declare is not the page's to add:
	// the request is re-encoded from the method's message, so it never reaches
	// the module, and it can name no path or prefix of its own.
	status, body := call(t, s, searchPath, "Bearer viewer", `{"entryId":"e1","path":"/v1/other","prefix":"/v1/admin"}`)
	if status != http.StatusOK {
		t.Fatalf("status %d %v", status, body)
	}
	if gw.calls[0].URL.Path != "/v1/things/search" || strings.Contains(gw.bodys[0], "other") || strings.Contains(gw.bodys[0], "admin") {
		t.Fatalf("module received %s %q", gw.calls[0].URL, gw.bodys[0])
	}
}

func TestPassthroughRelaysTheModulesRefusal(t *testing.T) {
	for _, tc := range []struct {
		name, reply string
		status      int
		wantStatus  int
		wantCode    string
		wantMessage string
	}{
		{"a google.rpc.Status keeps its code and message", `{"code":5,"message":"document not found"}`, http.StatusNotFound, http.StatusNotFound, "not_found", "document not found"},
		{"another JSON refusal is relayed verbatim", `{"failure":{"code":"HISTORY_UNAVAILABLE","admission":"unknown"}}`, http.StatusConflict, http.StatusConflict, "aborted", `{"failure":{"code":"HISTORY_UNAVAILABLE","admission":"unknown"}}`},
		{"a non-JSON refusal says only its status", `upstream connect error: 10.0.0.7:8080 refused`, http.StatusBadGateway, http.StatusServiceUnavailable, "unavailable", "Bad Gateway"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw := newModuleGateway(t, tc.status, tc.reply)
			s := passthroughServer(gw.URL, passthroughModule())
			status, body := call(t, s, searchPath, "Bearer viewer", `{}`)
			if status != tc.wantStatus || body["code"] != tc.wantCode || body["message"] != tc.wantMessage {
				t.Fatalf("status %d %v, want %d %s %q", status, body, tc.wantStatus, tc.wantCode, tc.wantMessage)
			}
		})
	}
}

func TestPassthroughRefusesADeclarationItCannotServe(t *testing.T) {
	search := func(m ConsumedMethod) ConsumedModule {
		module := passthroughModule()
		module.Methods = []ConsumedMethod{m}
		return module
	}
	mask := MustFieldMask(thingMessage("Thing"), "entry_id")
	for name, modules := range map[string][]ConsumedModule{
		"no as":                         {{Scopes: passthroughModule().Scopes, Methods: passthroughModule().Methods}},
		"an as with a path":             {{As: "things/v2", Scopes: passthroughModule().Scopes, Methods: passthroughModule().Methods}},
		"neither scopes nor bearer":     {{As: "things", Methods: passthroughModule().Methods}},
		"both scopes and bearer":        {{As: "things", ViewerBearer: true, Scopes: passthroughModule().Scopes, Methods: passthroughModule().Methods}},
		"no methods":                    {{As: "things", ViewerBearer: true}},
		"a method not in the registry":  {search(ConsumedMethod{Name: "/things.v1.Things/Nope", Response: mask})},
		"a method with no binding":      {search(ConsumedMethod{Name: "/things.v1.Things/Unbound", Response: mask})},
		"no response fields":            {search(ConsumedMethod{Name: "/things.v1.Things/Search"})},
		"a mask and the whole response": {search(ConsumedMethod{Name: "/things.v1.Things/Search", Response: mask, WholeResponse: true})},
		"a mask over another message":   {search(ConsumedMethod{Name: "/things.v1.Things/Search", Response: MustFieldMask(thingMessage("Sub"), "name")})},
		"a method twice":                {{As: "things", ViewerBearer: true, Methods: []ConsumedMethod{passthroughModule().Methods[0], passthroughModule().Methods[0]}}},
		"a module twice":                {passthroughModule(), passthroughModule()},
	} {
		if _, err := resolvePassthrough(modules); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A binding under another prefix is not a binding under the declared one.
	module := passthroughModule()
	module.As = "other"
	if _, err := resolvePassthrough([]ConsumedModule{module}); err == nil || !strings.Contains(err.Error(), "no google.api.http binding under /v1/other") {
		t.Errorf("a module whose methods have no binding under its prefix: %v", err)
	}
}

func TestPassthroughRefusesAModuleTheSolutionDoesNotConsume(t *testing.T) {
	modules := []ConsumedModule{passthroughModule()}
	if err := checkConsumed(modules, []manifest.ConsumedAPI{{ID: "things", Module: "things", As: "things"}}); err != nil {
		t.Fatalf("a consumed module was refused: %v", err)
	}
	if err := checkConsumed(modules, []manifest.ConsumedAPI{{ID: "things", Module: "things", As: "stuff"}}); err == nil {
		t.Fatal("a module consumed under another name was accepted")
	}
	if err := checkConsumed(modules, nil); err == nil {
		t.Fatal("a module the solution does not consume was accepted")
	}
}

func TestPassthroughOperationsDocumentTheDeclaration(t *testing.T) {
	ops, err := PassthroughOperations(passthroughModule())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := InterfaceDocument(InterfaceInfo{Title: "t", Version: "0.0.1", Description: "d", BasePath: "/solutions/test", OperationPrefix: "Test", Tag: "test"}, ops)
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Paths       map[string]map[string]map[string]any `json:"paths"`
		Definitions map[string]any                       `json:"definitions"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatal(err)
	}
	op := parsed.Paths[searchPath]["post"]
	if op == nil {
		t.Fatalf("paths = %v", parsed.Paths)
	}
	description, _ := op["description"].(string)
	if !strings.Contains(description, "POST /v1/things/search") || !strings.Contains(description, "big, entry_id") || !strings.Contains(description, "things:[read]") {
		t.Fatalf("description = %q", description)
	}
	if parsed.Definitions["ThingsV1Thing"] == nil || parsed.Definitions["ThingsV1GetThingRequest"] == nil {
		t.Fatalf("definitions = %v", parsed.Definitions)
	}
}

func TestPassthroughMergesTheDeclaredPinIntoEveryRequest(t *testing.T) {
	gw := newModuleGateway(t, http.StatusOK, `{}`)
	pin := thingMessage("GetThingRequest")
	setField(pin, "tenant", protoreflect.ValueOfString("pinned-tenant"))
	ids := pin.NewField(pin.Descriptor().Fields().ByName("ids"))
	ids.List().Append(protoreflect.ValueOfString("pinned-id"))
	pin.Set(pin.Descriptor().Fields().ByName("ids"), ids)
	module := passthroughModule()
	module.Methods[0].Pin = pin
	s := passthroughServer(gw.URL, module)

	if status, body := call(t, s, searchPath, "Bearer viewer", `{"tenant":"page-tenant","ids":["page-id"]}`); status != http.StatusOK {
		t.Fatalf("status %d %v", status, body)
	}
	var sent struct {
		Tenant string   `json:"tenant"`
		IDs    []string `json:"ids"`
	}
	if err := json.Unmarshal([]byte(gw.bodys[0]), &sent); err != nil {
		t.Fatal(err)
	}
	// A pinned scalar replaces the page's; a pinned repeated value is added to
	// the page's, so a module that ANDs them keeps the pin whatever the page sends.
	if sent.Tenant != "pinned-tenant" || len(sent.IDs) != 2 || sent.IDs[0] != "page-id" || sent.IDs[1] != "pinned-id" {
		t.Fatalf("module received %q", gw.bodys[0])
	}

	module.Methods[0].Pin = thingMessage("Thing")
	if _, err := resolvePassthrough([]ConsumedModule{module}); err == nil {
		t.Fatal("a pin of another type was accepted")
	}
}

func TestInterfaceArtifactCarriesTheManifestVersionAndBothSurfaces(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "service.codefly.yaml"), []byte("kind: service\nname: backend\nversion: 1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	own := Operation{Path: "/own", Summary: "s", Callers: "c", Behavior: "b", Response: map[string]string{},
		Handler: func(context.Context, *Gateway) (any, error) { return nil, nil }}
	doc, err := InterfaceArtifact(dir, InterfaceInfo{Title: "t", BasePath: "/solutions/test", OperationPrefix: "Test", Tag: "test"}, []Operation{own}, passthroughModule())
	if err != nil {
		t.Fatal(err)
	}
	var parsed struct {
		Info  struct{ Version string } `json:"info"`
		Paths map[string]any           `json:"paths"`
	}
	if err := json.Unmarshal(doc, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Info.Version != "1.2.3" || parsed.Paths["/own"] == nil || parsed.Paths[searchPath] == nil {
		t.Fatalf("artifact: version %q, paths %v", parsed.Info.Version, parsed.Paths)
	}
	if _, err := InterfaceArtifact(t.TempDir(), InterfaceInfo{}, nil); err == nil {
		t.Fatal("a backend with no service manifest rendered a version")
	}
}
