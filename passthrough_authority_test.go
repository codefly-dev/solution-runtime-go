package solution

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// relayedModule stands in for a module behind the hop: it answers every
// method with a Thing, or with the refusal it is told to give, and records the
// Work Context and the request each call carried.
type relayedModule struct {
	refuse error
	mu     sync.Mutex
	calls  []relayedCall
}

type relayedCall struct {
	method, workContext string
	request             *dynamicpb.Message
}

func (m *relayedModule) serve(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	g := grpc.NewServer(grpc.UnknownServiceHandler(func(_ any, stream grpc.ServerStream) error {
		method, _ := grpc.MethodFromServerStream(stream)
		in := thingMessage("GetThingRequest")
		if err := stream.RecvMsg(in); err != nil {
			return err
		}
		md, _ := grpcmetadata.FromIncomingContext(stream.Context())
		m.mu.Lock()
		m.calls = append(m.calls, relayedCall{method: method, workContext: strings.Join(md.Get(WorkContextHeader), ","), request: in})
		refuse := m.refuse
		m.mu.Unlock()
		if refuse != nil {
			return refuse
		}
		out := thingMessage("Thing")
		setField(out, "entry_id", protoreflect.ValueOfString(in.Get(in.Descriptor().Fields().ByName("entry_id")).String()))
		setField(out, "big", protoreflect.ValueOfInt64(42))
		setField(out, "secret", protoreflect.ValueOfString("never-to-the-page"))
		return stream.SendMsg(out)
	}))
	go func() { _ = g.Serve(l) }()
	t.Cleanup(g.Stop)
	return l.Addr().String()
}

// relayedPage is a page under the authority consuming the "things" module,
// relayed through the hop at the address its slots name, served as Serve
// mounts it.
func relayedPage(t *testing.T, binding string, refuse error) (*httptest.Server, *relayedModule, *interfaceAuthority) {
	t.Helper()
	s, stand := authorityServer(t)
	module := &relayedModule{refuse: refuse}
	slots := map[string]string{"page/THINGS_ENDPOINT": "grpc://" + module.serve(t), "page/THINGS_BINDING": binding}
	declared := passthroughModule()
	declared.Methods[0].Pin = func() *dynamicpb.Message {
		pin := thingMessage("GetThingRequest")
		setField(pin, "tenant", protoreflect.ValueOfString("pinned-tenant"))
		return pin
	}()
	declared.Authority = AuthorityRelay{Group: "page", EndpointKey: "THINGS_ENDPOINT", BindingKey: "THINGS_BINDING"}
	notRelayed := ConsumedModule{As: "tenants", Scopes: declared.Scopes, Methods: []ConsumedMethod{{Name: "/things.v1.Things/Get", WholeResponse: true}}}
	s.Consumes(declared, notRelayed)
	s.cfg.transport = meshTransport{local: true}
	routes, err := resolvePassthrough(s.consumed)
	if err != nil {
		t.Fatal(err)
	}
	if s.relays, err = s.openRelays(routes, func(group, key string) (string, error) { return slots[group+"/"+key], nil }); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := s.mountPassthrough(mux); err != nil {
		t.Fatal(err)
	}
	page := httptest.NewServer(mux)
	t.Cleanup(page.Close)
	return page, module, stand
}

// connectCall posts one Connect unary JSON call as the module's generated
// client does, with the Work Context the edge sends it on with.
func connectCall(t *testing.T, url, workContext, body string) (int, map[string]any) {
	t.Helper()
	request, _ := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Connect-Protocol-Version", "1")
	if workContext != "" {
		request.Header.Set(WorkContextHeader, workContext)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	raw, _ := io.ReadAll(response.Body)
	answer := map[string]any{}
	_ = json.Unmarshal(raw, &answer)
	return response.StatusCode, answer
}

const relayedSearchPath = "/v1/page/modules/things/things.v1.Things/Search"

// Under the authority the passthrough relays a declared method to the module
// through the hop, as the viewer: a child of the edge's Work Context issued
// through the module's binding with the declared scopes, the pin merged in,
// and only the declared response fields returned.
func TestUnderTheAuthorityThePassthroughRelaysAsTheViewer(t *testing.T) {
	page, module, stand := relayedPage(t, "things-binding", nil)
	code, answer := connectCall(t, page.URL+relayedSearchPath, edgeContext, `{"entryId":"e1","tenant":"the-page-wrote"}`)
	if code != http.StatusOK || answer["entryId"] != "e1" || answer["big"] != "42" || answer["secret"] != nil {
		t.Fatalf("answered %d %v", code, answer)
	}
	call := module.calls[0]
	tenant := call.request.Get(call.request.Descriptor().Fields().ByName("tenant")).String()
	if call.method != "/things.v1.Things/Search" || call.workContext != "issued-things-binding" || tenant != "pinned-tenant" {
		t.Fatalf("the module was called %+v (tenant %q)", call, tenant)
	}
	asked := stand.asked()[0]
	if asked.GetParentToken() != edgeContext || asked.GetOperationBindingId() != "things-binding" || len(asked.GetScopes()) != 1 || asked.GetScopes()[0].GetResourceKind() != "things" {
		t.Fatalf("the child was asked %v", asked)
	}
	// A module the composition names no slots for is not relayed here, and a
	// request the edge did not send carries no viewer.
	if code, _ := connectCall(t, page.URL+"/v1/page/modules/tenants/things.v1.Things/Get", edgeContext, `{}`); code != http.StatusNotFound {
		t.Errorf("a module with no slots answered %d", code)
	}
	if code, answer := connectCall(t, page.URL+relayedSearchPath, "", `{}`); code != http.StatusUnauthorized || answer["code"] != "unauthenticated" {
		t.Errorf("no Work Context answered %d %v", code, answer)
	}
	if len(module.calls) != 1 {
		t.Fatalf("the module was called %d times", len(module.calls))
	}
}

// The authority's refusal reaches the page with the authority's code and its
// reason; a module's refusal of the page's request keeps its code and reason;
// a module failure is reported by kind, and its text reaches no page.
func TestUnderTheAuthorityARelayedRefusalNamesItsReason(t *testing.T) {
	page, _, _ := relayedPage(t, "refused", nil)
	code, answer := connectCall(t, page.URL+relayedSearchPath, edgeContext, `{}`)
	if code != http.StatusForbidden || answer["code"] != "permission_denied" || !strings.Contains(answer["message"].(string), "person-1 holds nothing through that binding") {
		t.Fatalf("the authority's refusal answered %d %v", code, answer)
	}
	page, _, _ = relayedPage(t, "things-binding", status.Error(codes.NotFound, "no such thing in this collection"))
	if code, answer := connectCall(t, page.URL+relayedSearchPath, edgeContext, `{}`); code != http.StatusNotFound || answer["message"] != "no such thing in this collection" {
		t.Fatalf("the module's refusal answered %d %v", code, answer)
	}
	page, _, _ = relayedPage(t, "things-binding", status.Error(codes.Internal, "dial tcp 10.0.0.7:5432: refused"))
	if code, answer := connectCall(t, page.URL+relayedSearchPath, edgeContext, `{}`); code != http.StatusServiceUnavailable || strings.Contains(answer["message"].(string), "10.0.0.7") {
		t.Fatalf("a module failure answered %d %v", code, answer)
	}
}

// A relay the composition cannot complete refuses the boot, naming the slot;
// a cleartext address that leaves the machine is not one the viewer's Work
// Context may travel to.
func TestUnderTheAuthorityARelayNeedsItsSlots(t *testing.T) {
	s, _ := authorityServer(t)
	declared := passthroughModule()
	declared.Authority = AuthorityRelay{Group: "page", EndpointKey: "THINGS_ENDPOINT", BindingKey: "THINGS_BINDING"}
	s.Consumes(declared)
	routes, err := resolvePassthrough(s.consumed)
	if err != nil {
		t.Fatal(err)
	}
	for name, c := range map[string]struct {
		slots map[string]string
		want  string
	}{
		"no binding":                {map[string]string{"THINGS_ENDPOINT": "127.0.0.1:1"}, "page/THINGS_BINDING"},
		"no address":                {map[string]string{"THINGS_BINDING": "b"}, "page/THINGS_ENDPOINT"},
		"cleartext off the machine": {map[string]string{"THINGS_ENDPOINT": "hop.example.com:9090", "THINGS_BINDING": "b"}, "plaintext"},
	} {
		_, err := s.openRelays(routes, func(_, key string) (string, error) {
			if v, ok := c.slots[key]; ok {
				return v, nil
			}
			return "", errors.New("unset")
		})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// A refusal on a route the solution serves itself is a Connect error to a
// Connect client, which reads nothing else, and {"error"} to a REST caller;
// an authority refusal a handler returns keeps the authority's code and reason.
func TestARefusalIsWrittenInTheCallersProtocol(t *testing.T) {
	s, _ := authorityServer(t)
	handler := s.wrapRequest(func(r *http.Request, gw *Gateway) (any, error) {
		_, err := gw.ForParent(r.Context(), "refused", Scope{ResourceKind: "things", Actions: []string{"read"}})
		return nil, err
	})
	call := func(connectClient bool, workContext string) (int, map[string]any) {
		request := httptest.NewRequest(http.MethodPost, "/v1/page/things", strings.NewReader("{}"))
		request.Header.Set("Content-Type", "application/json")
		if connectClient {
			request.Header.Set("Connect-Protocol-Version", "1")
		}
		if workContext != "" {
			request.Header.Set(WorkContextHeader, workContext)
		}
		recorder := httptest.NewRecorder()
		handler(recorder, request)
		answer := map[string]any{}
		_ = json.Unmarshal(recorder.Body.Bytes(), &answer)
		return recorder.Code, answer
	}
	if code, answer := call(true, edgeContext); code != http.StatusForbidden || answer["code"] != "permission_denied" || !strings.Contains(answer["message"].(string), "person-1 holds nothing through that binding") {
		t.Errorf("a Connect client was answered %d %v", code, answer)
	}
	if code, answer := call(false, edgeContext); code != http.StatusForbidden || !strings.Contains(answer["error"].(string), "person-1 holds nothing through that binding") || answer["code"] != nil {
		t.Errorf("a REST caller was answered %d %v", code, answer)
	}
	if code, answer := call(true, ""); code != http.StatusUnauthorized || answer["code"] != "unauthenticated" || answer["message"] == "" {
		t.Errorf("a Connect client with no Work Context was answered %d %v", code, answer)
	}
	if code, answer := call(false, "forged"); code != http.StatusUnauthorized || !strings.Contains(answer["error"].(string), "not a context for this audience") {
		t.Errorf("a forged Work Context was answered %d %v", code, answer)
	}
}

// The authority's reason survives the refusal; a failure to reach it is not a
// refusal and keeps no text.
func TestAWorkContextRefusalKeepsTheAuthoritysReason(t *testing.T) {
	s, _ := authorityServer(t)
	gw := s.gatewayFor(http.Header{})
	gw.parentContext = edgeContext
	_, err := gw.ForParent(context.Background(), "refused")
	var refusal *WorkContextRefusal
	if !errors.As(err, &refusal) || refusal.Reason != "person-1 holds nothing through that binding" || refusal.StatusCode != http.StatusForbidden || !strings.Contains(err.Error(), refusal.Reason) {
		t.Fatalf("the refusal: %#v", err)
	}
	if status, message := handlerErrorResponse(err); status != http.StatusForbidden || !strings.Contains(message, refusal.Reason) {
		t.Fatalf("a handler's refusal answered %d %q", status, message)
	}
	_ = s.host.conn.Close()
	unreachable := s.gatewayFor(http.Header{})
	unreachable.orgID = "org-from-the-authority"
	_, err = unreachable.ForBinding(context.Background(), "any")
	if !errors.As(err, &refusal) || refusal.Reason != "" {
		t.Fatalf("an unreachable authority: %#v", err)
	}
}
