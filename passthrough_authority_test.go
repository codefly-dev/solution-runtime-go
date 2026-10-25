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
	"time"

	"connectrpc.com/connect"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// relayedModule stands in for a module behind the hop, serving the procedures
// of relayedTestFile: every unary method answers with a Thing, Watch streams
// `streamed` of them, and either ends with the refusal it is told to give. It
// records the Work Context and the request each call carried.
type relayedModule struct {
	refuse error
	// streamed is how many Things Watch sends before it ends; hold keeps it
	// open until the caller goes away.
	streamed int
	hold     bool
	// secret is the Thing's undeclared field, which never reaches the page.
	secret string
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
		refuse, streamed, hold, secret := m.refuse, m.streamed, m.hold, m.secret
		m.mu.Unlock()
		if secret == "" {
			secret = "never-to-the-page"
		}
		thing := func() *dynamicpb.Message {
			out := thingMessage("Thing")
			setField(out, "entry_id", protoreflect.ValueOfString(in.Get(in.Descriptor().Fields().ByName("entry_id")).String()))
			setField(out, "big", protoreflect.ValueOfInt64(42))
			setField(out, "secret", protoreflect.ValueOfString(secret))
			return out
		}
		if method != watchName {
			if refuse != nil {
				return refuse
			}
			return stream.SendMsg(thing())
		}
		for i := 0; i < streamed; i++ {
			if err := stream.SendMsg(thing()); err != nil {
				return err
			}
		}
		if hold {
			<-stream.Context().Done()
			return stream.Context().Err()
		}
		return refuse
	}))
	go func() { _ = g.Serve(l) }()
	t.Cleanup(g.Stop)
	return l.Addr().String()
}

func (m *relayedModule) observed() []relayedCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]relayedCall(nil), m.calls...)
}

// pinnedSearch pins Search's tenant, as a solution fixes part of a request.
func pinnedSearch(declared ConsumedModule) ConsumedModule {
	pin := thingMessage("GetThingRequest")
	setField(pin, "tenant", protoreflect.ValueOfString("pinned-tenant"))
	declared.Methods[0].Pin = pin
	return declared
}

// relayedPage is a page under the authority consuming declared, relayed to
// module through the hop at the address its slots name and through binding,
// served as Serve mounts it.
func relayedPage(t *testing.T, declared ConsumedModule, module *relayedModule, binding string) (*httptest.Server, *interfaceAuthority) {
	t.Helper()
	s, stand := authorityServer(t)
	slots := map[string]string{"page/THINGS_ENDPOINT": "grpc://" + module.serve(t), "page/THINGS_BINDING": binding}
	s.Consumes(declared)
	s.cfg.transport = meshTransport{local: true}
	var err error
	if s.relays, err = s.openRelays(func(group, key string) (string, error) { return slots[group+"/"+key], nil }); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	if err := s.mountPassthrough(mux); err != nil {
		t.Fatal(err)
	}
	page := httptest.NewServer(mux)
	t.Cleanup(page.Close)
	return page, stand
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

// watch opens Watch through the page's passthrough, as connect-go would, and
// reads the stream to its end.
func watch(t *testing.T, base, workContext string) ([]*dynamicpb.Message, error) {
	t.Helper()
	md := relayedTestFile.Services().ByName("Things").Methods().ByName("Watch")
	client := connect.NewClient[dynamicpb.Message, dynamicpb.Message](http.DefaultClient, base+"/v1/page/modules/things/relayed.v1.Things/Watch",
		connect.WithSchema(md), connect.WithResponseInitializer(func(_ connect.Spec, msg any) error {
			*msg.(*dynamicpb.Message) = *dynamicpb.NewMessage(md.Output())
			return nil
		}))
	request := connect.NewRequest(thingMessage("GetThingRequest"))
	setField(request.Msg, "entry_id", protoreflect.ValueOfString("e1"))
	if workContext != "" {
		request.Header().Set(WorkContextHeader, workContext)
	}
	stream, err := client.CallServerStream(context.Background(), request)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	var got []*dynamicpb.Message
	for stream.Receive() {
		got = append(got, stream.Msg())
	}
	return got, stream.Err()
}

const relayedSearchPath = "/v1/page" + searchPath

// The passthrough relays a declared method to the module's own procedure
// through the hop, as the viewer: a child of the edge's Work Context issued
// through the module's binding with the declared scopes, the pin merged in,
// and only the declared response fields returned.
func TestThePassthroughRelaysAsTheViewer(t *testing.T) {
	module := &relayedModule{}
	page, stand := relayedPage(t, pinnedSearch(passthroughModule()), module, "things-binding")
	code, answer := connectCall(t, page.URL+relayedSearchPath, edgeContext, `{"entryId":"e1","tenant":"the-page-wrote"}`)
	if code != http.StatusOK || answer["entryId"] != "e1" || answer["big"] != "42" || answer["secret"] != nil {
		t.Fatalf("answered %d %v", code, answer)
	}
	call := module.observed()[0]
	tenant := call.request.Get(call.request.Descriptor().Fields().ByName("tenant")).String()
	if call.method != searchName || call.workContext != "issued-things-binding" || tenant != "pinned-tenant" {
		t.Fatalf("the module was called %+v (tenant %q)", call, tenant)
	}
	asked := stand.asked()[0]
	if asked.GetParentToken() != edgeContext || asked.GetOperationBindingId() != "things-binding" || len(asked.GetScopes()) != 1 || asked.GetScopes()[0].GetResourceKind() != "things" {
		t.Fatalf("the child was asked %v", asked)
	}
	// What is not declared is not served, whatever the module offers; a
	// request the edge did not send carries no viewer.
	for _, undeclared := range []string{"/v1/page" + getPath, "/v1/page/modules/tenants/relayed.v1.Things/Search"} {
		if code, _ := connectCall(t, page.URL+undeclared, edgeContext, `{}`); code != http.StatusNotFound {
			t.Errorf("%s answered %d", undeclared, code)
		}
	}
	if code, answer := connectCall(t, page.URL+relayedSearchPath, "", `{}`); code != http.StatusUnauthorized || answer["code"] != "unauthenticated" {
		t.Errorf("no Work Context answered %d %v", code, answer)
	}
	if len(module.observed()) != 1 {
		t.Fatalf("the module was called %d times", len(module.observed()))
	}
}

// Each call asks only its own method's scopes: a method's Scopes replace the
// module's, never add to them.
func TestThePassthroughAsksOnlyTheCalledMethodsScopes(t *testing.T) {
	declared := passthroughModule()
	declared.Scopes = nil
	declared.Methods = []ConsumedMethod{
		{Name: searchName, Scopes: []Scope{{ResourceKind: "things", Actions: []string{"list"}}}, WholeResponse: true},
		{Name: getName, Scopes: []Scope{{ResourceKind: "things", Actions: []string{"inspect"}}}, WholeResponse: true},
	}
	page, stand := relayedPage(t, declared, &relayedModule{}, "things-binding")
	for path, want := range map[string]string{relayedSearchPath: "list", "/v1/page" + getPath: "inspect"} {
		if code, answer := connectCall(t, page.URL+path, edgeContext, `{}`); code != http.StatusOK {
			t.Fatalf("%s answered %d %v", path, code, answer)
		}
		asked := stand.asked()
		scopes := asked[len(asked)-1].GetScopes()
		if len(scopes) != 1 || strings.Join(scopes[0].GetActions(), ",") != want {
			t.Fatalf("%s asked %v, want things:%s only", path, scopes, want)
		}
	}
}

// The authority's refusal reaches the page with the authority's code and its
// reason; a module's refusal of the page's request keeps its code and reason;
// a module failure is reported by kind, and its text reaches no page.
func TestARelayedRefusalNamesItsReason(t *testing.T) {
	page, _ := relayedPage(t, passthroughModule(), &relayedModule{}, "refused")
	code, answer := connectCall(t, page.URL+relayedSearchPath, edgeContext, `{}`)
	if code != http.StatusForbidden || answer["code"] != "permission_denied" || !strings.Contains(answer["message"].(string), "person-1 holds nothing through that binding") {
		t.Fatalf("the authority's refusal answered %d %v", code, answer)
	}
	page, _ = relayedPage(t, passthroughModule(), &relayedModule{refuse: status.Error(codes.NotFound, "no such thing in this collection")}, "things-binding")
	if code, answer := connectCall(t, page.URL+relayedSearchPath, edgeContext, `{}`); code != http.StatusNotFound || answer["message"] != "no such thing in this collection" {
		t.Fatalf("the module's refusal answered %d %v", code, answer)
	}
	page, _ = relayedPage(t, passthroughModule(), &relayedModule{refuse: status.Error(codes.Internal, "dial tcp 10.0.0.7:5432: refused")}, "things-binding")
	if code, answer := connectCall(t, page.URL+relayedSearchPath, edgeContext, `{}`); code != http.StatusServiceUnavailable || strings.Contains(answer["message"].(string), "10.0.0.7") {
		t.Fatalf("a module failure answered %d %v", code, answer)
	}
}

// A server-streaming method is relayed as a stream: every message the module
// sends reaches the page with only the declared fields, under the child the
// authority issued for that method.
func TestAStreamedMethodIsRelayedMessageByMessage(t *testing.T) {
	module := &relayedModule{streamed: 3}
	page, stand := relayedPage(t, watchModule(ConsumedMethod{}), module, "things-binding")
	got, err := watch(t, page.URL, edgeContext)
	if err != nil || len(got) != 3 {
		t.Fatalf("received %d messages: %v", len(got), err)
	}
	for _, msg := range got {
		if msg.Get(msg.Descriptor().Fields().ByName("entry_id")).String() != "e1" || msg.Has(msg.Descriptor().Fields().ByName("secret")) {
			t.Fatalf("a streamed message reached the page as %v", msg)
		}
	}
	if call := module.observed()[0]; call.method != watchName || call.workContext != "issued-things-binding" || len(stand.asked()) != 1 {
		t.Fatalf("the module was called %+v after %d issues", call, len(stand.asked()))
	}
	if _, err := watch(t, page.URL, ""); connect.CodeOf(err) != connect.CodeUnauthenticated {
		t.Fatalf("a stream with no Work Context: %v", err)
	}
}

// The module ending its stream with a status ends the page's with the same
// code and reason; a message past its bound ends it, never truncated; and a
// stream that outlives its declared duration ends with deadline_exceeded.
func TestAStreamEndsAsTheModuleOrItsBoundsSay(t *testing.T) {
	page, _ := relayedPage(t, watchModule(ConsumedMethod{}), &relayedModule{streamed: 1, refuse: status.Error(codes.FailedPrecondition, "the run is not observable yet")}, "things-binding")
	got, err := watch(t, page.URL, edgeContext)
	if len(got) != 1 || connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "the run is not observable yet") {
		t.Fatalf("received %d, then %v", len(got), err)
	}
	page, _ = relayedPage(t, watchModule(ConsumedMethod{MaxStreamMessageBytes: 64}), &relayedModule{streamed: 1, secret: strings.Repeat("x", 128)}, "things-binding")
	if got, err := watch(t, page.URL, edgeContext); len(got) != 0 || connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("an oversized message: received %d, then %v", len(got), err)
	}
	page, _ = relayedPage(t, watchModule(ConsumedMethod{MaxStreamDuration: 300 * time.Millisecond}), &relayedModule{streamed: 1, hold: true}, "things-binding")
	if got, err := watch(t, page.URL, edgeContext); len(got) != 1 || connect.CodeOf(err) != connect.CodeDeadlineExceeded || !strings.Contains(err.Error(), "declared duration") {
		t.Fatalf("a held stream: received %d, then %v", len(got), err)
	}
	// r1 F6: a module that accepts the stream and never sends is cut off at
	// the method's Timeout, its first-answer bound, not at the whole
	// duration; once it has answered, only the duration bounds it.
	start := time.Now()
	page, _ = relayedPage(t, watchModule(ConsumedMethod{Timeout: 200 * time.Millisecond, MaxStreamDuration: time.Minute}), &relayedModule{hold: true}, "things-binding")
	if got, err := watch(t, page.URL, edgeContext); len(got) != 0 || connect.CodeOf(err) != connect.CodeDeadlineExceeded || !strings.Contains(err.Error(), "did not start its stream within 200ms") {
		t.Fatalf("a silent stream: received %d, then %v", len(got), err)
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("a silent stream was cut off after %s, not at its 200ms first-answer bound", elapsed)
	}
	page, _ = relayedPage(t, watchModule(ConsumedMethod{Timeout: 200 * time.Millisecond, MaxStreamDuration: 700 * time.Millisecond}), &relayedModule{streamed: 1, hold: true}, "things-binding")
	if got, err := watch(t, page.URL, edgeContext); len(got) != 1 || connect.CodeOf(err) != connect.CodeDeadlineExceeded || !strings.Contains(err.Error(), "declared duration") {
		t.Fatalf("a stream that answered within its first-answer bound: received %d, then %v", len(got), err)
	}
}

// A relay the composition cannot complete refuses the boot, naming the slot;
// a cleartext address that leaves the machine is not one the viewer's Work
// Context may travel to.
func TestARelayNeedsItsSlots(t *testing.T) {
	s, _ := authorityServer(t)
	s.Consumes(passthroughModule())
	for name, c := range map[string]struct {
		slots map[string]string
		want  string
	}{
		"no binding":                {map[string]string{"THINGS_ENDPOINT": "127.0.0.1:1"}, "page/THINGS_BINDING"},
		"no address":                {map[string]string{"THINGS_BINDING": "b"}, "page/THINGS_ENDPOINT"},
		"cleartext off the machine": {map[string]string{"THINGS_ENDPOINT": "hop.example.com:9090", "THINGS_BINDING": "b"}, "plaintext"},
	} {
		_, err := s.openRelays(func(_, key string) (string, error) {
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

// A solution consuming a module whose procedures carry no google.api.http
// binding — as every module serves them behind the hop — boots through the
// whole of start() and relays both a unary call and a stream to the module, as
// the viewer, at the address and binding the composition names.
func TestABootedPassthroughRelaysProceduresThatCarryNoHTTPBinding(t *testing.T) {
	module := &relayedModule{streamed: 2}
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__PAGE__THINGS_ENDPOINT", "grpc://"+module.serve(t))
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__PAGE__THINGS_BINDING", "things-binding")
	b := boot(t, New(Manifest{ID: "page", Frontend: []byte(testFrontend)}).Consumes(watchModule(ConsumedMethod{})))
	stand := b.authority
	code, answer := connectCall(t, b.base+relayedSearchPath, edgeContext, `{"entryId":"e1"}`)
	if code != http.StatusOK || answer["entryId"] != "e1" || answer["secret"] != nil {
		t.Fatalf("the relayed call answered %d %v", code, answer)
	}
	if got, err := watch(t, b.base, edgeContext); err != nil || len(got) != 2 {
		t.Fatalf("the relayed stream: %d messages, %v", len(got), err)
	}
	calls := module.observed()
	if len(calls) != 2 || calls[0].method != searchName || calls[1].method != watchName || calls[0].workContext != "issued-things-binding" {
		t.Fatalf("the module was called %+v", calls)
	}
	if asked := stand.asked(); len(asked) != 2 || asked[0].GetOperationBindingId() != "things-binding" || asked[0].GetParentToken() != edgeContext {
		t.Fatalf("the authority was asked %v", asked)
	}
}

// A refusal on a route the solution serves itself is a Connect error to a
// Connect client, which reads nothing else, and {"error"} to a REST caller;
// an authority refusal a handler returns keeps the authority's code and reason.
func TestARefusalIsWrittenInTheCallersProtocol(t *testing.T) {
	s, _ := authorityServer(t)
	handler := s.wrapRequest("POST /v1/page/things", func(r *http.Request, gw *Gateway) (any, error) {
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
	gw := s.newGateway()
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
	unreachable := s.newGateway()
	unreachable.orgID = "org-from-the-authority"
	_, err = unreachable.ForBinding(context.Background(), "any")
	if !errors.As(err, &refusal) || refusal.Reason != "" {
		t.Fatalf("an unreachable authority: %#v", err)
	}
}
