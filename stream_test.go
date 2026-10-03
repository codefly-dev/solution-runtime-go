package solution

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/codefly-dev/sdk-go/workcontext"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

const watchName = "/things.v1.Things/Watch"

// streamModule declares the things module's Watch stream, returning only
// entry_id and big of each message, with Search as a unary method beside it.
func streamModule(watch ConsumedMethod) ConsumedModule {
	module := passthroughModule()
	watch.Name = watchName
	if watch.Response.desc == nil && !watch.WholeResponse {
		watch.Response = MustFieldMask(thingMessage("Thing"), "entry_id", "big")
	}
	watch.Scopes = []Scope{{ResourceKind: "things", Actions: []string{"watch"}}}
	module.Methods = append(module.Methods, watch)
	return module
}

// streamGateway is the host gateway with a module whose Watch answers with the
// lines its test writes, flushed one by one; the unary routes answer as
// moduleGateway does.
type streamGateway struct {
	*httptest.Server
	lines       chan string
	contentType string
	status      int

	mu       sync.Mutex
	mints    []mintRequest
	watches  []*http.Request
	canceled chan struct{}
}

func newStreamGateway(t *testing.T) *streamGateway {
	t.Helper()
	g := &streamGateway{lines: make(chan string, 16), contentType: "application/x-ndjson", status: http.StatusOK, canceled: make(chan struct{}, 1)}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == workContextStartTaskProcedure {
			var mint mintRequest
			_ = json.Unmarshal(body, &mint)
			g.mu.Lock()
			g.mints = append(g.mints, mint)
			g.mu.Unlock()
			writeJSON(w, http.StatusOK, map[string]any{
				"token": capability("context-" + mint.Audience + ".1"), "orgId": mint.OrgID,
				"ownerPrincipalId": "viewer", "currentActorPrincipalId": "viewer",
				"expiresAt": time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano),
			})
			return
		}
		g.mu.Lock()
		g.watches = append(g.watches, r.Clone(context.Background()))
		g.mu.Unlock()
		if g.status != http.StatusOK {
			w.WriteHeader(g.status)
			_, _ = io.WriteString(w, `{"code":7,"message":"not yours"}`)
			return
		}
		w.Header().Set("content-type", g.contentType)
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		for {
			select {
			case line, ok := <-g.lines:
				if !ok {
					return
				}
				_, _ = io.WriteString(w, line+"\n")
				w.(http.Flusher).Flush()
			case <-r.Context().Done():
				g.canceled <- struct{}{}
				return
			}
		}
	}))
	t.Cleanup(g.Close)
	return g
}

// watchClient is the page: a Connect server-streaming client over JSON, as
// connect-es is, against the solution's passthrough served for real.
func watchClient(t *testing.T, s *Server) *connect.Client[dynamicpb.Message, dynamicpb.Message] {
	t.Helper()
	routes, err := s.validatePassthroughRoutesForTest()
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(s.passthroughHandler(routes))
	t.Cleanup(srv.Close)
	md := transcodeTestFile.Services().ByName("Things").Methods().ByName("Watch")
	return connect.NewClient[dynamicpb.Message, dynamicpb.Message](srv.Client(), srv.URL+"/modules/things/things.v1.Things/Watch",
		connect.WithSchema(md), connect.WithProtoJSON(),
		connect.WithResponseInitializer(func(_ connect.Spec, msg any) error {
			*msg.(*dynamicpb.Message) = *dynamicpb.NewMessage(md.Output())
			return nil
		}))
}

func (s *Server) validatePassthroughRoutesForTest() (map[string]passthroughRoute, error) {
	return resolvePassthrough(s.consumed)
}

func watchRequest(entry string) *connect.Request[dynamicpb.Message] {
	msg := thingMessage("GetThingRequest")
	setField(msg, "entry_id", protoreflect.ValueOfString(entry))
	req := connect.NewRequest(msg)
	req.Header().Set("authorization", "Bearer viewer")
	req.Header().Set(orgHeader, "org-1")
	req.Header().Set(sessionHeader, "session-1")
	return req
}

func field(m *dynamicpb.Message, name string) protoreflect.Value {
	return m.Get(m.Descriptor().Fields().ByName(protoreflect.Name(name)))
}

func has(m *dynamicpb.Message, name string) bool {
	return m.Has(m.Descriptor().Fields().ByName(protoreflect.Name(name)))
}

func TestPassthroughStreamsEachMessageMaskedAsTheViewer(t *testing.T) {
	gw := newStreamGateway(t)
	s := passthroughServer(t, gw.URL, streamModule(ConsumedMethod{}))
	gw.lines <- `{"result":{"entryId":"e1","big":"1","secret":"s1"}}`
	gw.lines <- ``
	gw.lines <- `{"result":{"entryId":"e1","big":"2","secret":"s2","sub":{"name":"x"}}}`
	close(gw.lines)
	stream, err := watchClient(t, s).CallServerStream(context.Background(), watchRequest("e1"))
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for stream.Receive() {
		msg := stream.Msg()
		// The declared fields reach the page, on every message; nothing else does.
		if has(msg, "secret") || has(msg, "sub") {
			t.Fatalf("an undeclared field reached the page: %v", msg)
		}
		got = append(got, fmt.Sprintf("%s/%d", field(msg, "entry_id").String(), field(msg, "big").Int()))
	}
	if err := stream.Err(); err != nil {
		t.Fatalf("stream: %v", err)
	}
	if strings.Join(got, ",") != "e1/1,e1/2" {
		t.Fatalf("messages = %v", got)
	}
	// Called over the binding, with the authority minted for this method alone.
	if len(gw.watches) != 1 || gw.watches[0].Method != http.MethodGet || gw.watches[0].URL.Path != "/v1/things/e1/watch" {
		t.Fatalf("module calls = %v", gw.watches)
	}
	if gw.watches[0].Header.Get(workcontext.HeaderName) != capability("context-things.1") || !strings.Contains(gw.watches[0].Header.Get("accept"), "application/x-ndjson") {
		t.Fatalf("headers = %v", gw.watches[0].Header)
	}
	if len(gw.mints) != 1 || mintedActions(gw.mints[0]) != "things:watch" {
		t.Fatalf("mints = %+v, want the Watch method's scope only", gw.mints)
	}
}

func TestPassthroughStreamForwardsOnlyTheBearerForAModuleThatAuthenticatesTheViewer(t *testing.T) {
	gw := newStreamGateway(t)
	module := streamModule(ConsumedMethod{})
	module.Scopes, module.ViewerBearer = nil, true
	for i := range module.Methods {
		module.Methods[i].Scopes = nil
	}
	s := passthroughServer(t, gw.URL, module)
	close(gw.lines)
	stream, err := watchClient(t, s).CallServerStream(context.Background(), watchRequest("e1"))
	if err != nil {
		t.Fatal(err)
	}
	for stream.Receive() {
	}
	if err := stream.Err(); err != nil {
		t.Fatal(err)
	}
	if len(gw.mints) != 0 || gw.watches[0].Header.Get(workcontext.HeaderName) != "" || gw.watches[0].Header.Get("authorization") != "Bearer viewer" {
		t.Fatalf("want the viewer's bearer and no capability: mints %d, headers %v", len(gw.mints), gw.watches[0].Header)
	}
}

func receiveAll(stream *connect.ServerStreamForClient[dynamicpb.Message]) (int, error) {
	n := 0
	for stream.Receive() {
		n++
	}
	return n, stream.Err()
}

func TestPassthroughStreamEndsWithTheModulesErrorLine(t *testing.T) {
	gw := newStreamGateway(t)
	s := passthroughServer(t, gw.URL, streamModule(ConsumedMethod{}))
	gw.lines <- `{"result":{"entryId":"e1"}}`
	gw.lines <- `{"error":{"code":9,"message":"the turn was deleted"}}`
	stream, err := watchClient(t, s).CallServerStream(context.Background(), watchRequest("e1"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := receiveAll(stream)
	if n != 1 || connect.CodeOf(err) != connect.CodeFailedPrecondition || !strings.Contains(err.Error(), "the turn was deleted") {
		t.Fatalf("got %d messages, err %v; want one message then failed_precondition", n, err)
	}
}

func TestPassthroughStreamRelaysARefusalBeforeTheStream(t *testing.T) {
	gw := newStreamGateway(t)
	gw.status = http.StatusForbidden
	s := passthroughServer(t, gw.URL, streamModule(ConsumedMethod{}))
	stream, err := watchClient(t, s).CallServerStream(context.Background(), watchRequest("e1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiveAll(stream); connect.CodeOf(err) != connect.CodePermissionDenied {
		t.Fatalf("err = %v, want the module's permission_denied", err)
	}
}

func TestPassthroughStreamRefusesAnOversizedMessageWithoutTruncating(t *testing.T) {
	gw := newStreamGateway(t)
	s := passthroughServer(t, gw.URL, streamModule(ConsumedMethod{MaxStreamMessageBytes: 64}))
	gw.lines <- `{"result":{"entryId":"e1"}}`
	gw.lines <- `{"result":{"entryId":"` + strings.Repeat("x", 200) + `"}}`
	stream, err := watchClient(t, s).CallServerStream(context.Background(), watchRequest("e1"))
	if err != nil {
		t.Fatal(err)
	}
	n, err := receiveAll(stream)
	if n != 1 || connect.CodeOf(err) != connect.CodeResourceExhausted {
		t.Fatalf("got %d messages, err %v; want one message then resource_exhausted", n, err)
	}
}

func TestPassthroughStreamEndsAtItsDeclaredDuration(t *testing.T) {
	gw := newStreamGateway(t)
	s := passthroughServer(t, gw.URL, streamModule(ConsumedMethod{MaxStreamDuration: 300 * time.Millisecond}))
	gw.lines <- `{"result":{"entryId":"e1"}}`
	stream, err := watchClient(t, s).CallServerStream(context.Background(), watchRequest("e1"))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	n, err := receiveAll(stream)
	if n != 1 || connect.CodeOf(err) != connect.CodeDeadlineExceeded || !strings.Contains(err.Error(), "declared duration") {
		t.Fatalf("got %d messages, err %v; want one message then deadline_exceeded", n, err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the stream outlived its duration: %s", elapsed)
	}
	select {
	case <-gw.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("the module's request was not cancelled when the stream ended")
	}
}

func TestPassthroughStreamCancelsTheModuleWhenThePageGoesAway(t *testing.T) {
	gw := newStreamGateway(t)
	s := passthroughServer(t, gw.URL, streamModule(ConsumedMethod{}))
	gw.lines <- `{"result":{"entryId":"e1"}}`
	ctx, cancel := context.WithCancel(context.Background())
	stream, err := watchClient(t, s).CallServerStream(ctx, watchRequest("e1"))
	if err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatalf("first message: %v", stream.Err())
	}
	cancel()
	_ = stream.Close()
	select {
	case <-gw.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("the module's request outlived the page")
	}
}

func TestPassthroughStreamRefusesAnAnswerThatIsNotAStream(t *testing.T) {
	gw := newStreamGateway(t)
	gw.contentType = "text/html"
	s := passthroughServer(t, gw.URL, streamModule(ConsumedMethod{}))
	close(gw.lines)
	stream, err := watchClient(t, s).CallServerStream(context.Background(), watchRequest("e1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := receiveAll(stream); connect.CodeOf(err) != connect.CodeUnavailable {
		t.Fatalf("err = %v, want unavailable, never the body as a message", err)
	}
}

func TestPassthroughRefusesStreamBoundsItCannotKeep(t *testing.T) {
	search := passthroughModule().Methods[0]
	for name, module := range map[string]ConsumedModule{
		"a client stream":             streamModule(ConsumedMethod{}),
		"bounds on a unary method":    {As: "things", ViewerBearer: true, Methods: []ConsumedMethod{{Name: search.Name, Response: search.Response, MaxStreamDuration: time.Minute}}},
		"a negative duration":         streamModule(ConsumedMethod{MaxStreamDuration: -time.Second}),
		"a duration over the limit":   streamModule(ConsumedMethod{MaxStreamDuration: MaxStreamDurationLimit + time.Second}),
		"a negative message bound":    streamModule(ConsumedMethod{MaxStreamMessageBytes: -1}),
		"a response bound on streams": streamModule(ConsumedMethod{MaxResponseBytes: 10}),
	} {
		if name == "a client stream" {
			module.Methods = append(module.Methods, ConsumedMethod{Name: "/things.v1.Things/Upload", WholeResponse: true})
		}
		if _, err := resolvePassthrough([]ConsumedModule{module}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := resolvePassthrough([]ConsumedModule{streamModule(ConsumedMethod{MaxStreamDuration: time.Minute, MaxStreamMessageBytes: 4096})}); err != nil {
		t.Fatalf("a bounded stream: %v", err)
	}
}

func TestPassthroughOperationsDocumentAStreamedMethod(t *testing.T) {
	ops, err := PassthroughOperations(streamModule(ConsumedMethod{MaxStreamDuration: time.Minute, MaxStreamMessageBytes: 4096}))
	if err != nil {
		t.Fatal(err)
	}
	var watch *Operation
	for i := range ops {
		if strings.HasSuffix(ops[i].Path, "/Watch") {
			watch = &ops[i]
		}
	}
	if watch == nil || !watch.Streaming || !strings.Contains(watch.Behavior, "server-streaming") ||
		!strings.Contains(watch.Behavior, "1m0s") || !strings.Contains(watch.Behavior, "4096 bytes") || !strings.Contains(watch.Behavior, "every streamed message") {
		t.Fatalf("watch operation = %+v", watch)
	}
	doc, err := InterfaceDocument(InterfaceInfo{Title: "t", Version: "1", Tag: "t", OperationPrefix: "T"}, ops)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), `"x-streaming": "server"`) {
		t.Fatalf("the document does not mark the stream: %s", doc)
	}
}
