package passthroughtest_test

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
	codefly "github.com/codefly-dev/sdk-go"
	solution "github.com/codefly-dev/solution-runtime-go"
	"github.com/codefly-dev/solution-runtime-go/passthroughtest"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// widgetsFile is a composed module's API as its generated package registers
// it: a unary Search and a server-streaming Watch, each with a google.api.http
// binding under /v1/widgets.
var widgetsFile = func() protoreflect.FileDescriptor {
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	field := func(name, json string, number int32) *descriptorpb.FieldDescriptorProto {
		return &descriptorpb.FieldDescriptorProto{Name: proto.String(name), JsonName: proto.String(json), Number: proto.Int32(number), Label: opt, Type: str}
	}
	binding := func(rule *annotations.HttpRule) *descriptorpb.MethodOptions {
		options := &descriptorpb.MethodOptions{}
		proto.SetExtension(options, annotations.E_Http, rule)
		return options
	}
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("passthroughtest_test/widgets.proto"),
		Package: proto.String("acme.widgets.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("WidgetRequest"), Field: []*descriptorpb.FieldDescriptorProto{field("widget_id", "widgetId", 1)}},
			{Name: proto.String("Widget"), Field: []*descriptorpb.FieldDescriptorProto{
				field("widget_id", "widgetId", 1), field("name", "name", 2), field("secret", "secret", 3),
			}},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("Widgets"),
			Method: []*descriptorpb.MethodDescriptorProto{
				{Name: proto.String("Search"), InputType: proto.String(".acme.widgets.v1.WidgetRequest"), OutputType: proto.String(".acme.widgets.v1.Widget"),
					Options: binding(&annotations.HttpRule{Pattern: &annotations.HttpRule_Post{Post: "/v1/widgets/search"}, Body: "*"})},
				{Name: proto.String("Watch"), InputType: proto.String(".acme.widgets.v1.WidgetRequest"), OutputType: proto.String(".acme.widgets.v1.Widget"),
					ServerStreaming: proto.Bool(true),
					Options:         binding(&annotations.HttpRule{Pattern: &annotations.HttpRule_Get{Get: "/v1/widgets/{widget_id}/watch"}})},
			},
		}},
	}
	fd, err := protodesc.NewFile(file, protoregistry.GlobalFiles)
	if err != nil {
		panic(err)
	}
	if err := protoregistry.GlobalFiles.RegisterFile(fd); err != nil {
		panic(err)
	}
	return fd
}()

var (
	searchMethod = widgetsFile.Services().ByName("Widgets").Methods().ByName("Search")
	watchMethod  = widgetsFile.Services().ByName("Widgets").Methods().ByName("Watch")
	readScope    = solution.Scope{ResourceKind: "widgets", Actions: []string{"read"}}
	watchScope   = solution.Scope{ResourceKind: "widgets", Actions: []string{"watch"}}
)

// declaration is a consuming solution's Consumes: Search under the module's
// read scope, Watch under its own watch scope, each returning only widget_id
// and name.
func declaration() solution.ConsumedModule {
	mask := solution.MustFieldMask(dynamicpb.NewMessage(searchMethod.Output()), "widget_id", "name")
	return solution.ConsumedModule{
		As:     "widgets",
		Scopes: []solution.Scope{readScope},
		Methods: []solution.ConsumedMethod{
			{Name: "/acme.widgets.v1.Widgets/Search", Response: mask},
			{Name: "/acme.widgets.v1.Widgets/Watch", Response: mask, Scopes: []solution.Scope{watchScope}},
		},
	}
}

// module is the test's stand-in for the composed module: it answers Search
// with one widget and Watch with the lines the test feeds it, flushed one by
// one, and reports when a Watch request is cancelled.
type module struct {
	*httptest.Server
	lines    chan string
	canceled chan struct{}
	// done ends every open stream when the test ends, so a stream the
	// passthrough failed to cancel fails the test instead of hanging it.
	done chan struct{}

	mu      sync.Mutex
	headers []http.Header
}

func newModule(t *testing.T) *module {
	t.Helper()
	m := &module{lines: make(chan string, 16), canceled: make(chan struct{}, 1), done: make(chan struct{})}
	m.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		m.headers = append(m.headers, r.Header.Clone())
		m.mu.Unlock()
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/widgets/search":
			var req struct {
				WidgetID string `json:"widgetId"`
			}
			_ = json.NewDecoder(r.Body).Decode(&req)
			w.Header().Set("content-type", "application/json")
			_, _ = fmt.Fprintf(w, `{"widgetId":%q,"name":"Acme widget","secret":"s3cret"}`, req.WidgetID)
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/watch"):
			w.Header().Set("content-type", "application/x-ndjson")
			w.WriteHeader(http.StatusOK)
			w.(http.Flusher).Flush()
			for {
				select {
				case line, ok := <-m.lines:
					if !ok {
						return
					}
					_, _ = io.WriteString(w, line+"\n")
					w.(http.Flusher).Flush()
				case <-r.Context().Done():
					m.canceled <- struct{}{}
					return
				case <-m.done:
					return
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.Close)
	return m
}

func widget(id string) string {
	return fmt.Sprintf(`{"result":{"widgetId":%q,"name":"Acme widget","secret":"s3cret"}}`, id)
}

// clients are the page: the module's Connect clients, over JSON as connect-es
// speaks, against the passthrough's base URL.
func clients(page *passthroughtest.Solution) (search, watch *connect.Client[dynamicpb.Message, dynamicpb.Message]) {
	client := func(md protoreflect.MethodDescriptor) *connect.Client[dynamicpb.Message, dynamicpb.Message] {
		return connect.NewClient[dynamicpb.Message, dynamicpb.Message](page.Client(),
			page.BaseURL("widgets")+"/"+string(md.Parent().FullName())+"/"+string(md.Name()),
			connect.WithSchema(md), connect.WithProtoJSON(),
			connect.WithResponseInitializer(func(_ connect.Spec, msg any) error {
				*msg.(*dynamicpb.Message) = *dynamicpb.NewMessage(md.Output())
				return nil
			}))
	}
	return client(searchMethod), client(watchMethod)
}

func request(id string) *connect.Request[dynamicpb.Message] {
	msg := dynamicpb.NewMessage(searchMethod.Input())
	msg.Set(msg.Descriptor().Fields().ByName("widget_id"), protoreflect.ValueOfString(id))
	return connect.NewRequest(msg)
}

func get(m *dynamicpb.Message, name string) string {
	return m.Get(m.Descriptor().Fields().ByName(protoreflect.Name(name))).String()
}

func has(m *dynamicpb.Message, name string) bool {
	return m.Has(m.Descriptor().Fields().ByName(protoreflect.Name(name)))
}

func start(t *testing.T) (*passthroughtest.Host, *module, *connect.Client[dynamicpb.Message, dynamicpb.Message], *connect.Client[dynamicpb.Message, dynamicpb.Message]) {
	t.Helper()
	upstream := newModule(t)
	host := passthroughtest.NewHost(t).Module("widgets", upstream.URL)
	search, watch := clients(passthroughtest.Start(t, host, declaration()))
	// Registered last, so it runs first (cleanups run last-in, first-out):
	// before any server's Close waits on a stream still open.
	t.Cleanup(func() { close(upstream.done) })
	return host, upstream, search, watch
}

func TestAUnaryCallIsAnsweredByTheModuleAsTheViewer(t *testing.T) {
	host, upstream, search, _ := start(t)

	resp, err := search.CallUnary(context.Background(), request("w1"))
	if err != nil {
		t.Fatal(err)
	}
	if get(resp.Msg, "widget_id") != "w1" || get(resp.Msg, "name") != "Acme widget" {
		t.Fatalf("response = %v", resp.Msg)
	}
	calls := host.Calls()
	if len(calls) != 1 || calls[0].Method != http.MethodPost || calls[0].Path != "/v1/widgets/search" || calls[0].Mint == nil {
		t.Fatalf("calls = %+v, want Search over its binding, presenting a minted capability", calls)
	}
	if calls[0].Bearer != passthroughtest.DefaultViewer.Bearer {
		t.Fatalf("bearer = %q, want the viewer's", calls[0].Bearer)
	}
	mint := calls[0].Mint
	if mint.Audience != "widgets" || mint.OrgID != passthroughtest.DefaultViewer.OrgID || mint.SessionID != passthroughtest.DefaultViewer.SessionID {
		t.Fatalf("mint = %+v, want the module's audience in the viewer's org and session", mint)
	}
	upstream.mu.Lock()
	presented := upstream.headers[0].Get(codefly.WorkContextHeaderName)
	upstream.mu.Unlock()
	if got := presented; got != mint.Token {
		t.Fatalf("the module was presented %q, want the minted %q", got, mint.Token)
	}
}

func TestAStreamedCallYieldsEveryMessage(t *testing.T) {
	_, upstream, _, watch := start(t)
	for _, id := range []string{"w1", "w2", "w3"} {
		upstream.lines <- widget(id)
	}
	close(upstream.lines)

	stream, err := watch.CallServerStream(context.Background(), request("w1"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	var ids []string
	for stream.Receive() {
		ids = append(ids, get(stream.Msg(), "widget_id"))
	}
	if err := stream.Err(); err != nil {
		t.Fatal(err)
	}
	if strings.Join(ids, ",") != "w1,w2,w3" {
		t.Fatalf("received %v, want w1,w2,w3 in order", ids)
	}
}

func TestEachMethodMintsItsOwnAuthority(t *testing.T) {
	host, upstream, search, watch := start(t)
	close(upstream.lines)

	if _, err := search.CallUnary(context.Background(), request("w1")); err != nil {
		t.Fatal(err)
	}
	stream, err := watch.CallServerStream(context.Background(), request("w1"))
	if err != nil {
		t.Fatal(err)
	}
	for stream.Receive() {
	}
	if err := stream.Err(); err != nil {
		t.Fatal(err)
	}
	_ = stream.Close()

	mints := host.Mints()
	if len(mints) != 2 {
		t.Fatalf("mints = %+v, want one per call", mints)
	}
	authority := map[string]string{}
	for _, call := range host.Calls() {
		if call.Mint == nil || len(call.Mint.Scopes) != 1 {
			t.Fatalf("call %s %s presented %+v", call.Method, call.Path, call.Mint)
		}
		scope := call.Mint.Scopes[0]
		authority[call.Path] = scope.ResourceKind + ":" + strings.Join(scope.Actions, ",")
	}
	if authority["/v1/widgets/search"] != "widgets:read" || authority["/v1/widgets/w1/watch"] != "widgets:watch" {
		t.Fatalf("authority per call = %v, want Search under widgets:read and Watch under its own widgets:watch", authority)
	}
}

func TestOnlyTheDeclaredFieldsReachThePage(t *testing.T) {
	_, upstream, search, watch := start(t)
	upstream.lines <- widget("w1")
	close(upstream.lines)

	resp, err := search.CallUnary(context.Background(), request("w1"))
	if err != nil {
		t.Fatal(err)
	}
	if has(resp.Msg, "secret") || !has(resp.Msg, "name") {
		t.Fatalf("unary response = %v, want name and no secret", resp.Msg)
	}
	stream, err := watch.CallServerStream(context.Background(), request("w1"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = stream.Close() }()
	if !stream.Receive() {
		t.Fatalf("no streamed message: %v", stream.Err())
	}
	if has(stream.Msg(), "secret") || !has(stream.Msg(), "name") {
		t.Fatalf("streamed message = %v, want name and no secret", stream.Msg())
	}
}

func TestThePageDisconnectingCancelsTheModulesStream(t *testing.T) {
	_, upstream, _, watch := start(t)
	upstream.lines <- widget("w1")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	stream, err := watch.CallServerStream(ctx, request("w1"))
	if err != nil {
		t.Fatal(err)
	}
	if !stream.Receive() {
		t.Fatalf("no streamed message: %v", stream.Err())
	}
	// The page goes away mid-stream; the module never ends its stream itself.
	cancel()
	_ = stream.Close()
	select {
	case <-upstream.canceled:
	case <-time.After(5 * time.Second):
		t.Fatal("the module's stream was not cancelled when the page disconnected")
	}
}

func TestARefusedMintRefusesOnlyThatMethod(t *testing.T) {
	host, upstream, search, watch := start(t)
	close(upstream.lines)
	host.RefuseMints(func(mint passthroughtest.Mint) *passthroughtest.Refusal {
		for _, scope := range mint.Scopes {
			for _, action := range scope.Actions {
				if action == "watch" {
					return &passthroughtest.Refusal{Code: "permission_denied", Message: "viewer is not allowed widgets:watch"}
				}
			}
		}
		return nil
	})

	stream, err := watch.CallServerStream(context.Background(), request("w1"))
	if err == nil {
		for stream.Receive() {
		}
		err = stream.Err()
		_ = stream.Close()
	}
	if connect.CodeOf(err) != connect.CodePermissionDenied || !strings.Contains(err.Error(), "widgets:watch") {
		t.Fatalf("watch = %v, want permission_denied naming the missing permission", err)
	}
	if _, err := search.CallUnary(context.Background(), request("w1")); err != nil {
		t.Fatalf("search, whose authority the viewer holds, was refused: %v", err)
	}
	for _, call := range host.Calls() {
		if strings.HasSuffix(call.Path, "/watch") {
			t.Fatal("a refused method reached the module")
		}
	}
}

func TestADeclarationServeWouldRefuseIsRefused(t *testing.T) {
	host := passthroughtest.NewHost(t) // routes no module, so api.consumes lists none
	_, err := passthroughtest.Handler(host, declaration())
	if err == nil || !strings.Contains(err.Error(), "api.consumes lists no module") {
		t.Fatalf("err = %v, want the boot refusal of a module the solution does not consume", err)
	}
}
