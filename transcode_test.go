package solution

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// transcodeTestFile is a module API the way a generated package registers
// one: a service whose methods carry google.api.http bindings, one of them
// with an additional binding under a different prefix.
var transcodeTestFile = func() protoreflect.FileDescriptor {
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()
	i32 := descriptorpb.FieldDescriptorProto_TYPE_INT32.Enum()
	i64 := descriptorpb.FieldDescriptorProto_TYPE_INT64.Enum()
	msg := descriptorpb.FieldDescriptorProto_TYPE_MESSAGE.Enum()
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	rep := descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	field := func(name string, number int32, label *descriptorpb.FieldDescriptorProto_Label, typ *descriptorpb.FieldDescriptorProto_Type, typeName string) *descriptorpb.FieldDescriptorProto {
		f := &descriptorpb.FieldDescriptorProto{Name: proto.String(name), Number: proto.Int32(number), Label: label, Type: typ, JsonName: proto.String(jsonName(name))}
		if typeName != "" {
			f.TypeName = proto.String(typeName)
		}
		return f
	}
	http := func(rule *annotations.HttpRule) *descriptorpb.MethodOptions {
		options := &descriptorpb.MethodOptions{}
		proto.SetExtension(options, annotations.E_Http, rule)
		return options
	}
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("solution_runtime_test/things.proto"),
		Package: proto.String("things.v1"),
		Syntax:  proto.String("proto3"),
		MessageType: []*descriptorpb.DescriptorProto{
			{Name: proto.String("Sub"), Field: []*descriptorpb.FieldDescriptorProto{field("name", 1, opt, str, "")}},
			{Name: proto.String("GetThingRequest"), Field: []*descriptorpb.FieldDescriptorProto{
				field("tenant", 1, opt, str, ""),
				field("entry_id", 2, opt, str, ""),
				field("page_size", 3, opt, i32, ""),
				field("ids", 4, rep, str, ""),
				field("filter", 5, opt, msg, ".things.v1.Sub"),
			}},
			{Name: proto.String("Thing"), Field: []*descriptorpb.FieldDescriptorProto{
				field("entry_id", 1, opt, str, ""),
				field("big", 2, opt, i64, ""),
				field("secret", 3, opt, str, ""),
				field("sub", 4, opt, msg, ".things.v1.Sub"),
				field("subs", 5, rep, msg, ".things.v1.Sub"),
			}},
		},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("Things"),
			Method: []*descriptorpb.MethodDescriptorProto{
				{Name: proto.String("Get"), InputType: proto.String(".things.v1.GetThingRequest"), OutputType: proto.String(".things.v1.Thing"),
					Options: http(&annotations.HttpRule{
						Pattern:            &annotations.HttpRule_Get{Get: "/v1/tenants/{tenant}/things/{entry_id}"},
						AdditionalBindings: []*annotations.HttpRule{{Pattern: &annotations.HttpRule_Get{Get: "/v1/things/{entry_id}"}}},
					})},
				{Name: proto.String("Search"), InputType: proto.String(".things.v1.GetThingRequest"), OutputType: proto.String(".things.v1.Thing"),
					Options: http(&annotations.HttpRule{Pattern: &annotations.HttpRule_Post{Post: "/v1/things/search"}, Body: "*"})},
				{Name: proto.String("Unbound"), InputType: proto.String(".things.v1.GetThingRequest"), OutputType: proto.String(".things.v1.Thing")},
				{Name: proto.String("Wide"), InputType: proto.String(".things.v1.GetThingRequest"), OutputType: proto.String(".things.v1.Thing"),
					Options: http(&annotations.HttpRule{Pattern: &annotations.HttpRule_Get{Get: "/v1/things/{entry_id=**}"}})},
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

func jsonName(name string) string {
	parts := strings.Split(name, "_")
	for i := 1; i < len(parts); i++ {
		parts[i] = title(parts[i])
	}
	return strings.Join(parts, "")
}

func thingMessage(name string) *dynamicpb.Message {
	return dynamicpb.NewMessage(transcodeTestFile.Messages().ByName(protoreflect.Name(name)))
}

func setField(m *dynamicpb.Message, name string, v protoreflect.Value) {
	m.Set(m.Descriptor().Fields().ByName(protoreflect.Name(name)), v)
}

type recorded struct {
	method, uri, body string
}

func transcodeServer(t *testing.T, status int, reply string) (*Gateway, *recorded, *atomic.Int32) {
	t.Helper()
	got := &recorded{}
	hits := &atomic.Int32{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		got.method, got.uri, got.body = r.Method, r.URL.RequestURI(), string(body)
		w.WriteHeader(status)
		_, _ = io.WriteString(w, reply)
	}))
	t.Cleanup(srv.Close)
	return newGateway(srv.URL, "Bearer viewer", "org-1", "session-1"), got, hits
}

func TestTranscodedUsesTheBindingUnderThePrefix(t *testing.T) {
	gw, got, _ := transcodeServer(t, http.StatusOK, `{"entryId":"e/1","big":"9007199254740993","added":"by a newer owner"}`)
	req := thingMessage("GetThingRequest")
	setField(req, "tenant", protoreflect.ValueOfString("org-1"))
	setField(req, "entry_id", protoreflect.ValueOfString("e/1"))
	setField(req, "page_size", protoreflect.ValueOfInt32(100))
	ids := req.Mutable(req.Descriptor().Fields().ByName("ids")).List()
	ids.Append(protoreflect.ValueOfString("a"))
	ids.Append(protoreflect.ValueOfString("b"))
	filter := req.Mutable(req.Descriptor().Fields().ByName("filter")).Message()
	filter.Set(filter.Descriptor().Fields().ByName("name"), protoreflect.ValueOfString("x"))
	resp := thingMessage("Thing")

	if err := gw.Transcoded(context.Background(), "/v1/things", "/things.v1.Things/Get", req, resp); err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodGet {
		t.Fatalf("method = %s", got.method)
	}
	// The additional binding is the one under the prefix; the path variable is
	// escaped so its slash cannot add a segment; every other set field is a
	// query parameter by proto name.
	want := "/v1/things/e%2F1?filter.name=x&ids=a&ids=b&page_size=100&tenant=org-1"
	if got.uri != want {
		t.Fatalf("uri = %s, want %s", got.uri, want)
	}
	if got.body != "" {
		t.Fatalf("a GET binding sent a body: %q", got.body)
	}
	if v := resp.Get(resp.Descriptor().Fields().ByName("big")).Int(); v != 9007199254740993 {
		t.Fatalf("big = %d", v)
	}
}

func TestTranscodedSendsTheBodyTheBindingNames(t *testing.T) {
	gw, got, _ := transcodeServer(t, http.StatusOK, `{}`)
	req := thingMessage("GetThingRequest")
	setField(req, "tenant", protoreflect.ValueOfString("org-1"))
	setField(req, "page_size", protoreflect.ValueOfInt32(5))
	if err := gw.Transcoded(context.Background(), "/v1/things", "/things.v1.Things/Search", req, thingMessage("Thing")); err != nil {
		t.Fatal(err)
	}
	if got.method != http.MethodPost || got.uri != "/v1/things/search" {
		t.Fatalf("request = %s %s", got.method, got.uri)
	}
	var body map[string]any
	if err := json.Unmarshal([]byte(got.body), &body); err != nil || body["tenant"] != "org-1" || body["pageSize"] != float64(5) {
		t.Fatalf("body = %s (%v)", got.body, err)
	}
}

func TestTranscodedRefusesBeforeSending(t *testing.T) {
	get := thingMessage("GetThingRequest")
	setField(get, "entry_id", protoreflect.ValueOfString("e1"))
	cases := []struct {
		name, prefix, method string
		req, resp            proto.Message
		want                 string
	}{
		{"no binding under the prefix", "/v1/other", "/things.v1.Things/Get", get, thingMessage("Thing"), "no google.api.http binding under /v1/other"},
		{"a prefix that is only a string prefix", "/v1/thing", "/things.v1.Things/Get", get, thingMessage("Thing"), "no google.api.http binding"},
		{"no binding at all", "/v1/things", "/things.v1.Things/Unbound", get, thingMessage("Thing"), "declares no google.api.http binding"},
		{"a multi-segment variable", "/v1/things", "/things.v1.Things/Wide", get, thingMessage("Thing"), "multi-segment"},
		{"an unknown method", "/v1/things", "/things.v1.Things/Missing", get, thingMessage("Thing"), "not in the protobuf registry"},
		{"the wrong request type", "/v1/things", "/things.v1.Things/Get", thingMessage("Thing"), thingMessage("Thing"), "request is things.v1.Thing"},
		{"the wrong response type", "/v1/things", "/things.v1.Things/Get", get, thingMessage("Sub"), "response is things.v1.Sub"},
		{"an empty path variable", "/v1/things", "/things.v1.Things/Get", thingMessage("GetThingRequest"), thingMessage("Thing"), "{entry_id} is empty"},
		{"a dot-segment value", "/v1/things", "/things.v1.Things/Get", func() proto.Message {
			m := thingMessage("GetThingRequest")
			setField(m, "entry_id", protoreflect.ValueOfString(".."))
			return m
		}(), thingMessage("Thing"), "is a dot segment"},
		{"a trailing slash", "/v1/things/", "/things.v1.Things/Get", get, thingMessage("Thing"), "must be an absolute path"},
		{"a relative prefix", "v1/things", "/things.v1.Things/Get", get, thingMessage("Thing"), "must be an absolute path"},
		{"a dot segment", "/v1/../things", "/things.v1.Things/Get", get, thingMessage("Thing"), "must be an absolute path"},
		{"a query", "/v1/things?x=1", "/things.v1.Things/Get", get, thingMessage("Thing"), "must be an absolute path"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gw, _, hits := transcodeServer(t, http.StatusOK, `{}`)
			err := gw.Transcoded(context.Background(), tc.prefix, tc.method, tc.req, tc.resp)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want %q", err, tc.want)
			}
			if hits.Load() != 0 {
				t.Fatalf("a refused call reached the gateway")
			}
		})
	}
}

func TestTranscodedKeepsTheStatusOfAFailure(t *testing.T) {
	gw, _, _ := transcodeServer(t, http.StatusForbidden, `{"code":7,"message":"denied"}`)
	req := thingMessage("GetThingRequest")
	setField(req, "entry_id", protoreflect.ValueOfString("e1"))
	err := gw.Transcoded(context.Background(), "/v1/things", "/things.v1.Things/Get", req, thingMessage("Thing"))
	var status *GatewayError
	if !errors.As(err, &status) || status.StatusCode != http.StatusForbidden {
		t.Fatalf("err = %v, want a GatewayError with 403", err)
	}
}

func TestTranscodedBoundsTheResponse(t *testing.T) {
	gw, _, _ := transcodeServer(t, http.StatusOK, `{"entryId":"`+strings.Repeat("x", 64)+`"}`)
	req := thingMessage("GetThingRequest")
	setField(req, "entry_id", protoreflect.ValueOfString("e1"))
	err := gw.Transcoded(context.Background(), "/v1/things", "/things.v1.Things/Get", req, thingMessage("Thing"), MaxResponseBytes(32))
	if err == nil || !strings.Contains(err.Error(), "exceeds 32 bytes") {
		t.Fatalf("err = %v", err)
	}
}

func TestTranscodedPresentsTheViewersCredentials(t *testing.T) {
	var authorization string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authorization = r.Header.Get("authorization")
		_, _ = io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	gw := newGateway(srv.URL, "Bearer viewer", "org-1", "session-1")
	req := thingMessage("GetThingRequest")
	setField(req, "entry_id", protoreflect.ValueOfString("e1"))
	if err := gw.Transcoded(context.Background(), "/v1/things", "/things.v1.Things/Get", req, thingMessage("Thing")); err != nil {
		t.Fatal(err)
	}
	if authorization != "Bearer viewer" {
		t.Fatalf("authorization = %q", authorization)
	}
}

func TestFieldMaskKeepsOnlyWhatItNames(t *testing.T) {
	thing := thingMessage("Thing")
	setField(thing, "entry_id", protoreflect.ValueOfString("e1"))
	setField(thing, "big", protoreflect.ValueOfInt64(7))
	setField(thing, "secret", protoreflect.ValueOfString("storage://bucket/key"))
	sub := thing.Mutable(thing.Descriptor().Fields().ByName("sub")).Message()
	sub.Set(sub.Descriptor().Fields().ByName("name"), protoreflect.ValueOfString("kept"))
	subs := thing.Mutable(thing.Descriptor().Fields().ByName("subs")).List()
	element := subs.NewElement()
	element.Message().Set(element.Message().Descriptor().Fields().ByName("name"), protoreflect.ValueOfString("kept too"))
	subs.Append(element)

	mask := MustFieldMask(thing, "entry_id", "sub", "subs.name")
	out := Apply(mask, thing)
	fields := out.Descriptor().Fields()
	if out.Has(fields.ByName("secret")) || out.Has(fields.ByName("big")) {
		t.Fatalf("unnamed fields survived: %v", out)
	}
	if out.Get(fields.ByName("entry_id")).String() != "e1" || out.Get(fields.ByName("sub")).Message().Get(sub.Descriptor().Fields().ByName("name")).String() != "kept" {
		t.Fatalf("named fields were dropped: %v", out)
	}
	if out.Get(fields.ByName("subs")).List().Len() != 1 {
		t.Fatalf("repeated field was dropped: %v", out)
	}
	if !thing.Has(fields.ByName("secret")) {
		t.Fatalf("Apply modified its input")
	}
	if _, err := NewFieldMask(thing, "entry_id", "storage_uri"); err == nil {
		t.Fatalf("a mask naming an unknown field was accepted")
	}
	if _, err := NewFieldMask(thing, "entry_id.x"); err == nil {
		t.Fatalf("a mask descending into a scalar was accepted")
	}
}

func TestMessageEncodesProtobufJSON(t *testing.T) {
	rule := &annotations.HttpRule{Pattern: &annotations.HttpRule_Get{Get: "/v1/x"}, ResponseBody: "items"}
	out, err := json.Marshal(struct {
		Rule Message[*annotations.HttpRule] `json:"rule"`
		None Message[*annotations.HttpRule] `json:"none"`
	}{Rule: MessageOf(rule)})
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]map[string]any
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["rule"]["responseBody"] != "items" || decoded["rule"]["get"] != "/v1/x" {
		t.Fatalf("not protobuf JSON: %s", out)
	}
	if !strings.Contains(string(out), `"none":null`) {
		t.Fatalf("a nil message did not encode as null: %s", out)
	}
}
