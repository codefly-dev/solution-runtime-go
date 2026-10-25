package solution

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// relayedTestFile is a module API as the modules serve one behind the hop: a
// service of Connect/gRPC procedures, none carrying a google.api.http binding.
// Its messages are transcodeTestFile's.
var relayedTestFile = func() protoreflect.FileDescriptor {
	things := transcodeTestFile.Path()
	method := func(name string, serverStreams, clientStreams bool) *descriptorpb.MethodDescriptorProto {
		return &descriptorpb.MethodDescriptorProto{Name: proto.String(name), InputType: proto.String(".things.v1.GetThingRequest"), OutputType: proto.String(".things.v1.Thing"),
			ServerStreaming: proto.Bool(serverStreams), ClientStreaming: proto.Bool(clientStreams)}
	}
	file := &descriptorpb.FileDescriptorProto{
		Name:       proto.String("solution_runtime_test/relayed.proto"),
		Package:    proto.String("relayed.v1"),
		Syntax:     proto.String("proto3"),
		Dependency: []string{things},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("Things"),
			Method: []*descriptorpb.MethodDescriptorProto{
				method("Search", false, false), method("Get", false, false), method("Watch", true, false), method("Upload", false, true),
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

const (
	searchName = "/relayed.v1.Things/Search"
	getName    = "/relayed.v1.Things/Get"
	watchName  = "/relayed.v1.Things/Watch"
	searchPath = "/modules/things/relayed.v1.Things/Search"
	getPath    = "/modules/things/relayed.v1.Things/Get"
)

// passthroughModule is the "things" module of relayedTestFile as a solution
// declares it: Search passes through, with only entry_id and big returned,
// relayed through the hop at the address and binding its slots name.
func passthroughModule() ConsumedModule {
	return ConsumedModule{
		As:     "things",
		Scopes: []Scope{{ResourceKind: "things", Actions: []string{"read"}}},
		Methods: []ConsumedMethod{{
			Name:     searchName,
			Response: MustFieldMask(thingMessage("Thing"), "entry_id", "big"),
		}},
		Authority: AuthorityRelay{Group: "page", EndpointKey: "THINGS_ENDPOINT", BindingKey: "THINGS_BINDING"},
	}
}

// watchModule is passthroughModule with its Watch stream declared beside
// Search, bounded as watch says.
func watchModule(watch ConsumedMethod) ConsumedModule {
	module := passthroughModule()
	watch.Name = watchName
	if !watch.WholeResponse {
		watch.Response = MustFieldMask(thingMessage("Thing"), "entry_id", "big")
	}
	module.Methods = append(module.Methods, watch)
	return module
}

// No method the passthrough relays needs a google.api.http binding: the
// modules serve none behind the hop.
func TestTheRelayedTestModuleCarriesNoHTTPBinding(t *testing.T) {
	methods := relayedTestFile.Services().ByName("Things").Methods()
	for i := 0; i < methods.Len(); i++ {
		if proto.HasExtension(methods.Get(i).Options(), annotations.E_Http) {
			t.Fatalf("%s carries an http binding", methods.Get(i).FullName())
		}
	}
	if _, err := resolvePassthrough([]ConsumedModule{watchModule(ConsumedMethod{})}); err != nil {
		t.Fatalf("a module with no http binding was refused: %v", err)
	}
}

func TestPassthroughRefusesADeclarationItCannotServe(t *testing.T) {
	search := func(m ConsumedMethod) ConsumedModule {
		module := passthroughModule()
		module.Methods = []ConsumedMethod{m}
		return module
	}
	module := func(edit func(*ConsumedModule)) []ConsumedModule {
		m := passthroughModule()
		edit(&m)
		return []ConsumedModule{m}
	}
	mask := MustFieldMask(thingMessage("Thing"), "entry_id")
	for name, c := range map[string]struct {
		modules []ConsumedModule
		want    string
	}{
		"no as":                         {module(func(m *ConsumedModule) { m.As = "" }), "one path segment"},
		"an as with a path":             {module(func(m *ConsumedModule) { m.As = "things/v2" }), "one path segment"},
		"no scopes":                     {module(func(m *ConsumedModule) { m.Scopes = nil }), "declares no Scopes"},
		"no methods":                    {module(func(m *ConsumedModule) { m.Methods = nil }), "declares no methods"},
		"no authority relay":            {module(func(m *ConsumedModule) { m.Authority = AuthorityRelay{} }), "authority's hop"},
		"a relay missing its binding":   {module(func(m *ConsumedModule) { m.Authority.BindingKey = "" }), "all three"},
		"a method not in the registry":  {[]ConsumedModule{search(ConsumedMethod{Name: "/relayed.v1.Things/Nope", Response: mask})}, "not in the protobuf registry"},
		"no response fields":            {[]ConsumedModule{search(ConsumedMethod{Name: searchName})}, "declares no response fields"},
		"a mask and the whole response": {[]ConsumedModule{search(ConsumedMethod{Name: searchName, Response: mask, WholeResponse: true})}, "both a response mask"},
		"a mask over another message":   {[]ConsumedModule{search(ConsumedMethod{Name: searchName, Response: MustFieldMask(thingMessage("Sub"), "name")})}, "response mask is over"},
		"a pin of another type":         {[]ConsumedModule{search(ConsumedMethod{Name: searchName, WholeResponse: true, Pin: thingMessage("Thing")})}, "its pin is a"},
		"a method twice":                {module(func(m *ConsumedModule) { m.Methods = append(m.Methods, m.Methods[0]) }), "declared twice"},
		"a module twice":                {[]ConsumedModule{passthroughModule(), passthroughModule()}, "declared twice"},
	} {
		if _, err := resolvePassthrough(c.modules); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a refusal naming %q", name, err, c.want)
		}
	}
}

func TestPassthroughRefusesAnUnservableScopeDeclarationAtBoot(t *testing.T) {
	read := Scope{ResourceKind: "things", Actions: []string{"read"}}
	module := func(moduleScopes []Scope, methodScopes ...Scope) ConsumedModule {
		m := passthroughModule()
		m.Scopes = moduleScopes
		m.Methods = []ConsumedMethod{{Name: searchName, Scopes: methodScopes, WholeResponse: true}}
		return m
	}
	oneUnscoped := module(nil, read)
	oneUnscoped.Methods = append(oneUnscoped.Methods, ConsumedMethod{Name: getName, WholeResponse: true})
	for name, c := range map[string]struct {
		module ConsumedModule
		want   string
	}{
		"no scopes anywhere":                      {module(nil), "declares no Scopes"},
		"one method without scopes and no module": {oneUnscoped, "Get declares no Scopes"},
		"empty action list on a method":           {module(nil, Scope{ResourceKind: "things"}), "names no action"},
		"empty action list on the module":         {module([]Scope{{ResourceKind: "things", Actions: []string{}}}), "names no action"},
		"blank action":                            {module(nil, Scope{ResourceKind: "things", Actions: []string{" "}}), "blank action"},
		"no resource kind":                        {module(nil, Scope{Actions: []string{"read"}}), "no resource kind"},
		"duplicated action":                       {module(nil, Scope{ResourceKind: "things", Actions: []string{"read", "read"}}), "twice"},
	} {
		if _, err := resolvePassthrough([]ConsumedModule{c.module}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a refusal naming %q", name, err, c.want)
		}
	}
}

func TestPassthroughRefusesStreamBoundsItCannotKeep(t *testing.T) {
	for name, module := range map[string]ConsumedModule{
		"a client stream":             passthroughModule(),
		"bounds on a unary method":    passthroughModule(),
		"a negative duration":         watchModule(ConsumedMethod{MaxStreamDuration: -time.Second}),
		"a duration over the limit":   watchModule(ConsumedMethod{MaxStreamDuration: MaxStreamDurationLimit + time.Second}),
		"a negative message bound":    watchModule(ConsumedMethod{MaxStreamMessageBytes: -1}),
		"a response bound on streams": watchModule(ConsumedMethod{MaxResponseBytes: 10}),
	} {
		switch name {
		case "a client stream":
			module.Methods = append(module.Methods, ConsumedMethod{Name: "/relayed.v1.Things/Upload", WholeResponse: true})
		case "bounds on a unary method":
			module.Methods[0].MaxStreamDuration = time.Minute
		}
		if _, err := resolvePassthrough([]ConsumedModule{module}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := resolvePassthrough([]ConsumedModule{watchModule(ConsumedMethod{MaxStreamDuration: time.Minute, MaxStreamMessageBytes: 4096})}); err != nil {
		t.Fatalf("a bounded stream: %v", err)
	}
}

func TestPassthroughOperationsDocumentTheDeclaration(t *testing.T) {
	ops, err := PassthroughOperations(passthroughModule())
	if err != nil {
		t.Fatal(err)
	}
	doc, err := InterfaceDocument(InterfaceInfo{Title: "t", Version: "0.0.1", Description: "d", BasePath: "/v1/test", OperationPrefix: "Test", Tag: "test"}, ops)
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
	if !strings.Contains(description, "procedure "+searchName+" through the authority's hop") || !strings.Contains(description, "big, entry_id") || !strings.Contains(description, "things:[read]") {
		t.Fatalf("description = %q", description)
	}
	if parsed.Definitions["ThingsV1Thing"] == nil || parsed.Definitions["ThingsV1GetThingRequest"] == nil {
		t.Fatalf("definitions = %v", parsed.Definitions)
	}
}

func TestPassthroughOperationsDocumentEachMethodsOwnScopes(t *testing.T) {
	module := passthroughModule()
	module.Scopes = nil
	module.Methods = []ConsumedMethod{
		{Name: searchName, Scopes: []Scope{{ResourceKind: "things", Actions: []string{"list"}}}, WholeResponse: true},
		{Name: getName, Scopes: []Scope{{ResourceKind: "things", Actions: []string{"inspect"}}}, WholeResponse: true},
	}
	ops, err := PassthroughOperations(module)
	if err != nil {
		t.Fatal(err)
	}
	found := map[string]string{}
	for _, op := range ops {
		found[op.Path] = op.Callers
	}
	if !strings.Contains(found[searchPath], "things:[list]") || strings.Contains(found[searchPath], "inspect") {
		t.Fatalf("search callers = %q", found[searchPath])
	}
	if !strings.Contains(found[getPath], "things:[inspect]") || strings.Contains(found[getPath], "list") {
		t.Fatalf("get callers = %q", found[getPath])
	}
}

func TestPassthroughOperationsDocumentAStreamedMethod(t *testing.T) {
	ops, err := PassthroughOperations(watchModule(ConsumedMethod{MaxStreamDuration: time.Minute, MaxStreamMessageBytes: 4096}))
	if err != nil {
		t.Fatal(err)
	}
	var watch *Operation
	for i := range ops {
		if strings.HasSuffix(ops[i].Path, "/Watch") {
			watch = &ops[i]
		}
	}
	if watch == nil || !watch.Streaming || !strings.Contains(watch.Behavior, "server-streaming") || !strings.Contains(watch.Behavior, watchName) ||
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

func TestInterfaceArtifactCarriesTheManifestVersionAndBothSurfaces(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "service.codefly.yaml"), []byte("kind: service\nname: backend\nversion: 1.2.3\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	own := Operation{Path: "/own", Summary: "s", Callers: "c", Behavior: "b", Response: map[string]string{},
		Policy: AnyCheckedCaller(), Handler: func(context.Context, *Gateway) (any, error) { return nil, nil }}
	doc, err := InterfaceArtifact(dir, InterfaceInfo{Title: "t", BasePath: "/v1/test", OperationPrefix: "Test", Tag: "test"}, []Operation{own}, passthroughModule())
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
	// A relayed route is held to its module's own method policy, by the hop
	// in front of the module: it carries none of the solution's.
	relayed, _ := json.Marshal(parsed.Paths[searchPath])
	if strings.Contains(string(relayed), PolicyExtension) {
		t.Fatalf("a relayed route declares a solution policy: %s", relayed)
	}
	ops, err := PassthroughOperations(passthroughModule())
	if err != nil {
		t.Fatal(err)
	}
	ops[0].Policy = AnyCheckedCaller()
	if _, err := InterfaceDocument(InterfaceInfo{}, ops); err == nil {
		t.Fatal("a relayed route rendered with a solution policy")
	}
	if _, err := InterfaceArtifact(t.TempDir(), InterfaceInfo{}, nil); err == nil {
		t.Fatal("a backend with no service manifest rendered a version")
	}
}
