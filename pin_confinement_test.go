package solution

import (
	"math"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
)

// pinShapes is a proto2 request with the shapes a pinned list can hide in
// beyond proto3 fields: a singular group holding a list, a list extension, and
// a list of doubles.
var pinShapes = func() (protoreflect.MessageDescriptor, protoreflect.ExtensionType) {
	opt := descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum()
	rep := descriptorpb.FieldDescriptorProto_LABEL_REPEATED.Enum()
	str := descriptorpb.FieldDescriptorProto_TYPE_STRING.Enum()
	dbl := descriptorpb.FieldDescriptorProto_TYPE_DOUBLE.Enum()
	group := descriptorpb.FieldDescriptorProto_TYPE_GROUP.Enum()
	file := &descriptorpb.FileDescriptorProto{
		Name:    proto.String("solution_runtime_test/pin_shapes.proto"),
		Package: proto.String("pinshapes.v1"),
		Syntax:  proto.String("proto2"),
		MessageType: []*descriptorpb.DescriptorProto{{
			Name: proto.String("Outer"),
			Field: []*descriptorpb.FieldDescriptorProto{
				{Name: proto.String("inner"), Number: proto.Int32(1), Label: opt, Type: group, TypeName: proto.String(".pinshapes.v1.Outer.Inner")},
				{Name: proto.String("scores"), Number: proto.Int32(3), Label: rep, Type: dbl},
			},
			NestedType: []*descriptorpb.DescriptorProto{{
				Name:  proto.String("Inner"),
				Field: []*descriptorpb.FieldDescriptorProto{{Name: proto.String("ids"), Number: proto.Int32(2), Label: rep, Type: str}},
			}},
			ExtensionRange: []*descriptorpb.DescriptorProto_ExtensionRange{{Start: proto.Int32(100), End: proto.Int32(200)}},
		}},
		Extension: []*descriptorpb.FieldDescriptorProto{
			{Name: proto.String("ext_ids"), Number: proto.Int32(100), Label: rep, Type: str, Extendee: proto.String(".pinshapes.v1.Outer")},
		},
	}
	fd, err := protodesc.NewFile(file, protoregistry.GlobalFiles)
	if err != nil {
		panic(err)
	}
	return fd.Messages().ByName("Outer"), dynamicpb.NewExtensionType(fd.Extensions().ByName("ext_ids"))
}

func strings2(l protoreflect.List) []string {
	var out []string
	for i := 0; i < l.Len(); i++ {
		out = append(out, l.Get(i).String())
	}
	return out
}

// A pinned list inside a group, or on an extension, is a ceiling exactly as a
// field's is; equal NaNs are one value.
func TestAPinnedListConfinesGroupsExtensionsAndNaNs(t *testing.T) {
	outer, ext := pinShapes()
	inner := outer.Fields().ByName("inner")
	ids := inner.Message().Fields().ByName("ids")
	scores := outer.Fields().ByName("scores")
	newPin := func() *dynamicpb.Message {
		pin := dynamicpb.NewMessage(outer)
		pin.Mutable(inner).Message().Mutable(ids).List().Append(protoreflect.ValueOfString("allowed"))
		pin.Mutable(ext.TypeDescriptor()).List().Append(protoreflect.ValueOfString("allowed"))
		pin.Mutable(scores).List().Append(protoreflect.ValueOfFloat64(math.NaN()))
		return pin
	}
	route := passthroughRoute{method: ConsumedMethod{Pin: newPin()}}

	// Naming none takes the pin's; naming them, including NaN, is relayed.
	for name, request := range map[string]*dynamicpb.Message{
		"none named": dynamicpb.NewMessage(outer),
		"the pin's own": func() *dynamicpb.Message {
			m := newPin()
			return m
		}(),
	} {
		if err := applyPin(route, request); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := strings2(request.Get(inner).Message().Get(ids).List()); strings.Join(got, ",") != "allowed" {
			t.Errorf("%s: group ids %v, want [allowed]", name, got)
		}
		if got := strings2(request.Get(ext.TypeDescriptor()).List()); strings.Join(got, ",") != "allowed" {
			t.Errorf("%s: extension ids %v, want [allowed]", name, got)
		}
		if l := request.Get(scores).List(); l.Len() != 1 || !math.IsNaN(l.Get(0).Float()) {
			t.Errorf("%s: scores %v, want [NaN]", name, l)
		}
	}
	// Naming outside it, in a group or an extension, is refused by the field.
	for name, set := range map[string]func(*dynamicpb.Message){
		"a group value outside the pin": func(m *dynamicpb.Message) {
			m.Mutable(inner).Message().Mutable(ids).List().Append(protoreflect.ValueOfString("outside"))
		},
		"an extension value outside the pin": func(m *dynamicpb.Message) {
			m.Mutable(ext.TypeDescriptor()).List().Append(protoreflect.ValueOfString("outside"))
		},
	} {
		request := dynamicpb.NewMessage(outer)
		set(request)
		err := applyPin(route, request)
		if connect.CodeOf(err) != connect.CodePermissionDenied || !strings.Contains(err.Error(), "pinshapes.v1.") || strings.Contains(err.Error(), "outside") || strings.Contains(err.Error(), "allowed") {
			t.Errorf("%s: %v; want permission_denied naming the field and no value", name, err)
		}
	}
	// The declared pin is never changed by applying it.
	if got := strings2(route.method.Pin.ProtoReflect().Get(ext.TypeDescriptor()).List()); strings.Join(got, ",") != "allowed" {
		t.Errorf("the pin itself moved: %v", got)
	}
}

// A pin of several fields is described with the same bytes from every binary:
// protojson's single-line form adds a space after a comma at random per
// binary, which made a committed interface artifact drift between builds.
func TestAPinOfSeveralFieldsIsDescribedStably(t *testing.T) {
	pin := thingMessage("GetThingRequest")
	setField(pin, "tenant", protoreflect.ValueOfString("t, with a comma"))
	setField(pin, "page_size", protoreflect.ValueOfInt32(3))
	pin.Mutable(pin.Descriptor().Fields().ByName("ids")).List().Append(protoreflect.ValueOfString("a"))
	pin.Mutable(pin.Descriptor().Fields().ByName("ids")).List().Append(protoreflect.ValueOfString("b"))
	if got, want := pinText(pin), `{"tenant":"t, with a comma","pageSize":3,"ids":["a","b"]}`; got != want {
		t.Fatalf("the pin is described as %s, want %s", got, want)
	}
}
