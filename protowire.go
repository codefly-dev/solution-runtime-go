package solution

import (
	"encoding/json"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// --- Generated messages on a handler's wire ---
//
// A handler returns any JSON-serializable value and the runtime encodes it with
// encoding/json. A generated protobuf message is not one: encoding/json reads
// its Go struct tags (snake_case names, int64 as numbers, oneofs as Go
// interfaces), which is not the protobuf JSON a browser SDK parses. A handler
// that returns an owner's message therefore wraps it in Message, which encodes
// with protojson wherever the value sits in the response.

// Message carries a generated protobuf message inside a handler's response and
// encodes it as protobuf JSON (lowerCamel names, int64 as strings, enums by
// name, well-known types in their JSON form). A nil message encodes as null.
type Message[T proto.Message] struct {
	Value T
}

// MessageOf wraps m for a handler's response.
func MessageOf[T proto.Message](m T) Message[T] { return Message[T]{Value: m} }

// MarshalJSON encodes the message as protobuf JSON.
func (m Message[T]) MarshalJSON() ([]byte, error) {
	if any(m.Value) == nil || !m.Value.ProtoReflect().IsValid() {
		return []byte("null"), nil
	}
	return protojson.Marshal(m.Value)
}

// messageDescriptor lets the operation documentation describe the wrapped
// message from its descriptor rather than from its Go struct.
func (m Message[T]) messageDescriptor() protoreflect.MessageDescriptor {
	return m.Value.ProtoReflect().Descriptor()
}

var _ json.Marshaler = Message[proto.Message]{}

// FieldMask is a declared allowlist of the fields of one message type that a
// handler may pass on. Build it once, at package level, from the paths it
// allows; Apply then drops everything else. An owner adding a field to its
// message later does not widen what reaches the browser: a new field is
// outside every mask until someone names it.
//
// A path is a dotted chain of proto field names ("entry.entry_id"). Naming a
// message field allows the whole submessage; naming a path inside it allows
// only that part. Paths into a repeated message apply to every element.
type FieldMask struct {
	desc protoreflect.MessageDescriptor
	root *maskNode
}

type maskNode struct {
	all      bool
	children map[protoreflect.Name]*maskNode
}

// NewFieldMask declares an allowlist over the message type of example. Every
// path must name fields that exist; an unknown path is an error, so a mask
// cannot silently allow nothing after a rename.
func NewFieldMask(example proto.Message, paths ...string) (FieldMask, error) {
	desc := example.ProtoReflect().Descriptor()
	root := &maskNode{children: map[protoreflect.Name]*maskNode{}}
	for _, path := range paths {
		node, current := root, desc
		names := strings.Split(path, ".")
		for i, name := range names {
			fd := current.Fields().ByName(protoreflect.Name(name))
			if fd == nil {
				return FieldMask{}, fmt.Errorf("field mask over %s: %q has no field %q", desc.FullName(), path, name)
			}
			child := node.children[fd.Name()]
			if child == nil {
				child = &maskNode{children: map[protoreflect.Name]*maskNode{}}
				node.children[fd.Name()] = child
			}
			node = child
			if i == len(names)-1 {
				node.all = true
				break
			}
			if fd.Kind() != protoreflect.MessageKind || fd.IsMap() {
				return FieldMask{}, fmt.Errorf("field mask over %s: %q descends into %q, which is not a message", desc.FullName(), path, name)
			}
			current = fd.Message()
		}
	}
	return FieldMask{desc: desc, root: root}, nil
}

// MustFieldMask is NewFieldMask for package-level declarations: an invalid
// mask is a programming error found at start-up.
func MustFieldMask(example proto.Message, paths ...string) FieldMask {
	mask, err := NewFieldMask(example, paths...)
	if err != nil {
		panic(err)
	}
	return mask
}

// Apply returns a copy of m carrying only the allowed fields. m is not
// modified. It panics if m is not the type the mask was declared over.
func Apply[T proto.Message](mask FieldMask, m T) T {
	if any(m) == nil || !m.ProtoReflect().IsValid() {
		return m
	}
	if got := m.ProtoReflect().Descriptor().FullName(); got != mask.desc.FullName() {
		panic(fmt.Sprintf("field mask over %s applied to %s", mask.desc.FullName(), got))
	}
	out := proto.Clone(m).(T)
	prune(out.ProtoReflect(), mask.root)
	return out
}

func prune(msg protoreflect.Message, node *maskNode) {
	if node.all {
		return
	}
	// Clearing is deferred past Range: a message is not mutated while it is
	// being ranged over.
	var disallowed []protoreflect.FieldDescriptor
	msg.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		child := node.children[fd.Name()]
		switch {
		case child == nil:
			disallowed = append(disallowed, fd)
		case child.all:
		case fd.IsList():
			list := v.List()
			for i := 0; i < list.Len(); i++ {
				prune(list.Get(i).Message(), child)
			}
		default:
			prune(v.Message(), child)
		}
		return true
	})
	for _, fd := range disallowed {
		msg.Clear(fd)
	}
}
