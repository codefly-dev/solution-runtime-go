package solution

import (
	"crypto/sha256"
	"encoding"
	"encoding/json"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"
	"unicode"
)

// RequiredFields wraps an Operation.Request to declare top-level JSON keys
// that must be present. It describes key presence only: it neither validates
// requests nor requires non-null, nonzero or nonblank values. The handler
// retains those rules. Names are exact JSON property names, in output order.
//
// With no names the request schema is unchanged. Otherwise request must be a named
// ordinary struct or a non-nil pointer to one, with direct, uniquely named JSON
// fields. Reachable types may be named structs, strings, booleans, signed
// integers, floats, pointers, arrays, non-byte slices and string-keyed maps.
// Embedding, custom JSON/text codecs, protobuf Messages, byte slices, interfaces
// and ambiguous definition names are unsupported anywhere in that graph.
// Schemas retain the generator's non-null input subset, even for pointers and
// collections; a handler may accept more. Invalid declarations fail generation
// and boot.
//
// The requirement applies only to this operation's root request object. Other
// uses of the type, including nested recursive occurrences and responses, keep
// their original schemas. RequiredFields is not a response declaration.
func RequiredFields(request any, names ...string) RequiredRequest {
	return RequiredRequest{request: request, names: slices.Clone(names)}
}

// RequiredRequest is the request declaration returned by RequiredFields. Its
// zero value declares no request body. Use it only as Operation.Request.
type RequiredRequest struct {
	request any
	names   []string
}

func requestValue(request any) any {
	if d, ok := request.(RequiredRequest); ok {
		return d.request
	}
	return request
}

// A dot/hyphen namespace cannot be a Go identifier or the generator's flattened
// protobuf definition name. Hashing the served method/path avoids JSON Pointer
// escaping and keeps identity stable regardless of operation order.
func requiredRequestDefinition(op Operation) string {
	return fmt.Sprintf("codefly.required-request.%x", sha256.Sum256([]byte(op.verb()+" "+servedRoute(op.Path))))
}

func requestSchema(request any, definitions map[string]any, namespace string) (map[string]any, error) {
	declaration, wrapped := request.(RequiredRequest)
	if !wrapped {
		return valueSchema(request, definitions), nil
	}
	if len(declaration.names) == 0 {
		return valueSchema(declaration.request, definitions), nil
	}
	if err := declaration.validateShape(); err != nil {
		return nil, err
	}
	local := map[string]any{}
	schema := valueSchema(declaration.request, local)
	root, ok := local[strings.TrimPrefix(schema["$ref"].(string), "#/definitions/")].(map[string]any)
	if !ok || root["type"] != "object" || root["additionalProperties"] != false {
		return nil, fmt.Errorf("RequiredFields needs a fixed request object")
	}
	properties := root["properties"].(map[string]any)
	seen := map[string]bool{}
	for _, name := range declaration.names {
		switch {
		case strings.TrimSpace(name) == "":
			return nil, fmt.Errorf("RequiredFields property %q is blank", name)
		case seen[name]:
			return nil, fmt.Errorf("RequiredFields property %q is duplicated", name)
		case properties[name] == nil:
			return nil, fmt.Errorf("RequiredFields property %q is not emitted by the request", name)
		}
		seen[name] = true
	}
	// Each request graph is generated independently: the legacy generator keys
	// by short type name, which may already mean a different type in the
	// shared document (including its built-in Error). Relocate every local
	// reference, keeping the optional recursive root distinct from this root.
	for name, definition := range local {
		definitions[namespace+"."+name] = relocateRequestSchema(definition.(map[string]any), namespace)
	}
	detached := relocateRequestSchema(root, namespace)
	detached["required"] = slices.Clone(declaration.names)
	return detached, nil
}

func (d RequiredRequest) validateShape() error {
	t := reflect.TypeOf(d.request)
	if t == nil {
		return fmt.Errorf("RequiredFields needs a named struct request, not nil")
	}
	if t.Kind() == reflect.Pointer {
		if reflect.ValueOf(d.request).IsNil() {
			return fmt.Errorf("RequiredFields needs a non-nil request pointer")
		}
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct || t.Name() == "" || t == reflect.TypeFor[RequiredRequest]() || t.Implements(messageDescribedType) {
		return fmt.Errorf("RequiredFields needs a named ordinary struct request, got %s", t)
	}
	return validateRequestType(t, "request", map[reflect.Type]bool{}, map[string]reflect.Type{})
}

// This checks the subset already represented faithfully by schemaFor; it does
// not derive a second schema or infer business validation from Go zero values.
func validateRequestType(t reflect.Type, path string, seen map[reflect.Type]bool, definitions map[string]reflect.Type) error {
	if seen[t] {
		return nil
	}
	seen[t] = true
	for _, codec := range []reflect.Type{reflect.TypeFor[json.Unmarshaler](), reflect.TypeFor[json.Marshaler](), reflect.TypeFor[encoding.TextUnmarshaler](), reflect.TypeFor[encoding.TextMarshaler]()} {
		if t.Implements(codec) || reflect.PointerTo(t).Implements(codec) {
			return fmt.Errorf("RequiredFields %s (%s) has a custom JSON/text codec", path, t)
		}
	}
	if t.Implements(messageDescribedType) || t == reflect.TypeFor[RequiredRequest]() {
		return fmt.Errorf("RequiredFields %s has unsupported type %s", path, t)
	}
	switch t.Kind() {
	case reflect.Pointer:
		return validateRequestType(t.Elem(), path, seen, definitions)
	case reflect.Slice, reflect.Array:
		if t.Kind() == reflect.Slice && t.Elem().Kind() == reflect.Uint8 {
			return fmt.Errorf("RequiredFields %s is a byte slice: base64 JSON is outside the supported request shapes", path)
		}
		return validateRequestType(t.Elem(), path+"[]", seen, definitions)
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			return fmt.Errorf("RequiredFields %s needs string map keys", path)
		}
		return validateRequestType(t.Elem(), path+"{}", seen, definitions)
	case reflect.String, reflect.Bool, reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64, reflect.Float32, reflect.Float64:
		return nil
	case reflect.Struct:
		if t.Name() == "" {
			return fmt.Errorf("RequiredFields %s needs a named struct", path)
		}
		name := title(t.Name())
		if previous, exists := definitions[name]; exists && previous != t {
			return fmt.Errorf("RequiredFields %s: types %s and %s collide at definition %q", path, previous, t, name)
		}
		definitions[name] = t
	default:
		return fmt.Errorf("RequiredFields %s has unsupported type %s", path, t)
	}
	names := map[string]bool{}
	for i := range t.NumField() {
		field := t.Field(i)
		tag := field.Tag.Get("json")
		if tag == "-" {
			continue
		}
		if field.Anonymous {
			return fmt.Errorf("RequiredFields %s field %s is embedded", path, field.Name)
		}
		if !field.IsExported() {
			continue
		}
		name, options, _ := strings.Cut(tag, ",")
		// encoding/json accepts letters, numbers and the punctuation below in
		// tag names (encode.go, isValidTag). The old generator does not model
		// invalid names or the string option; refuse those only on this path.
		for _, r := range name {
			if !unicode.IsLetter(r) && !unicode.IsDigit(r) && !strings.ContainsRune("!#$%&()*+-./:;<=>?@[]^_{|}~ ", r) {
				return fmt.Errorf("RequiredFields %s field %s has invalid JSON name %q", path, field.Name, name)
			}
		}
		if name == "-" || slices.Contains(strings.Split(options, ","), "string") {
			return fmt.Errorf("RequiredFields %s field %s has unsupported JSON tag %q", path, field.Name, tag)
		}
		if name == "" {
			name = field.Name
		}
		if names[name] {
			return fmt.Errorf("RequiredFields %s has colliding JSON property %q", path, name)
		}
		names[name] = true
		if err := validateRequestType(field.Type, path+"."+name, seen, definitions); err != nil {
			return err
		}
	}
	return nil
}

// Generated schemas contain maps and scalar/required values, never live types.
// Clone maps while moving refs; no shared response or unwrapped schema changes.
func relocateRequestSchema(schema map[string]any, namespace string) map[string]any {
	out := maps.Clone(schema)
	for key, value := range out {
		if ref, ok := value.(string); key == "$ref" && ok {
			out[key] = "#/definitions/" + namespace + "." + strings.TrimPrefix(ref, "#/definitions/")
		} else if nested, ok := value.(map[string]any); ok {
			out[key] = relocateRequestSchema(nested, namespace)
		}
	}
	return out
}
