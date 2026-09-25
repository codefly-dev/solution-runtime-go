package solution

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"unicode"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// --- Documented operations ---
//
// A solution's backend surface is its routes. Declaring each route as an
// Operation — the path, the handler, and the documentation a reader needs —
// makes one list the source of both what is served and what is published:
// Operations registers exactly these handlers, and InterfaceDocument renders
// exactly these into the interface artifact a solution commits and CI
// re-generates. A route cannot be served undocumented, and an operation cannot
// be documented without being served.

// Operation is one public route of a solution backend.
//
// Summary, Callers and Behavior are all required: InterfaceDocument refuses an
// operation missing any of them, which keeps an undocumented route out of the
// artifact. Errors are not declared per operation, because the runtime gives
// every operation the same failures.
type Operation struct {
	// Path is the gateway-relative route, e.g. "/sources".
	Path string
	// Method is the documented HTTP method, lowercase; empty means "get".
	Method string
	// Summary is the one-sentence functional statement of what the operation
	// does, written for a reader who will never see the code: no leading
	// article, no trailing period.
	Summary string
	// Callers states who may call the operation.
	Callers string
	// Behavior states what the caller gets back, and the pagination or limits
	// that shape it.
	Behavior string
	// Query lists the documented query parameters.
	Query []QueryParameter
	// Request is the zero value of the JSON body the operation reads, if any.
	Request any
	// Response is the zero value of the body the operation returns on 200;
	// the artifact's schema is derived from its type. A generated protobuf
	// message is carried as Message[T] and described from its descriptor.
	Response any
	// Exactly one of Handler and RequestHandler answers the route.
	Handler        Handler
	RequestHandler RequestHandler
}

// QueryParameter is one documented query parameter of an Operation.
type QueryParameter struct {
	Name     string
	Required bool
}

// Operations registers each operation's handler at its path.
func (s *Server) Operations(ops ...Operation) *Server {
	for _, op := range ops {
		if op.RequestHandler != nil {
			s.HandleRequest(op.Path, op.RequestHandler)
		} else {
			s.Handle(op.Path, op.Handler)
		}
	}
	return s
}

// InterfaceInfo is the document-level description of a solution's interface
// artifact.
type InterfaceInfo struct {
	// Title and Description head the document; Version is the service version
	// the artifact describes.
	Title       string
	Version     string
	Description string
	// BasePath is where the host gateway publishes the routes, e.g.
	// "/solutions/<id>": the backend serves them at its own root, but a caller
	// only ever reaches them prefixed.
	BasePath string
	// OperationPrefix starts every operationId ("Wiki" renders "/sources" as
	// "Wiki_Sources"); Tag is the one tag every operation carries.
	OperationPrefix string
	Tag             string
}

// InterfaceDocument renders ops as a Swagger 2.0 document — the dialect the
// platform's proto-generated modules emit, so one reader handles every
// repository's artifact — indented, with a trailing newline.
func InterfaceDocument(info InterfaceInfo, ops []Operation) ([]byte, error) {
	doc, err := swaggerDocument(info, ops)
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func swaggerDocument(info InterfaceInfo, ops []Operation) (map[string]any, error) {
	definitions := map[string]any{
		"Error": map[string]any{
			"type":       "object",
			"properties": map[string]any{"error": map[string]any{"type": "string"}},
		},
	}
	paths := map[string]any{}
	for _, op := range ops {
		if err := op.validate(); err != nil {
			return nil, err
		}
		method := op.Method
		if method == "" {
			method = "get"
		}
		endpoint := map[string]any{
			"operationId": operationID(info.OperationPrefix, op.Path),
			"summary":     op.Summary,
			"description": op.Callers + "\n\n" + op.Behavior,
			"tags":        []string{info.Tag},
			"responses":   operationResponses(op, definitions),
		}
		parameters := []any{}
		if op.Request != nil {
			parameters = append(parameters, map[string]any{"name": "body", "in": "body", "required": true, "schema": valueSchema(op.Request, definitions)})
		}
		for _, query := range op.Query {
			parameters = append(parameters, map[string]any{"name": query.Name, "in": "query", "required": query.Required, "type": "string"})
		}
		if len(parameters) > 0 {
			endpoint["parameters"] = parameters
		}
		paths[op.Path] = map[string]any{method: endpoint}
	}
	return map[string]any{
		"swagger": "2.0",
		"info": map[string]any{
			"title":       info.Title,
			"version":     info.Version,
			"description": info.Description,
		},
		"basePath": info.BasePath,
		"consumes": []string{"application/json"},
		"produces": []string{"application/json"},
		"securityDefinitions": map[string]any{
			"bearer": map[string]any{
				"type":        "apiKey",
				"name":        "Authorization",
				"in":          "header",
				"description": "The signed-in person's access token, forwarded by the host. Every operation requires it.",
			},
		},
		"security":    []any{map[string]any{"bearer": []string{}}},
		"paths":       paths,
		"definitions": definitions,
	}, nil
}

// operationResponses describes what one operation answers. The 200 schema is
// derived from the operation's response type; the failures are the runtime's,
// not the handler's: it rejects a request with no bearer, and turns an error a
// handler returns into a failure status.
func operationResponses(op Operation, definitions map[string]any) map[string]any {
	return map[string]any{
		"200": map[string]any{
			"description": "A successful response.",
			"schema":      valueSchema(op.Response, definitions),
		},
		"401": map[string]any{
			"description": "The request carried no bearer token.",
			"schema":      map[string]any{"$ref": "#/definitions/Error"},
		},
		"502": map[string]any{
			"description": "A call this operation makes through the host gateway failed.",
			"schema":      map[string]any{"$ref": "#/definitions/Error"},
		},
	}
}

// validate reports an operation that cannot be rendered because it is
// undocumented or unserved.
func (o Operation) validate() error {
	switch {
	case !strings.HasPrefix(o.Path, "/"):
		return fmt.Errorf("operation path %q must be gateway-relative", o.Path)
	case o.Summary == "":
		return fmt.Errorf("operation %s has no summary", o.Path)
	case o.Callers == "":
		return fmt.Errorf("operation %s does not say who may call it", o.Path)
	case o.Behavior == "":
		return fmt.Errorf("operation %s does not say what it returns, or its pagination and limits", o.Path)
	case o.Response == nil:
		return fmt.Errorf("operation %s declares no response body", o.Path)
	case o.Handler == nil && o.RequestHandler == nil:
		return fmt.Errorf("operation %s has no handler", o.Path)
	case o.Handler != nil && o.RequestHandler != nil:
		return fmt.Errorf("operation %s declares two handlers", o.Path)
	}
	return nil
}

// operationID renders "/sources" as "<prefix>_Sources"; a nested path
// contributes one segment per level rather than carrying a slash into an
// identifier.
func operationID(prefix, path string) string {
	id := prefix
	for _, segment := range strings.Split(strings.Trim(path, "/"), "/") {
		id += "_" + title(segment)
	}
	return id
}

// messageDescribed is a response value carrying a generated message
// (Message[T]); its schema comes from the descriptor, not the Go struct.
type messageDescribed interface {
	messageDescriptor() protoreflect.MessageDescriptor
}

var (
	messageDescribedType = reflect.TypeOf((*messageDescribed)(nil)).Elem()
	rawMessageType       = reflect.TypeOf(json.RawMessage{})
)

// valueSchema describes a declared request or response value: a message known
// only by its descriptor (a passthrough operation's) from that descriptor, and
// anything else from its type.
func valueSchema(v any, definitions map[string]any) map[string]any {
	if described, ok := v.(describedMessage); ok {
		return messageSchema(described.md, definitions)
	}
	return schemaFor(reflect.TypeOf(v), definitions)
}

// schemaFor derives a JSON schema from a response type, registering a
// definition for every struct it reaches so a self-referencing shape
// terminates in a $ref instead of recursing forever.
func schemaFor(t reflect.Type, definitions map[string]any) map[string]any {
	if t == rawMessageType {
		return map[string]any{"type": "object"}
	}
	// A pointer is described by what it points to. It is unwrapped first:
	// *Message[T] also has Message[T]'s methods, and its zero value is a nil
	// pointer no method can be called on.
	if t.Kind() == reflect.Pointer {
		return schemaFor(t.Elem(), definitions)
	}
	if t.Implements(messageDescribedType) {
		return messageSchema(reflect.Zero(t).Interface().(messageDescribed).messageDescriptor(), definitions)
	}
	switch t.Kind() {
	case reflect.Struct:
		name := title(t.Name())
		// An unnamed struct has no definition to be referenced by: keyed on ""
		// it would register a definition nothing can address and emit a $ref
		// that resolves to nothing. Naming the type is the fix.
		if name == "" {
			panic(fmt.Sprintf("no definition name for the anonymous struct %s; give the field a named type", t))
		}
		if _, seen := definitions[name]; !seen {
			definitions[name] = map[string]any{}
			definitions[name] = structSchema(t, definitions)
		}
		return map[string]any{"$ref": "#/definitions/" + name}
	case reflect.Slice, reflect.Array:
		return map[string]any{"type": "array", "items": schemaFor(t.Elem(), definitions)}
	case reflect.Map:
		return map[string]any{"type": "object", "additionalProperties": schemaFor(t.Elem(), definitions)}
	case reflect.Interface:
		// The empty interface is a value of any JSON shape, which an empty
		// schema describes exactly. An interface with methods describes a Go
		// contract, not a JSON one.
		if t.NumMethod() > 0 {
			panic(fmt.Sprintf("no schema for the interface %s; a response field must be a JSON shape", t))
		}
		return map[string]any{}
	case reflect.String:
		return map[string]any{"type": "string"}
	case reflect.Bool:
		return map[string]any{"type": "boolean"}
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return map[string]any{"type": "integer"}
	case reflect.Float32, reflect.Float64:
		return map[string]any{"type": "number"}
	}
	// Generation-time only: a response field of a kind with no JSON schema is
	// a mistake to fix, not a case to degrade for.
	panic(fmt.Sprintf("no schema for %s (kind %s)", t, t.Kind()))
}

func structSchema(t reflect.Type, definitions map[string]any) map[string]any {
	properties := map[string]any{}
	for i := range t.NumField() {
		field := t.Field(i)
		if !field.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		properties[name] = schemaFor(field.Type, definitions)
	}
	return map[string]any{"type": "object", "properties": properties}
}

// messageSchema describes a generated message as its protobuf JSON: lowerCamel
// field names, 64-bit integers as strings, enums by name, and the well-known
// types in their JSON form. Each message is one definition named after its
// full name.
func messageSchema(md protoreflect.MessageDescriptor, definitions map[string]any) map[string]any {
	if wkt, ok := wellKnownSchema(md); ok {
		return wkt
	}
	name := definitionName(md.FullName())
	if _, seen := definitions[name]; !seen {
		definitions[name] = map[string]any{}
		properties := map[string]any{}
		fields := md.Fields()
		for i := range fields.Len() {
			fd := fields.Get(i)
			properties[fd.JSONName()] = fieldSchema(fd, definitions)
		}
		definitions[name] = map[string]any{"type": "object", "properties": properties}
	}
	return map[string]any{"$ref": "#/definitions/" + name}
}

func fieldSchema(fd protoreflect.FieldDescriptor, definitions map[string]any) map[string]any {
	if fd.IsMap() {
		return map[string]any{"type": "object", "additionalProperties": singularSchema(fd.MapValue(), definitions)}
	}
	if fd.IsList() {
		return map[string]any{"type": "array", "items": singularSchema(fd, definitions)}
	}
	return singularSchema(fd, definitions)
}

func singularSchema(fd protoreflect.FieldDescriptor, definitions map[string]any) map[string]any {
	switch fd.Kind() {
	case protoreflect.StringKind:
		return map[string]any{"type": "string"}
	case protoreflect.BytesKind:
		return map[string]any{"type": "string", "format": "byte"}
	case protoreflect.BoolKind:
		return map[string]any{"type": "boolean"}
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		return map[string]any{"type": "integer", "format": "int32"}
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		return map[string]any{"type": "integer", "format": "int64"}
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		return map[string]any{"type": "string", "format": "int64"}
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		return map[string]any{"type": "string", "format": "uint64"}
	case protoreflect.FloatKind:
		return map[string]any{"type": "number", "format": "float"}
	case protoreflect.DoubleKind:
		return map[string]any{"type": "number", "format": "double"}
	case protoreflect.EnumKind:
		values := fd.Enum().Values()
		names := make([]string, 0, values.Len())
		for i := range values.Len() {
			names = append(names, string(values.Get(i).Name()))
		}
		return map[string]any{"type": "string", "enum": names}
	case protoreflect.MessageKind, protoreflect.GroupKind:
		return messageSchema(fd.Message(), definitions)
	}
	panic(fmt.Sprintf("no schema for field %s of kind %s", fd.FullName(), fd.Kind()))
}

func wellKnownSchema(md protoreflect.MessageDescriptor) (map[string]any, bool) {
	switch md.FullName() {
	case "google.protobuf.Timestamp":
		return map[string]any{"type": "string", "format": "date-time"}, true
	case "google.protobuf.Duration", "google.protobuf.FieldMask":
		return map[string]any{"type": "string"}, true
	case "google.protobuf.Struct":
		return map[string]any{"type": "object"}, true
	case "google.protobuf.Value", "google.protobuf.Any":
		return map[string]any{}, true
	case "google.protobuf.ListValue":
		return map[string]any{"type": "array", "items": map[string]any{}}, true
	case "google.protobuf.Empty":
		return map[string]any{"type": "object"}, true
	}
	return nil, false
}

// definitionName renders "documents.v1.Document" as "DocumentsV1Document".
func definitionName(name protoreflect.FullName) string {
	var out strings.Builder
	for _, part := range strings.Split(string(name), ".") {
		out.WriteString(title(part))
	}
	return out.String()
}

func title(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}
