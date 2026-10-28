package solution

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"unicode"

	corerunnable "github.com/codefly-dev/core/runnable"
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
//
// Each operation also declares what a call to it must hold (Policy). Under
// the authority interface the runtime asks the authority's Check, for every
// request, about the operation it was dispatched to, "<VERB> <template>" as
// served (servedRoute), and the authority holds it to the row the CLI derives
// from this artifact: the operation's x-codefly-authority-policy at its path. An operation that declares none is refused at generation, by
// name, so no served route reaches the artifact with nothing to be held to.

// Operation is one public route of a solution backend.
//
// Summary, Callers and Behavior are all required: InterfaceDocument refuses an
// operation missing any of them, which keeps an undocumented route out of the
// artifact; Policy is required the same way. Errors are not declared per
// operation, because the runtime gives every operation the same failures.
type Operation struct {
	// Path is the route as this backend serves it, e.g. "/sources", or under
	// the authority "/v1/<id>/sources". A pattern ending in "/" serves its
	// whole subtree, and the artifact says so ("/x/{path=**}").
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
	// Streaming marks an operation answered as a stream of Response messages
	// (a Connect server-streaming procedure) rather than one of them.
	Streaming bool
	// Policy is what a call to the route must hold, as the authority applies
	// it: required on every operation the backend serves.
	Policy *Policy
	// Exclude keeps the route from every agent, as
	// codefly.runnable.v0.exclude keeps a module's method: the artifact marks
	// it as no Runnable operation even when its policy is a read. The MCP
	// route and every relayed route carry it, being a protocol and another
	// module's call rather than this backend's own operation.
	Exclude bool
	// Tool is the name this operation is offered to a model under, when it is
	// marked as a Runnable operation at all. It is the one part of the marker
	// the owner says rather than core derives, because it is the one part a
	// model reads: snake_case, 1..64 characters, starting with a letter.
	//
	// Left empty the name falls back to the operationId, which is this
	// document's own identity for the route and a fine key but a poor word to
	// put in front of a model — `Wiki_Get_V1_Wiki_Upload-configuration` says
	// where the route is, not what calling it does. The operationId is not
	// changed to improve it: generated clients are named from it, so moving it
	// would rename every caller's method to make one tool read better.
	Tool string
	// Exactly one of Handler and RequestHandler answers the route.
	Handler        Handler
	RequestHandler RequestHandler
}

// Policy is what a call to an operation must hold: the authority's
// authority.hop.v1.Policy, the declaration a module marks each of its methods
// with, here for a route. Exactly one of its fields is set: an operation that
// requires nothing says so with AnyCheckedCaller, because an absent
// declaration and "nothing is required" must not look the same. Its JSON is
// the extension's value.
type Policy struct {
	// Requires lists what the call must hold, every entry: each action on its
	// resource kind, in the call's effective authority.
	Requires []Requirement `json:"requires,omitempty"`
	// AnyCheckedCaller lets through any call whose Work Context the authority
	// checked, holding nothing in particular.
	AnyCheckedCaller bool `json:"any_checked_caller,omitempty"`
}

// Requirement is actions on one resource kind, in the kind's own vocabulary as
// the solution's contract declares it (scope_ceilings).
type Requirement struct {
	ResourceKind string   `json:"resource_kind"`
	Actions      []string `json:"actions"`
}

// Requires is the policy that a call holds actions on kind.
func Requires(kind string, actions ...string) *Policy {
	return &Policy{Requires: []Requirement{{ResourceKind: kind, Actions: actions}}}
}

// AnyCheckedCaller is the policy that admits any call the authority checked.
func AnyCheckedCaller() *Policy { return &Policy{AnyCheckedCaller: true} }

// PolicyExtension is the operation extension the policy is written under, the
// one the CLI reads route policies from.
const PolicyExtension = "x-codefly-authority-policy"

// OperationExtension marks an operation as a Runnable one, and so a tool:
// core's x-codefly-operation, whose value is the proto3 JSON of
// codefly.runnable.v0.Operation. `codefly generate runnables` derives a
// Runnable package from every operation carrying it, as it does from every
// method a module serves behind the hop.
const OperationExtension = corerunnable.OpenAPIOperationMarker

// operationMarker is the x-codefly-operation an operation publishes beside its
// policy, or nil when it is no Runnable operation. It is core's own default
// for the route, written by core from the policy this operation already
// publishes (corerunnable.RouteMarker), so the runtime invents no bound: the
// tool is named by the operationId and described by the Summary the operation
// is required to carry, and audience is the principal this runtime's hop
// checks a Work Context against.
//
// Only a read is marked. A mutation is resolved by its effect receipt, read
// through a receipt route this runtime does not serve, so marking one would
// publish a tool whose uncertain outcome nothing could resolve; it stays a
// route its own page calls. A policy any checked caller satisfies requires
// nothing to mint a call's capability from, a stream is not one finite call,
// and a relayed subtree is a path template — core derives none of them. An
// operation the owner excludes is never marked. A marked read whose payload
// core cannot carry is refused by `codefly generate runnables`, naming the
// route and why, rather than silently left unmarked here: the owner either
// fixes the shape or excludes the route.
func operationMarker(op Operation, method, route, id, audience string) (json.RawMessage, error) {
	if audience == "" || op.Exclude || op.Streaming || !op.Policy.readOnly() {
		return nil, nil
	}
	policy, err := json.Marshal(op.Policy)
	if err != nil {
		return nil, err
	}
	marker, err := corerunnable.RouteMarker(method, route, policy, audience, id, op.Summary)
	if errors.Is(err, corerunnable.ErrNotDerivable) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("operation %s %s: %w", strings.ToUpper(method), route, err)
	}
	return marker, nil
}

// readOnly reports a policy whose every requirement is the one read action, as
// core reads one (corerunnable.Authority.ReadOnly): a call holding nothing but
// read cannot change what it reads.
func (p *Policy) readOnly() bool {
	if p == nil || p.AnyCheckedCaller || len(p.Requires) == 0 {
		return false
	}
	for _, r := range p.Requires {
		if len(r.Actions) != 1 || r.Actions[0] != corerunnable.ReadOnlyScopeAction {
			return false
		}
	}
	return true
}

// validate reports a policy that is absent, both things at once, or names a
// kind without an action. The vocabulary itself is the authority's to check.
func (p *Policy) validate() error {
	switch {
	case p == nil:
		return errors.New("declares no authority policy: every route this backend serves says what a call must hold, or that any checked caller may make it (AnyCheckedCaller)")
	case p.AnyCheckedCaller && len(p.Requires) > 0:
		return errors.New("declares both requirements and any checked caller")
	case !p.AnyCheckedCaller && len(p.Requires) == 0:
		return errors.New("declares an empty authority policy: name what a call must hold, or AnyCheckedCaller")
	}
	for _, r := range p.Requires {
		if r.ResourceKind == "" || len(r.Actions) == 0 {
			return fmt.Errorf("requires %q with actions %v: a requirement names a resource kind and at least one action", r.ResourceKind, r.Actions)
		}
		for _, action := range r.Actions {
			if action == "" {
				return fmt.Errorf("requires an empty action on %s", r.ResourceKind)
			}
		}
	}
	return nil
}

// QueryParameter is one documented query parameter of an Operation.
type QueryParameter struct {
	Name     string
	Required bool
}

// Operations declares the routes this backend serves itself. Chainable. Each
// is served for its own method only: a request is answered by the operation
// declared for its method on its path, which is the operation the authority's
// Check is asked about ("<VERB> <template>"), and a method the path does not
// declare is refused by name before the authority is asked or any handler
// runs. The boot refuses an operation that is undocumented, declares no
// policy, names a method twice on one path, or takes the MCP route.
func (s *Server) Operations(ops ...Operation) *Server {
	s.operations = append(s.operations, ops...)
	return s
}

// servedMethods are the methods an operation may declare. OPTIONS is the CORS
// preflight the runtime answers on every declared path, never an operation.
var servedMethods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete}

// verb is the operation's method as a request spells it.
func (o Operation) verb() string { return strings.ToUpper(cmp.Or(o.Method, "get")) }

// requestHandler is whichever of the operation's two handler shapes it set.
func (o Operation) requestHandler() RequestHandler {
	if o.RequestHandler != nil {
		return o.RequestHandler
	}
	handler := o.Handler
	return func(r *http.Request, gw *Gateway) (any, error) { return handler(r.Context(), gw) }
}

// operationTable is the declared operations by path and then by method, or the
// refusal of the first that cannot be served as declared.
func (s *Server) operationTable() (map[string]map[string]RequestHandler, error) {
	table := map[string]map[string]RequestHandler{}
	for _, op := range s.operations {
		if err := op.validate(); err != nil {
			return nil, err
		}
		if table[op.Path] == nil {
			table[op.Path] = map[string]RequestHandler{}
		}
		if _, taken := table[op.Path][op.verb()]; taken {
			return nil, fmt.Errorf("operation %s %s is declared twice: one request would have two handlers", op.verb(), op.Path)
		}
		table[op.Path][op.verb()] = op.requestHandler()
	}
	return table, nil
}

// mountOperations serves each declared path on mux, dispatching on the
// request's method to the operation declared for it, and asking the authority
// about that operation's own published row.
func (s *Server) mountOperations(mux *http.ServeMux) error {
	table, err := s.operationTable()
	if err != nil {
		return fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	for path, methods := range table {
		served := make(map[string]http.HandlerFunc, len(methods))
		for method, handler := range methods {
			served[method] = s.wrapRequest(method+" "+servedRoute(path), handler)
		}
		mux.HandleFunc(path, withCORS(byMethod(path, served)))
	}
	return nil
}

// byMethod answers a request with the handler declared for its method on
// path, or refuses a method path does not declare, by name, with the methods
// it does (405, and Allow).
func byMethod(path string, served map[string]http.HandlerFunc) http.HandlerFunc {
	methods := make([]string, 0, len(served))
	for method := range served {
		methods = append(methods, method)
	}
	slices.Sort(methods)
	allowed := strings.Join(methods, ", ")
	return func(w http.ResponseWriter, r *http.Request) {
		handler, ok := served[r.Method]
		if !ok {
			w.Header().Set("Allow", allowed)
			message := fmt.Sprintf("%s is not an operation of %s: it serves %s", r.Method, path, allowed)
			writeRefusal(w, r, http.StatusMethodNotAllowed, message, nil)
			return
		}
		handler(w, r)
	}
}

// InterfaceInfo is the document-level description of a solution's interface
// artifact.
type InterfaceInfo struct {
	// Title and Description head the document; Version is the service version
	// the artifact describes.
	Title       string
	Version     string
	Description string
	// There is no base path. The authority's edge forwards a solution's
	// requests on /v1/<id>, which its operations already carry, and the
	// runtime asks the authority about each route as served; a base path
	// prefixed every row the CLI derives and matched no request.
	// OperationPrefix starts every operationId ("Notes" renders GET "/sources"
	// as "Notes_Get_Sources"); Tag is the one tag every operation carries.
	OperationPrefix string
	Tag             string
}

// InterfaceDocument renders ops as a Swagger 2.0 document — the dialect the
// platform's proto-generated modules emit, so one reader handles every
// repository's artifact — indented, with a trailing newline. It marks no
// operation as a Runnable one: a marker names the audience the serving
// runtime's hop admits, which only the Server knows. A solution that commits
// this output therefore publishes no tool at all; the artifact a solution
// commits is Server.InterfaceArtifact's, and this is for documenting or
// validating a list of operations.
func InterfaceDocument(info InterfaceInfo, ops []Operation) ([]byte, error) {
	return interfaceDocument(info, ops, "")
}

// interfaceDocument is InterfaceDocument marking each Runnable operation for
// audience (operationMarker).
func interfaceDocument(info InterfaceInfo, ops []Operation, audience string) ([]byte, error) {
	doc, err := swaggerDocument(info, ops, audience)
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func swaggerDocument(info InterfaceInfo, ops []Operation, audience string) (map[string]any, error) {
	definitions := map[string]any{
		"Error": map[string]any{
			"type":                 "object",
			"properties":           map[string]any{"error": map[string]any{"type": "string"}},
			"additionalProperties": false,
		},
	}
	paths := map[string]map[string]any{}
	ids := map[string]string{}
	tools := map[string]string{}
	for _, op := range ops {
		if err := op.validate(); err != nil {
			return nil, err
		}
		method := strings.ToLower(op.Method)
		if method == "" {
			method = "get"
		}
		route := servedRoute(op.Path)
		if paths[route] == nil {
			paths[route] = map[string]any{}
		}
		if _, taken := paths[route][method]; taken {
			return nil, fmt.Errorf("operation %s %s is declared twice", strings.ToUpper(method), route)
		}
		id := operationID(info.OperationPrefix, method, route)
		if other, taken := ids[id]; taken {
			return nil, fmt.Errorf("operations %s and %s %s share the operationId %q", other, strings.ToUpper(method), route, id)
		}
		ids[id] = strings.ToUpper(method) + " " + route
		// A tool name is the identity a MODEL addresses, so it names exactly
		// one operation, as an operationId names exactly one route. Two reads
		// claiming one name publish two tools a model cannot tell apart, and
		// nothing downstream collapses them: a derived package is keyed by the
		// operationId, and Robin's catalogue dedupes on the operation, the
		// contract digest and the policy — never on the word.
		if op.Tool != "" {
			if other, taken := tools[op.Tool]; taken {
				return nil, fmt.Errorf("operations %s and %s %s both offer the tool %q", other, strings.ToUpper(method), route, op.Tool)
			}
			tools[op.Tool] = strings.ToUpper(method) + " " + route
		}
		endpoint := map[string]any{
			"operationId": id,
			"summary":     op.Summary,
			"description": op.Callers + "\n\n" + op.Behavior,
			"tags":        []string{info.Tag},
			"responses":   operationResponses(op, definitions),
		}
		if op.Streaming {
			// Swagger 2 has no stream: the 200 schema is one message of it.
			endpoint["x-streaming"] = "server"
		}
		if op.Policy != nil {
			endpoint[PolicyExtension] = op.Policy
		}
		marker, err := operationMarker(op, method, route, cmp.Or(op.Tool, id), audience)
		if err != nil {
			return nil, err
		}
		if marker != nil {
			endpoint[OperationExtension] = marker
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
		paths[route][method] = endpoint
	}
	doc := map[string]any{
		"swagger": "2.0",
		"info": map[string]any{
			"title":       info.Title,
			"version":     info.Version,
			"description": info.Description,
		},
		"consumes": []string{"application/json"},
		"produces": []string{"application/json"},
		"securityDefinitions": map[string]any{
			"workContext": map[string]any{
				"type":        "apiKey",
				"name":        WorkContextHeader,
				"in":          "header",
				"description": "The signed-in person's Work Context for this solution, sent by the authority's edge. Every operation requires it.",
			},
		},
		"security":    []any{map[string]any{"workContext": []string{}}},
		"paths":       paths,
		"definitions": definitions,
	}
	return doc, nil
}

// servedRoute spells an operation's path as the authority matches a request
// against it: a pattern ending in "/", which the backend's mux serves for its
// whole subtree, as that prefix and "{path=**}", the rest of the path; a
// "{name...}" wildcard as "{name=**}"; a "{$}" anchor as the "/" it anchors.
func servedRoute(path string) string {
	switch {
	case strings.HasSuffix(path, "/{$}"):
		return strings.TrimSuffix(path, "{$}")
	case strings.HasSuffix(path, "/"):
		return path + "{path=**}"
	case strings.HasSuffix(path, "...}"):
		return strings.TrimSuffix(path, "...}") + "=**}"
	}
	return path
}

// operationResponses describes what one operation answers. The 200 schema is
// derived from the operation's response type; the failures are the runtime's,
// not the handler's: it rejects a request whose Work Context the authority
// does not check, and turns an error a handler returns into a failure status.
func operationResponses(op Operation, definitions map[string]any) map[string]any {
	return map[string]any{
		"200": map[string]any{
			"description": "A successful response.",
			"schema":      valueSchema(op.Response, definitions),
		},
		"401": map[string]any{
			"description": "The request carried no Work Context the authority checks for this solution.",
			"schema":      map[string]any{"$ref": "#/definitions/Error"},
		},
		"502": map[string]any{
			"description": "A call this operation makes to a module failed.",
			"schema":      map[string]any{"$ref": "#/definitions/Error"},
		},
	}
}

// toolName is what a model-facing name may be: lowercase letters, digits and
// underscores, starting with a letter. It is core's admitted set narrowed to
// one spelling, so two owners' tools read the same way.
var toolName = regexp.MustCompile(`^[a-z][a-z0-9]*(_[a-z0-9]+)*$`)

// maxToolName is the longest name a model-facing tool carries, as core bounds
// one (corerunnable.BoundedName over its own maxToolName).
const maxToolName = 64

const toolNameSpelling = "lowercase letters and digits in underscore-separated words, starting with a letter"

// validate reports an operation that cannot be rendered because it is
// undocumented or unserved.
func (o Operation) validate() error {
	switch {
	case !strings.HasPrefix(o.Path, "/"):
		return fmt.Errorf("operation path %q must be an absolute path", o.Path)
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
	case !slices.Contains(servedMethods, o.verb()):
		return fmt.Errorf("operation %s declares the method %q: an operation is one of %s", o.Path, o.Method, strings.Join(servedMethods, ", "))
	case o.Tool != "" && (len(o.Tool) > maxToolName || !toolName.MatchString(o.Tool)):
		// Held here rather than sanitised: core's toolName keeps whatever it
		// is given, so a name typed with a capital or a hyphen would reach a
		// model as typed. An owner naming its own tool is told what a name is.
		return fmt.Errorf("operation %s names the tool %q: a tool name is 1..%d characters of %s", o.Path, o.Tool, maxToolName, toolNameSpelling)
	case o.Tool != "" && o.Exclude:
		return fmt.Errorf("operation %s names the tool %q and excludes itself from every agent: one of the two", o.Path, o.Tool)
	case o.Tool != "" && o.Streaming:
		return fmt.Errorf("operation %s names the tool %q and streams: a stream is not one finite call, so it is never offered as a tool", o.Path, o.Tool)
	case o.Tool != "" && !o.Policy.readOnly():
		// A name on something that can never be marked is a declaration that
		// does nothing, and it reads as the opposite: the owner believes they
		// exposed a tool. Only a read is marked, so only a read is named.
		return fmt.Errorf("operation %s names the tool %q, and only a read is offered as one: its policy requires more than %q, so the operation is resolved by its effect receipt and stays a route its own page calls", o.Path, o.Tool, corerunnable.ReadOnlyScopeAction)
	}
	if err := o.Policy.validate(); err != nil {
		return fmt.Errorf("operation %s %s %w", o.verb(), o.Path, err)
	}
	return nil
}

// operationID renders GET "/sources" as "<prefix>_Get_Sources" from the
// method and the route as served (servedRoute); a nested path contributes one
// segment per level rather than carrying a slash into an identifier, and a
// wildcard its name ("/x/{path=**}" ends "_X_Path"), so a path and the
// subtree under it are two ids. The method is part of it because two methods
// on one path are two operations, and an operationId names exactly one.
func operationID(prefix, method, route string) string {
	id := prefix + "_" + title(strings.ToLower(method))
	for _, segment := range strings.Split(strings.Trim(route, "/"), "/") {
		if name, ok := strings.CutPrefix(segment, "{"); ok {
			name, _, _ = strings.Cut(strings.TrimSuffix(name, "}"), "=")
			segment = name
		}
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
	// A struct marshals exactly its fields, so the object is closed: that is
	// what makes it a fixed shape a Runnable contract can describe.
	return map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
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
		// protojson refuses a field the message does not declare, so the
		// object is closed, as a struct's is.
		definitions[name] = map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
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
