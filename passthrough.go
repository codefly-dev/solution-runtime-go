package solution

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
	"gopkg.in/yaml.v3"
)

// --- Consumed-module passthrough ---
//
// A solution's page reaches only its own backend, through the authority's
// edge, and a module authenticates a call by a Work Context addressed to it.
// Without this, every module read a page makes needs a handler in the solution
// that decodes the page's request, has the viewer's Work Context issued, calls
// the module and re-encodes the answer — the same code in every solution, once
// per operation.
//
// Consumes declares, instead, which operations of which consumed module the
// page may call. The runtime serves each one as a Connect procedure at
//
//	/v1/<id>/modules/<as>/<package.Service>/<Method>
//
// the route the edge forwards this solution's requests on unchanged, so the
// module's own generated client (connect-es, connect-go) is used unmodified
// with the base URL `<apiBase>/modules/<as>`. Each call is relayed to the
// module's own procedure, the face it serves behind the authority's hop
// (passthrough_authority.go), as the viewer: a child of the edge's Work
// Context issued through this solution's binding for the module, carrying the
// method's declared scopes. A unary method is relayed as a unary call and a
// server-streaming one as a stream. The browser names a declared procedure and
// a request message; it never names an address, a binding or an authority.
// Authorization stays where it is: at the module.
//
// Least privilege is the default throughout. A method that is not declared is
// not served. A declared method returns only the response fields its mask
// names, unless the declaration explicitly passes the whole response.

// ConsumedModule declares the operations of one consumed module the solution's
// page may call through the passthrough.
type ConsumedModule struct {
	// As is the `as` of the module's api.consumes entry: the segment the page
	// calls it under (/modules/<As>) and the audience the published contract
	// names its ceiling for.
	As string
	// Scopes is the authority asked for the viewer on every call of a method
	// that declares none of its own, no more than those methods need. Set it,
	// or set Scopes on every one of the module's methods.
	Scopes []Scope
	// Methods is the allowlist. Nothing else of the module is reachable.
	Methods []ConsumedMethod
	// Authority names the configuration slots that say where the module is
	// and which of this solution's bindings the viewer's calls are issued
	// through (passthrough_authority.go). Every consumed module names them:
	// the hop is the only way a call reaches a module.
	Authority AuthorityRelay
}

// ConsumedMethod is one operation of a consumed module the page may call.
type ConsumedMethod struct {
	// Name is the RPC's full name as its generated code declares it, the
	// "/package.Service/Method" constant a gRPC or Connect stub exports. The
	// module's generated package must be linked into the solution.
	Name string
	// Scopes, when set, is the authority asked for the viewer on a call to
	// this method, instead of the module's Scopes — never in addition to them.
	// It is how one module's methods that need different authority are
	// declared under one `as`: each call asks only what its own method needs,
	// so a viewer who lacks one method's authority is refused that method
	// (permission_denied) and is still served every other.
	Scopes []Scope
	// Response is the allowlist of response fields returned to the page. A
	// field the module adds later is dropped until someone names it here.
	Response FieldMask
	// WholeResponse passes every response field, and must be said explicitly:
	// the zero value of a declaration returns nothing it did not name.
	WholeResponse bool
	// Pin, when set, is merged into every request the page sends before it is
	// relayed (proto.Merge): a scalar it sets replaces the page's value, a
	// message merges, and a repeated field is appended. It is how a solution
	// fixes part of a request server-side — a filter clause the module ANDs
	// with the page's own, say — so the page can narrow the call but not undo
	// the pin. It must be the method's request type.
	Pin proto.Message
	// MaxRequestBytes bounds the request message the page sends; zero is
	// DefaultPassthroughRequestLimit.
	MaxRequestBytes int
	// MaxResponseBytes bounds the module's answer; zero is
	// DefaultPassthroughResponseLimit.
	MaxResponseBytes int64
	// Timeout bounds one call, the issue of the viewer's Work Context
	// included; zero is DefaultPassthroughTimeout. For a server-streaming
	// method it bounds the issue alone; the stream itself is bounded by
	// MaxStreamDuration.
	Timeout time.Duration
	// MaxStreamDuration bounds how long one stream of a server-streaming
	// method stays open, from the call to its last message; zero is
	// DefaultStreamDuration, and no stream may be declared longer than
	// MaxStreamDurationLimit. A stream that reaches it ends with
	// deadline_exceeded. Only for a server-streaming method.
	MaxStreamDuration time.Duration
	// MaxStreamMessageBytes bounds each message of a server-streaming method's
	// stream, as the module sends it; zero is DefaultStreamMessageLimit. A
	// larger message ends the stream with resource_exhausted: it is never
	// truncated. Only for a server-streaming method.
	MaxStreamMessageBytes int64
}

const (
	// PassthroughPathPrefix is where the passthrough serves under the
	// solution's route: a declared method is at /v1/<id> +
	// PassthroughPathPrefix + <as> + "/" + <package.Service>/<Method>.
	PassthroughPathPrefix = "/modules/"
	// DefaultPassthroughRequestLimit bounds a request message unless the
	// method sets its own bound.
	DefaultPassthroughRequestLimit = 1 << 20
	// DefaultPassthroughResponseLimit bounds a module's unary answer unless the
	// method sets its own bound with MaxResponseBytes.
	DefaultPassthroughResponseLimit = 8 << 20
	// DefaultPassthroughTimeout bounds one call unless the method sets its own.
	DefaultPassthroughTimeout = 60 * time.Second
	// relayedMessageLimit bounds the module refusal text relayed to the page.
	relayedMessageLimit = 1024
)

// Consumes declares the consumed-module operations the page may call. It is
// chainable and may be called more than once; Serve refuses a declaration that
// cannot be served before it listens.
func (s *Server) Consumes(modules ...ConsumedModule) *Server {
	// Frozen at the declaration boundary, for the reason Contract() gives:
	// `append` copies the structs and leaves every slice inside them pointing
	// at the caller's arrays. These are the ASKED scopes — the other operand
	// of the ceiling comparison and what the published contract reports — so a
	// caller editing one after boot changes what this process claims to ask
	// for.
	for _, module := range modules {
		module.Scopes = frozenScopes(module.Scopes)
		methods := make([]ConsumedMethod, len(module.Methods))
		for i, method := range module.Methods {
			method.Scopes = frozenScopes(method.Scopes)
			methods[i] = method
		}
		if module.Methods != nil {
			module.Methods = methods
		}
		s.consumed = append(s.consumed, module)
	}
	return s
}

// passthroughRoute is one declared method, resolved against its descriptor.
type passthroughRoute struct {
	path   string
	module ConsumedModule
	method ConsumedMethod
	md     protoreflect.MethodDescriptor
}

// procedure is the module's own procedure the route relays to: the face the
// module serves behind the hop, which needs no binding of any other kind.
func (r passthroughRoute) procedure() string {
	return "/" + string(r.md.Parent().FullName()) + "/" + string(r.md.Name())
}

func (r passthroughRoute) timeout() time.Duration {
	if r.method.Timeout > 0 {
		return r.method.Timeout
	}
	return DefaultPassthroughTimeout
}

// answer is what of the module's answer reaches the page: the declared
// response fields, or all of them when the declaration says so.
func (r passthroughRoute) answer(out *dynamicpb.Message) *dynamicpb.Message {
	if r.method.WholeResponse {
		return out
	}
	return Apply(r.method.Response, out)
}

// resolvePassthrough checks every declaration against the generated
// descriptors and returns the routes, keyed on path. Every refusal is a
// mistake in the solution's declaration, found before anything is served.
func resolvePassthrough(modules []ConsumedModule) (map[string]passthroughRoute, error) {
	routes := map[string]passthroughRoute{}
	seen := map[string]bool{}
	for _, module := range modules {
		a := module.Authority
		switch {
		case module.As == "" || strings.ContainsAny(module.As, "/?#{}*:\\") || !cleanPrefix(PassthroughPathPrefix+module.As):
			return nil, fmt.Errorf("consumed module %q: as must be one path segment, the `as` of its api.consumes entry", module.As)
		case seen[module.As]:
			return nil, fmt.Errorf("consumed module %q is declared twice", module.As)
		case len(module.Methods) == 0:
			return nil, fmt.Errorf("consumed module %q declares no methods", module.As)
		case a.Group == "" || a.EndpointKey == "" || a.BindingKey == "":
			return nil, fmt.Errorf("consumed module %q: its authority relay names a group, an endpoint slot and a binding slot, all three; a call reaches a module only through the authority's hop, at the address and binding the composition names in them", module.As)
		}
		if err := checkScopes(module.Scopes); err != nil {
			return nil, fmt.Errorf("consumed module %q: %w", module.As, err)
		}
		seen[module.As] = true
		for _, method := range module.Methods {
			md, err := methodDescriptor(method.Name)
			if err != nil {
				return nil, fmt.Errorf("consumed module %q: %w", module.As, err)
			}
			if md.IsStreamingClient() {
				return nil, fmt.Errorf("consumed module %q: %s streams its requests; only unary and server-streaming methods pass through", module.As, md.FullName())
			}
			if err := checkStreamBounds(md, method); err != nil {
				return nil, fmt.Errorf("consumed module %q: %w", module.As, err)
			}
			switch {
			case method.WholeResponse && method.Response.desc != nil:
				return nil, fmt.Errorf("consumed module %q: %s declares both a response mask and the whole response", module.As, md.FullName())
			case !method.WholeResponse && method.Response.desc == nil:
				return nil, fmt.Errorf("consumed module %q: %s declares no response fields; name them in Response, or pass WholeResponse explicitly", module.As, md.FullName())
			case method.Response.desc != nil && method.Response.desc.FullName() != md.Output().FullName():
				return nil, fmt.Errorf("consumed module %q: %s answers %s, but its response mask is over %s", module.As, md.FullName(), md.Output().FullName(), method.Response.desc.FullName())
			case len(module.Scopes) == 0 && len(method.Scopes) == 0:
				return nil, fmt.Errorf("consumed module %q: %s declares no Scopes and the module declares none either; name the authority asked for the viewer", module.As, md.FullName())
			}
			if err := checkScopes(method.Scopes); err != nil {
				return nil, fmt.Errorf("consumed module %q: %s: %w", module.As, md.FullName(), err)
			}
			if method.Pin != nil && method.Pin.ProtoReflect().Descriptor().FullName() != md.Input().FullName() {
				return nil, fmt.Errorf("consumed module %q: %s reads %s, but its pin is a %s", module.As, md.FullName(), md.Input().FullName(), method.Pin.ProtoReflect().Descriptor().FullName())
			}
			path := PassthroughPathPrefix + module.As + "/" + string(md.Parent().FullName()) + "/" + string(md.Name())
			if _, dup := routes[path]; dup {
				return nil, fmt.Errorf("consumed module %q: %s is declared twice", module.As, md.FullName())
			}
			routes[path] = passthroughRoute{path: path, module: module, method: method, md: md}
		}
	}
	return routes, nil
}

// cleanPrefix reports whether prefix is an absolute path with no trailing
// slash, dot segment, query or fragment: the shape a passthrough segment has
// to have to be served under one route.
func cleanPrefix(prefix string) bool {
	if !strings.HasPrefix(prefix, "/") || strings.HasSuffix(prefix, "/") || strings.ContainsAny(prefix, "?#{}*:\\") {
		return false
	}
	for _, segment := range strings.Split(prefix[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

// methodDescriptor resolves "/package.Service/Method" (or the dotted
// "package.Service.Method") in the global registry, which is where a declared
// method's generated package must have been linked in.
func methodDescriptor(method string) (protoreflect.MethodDescriptor, error) {
	name := strings.TrimPrefix(method, "/")
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[:i] + "." + name[i+1:]
	}
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(protoreflect.FullName(name))
	if err != nil {
		return nil, fmt.Errorf("method %q is not in the protobuf registry (is its generated package linked in?): %w", method, err)
	}
	md, ok := d.(protoreflect.MethodDescriptor)
	if !ok {
		return nil, fmt.Errorf("%q names a %T, not a method", method, d)
	}
	return md, nil
}

// checkScopes refuses a scope that could not name an authority: one with no
// resource kind, no action, or a blank or duplicated action.
func checkScopes(scopes []Scope) error {
	for _, scope := range scopes {
		if strings.TrimSpace(scope.ResourceKind) == "" || scope.ResourceKind != strings.TrimSpace(scope.ResourceKind) {
			return fmt.Errorf("a scope names no resource kind (or pads it with spaces)")
		}
		if len(scope.Actions) == 0 {
			return fmt.Errorf("scope %q names no action", scope.ResourceKind)
		}
		seen := map[string]bool{}
		for _, action := range scope.Actions {
			if strings.TrimSpace(action) == "" || action != strings.TrimSpace(action) {
				return fmt.Errorf("scope %q names a blank action (or pads one with spaces)", scope.ResourceKind)
			}
			if seen[action] {
				return fmt.Errorf("scope %q names the action %q twice", scope.ResourceKind, action)
			}
			seen[action] = true
		}
	}
	return nil
}

// scopes is the authority a call to this route asks for the viewer: the
// method's own, else the module's. Never the union.
func (r passthroughRoute) scopes() []Scope {
	if len(r.method.Scopes) > 0 {
		return r.method.Scopes
	}
	return r.module.Scopes
}

// mountPassthrough mounts the declared routes on mux at the route the edge
// forwards this solution's requests on: the one place the passthrough is
// wired. Serve has already resolved the routes and opened the relays; a test
// that calls serve directly has resolved neither, and the routes are resolved
// here.
func (s *Server) mountPassthrough(mux *http.ServeMux) error {
	if len(s.consumed) == 0 {
		return nil
	}
	if s.host == nil {
		return fmt.Errorf("solution %q declares consumed modules and runs under no authority interface: the passthrough relays only through the authority's hop", s.manifest.ID)
	}
	routes := s.passthrough
	if routes == nil {
		var err error
		if routes, err = resolvePassthrough(s.consumed); err != nil {
			return err
		}
	}
	mux.Handle(s.authorityRoute()+PassthroughPathPrefix, http.StripPrefix(s.authorityRoute(), s.passthroughHandler(routes)))
	return nil
}

// passthroughHandler serves every route under PassthroughPathPrefix. Each
// route is a Connect handler over the method's own descriptor, so every
// protocol the module's generated clients speak is accepted and every refusal
// is written in the caller's protocol.
func (s *Server) passthroughHandler(routes map[string]passthroughRoute) http.Handler {
	mux := http.NewServeMux()
	for path, route := range routes {
		mux.Handle(path, s.passthroughRoute(route))
	}
	errorWriter := connect.NewErrorWriter()
	return withCORSHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := routes[r.URL.Path]; !ok {
			// Not declared, so not served — whatever the module offers.
			if errorWriter.IsSupported(r) {
				_ = errorWriter.Write(w, r, connect.NewError(connect.CodeNotFound, errors.New("no such operation")))
				return
			}
			http.NotFound(w, r)
			return
		}
		mux.ServeHTTP(w, r)
	}))
}

func (s *Server) passthroughRoute(route passthroughRoute) http.Handler {
	md := route.md
	initialize := func(spec connect.Spec, msg any) error {
		dynamic, ok := msg.(*dynamicpb.Message)
		if !ok {
			return fmt.Errorf("passthrough %s: unexpected message %T", md.FullName(), msg)
		}
		if spec.IsClient {
			*dynamic = *dynamicpb.NewMessage(md.Output())
		} else {
			*dynamic = *dynamicpb.NewMessage(md.Input())
		}
		return nil
	}
	limit := route.method.MaxRequestBytes
	if limit <= 0 {
		limit = DefaultPassthroughRequestLimit
	}
	if md.IsStreamingServer() {
		handler := connect.NewServerStreamHandler(route.procedure(), func(ctx context.Context, req *connect.Request[dynamicpb.Message], stream *connect.ServerStream[dynamicpb.Message]) error {
			return s.relayStream(ctx, route, req, stream)
		},
			connect.WithSchema(md),
			connect.WithRequestInitializer(initialize),
			connect.WithReadMaxBytes(limit),
		)
		return http.StripPrefix(PassthroughPathPrefix+route.module.As, handler)
	}
	handler := connect.NewUnaryHandler(route.procedure(), func(ctx context.Context, req *connect.Request[dynamicpb.Message]) (*connect.Response[dynamicpb.Message], error) {
		resp, err := s.relay(ctx, route, req)
		if err != nil {
			return nil, err
		}
		return connect.NewResponse(resp), nil
	},
		connect.WithSchema(md),
		connect.WithRequestInitializer(initialize),
		connect.WithReadMaxBytes(limit),
	)
	return http.StripPrefix(PassthroughPathPrefix+route.module.As, handler)
}

// applyPin merges the declared pin into the request. It is merged through the
// wire form: the pin is the generated type, the request a dynamic message over
// the same descriptor.
func applyPin(route passthroughRoute, msg *dynamicpb.Message) error {
	if route.method.Pin == nil {
		return nil
	}
	pinned, err := proto.Marshal(route.method.Pin)
	if err != nil {
		return connect.NewError(connect.CodeInternal, errors.New("the declared pin cannot be encoded"))
	}
	if err := (proto.UnmarshalOptions{Merge: true}).Unmarshal(pinned, msg); err != nil {
		return connect.NewError(connect.CodeInternal, errors.New("the declared pin cannot be applied"))
	}
	return nil
}

// relayedError turns a failure to act as the viewer into the Connect error the
// page receives: the authority's refusal of the viewer's Work Context keeps its
// code and reason, a refusal of the caller's own request keeps its message,
// and anything else is reported by kind only, never by its internal detail.
// The module's own answer is moduleRefusal's.
func relayedError(err error) error {
	var refusal *WorkContextRefusal
	if errors.As(err, &refusal) && refusal != nil && refusal.StatusCode >= 400 && refusal.StatusCode < 500 {
		code, message := codeForStatus(refusal.StatusCode), "the viewer's authority for this module was refused"
		if refusal.code != 0 {
			code = refusal.code
		}
		if refusal.Reason != "" {
			message += ": " + truncated(refusal.Reason)
		}
		return connect.NewError(code, errors.New(message))
	}
	var clientErr *ClientError
	if errors.As(err, &clientErr) && clientErr != nil {
		return connect.NewError(codeForStatus(clientErr.StatusCode), errors.New(clientErr.Message))
	}
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return connect.NewError(connect.CodeDeadlineExceeded, errors.New("the module did not answer in time"))
	case errors.Is(err, context.Canceled):
		return connect.NewError(connect.CodeCanceled, errors.New("the call was canceled"))
	}
	return connect.NewError(connect.CodeUnavailable, errors.New("the module call failed"))
}

func truncated(s string) string {
	if len(s) > relayedMessageLimit {
		return s[:relayedMessageLimit]
	}
	return s
}

// codeForStatus maps a module's HTTP status to the Connect code a generated
// client decodes.
func codeForStatus(status int) connect.Code {
	switch status {
	case http.StatusBadRequest:
		return connect.CodeInvalidArgument
	case http.StatusUnauthorized:
		return connect.CodeUnauthenticated
	case http.StatusForbidden:
		return connect.CodePermissionDenied
	case http.StatusNotFound, http.StatusGone:
		return connect.CodeNotFound
	case http.StatusConflict:
		return connect.CodeAborted
	case http.StatusPreconditionFailed, http.StatusUnprocessableEntity:
		return connect.CodeFailedPrecondition
	case http.StatusRequestEntityTooLarge, http.StatusTooManyRequests:
		return connect.CodeResourceExhausted
	case 499:
		return connect.CodeCanceled
	case http.StatusNotImplemented:
		return connect.CodeUnimplemented
	case http.StatusGatewayTimeout:
		return connect.CodeDeadlineExceeded
	case http.StatusInternalServerError:
		return connect.CodeInternal
	}
	if status >= 400 && status < 500 {
		return connect.CodeFailedPrecondition
	}
	return connect.CodeUnavailable
}

// PassthroughOperations documents the declared methods for the interface
// artifact, in path order, so a solution's committed description of what its
// page may call is rendered from the same declaration the runtime serves.
func PassthroughOperations(modules ...ConsumedModule) ([]Operation, error) {
	routes, err := resolvePassthrough(modules)
	if err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(routes))
	for path := range routes {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	ops := make([]Operation, 0, len(paths))
	for _, path := range paths {
		route := routes[path]
		callers := fmt.Sprintf("Signed-in people, through the authority's edge. The %s module authorizes every call itself, under a Work Context the authority issues for the viewer through this solution's binding for it (%s).",
			route.module.As, scopeText(route.scopes()))
		behavior := fmt.Sprintf("A Connect unary call, relayed to the module's own procedure %s through the authority's hop. ", route.procedure())
		if route.md.IsStreamingServer() {
			behavior = fmt.Sprintf("A Connect server-streaming call, relayed to the module's own procedure %s through the authority's hop. "+
				"The stream stays open at most %s and each message is at most %d bytes. ", route.procedure(), route.streamDuration(), route.streamMessageLimit())
		}
		if route.method.Pin != nil {
			pin, _ := protojson.Marshal(route.method.Pin)
			behavior += fmt.Sprintf("Every request is merged with the declared pin %s first. ", pin)
		}
		if route.method.WholeResponse {
			behavior += "The module's whole response is returned."
		} else {
			behavior += "Only these response fields are returned: " + strings.Join(route.method.Response.paths(), ", ") + "."
		}
		if route.md.IsStreamingServer() {
			behavior += " The response fields apply to every streamed message."
		}
		ops = append(ops, Operation{
			Path:      path,
			Method:    "post",
			Summary:   fmt.Sprintf("Call %s on the %s module as the viewer", route.md.FullName(), route.module.As),
			Streaming: route.md.IsStreamingServer(),
			Callers:   callers,
			Behavior:  behavior,
			Request:   describedMessage{route.md.Input()},
			Response:  describedMessage{route.md.Output()},
			// Documentation only: InterfaceDocument requires a handler, and the
			// passthrough, not Operations, serves these routes.
			Handler: func(context.Context, *Gateway) (any, error) { return nil, errors.New("served by the passthrough") },
			// The module holds each call to its own method policy: the route
			// declares none of the solution's.
			relayed: true,
		})
	}
	return ops, nil
}

func scopeText(scopes []Scope) string {
	parts := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		parts = append(parts, scope.ResourceKind+":["+strings.Join(scope.Actions, ",")+"]")
	}
	return strings.Join(parts, " ")
}

// describedMessage documents a message known only by its descriptor.
type describedMessage struct {
	md protoreflect.MessageDescriptor
}

func (d describedMessage) messageDescriptor() protoreflect.MessageDescriptor { return d.md }

// InterfaceArtifact renders the interface artifact of the solution backend
// rooted at dir: its own operations and the consumed-module operations its
// page may call, at the version its service.codefly.yaml declares. The
// artifact carries the version the platform ships, never a second number kept
// in step by hand. An empty info.Version is read from the manifest.
func InterfaceArtifact(dir string, info InterfaceInfo, ops []Operation, modules ...ConsumedModule) ([]byte, error) {
	if info.Version == "" {
		version, err := ServiceVersion(dir)
		if err != nil {
			return nil, err
		}
		info.Version = version
	}
	consumed, err := PassthroughOperations(modules...)
	if err != nil {
		return nil, err
	}
	return InterfaceDocument(info, append(append([]Operation{}, ops...), consumed...))
}

// ServiceVersion is the version the service manifest (service.codefly.yaml)
// in dir declares.
func ServiceVersion(dir string) (string, error) {
	data, err := os.ReadFile(filepath.Join(dir, "service.codefly.yaml"))
	if err != nil {
		return "", err
	}
	var svc struct {
		Version string `yaml:"version"`
	}
	if err := yaml.Unmarshal(data, &svc); err != nil {
		return "", fmt.Errorf("service.codefly.yaml: %w", err)
	}
	if svc.Version == "" {
		return "", fmt.Errorf("service.codefly.yaml declares no version")
	}
	return svc.Version, nil
}
