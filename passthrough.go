package solution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/codefly-dev/core/solution/manifest"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
	"gopkg.in/yaml.v3"
)

// --- Consumed-module passthrough ---
//
// A solution's page reaches only its own backend: the host proxy forwards the
// browser to /solutions/<id>/…, never to a composed module's /v1/<as>/* prefix,
// and a module that authenticates by Work Context would refuse the browser's
// bearer anyway. Without this, every module read a page makes needs a handler
// in the solution that decodes the browser's request, mints the viewer's
// capability, calls the module and re-encodes the answer — the same code in
// every solution, once per operation.
//
// Consumes declares, instead, which operations of which consumed module the
// page may call. The runtime serves each one as a Connect unary procedure at
//
//	/modules/<as>/<package.Service>/<Method>
//
// so the module's own generated client (connect-es, connect-go) is used
// unmodified with the base URL `<apiBase>/modules/<as>`. Each call is answered
// by the module, as the viewer: the runtime mints the viewer's Work Context for
// the module (Gateway.ForModule) — or forwards only the bearer, for a module
// that authenticates the viewer itself — and forwards the request over the
// method's google.api.http binding (Gateway.Transcoded). The browser names a
// declared procedure and a request message; it never names a path, a prefix,
// an audience or an authority. Authorization stays where it is: at the module.
//
// Least privilege is the default throughout. A method that is not declared is
// not served. A module whose `as` the solution does not consume is refused at
// boot. A declared method returns only the response fields its mask names,
// unless the declaration explicitly passes the whole response.

// ConsumedModule declares the operations of one consumed module the solution's
// page may call through the passthrough.
type ConsumedModule struct {
	// As is the `as` of the module's api.consumes entry: the gateway prefix
	// /v1/<As> the module is federated under, and the audience a Work Context
	// for it is minted for. A module the solution does not consume under this
	// name is refused at boot.
	As string
	// Scopes is the authority minted for the viewer on every call (ForModule),
	// no more than the declared operations need. Exactly one of Scopes and
	// ViewerBearer is set.
	Scopes []Scope
	// ViewerBearer forwards only the viewer's bearer: for a module that
	// authenticates the viewer and mints its own authority from that bearer,
	// so a capability minted here would be one it never reads.
	ViewerBearer bool
	// Methods is the allowlist. Nothing else of the module is reachable.
	Methods []ConsumedMethod
}

// ConsumedMethod is one operation of a consumed module the page may call.
type ConsumedMethod struct {
	// Name is the RPC's full name as its generated code declares it, the
	// "/package.Service/Method" constant a gRPC or Connect stub exports. The
	// module's generated package must be linked into the solution.
	Name string
	// Response is the allowlist of response fields returned to the page. A
	// field the module adds later is dropped until someone names it here.
	Response FieldMask
	// WholeResponse passes every response field, and must be said explicitly:
	// the zero value of a declaration returns nothing it did not name.
	WholeResponse bool
	// Pin, when set, is merged into every request the page sends before it is
	// forwarded (proto.Merge): a scalar it sets replaces the page's value, a
	// message merges, and a repeated field is appended. It is how a solution
	// fixes part of a request server-side — a filter clause the module ANDs
	// with the page's own, say — so the page can narrow the call but not undo
	// the pin. It must be the method's request type.
	Pin proto.Message
	// MaxRequestBytes bounds the request message the page sends; zero is
	// DefaultPassthroughRequestLimit.
	MaxRequestBytes int
	// MaxResponseBytes bounds the module's answer; zero is
	// DefaultTranscodedResponseLimit.
	MaxResponseBytes int64
	// Timeout bounds one call, the mint included; zero is
	// DefaultPassthroughTimeout.
	Timeout time.Duration
}

const (
	// PassthroughPathPrefix is where the passthrough serves: a declared method
	// is at PassthroughPathPrefix + <as> + "/" + <package.Service>/<Method>.
	PassthroughPathPrefix = "/modules/"
	// DefaultPassthroughRequestLimit bounds a request message unless the
	// method sets its own bound.
	DefaultPassthroughRequestLimit = 1 << 20
	// DefaultPassthroughTimeout bounds one call unless the method sets its own.
	DefaultPassthroughTimeout = 60 * time.Second
	// relayedMessageLimit bounds the module refusal text relayed to the page.
	relayedMessageLimit = 1024
)

// Consumes declares the consumed-module operations the page may call. It is
// chainable and may be called more than once; Serve refuses a declaration that
// cannot be served before it listens.
func (s *Server) Consumes(modules ...ConsumedModule) *Server {
	s.consumed = append(s.consumed, modules...)
	return s
}

// passthroughRoute is one declared method, resolved against its descriptor.
type passthroughRoute struct {
	path   string
	module ConsumedModule
	method ConsumedMethod
	md     protoreflect.MethodDescriptor
	verb   string
	// template is the module binding the call is forwarded over.
	template string
}

// resolvePassthrough checks every declaration against the generated
// descriptors and returns the routes, keyed on path. Every refusal is a
// mistake in the solution's declaration, found before anything is served.
func resolvePassthrough(modules []ConsumedModule) (map[string]passthroughRoute, error) {
	routes := map[string]passthroughRoute{}
	seen := map[string]bool{}
	for _, module := range modules {
		prefix := "/v1/" + module.As
		switch {
		case module.As == "" || strings.ContainsAny(module.As, "/?#{}*:\\") || !cleanPrefix(prefix):
			return nil, fmt.Errorf("consumed module %q: as must be one path segment, the `as` of its api.consumes entry", module.As)
		case seen[module.As]:
			return nil, fmt.Errorf("consumed module %q is declared twice", module.As)
		case module.ViewerBearer == (len(module.Scopes) > 0):
			return nil, fmt.Errorf("consumed module %q: declare exactly one of Scopes (the authority minted for the viewer) and ViewerBearer (the module authenticates the viewer itself)", module.As)
		case len(module.Methods) == 0:
			return nil, fmt.Errorf("consumed module %q declares no methods", module.As)
		}
		seen[module.As] = true
		for _, method := range module.Methods {
			md, err := methodDescriptor(method.Name)
			if err != nil {
				return nil, fmt.Errorf("consumed module %q: %w", module.As, err)
			}
			if md.IsStreamingClient() || md.IsStreamingServer() {
				return nil, fmt.Errorf("consumed module %q: %s streams; only unary methods pass through", module.As, md.FullName())
			}
			_, verb, template, err := bindingUnder(md, prefix)
			if err != nil {
				return nil, fmt.Errorf("consumed module %q: %w", module.As, err)
			}
			switch {
			case method.WholeResponse && method.Response.desc != nil:
				return nil, fmt.Errorf("consumed module %q: %s declares both a response mask and the whole response", module.As, md.FullName())
			case !method.WholeResponse && method.Response.desc == nil:
				return nil, fmt.Errorf("consumed module %q: %s declares no response fields; name them in Response, or pass WholeResponse explicitly", module.As, md.FullName())
			case method.Response.desc != nil && method.Response.desc.FullName() != md.Output().FullName():
				return nil, fmt.Errorf("consumed module %q: %s answers %s, but its response mask is over %s", module.As, md.FullName(), md.Output().FullName(), method.Response.desc.FullName())
			}
			if method.Pin != nil && method.Pin.ProtoReflect().Descriptor().FullName() != md.Input().FullName() {
				return nil, fmt.Errorf("consumed module %q: %s reads %s, but its pin is a %s", module.As, md.FullName(), md.Input().FullName(), method.Pin.ProtoReflect().Descriptor().FullName())
			}
			path := PassthroughPathPrefix + module.As + "/" + string(md.Parent().FullName()) + "/" + string(md.Name())
			if _, dup := routes[path]; dup {
				return nil, fmt.Errorf("consumed module %q: %s is declared twice", module.As, md.FullName())
			}
			routes[path] = passthroughRoute{path: path, module: module, method: method, md: md, verb: verb, template: template}
		}
	}
	return routes, nil
}

// checkConsumed refuses a declaration for a module the solution does not
// consume under that name: the gateway would federate no /v1/<as> prefix for
// it, so every call would fail at the gateway instead of here.
func checkConsumed(modules []ConsumedModule, consumed []manifest.ConsumedAPI) error {
	names := map[string]bool{}
	for _, c := range consumed {
		names[c.As] = true
	}
	for _, module := range modules {
		if !names[module.As] {
			return fmt.Errorf("consumed module %q is declared for the page, but api.consumes lists no module as %q", module.As, module.As)
		}
	}
	return nil
}

// validatePassthrough is Serve's boot check of the declaration.
func (s *Server) validatePassthrough() (map[string]passthroughRoute, error) {
	routes, err := resolvePassthrough(s.consumed)
	if err != nil || len(s.consumed) == 0 {
		return routes, err
	}
	consumed, err := manifest.ParseConsumedAPIs(s.cfg.apiConsumes)
	if err != nil {
		return nil, fmt.Errorf("consumed modules cannot be checked against api.consumes: %w", err)
	}
	return routes, checkConsumed(s.consumed, consumed)
}

// passthroughHandler serves every route under PassthroughPathPrefix. Each
// route is a Connect unary handler over the method's own descriptor, so every
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
	procedure := "/" + string(md.Parent().FullName()) + "/" + string(md.Name())
	handler := connect.NewUnaryHandler(procedure, func(ctx context.Context, req *connect.Request[dynamicpb.Message]) (*connect.Response[dynamicpb.Message], error) {
		resp, err := s.forward(ctx, route, req)
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

// forward answers one call as the viewer: it mints the declared authority (or
// forwards the bearer alone), calls the module over its binding, and returns
// only the declared response fields.
func (s *Server) forward(ctx context.Context, route passthroughRoute, req *connect.Request[dynamicpb.Message]) (*dynamicpb.Message, error) {
	bearer := req.Header().Get("authorization")
	if bearer == "" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("missing bearer"))
	}
	timeout := route.method.Timeout
	if timeout <= 0 {
		timeout = DefaultPassthroughTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	gw := newGateway(s.cfg.gatewayURL, bearer, req.Header().Get(orgHeader), req.Header().Get(sessionHeader))
	if !route.module.ViewerBearer {
		acting, err := gw.ForModule(ctx, route.module.As, route.module.Scopes...)
		if err != nil {
			return nil, relayedError(err)
		}
		gw = acting
	}
	if route.method.Pin != nil {
		// Merged through the wire form: the pin is the generated type, the
		// request a dynamic message over the same descriptor.
		pinned, err := proto.Marshal(route.method.Pin)
		if err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("the declared pin cannot be encoded"))
		}
		if err := (proto.UnmarshalOptions{Merge: true}).Unmarshal(pinned, req.Msg); err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("the declared pin cannot be applied"))
		}
	}
	out := dynamicpb.NewMessage(route.md.Output())
	var opts []TranscodeOption
	if route.method.MaxResponseBytes > 0 {
		opts = append(opts, MaxResponseBytes(route.method.MaxResponseBytes))
	}
	if err := gw.Transcoded(ctx, "/v1/"+route.module.As, route.method.Name, req.Msg, out, opts...); err != nil {
		return nil, relayedError(err)
	}
	if !route.method.WholeResponse {
		out = Apply(route.method.Response, out)
	}
	return out, nil
}

// relayedError turns a failed call into the Connect error the page receives.
// A module's own refusal keeps its meaning: a google.rpc.Status body keeps its
// code and message exactly, and any other small JSON refusal is relayed as the
// message, verbatim, with the code its HTTP status maps to — it is the module's
// answer to the page's own request. Anything else (a transport failure, an
// undecodable answer) is reported by kind only, never by its internal detail.
func relayedError(err error) error {
	var clientErr *ClientError
	if errors.As(err, &clientErr) && clientErr != nil {
		return connect.NewError(codeForStatus(clientErr.StatusCode), errors.New(clientErr.Message))
	}
	var gatewayErr *GatewayError
	if errors.As(err, &gatewayErr) && gatewayErr != nil {
		var status struct {
			Code    *int32 `json:"code"`
			Message string `json:"message"`
		}
		detail := gatewayErr.detail
		if json.Unmarshal(detail, &status) == nil && status.Code != nil && *status.Code > 0 && *status.Code <= 16 {
			return connect.NewError(connect.Code(*status.Code), errors.New(truncated(status.Message)))
		}
		message := http.StatusText(gatewayErr.StatusCode)
		if len(detail) > 0 && len(detail) <= relayedMessageLimit && json.Valid(detail) {
			message = string(detail)
		}
		return connect.NewError(codeForStatus(gatewayErr.StatusCode), errors.New(message))
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
		callers := fmt.Sprintf("Signed-in viewers. The %s module authorizes every call itself, under a Work Context minted for the viewer (audience %q, %s).",
			route.module.As, route.module.As, scopeText(route.module.Scopes))
		if route.module.ViewerBearer {
			callers = fmt.Sprintf("Signed-in viewers. The %s module authenticates the viewer's bearer and authorizes every call itself.", route.module.As)
		}
		behavior := fmt.Sprintf("A Connect unary call, forwarded to the module's %s %s binding. ", route.verb, route.template)
		if route.method.Pin != nil {
			pin, _ := protojson.Marshal(route.method.Pin)
			behavior += fmt.Sprintf("Every request is merged with the declared pin %s first. ", pin)
		}
		if route.method.WholeResponse {
			behavior += "The module's whole response is returned."
		} else {
			behavior += "Only these response fields are returned: " + strings.Join(route.method.Response.paths(), ", ") + "."
		}
		ops = append(ops, Operation{
			Path:     path,
			Method:   "post",
			Summary:  fmt.Sprintf("Call %s on the %s module as the viewer", route.md.FullName(), route.module.As),
			Callers:  callers,
			Behavior: behavior,
			Request:  describedMessage{route.md.Input()},
			Response: describedMessage{route.md.Output()},
			// Documentation only: InterfaceDocument requires a handler, and the
			// passthrough, not Operations, serves these routes.
			Handler: func(context.Context, *Gateway) (any, error) { return nil, errors.New("served by the passthrough") },
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
