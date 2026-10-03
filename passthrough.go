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
	"github.com/codefly-dev/sdk-go/workcontext"
	"github.com/codefly-dev/solution-runtime-go/internal/seam"
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
// unmodified with the base URL `<apiBase>/modules/<as>`. A server-streaming
// method is served the same way as a Connect server-streaming procedure; see
// "Streamed methods" in stream.go for the wire a module answers it with. Each call is answered
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
	// Scopes is the authority minted for the viewer on every call (ForModule)
	// of a method that declares none of its own, no more than those methods
	// need. A module that is not ViewerBearer sets Scopes, or sets Scopes on
	// every one of its methods.
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
	// Scopes, when set, is the authority minted for the viewer on a call to
	// this method, instead of the module's Scopes — never in addition to them.
	// It is how one module's methods that need different authority are
	// declared under one `as`: each call mints only what its own method needs,
	// so a viewer who lacks one method's authority is refused that method
	// (permission_denied) and is still served every other. Not allowed on a
	// ViewerBearer module, which mints nothing.
	Scopes []Scope
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
	// DefaultPassthroughTimeout. For a server-streaming method it bounds the
	// mint and the module's first answer (its status line and headers); the
	// stream itself is bounded by MaxStreamDuration.
	Timeout time.Duration
	// MaxStreamDuration bounds how long one stream of a server-streaming
	// method stays open, from the call to its last message; zero is
	// DefaultStreamDuration, and no stream may be declared longer than
	// MaxStreamDurationLimit. A stream that reaches it ends with
	// deadline_exceeded. Only for a server-streaming method.
	MaxStreamDuration time.Duration
	// MaxStreamMessageBytes bounds each message of a server-streaming method's
	// stream, as the module sends it (one line of its answer); zero is
	// DefaultStreamMessageLimit. A larger message ends the stream with
	// resource_exhausted: it is never truncated. Only for a server-streaming
	// method.
	MaxStreamMessageBytes int64
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
		case module.ViewerBearer && len(module.Scopes) > 0:
			return nil, fmt.Errorf("consumed module %q: declare exactly one of Scopes (the authority minted for the viewer) and ViewerBearer (the module authenticates the viewer itself)", module.As)
		case len(module.Methods) == 0:
			return nil, fmt.Errorf("consumed module %q declares no methods", module.As)
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
			switch {
			case module.ViewerBearer && len(method.Scopes) > 0:
				return nil, fmt.Errorf("consumed module %q: %s declares Scopes, but the module is ViewerBearer: it mints nothing, so the scopes would never be asked for", module.As, md.FullName())
			case !module.ViewerBearer && len(module.Scopes) == 0 && len(method.Scopes) == 0:
				return nil, fmt.Errorf("consumed module %q: %s declares no Scopes and the module declares none either; name the authority minted for the viewer, or declare the module ViewerBearer", module.As, md.FullName())
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
			routes[path] = passthroughRoute{path: path, module: module, method: method, md: md, verb: verb, template: template}
		}
	}
	return routes, nil
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

// scopes is the authority a call to this route mints for the viewer: the
// method's own, else the module's. Never the union.
func (r passthroughRoute) scopes() []Scope {
	if len(r.method.Scopes) > 0 {
		return r.method.Scopes
	}
	return r.module.Scopes
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

// mountPassthrough mounts the declared routes on mux at PassthroughPathPrefix:
// the one place the passthrough is wired, so the test seam serves what Serve
// serves. Serve has already resolved and checked the routes; a test that calls
// serve directly has not, and resolves them here.
//
// It named Server.PassthroughHandler as the other caller, which was removed —
// an exported constructor for a credential-bearing handler with no boot behind
// it. The seam reached through internal/seam replaced it.
func (s *Server) mountPassthrough(mux *http.ServeMux) error {
	if len(s.consumed) == 0 {
		return nil
	}
	routes := s.passthrough
	if routes == nil {
		var err error
		if routes, err = resolvePassthrough(s.consumed); err != nil {
			return err
		}
	}
	mux.Handle(PassthroughPathPrefix, s.passthroughHandler(routes))
	return nil
}

// init registers the passthrough seam for package passthroughtest, which is the
// only caller that can reach it: internal/seam is importable inside this module
// and nowhere else.
func init() {
	seam.Passthrough = passthroughSeam
}

// passthroughSeam is what Server.PassthroughHandler used to be, minus the
// "exported" part.
//
// Exported, it was a production bypass: a solution could build a usable
// credential-bearing handler that had skipped validate(), the mTLS boot, the
// caller allow-list, the published ceiling and authenticated outbound, and a
// deployment calling it completed a viewer mint and a module call over
// plaintext, 200, with the viewer's bearer and this workload's own credential
// on the wire. Supplying a credential source — which a real deployment does —
// defeated the "no source, nothing to mint with" mitigation it relied on. Fail
// closed admits no exception for a shape that exists to make testing
// convenient, so the shape moved behind the compiler instead: see
// internal/seam.
//
// What it builds is otherwise unchanged, and deliberately so — it is the
// declaration checked by the same boot check and mounted by the same code at
// PassthroughPathPrefix, so a consumer's test serves what Serve serves. Serve
// overwrites the environment set here when it resolves its own.
func passthroughSeam(server any, gatewayURL, consumesJSON string) (http.Handler, error) {
	s, ok := server.(*Server)
	if !ok {
		return nil, fmt.Errorf("the passthrough seam was handed a %T rather than a solution server", server)
	}
	if len(s.consumed) == 0 {
		return nil, fmt.Errorf("solution %q declares no consumed modules (Consumes)", s.manifest.ID)
	}
	s.cfg.gatewayURL, s.cfg.apiConsumes = gatewayURL, consumesJSON
	routes, err := s.validatePassthrough()
	if err != nil {
		return nil, fmt.Errorf("solution %q: %w", s.manifest.ID, err)
	}
	s.passthrough = routes
	mux := http.NewServeMux()
	if err := s.mountPassthrough(mux); err != nil {
		return nil, err
	}
	return mux, nil
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
	if md.IsStreamingServer() {
		handler := connect.NewServerStreamHandler(procedure, func(ctx context.Context, req *connect.Request[dynamicpb.Message], stream *connect.ServerStream[dynamicpb.Message]) error {
			return s.forwardStream(ctx, route, req, stream)
		},
			connect.WithSchema(md),
			connect.WithRequestInitializer(initialize),
			connect.WithReadMaxBytes(limit),
		)
		return http.StripPrefix(PassthroughPathPrefix+route.module.As, handler)
	}
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
	gw, err := s.authorize(ctx, route, req.Header(), req.Msg)
	if err != nil {
		return nil, err
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

// authorize prepares one call as the viewer: the declared authority minted for
// this method (or the bearer alone, for a ViewerBearer module), and the
// declared pin merged into the request.
func (s *Server) authorize(ctx context.Context, route passthroughRoute, header http.Header, msg *dynamicpb.Message) (*Gateway, error) {
	// Whether or not this route mints anything. A ViewerBearer route forwards
	// the viewer's bearer and asks the credential for nothing, so it was the
	// one route that never consulted it — and it kept forwarding that bearer
	// to the gateway after the issuer refused this build. See
	// actingForAViewer: the credential is what authorises this process to act
	// for a viewer, not merely what it mints with.
	if err := s.actingForAViewer(ctx); err != nil {
		return nil, connect.NewError(connect.CodeUnavailable, err)
	}
	gw := s.gatewayFor(header)
	if !route.module.ViewerBearer {
		acting, err := gw.ForModule(ctx, route.module.As, route.scopes()...)
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
		if err := (proto.UnmarshalOptions{Merge: true}).Unmarshal(pinned, msg); err != nil {
			return nil, connect.NewError(connect.CodeInternal, errors.New("the declared pin cannot be applied"))
		}
	}
	return gw, nil
}

// relayedError turns a failed call into the Connect error the page receives.
// A module's own refusal keeps its meaning: a google.rpc.Status body keeps its
// code and message exactly, and any other small JSON refusal is relayed as the
// message, verbatim, with the code its HTTP status maps to — it is the module's
// answer to the page's own request. Anything else (a transport failure, an
// undecodable answer) is reported by kind only, never by its internal detail.
func relayedError(err error) error {
	var refusal *WorkContextRefusal
	if errors.As(err, &refusal) && refusal != nil && refusal.StatusCode >= 400 && refusal.StatusCode < 500 {
		// The issuer refused the viewer's authority for this call: say so, in
		// its own code and words (they name the missing permission), rather
		// than as a failed module call. It is the viewer's own authorization,
		// so nothing of another principal is disclosed.
		code := codeForStatus(refusal.StatusCode)
		var parsed connect.Code
		if refusal.Code != "" && parsed.UnmarshalText([]byte(refusal.Code)) == nil && parsed != connect.CodeUnknown {
			code = parsed
		}
		message := "the viewer's authority for the " + refusal.Audience + " module was refused"
		if refusal.Message != "" {
			message += ": " + truncated(refusal.Message)
		}
		return connect.NewError(code, errors.New(message))
	}
	var streamErr *StreamError
	if errors.As(err, &streamErr) && streamErr != nil {
		code := connect.CodeUnknown
		if streamErr.Code > 0 && streamErr.Code <= 16 {
			code = connect.Code(streamErr.Code)
		}
		return connect.NewError(code, errors.New(truncated(streamErr.Message)))
	}
	if errors.Is(err, ErrStreamMessageTooLarge) {
		return connect.NewError(connect.CodeResourceExhausted, errors.New("a message of the module's stream exceeds its declared bound"))
	}
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
	case errors.Is(err, workcontext.ErrRevoked):
		// Checked before ErrNotAttested, which now wraps it: a renewal the
		// issuer refuses because the state the credential is sealed to has
		// moved arrives here as both, and the first matching branch decides
		// what a page is told. Reported as unavailable it reads as "retry
		// shortly", which is the one thing that cannot help.
		//
		// The capability was sound when it was minted and the state moved under
		// it — an installation revision, a principal's epoch, a build
		// incarnation, a binding. The holder's answer to every one of those is
		// the same and it is not "retry": it is to mint again. Reported as the
		// unavailable fallthrough below, a page or a client policy would retry
		// against a credential guaranteed to keep failing; reported as a plain
		// denial, a condition one mint fixes would reach the viewer as their
		// own authorization failing. Aborted is neither, and a caller that
		// re-asks gets a fresh mint because the cache no longer holds a current
		// one.
		return connect.NewError(connect.CodeAborted, errors.New("the authority this solution presented has been superseded; the call was not made"))
	case errors.Is(err, ErrNotAttested):
		// This solution could not attest which module is asking, so it did not
		// ask. The viewer's authority is not in question and the condition is
		// one renewal away, which is what unavailable says and what neither
		// internal nor permission_denied would.
		return connect.NewError(connect.CodeUnavailable, errors.New("this solution cannot currently act for the viewer against the module"))
	case errors.Is(err, workcontext.ErrUnsealed), errors.Is(err, workcontext.ErrNotACoreToken), errors.Is(err, workcontext.ErrInvalid):
		// A capability this solution could not present is this solution's
		// problem, not a module that is briefly unreachable, and not the
		// viewer's authorization. Reported as the unavailable fallthrough it
		// would be retried against a credential that will be exactly as
		// unusable next time, and the one signal that the issuer handed back
		// something this runtime cannot carry would be spent on a retry loop.
		// The three are kept apart from each other at the point they are
		// logged, not here: "another format", "no seal" and "bad capability"
		// have different owners, and core deliberately does not let one
		// errors.Is branch reach all three.
		return connect.NewError(connect.CodeInternal, errors.New("this solution could not present a usable credential for the module"))
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
			route.module.As, route.module.As, scopeText(route.scopes()))
		if route.module.ViewerBearer {
			callers = fmt.Sprintf("Signed-in viewers. The %s module authenticates the viewer's bearer and authorizes every call itself.", route.module.As)
		}
		behavior := fmt.Sprintf("A Connect unary call, forwarded to the module's %s %s binding. ", route.verb, route.template)
		if route.md.IsStreamingServer() {
			behavior = fmt.Sprintf("A Connect server-streaming call, forwarded to the module's %s %s binding, which answers as newline-delimited JSON. "+
				"The stream stays open at most %s and each message is at most %d bytes. ", route.verb, route.template, route.streamDuration(), route.streamMessageLimit())
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
