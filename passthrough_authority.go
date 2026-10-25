package solution

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"

	"connectrpc.com/connect"
	"github.com/codefly-dev/sdk-go/workcontext"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/dynamicpb"
)

// --- The passthrough under the authority interface ---
//
// Under the authority there is no saas gateway to transcode through. The same
// declaration (Consumes) is served instead by relaying each declared method
// over gRPC to the module, through the hop in front of it, as the viewer: a
// child of the Work Context the edge sent the request with, issued by the
// authority through one of this solution's bindings (ForParent) and carrying
// the method's declared scopes. The pin and the response allowlist apply
// exactly as they do under the gateway, and the module authorizes every call.
//
// Where the module is and which binding the child is issued through are the
// composition's to say, in two workspace configuration slots the module's
// declaration names (AuthorityRelay). A consumed module that names none is not
// relayed under the authority: its routes are left to the solution.
//
// The page reaches this backend through the edge, which routes a solution at
// /v1/<id> and forwards each request unchanged, so the passthrough is served at
// /v1/<id>/modules/<as>/<package.Service>/<Method> — the path the module's
// generated client already calls with the base URL `<apiBase>/modules/<as>`.

// AuthorityRelay names, for one consumed module, the workspace configuration
// slots the composition fills under the authority interface: the module's gRPC
// address (the hop in front of it, an ${endpoint:…} reference the run
// resolves) and the id this solution's binding for the module is installed
// under. All three are set, or none.
type AuthorityRelay struct {
	Group       string
	EndpointKey string
	BindingKey  string
}

func (a AuthorityRelay) declared() bool { return a != AuthorityRelay{} }

// moduleRelay is one relayed module: the binding its children are issued
// through and its connection.
type moduleRelay struct {
	binding string
	conn    *grpc.ClientConn
}

// authorityRoute is where the authority's edge routes this solution.
func (s *Server) authorityRoute() string { return "/v1/" + s.manifest.ID }

// openRelays reads every relayed module's slots and opens its connection, or
// refuses the boot naming what is missing: a backend that cannot name a
// binding cannot be issued a capability, and that belongs at start-up.
func (s *Server) openRelays(routes map[string]passthroughRoute, lookup func(group, key string) (string, error)) (map[string]*moduleRelay, error) {
	relays := map[string]*moduleRelay{}
	for _, module := range s.consumed {
		a := module.Authority
		if !a.declared() {
			continue
		}
		if a.Group == "" || a.EndpointKey == "" || a.BindingKey == "" {
			return nil, fmt.Errorf("consumed module %q: its authority relay names a group, an endpoint slot and a binding slot, all three", module.As)
		}
		if module.ViewerBearer {
			return nil, fmt.Errorf("consumed module %q is ViewerBearer: under the authority interface no bearer reaches this process, so it cannot be relayed", module.As)
		}
		for _, route := range routes {
			if route.module.As == module.As && route.md.IsStreamingServer() {
				return nil, fmt.Errorf("consumed module %q: %s streams its answer, which is not relayed under the authority interface", module.As, route.md.FullName())
			}
		}
		slot := func(key, what string) (string, error) {
			value, err := lookup(a.Group, key)
			if err != nil || strings.TrimSpace(value) == "" {
				return "", fmt.Errorf("consumed module %q: %s/%s names no %s; the composition supplies it under the authority interface", module.As, a.Group, key, what)
			}
			return strings.TrimSpace(value), nil
		}
		endpoint, err := slot(a.EndpointKey, "address")
		if err != nil {
			return nil, err
		}
		binding, err := slot(a.BindingKey, "binding")
		if err != nil {
			return nil, err
		}
		conn, err := dialModule(endpoint, s.cfg.transport, a.Group+"/"+a.EndpointKey)
		if err != nil {
			return nil, fmt.Errorf("consumed module %q: %w", module.As, err)
		}
		relays[module.As] = &moduleRelay{binding: binding, conn: conn}
	}
	return relays, nil
}

// dialModule connects to a module's gRPC address. The viewer's Work Context
// travels on it, so where it may go is the SDK's one rule for a credential's
// destination (workcontext.AdmitEndpoint): https anywhere; cleartext to a
// loopback host on a local run, or to an in-cluster address the mesh carries.
// A bare host:port, as an endpoint reference resolves, is cleartext.
func dialModule(endpoint string, transport workcontext.TransportSource, what string) (*grpc.ClientConn, error) {
	raw := strings.TrimSpace(endpoint)
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	admitted, err := workcontext.AdmitEndpoint(raw, transport, what)
	if err != nil {
		return nil, err
	}
	creds := insecure.NewCredentials()
	if admitted.Scheme == "https" {
		creds = credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12})
	}
	return grpc.NewClient(admitted.Host, grpc.WithTransportCredentials(creds))
}

// relayedRoutes is the passthrough under the authority: the routes of the
// modules that are relayed.
func relayedRoutes(routes map[string]passthroughRoute, relays map[string]*moduleRelay) map[string]passthroughRoute {
	relayed := map[string]passthroughRoute{}
	for path, route := range routes {
		if relays[route.module.As] != nil {
			relayed[path] = route
		}
	}
	return relayed
}

// viewerGateway is the gateway for the person whose Work Context the edge sent
// a request with: who it is for is the authority's Check of that context, never
// a header the request wrote about itself.
func (s *Server) viewerGateway(ctx context.Context, carried string) (*Gateway, error) {
	if carried == "" {
		return nil, errors.New("no Work Context: this page is reached through the authority's edge, which signs the person in")
	}
	viewer, err := s.host.viewer(ctx, carried)
	if err != nil {
		return nil, err
	}
	gw := s.gatewayFor(http.Header{})
	gw.parentContext = carried
	gw.orgID, gw.sessionID, gw.installationID, gw.installationErr = viewer.GetTenantId(), viewer.GetSessionId(), "", nil
	return gw, nil
}

// relay answers one call as the viewer under the authority: the child Work
// Context issued through the module's binding with the declared scopes, the
// pin merged in, the module called over gRPC, and only the declared response
// fields returned.
func (s *Server) relay(ctx context.Context, route passthroughRoute, req *connect.Request[dynamicpb.Message]) (*dynamicpb.Message, error) {
	relay := s.relays[route.module.As]
	if relay == nil {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no such operation"))
	}
	gw, err := s.viewerGateway(ctx, req.Header().Get(WorkContextHeader))
	if err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	timeout := route.method.Timeout
	if timeout <= 0 {
		timeout = DefaultPassthroughTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	acting, err := gw.ForParent(ctx, relay.binding, route.scopes()...)
	if err != nil {
		return nil, relayedError(err)
	}
	token, err := acting.WorkContext(ctx)
	if err != nil {
		return nil, relayedError(err)
	}
	if err := applyPin(route, req.Msg); err != nil {
		return nil, err
	}
	limit := route.method.MaxResponseBytes
	if limit <= 0 {
		limit = DefaultTranscodedResponseLimit
	}
	out := dynamicpb.NewMessage(route.md.Output())
	procedure := "/" + string(route.md.Parent().FullName()) + "/" + string(route.md.Name())
	calling := grpcmetadata.AppendToOutgoingContext(ctx, WorkContextHeader, token)
	if err := relay.conn.Invoke(calling, procedure, req.Msg, out, grpc.MaxCallRecvMsgSize(int(limit))); err != nil {
		return nil, s.moduleRefusal(route, err)
	}
	if !route.method.WholeResponse {
		out = Apply(route.method.Response, out)
	}
	return out, nil
}

// moduleRefusal turns a module's gRPC answer into the Connect error the page
// receives, on the line relayedError draws for the gateway: a refusal of the
// page's own request keeps its code and the module's reason; anything else —
// unavailable, internal, a transport failure — is reported by kind and logged
// where an operator reads it, since its text may name what the page must not.
func (s *Server) moduleRefusal(route passthroughRoute, err error) error {
	st := status.Convert(err)
	switch st.Code() {
	case codes.InvalidArgument, codes.NotFound, codes.AlreadyExists, codes.PermissionDenied, codes.Unauthenticated,
		codes.FailedPrecondition, codes.Aborted, codes.OutOfRange, codes.ResourceExhausted, codes.Unimplemented:
		return connect.NewError(connect.Code(st.Code()), errors.New(truncated(st.Message())))
	case codes.DeadlineExceeded:
		return relayedError(context.DeadlineExceeded)
	case codes.Canceled:
		return relayedError(context.Canceled)
	}
	log.Printf("solution %q: relaying %s to %q failed: %v", s.manifest.ID, route.md.FullName(), route.module.As, err)
	return connect.NewError(connect.CodeUnavailable, errors.New("the module call failed"))
}
