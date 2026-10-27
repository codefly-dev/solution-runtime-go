package solution

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
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

// --- The relay ---
//
// The passthrough (Consumes) relays each declared method over gRPC to the
// module's own procedure, through the hop in front of it, as the viewer: a
// child of the Work Context the edge sent the request with, issued by the
// authority through one of this solution's bindings (ForParent) and carrying
// the method's declared scopes. The pin and the response allowlist apply to
// every call, and the module authorizes it.
//
// Where the module is and which binding the child is issued through are the
// composition's to say, in two workspace configuration slots the module's
// declaration names (AuthorityRelay): the endpoint slot holds the hop's gRPC
// address, an ${endpoint:authority/hop/grpc} reference the run resolves.
//
// The page reaches this backend through the edge, which routes a solution at
// /v1/<id> and forwards each request unchanged, so the passthrough is served at
// /v1/<id>/modules/<as>/<package.Service>/<Method> — the path the module's
// generated client already calls with the base URL `<apiBase>/modules/<as>`.

// AuthorityRelay names, for one consumed module, the workspace configuration
// slots the composition fills: the module's gRPC address (the hop in front of
// it, an ${endpoint:…} reference the run resolves) and the id this solution's
// binding for the module is installed under. All three are set.
type AuthorityRelay struct {
	Group       string
	EndpointKey string
	BindingKey  string
}

// moduleRelay is one relayed module: the binding its children are issued
// through and its connection.
type moduleRelay struct {
	binding string
	conn    *grpc.ClientConn
}

// authorityRoute is where the authority's edge routes this solution.
func (s *Server) authorityRoute() string { return "/v1/" + s.manifest.ID }

// openRelays reads every consumed module's slots and opens its connection, or
// refuses the boot naming what is missing: a backend that cannot name a
// binding cannot be issued a capability, and that belongs at start-up.
func (s *Server) openRelays(lookup func(group, key string) (string, error)) (map[string]*moduleRelay, error) {
	relays := map[string]*moduleRelay{}
	for _, module := range s.consumed {
		a := module.Authority
		slot := func(key, what string) (string, error) {
			value, err := lookup(a.Group, key)
			if err != nil || strings.TrimSpace(value) == "" {
				return "", fmt.Errorf("consumed module %q: %s/%s names no %s; the composition supplies it", module.As, a.Group, key, what)
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
		// Dialled, so a tool's error result cannot name it (withoutRuntimeAddresses).
		s.cfg.dialled = append(s.cfg.dialled, dialledAddresses(endpoint)...)
	}
	return relays, nil
}

// dialModule connects to a module's gRPC address. The viewer's Work Context
// travels on it, so where it may go is the SDK's one rule for a credential's
// destination (workcontext.AdmitEndpoint): https anywhere; cleartext to a
// loopback host on a local run, or to an in-cluster address the mesh carries.
// A bare host:port, as an endpoint reference resolves, and grpc:// are
// cleartext.
func dialModule(endpoint string, transport workcontext.TransportSource, what string) (*grpc.ClientConn, error) {
	raw := strings.TrimPrefix(strings.TrimSpace(endpoint), "grpc://")
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

// viewerGateway is the gateway for the person whose Work Context a request
// carries — the edge's for the page, or a module's child of it for a tool call:
// who it is for, and which module acts for them, is the authority's Check of
// that context, never a header the request wrote about itself. route, when
// named, is the dispatched operation "<VERB> <template>", spelled as its
// published row, that the authority applies this module's delivered route
// policy to.
func (s *Server) viewerGateway(ctx context.Context, carried, route string) (*Gateway, error) {
	if carried == "" {
		return nil, errors.New("no Work Context: this page is reached through the authority's edge, which signs the person in")
	}
	viewer, err := s.host.viewer(ctx, carried, route)
	if err != nil {
		return nil, err
	}
	gw := s.newGateway()
	gw.parentContext = carried
	gw.orgID = viewer.GetTenantId()
	principals, actors := principalsOf(viewer)
	gw.viewer = &requestViewer{principals: principals, actors: actors, owner: selectedOwner(viewer)}
	return gw, nil
}

// asTheViewer prepares one relayed call: the module's connection, the child
// Work Context issued through its binding with the method's declared scopes,
// and the pin merged into the request.
func (s *Server) asTheViewer(ctx context.Context, route passthroughRoute, req *connect.Request[dynamicpb.Message]) (*moduleRelay, string, error) {
	relay := s.relays[route.module.As]
	if relay == nil {
		return nil, "", connect.NewError(connect.CodeNotFound, errors.New("no such operation"))
	}
	// The route is named as served, so the authority applies the row the
	// interface artifact publishes for it: any checked caller. What the call
	// may do is the child issued below through the binding, and the module's
	// own method policy, which its hop applies to that child.
	gw, err := s.viewerGateway(ctx, req.Header().Get(WorkContextHeader), req.HTTPMethod()+" "+s.authorityRoute()+route.path)
	if err != nil {
		code := connect.CodeUnauthenticated
		switch {
		case errors.Is(err, ErrRequestRefused):
			code = connect.CodePermissionDenied
		case errors.Is(err, ErrRequestInvalid):
			code = connect.CodeInvalidArgument
		case errors.Is(err, ErrAuthorityUnavailable):
			code = connect.CodeUnavailable
		}
		return nil, "", connect.NewError(code, err)
	}
	acting, err := gw.ForParent(ctx, relay.binding, route.scopes()...)
	if err != nil {
		return nil, "", relayedError(err)
	}
	token, err := acting.WorkContext(ctx)
	if err != nil {
		return nil, "", relayedError(err)
	}
	if err := applyPin(route, req.Msg); err != nil {
		return nil, "", err
	}
	return relay, token, nil
}

// relay answers one unary call as the viewer: the module's own procedure
// called over gRPC with the child Work Context, and only the declared response
// fields returned.
func (s *Server) relay(ctx context.Context, route passthroughRoute, req *connect.Request[dynamicpb.Message]) (*dynamicpb.Message, error) {
	ctx, cancel := context.WithTimeout(ctx, route.timeout())
	defer cancel()
	relay, token, err := s.asTheViewer(ctx, route, req)
	if err != nil {
		return nil, err
	}
	limit := route.method.MaxResponseBytes
	if limit <= 0 {
		limit = DefaultPassthroughResponseLimit
	}
	out := dynamicpb.NewMessage(route.md.Output())
	calling := grpcmetadata.AppendToOutgoingContext(ctx, WorkContextHeader, token)
	if err := relay.conn.Invoke(calling, route.procedure(), req.Msg, out, grpc.MaxCallRecvMsgSize(int(limit))); err != nil {
		return nil, s.moduleRefusal(route, err)
	}
	return route.answer(out), nil
}

// moduleRefusal turns a module's gRPC answer into the Connect error the page
// receives: a refusal of the page's own request keeps its code and the module's reason; anything else —
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
