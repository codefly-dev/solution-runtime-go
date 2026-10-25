package solution

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// The authority interface (codefly-dev/authority): the authority gateway on a
// laptop, the host in a cell. The composition names it (authority/endpoint),
// and the page is reached through the authority's edge, which signs the person
// in and sends each request on with the person's Work Context addressed to
// this module. The runtime holds no session bearer: it asks the authority's
// Check who that context is for, and every call it makes to a module is issued
// by the authority as a child of that context through one of this module's
// bindings (ForParent), or as this module's own work (ForBinding). The runtime
// mints nothing.
const (
	// AuthorityInterfaceGroup and AuthorityEndpointKey name where the
	// composition says which authority answers.
	AuthorityInterfaceGroup = "authority"
	AuthorityEndpointKey    = "endpoint"
	// EnforcementGroup and EnforcementKey are the composition's one switch for
	// a permissive run, hop/ENFORCEMENT, which the authority's hop reads too:
	// "warn" makes the route check advisory, anything else enforces it. A
	// developer's composition says so; a cell never does.
	EnforcementGroup = "hop"
	EnforcementKey   = "ENFORCEMENT"
	// authorityCallTimeout bounds one call to the authority.
	authorityCallTimeout = 10 * time.Second
)

// WorkContextHeader carries the person's Work Context the edge sends a request
// on with.
const WorkContextHeader = "x-codefly-work-context"

// ErrNoViewer is a request whose Work Context the authority does not check.
var ErrNoViewer = errors.New("the authority does not check the Work Context this request carries for this module")

// ErrRequestRefused is a request the authority refuses the Work Context it
// carries for: the route's delivered policy is not held, the route declares
// none or is not served, or the context no longer stands. Answered 403, with
// the authority's reason.
var ErrRequestRefused = errors.New("the authority refuses this request")

// hostAuthority is the runtime's connection to the authority interface.
type hostAuthority struct {
	conn      *grpc.ClientConn
	authority authorityv1.AuthorityServiceClient
	// principal is this module's: the audience a context the edge sends it is
	// addressed to.
	principal string
	// credential is this workload's credential as the run attests it, read on
	// every call so a rotation takes effect.
	credential func() (string, error)
	// advisory is hop/ENFORCEMENT=warn: the route check is asked as advice,
	// and a route the call does not hold is let through with the authority's
	// reason logged. A Work Context the authority does not check is refused
	// either way.
	advisory bool
}

// dialAuthority connects to the authority at endpoint. The connection is
// in-cell transport, which the mesh carries; the runtime terminates no TLS to
// it.
func dialAuthority(endpoint, tokenFile, principal string, advisory bool) (*hostAuthority, error) {
	target := strings.TrimSpace(endpoint)
	for _, scheme := range []string{"grpc://", "http://", "tcp://"} {
		target = strings.TrimPrefix(target, scheme)
	}
	if target == "" {
		return nil, fmt.Errorf("%s/%s names no address", AuthorityInterfaceGroup, AuthorityEndpointKey)
	}
	conn, err := grpc.NewClient(target, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("%s/%s: %w", AuthorityInterfaceGroup, AuthorityEndpointKey, err)
	}
	return &hostAuthority{
		conn:      conn,
		authority: authorityv1.NewAuthorityServiceClient(conn),
		principal: principal,
		advisory:  advisory,
		credential: func() (string, error) {
			raw, err := os.ReadFile(tokenFile)
			if err != nil || strings.TrimSpace(string(raw)) == "" {
				return "", fmt.Errorf("this workload's credential at %s is missing or empty (declare module-identity)", tokenFile)
			}
			return strings.TrimSpace(string(raw)), nil
		},
	}, nil
}

// viewer asks the authority's Check whose the Work Context a request carries
// is, addressed to this module, and, when route is named, whether it holds
// what this module's delivery declares for that route: "<VERB> <path>", the
// request as this module serves it, which the authority matches against the
// "<VERB> <template>" rows the CLI derives from the published contract. A
// context the authority does not check is no viewer, whatever it claims.
func (h *hostAuthority) viewer(ctx context.Context, workContext, route string) (*authorityv1.WorkContextV1, error) {
	ctx, cancel := context.WithTimeout(ctx, authorityCallTimeout)
	defer cancel()
	checked, err := h.authority.Check(ctx, &authorityv1.CheckRequest{Token: workContext, Audience: h.principal, Method: route, Advisory: h.advisory && route != ""})
	if err != nil && refusalStatus(err) < http.StatusInternalServerError {
		if status.Code(err) == codes.Unauthenticated {
			return nil, fmt.Errorf("%w: %s", ErrNoViewer, status.Convert(err).Message())
		}
		return nil, fmt.Errorf("%w: %s", ErrRequestRefused, status.Convert(err).Message())
	}
	if err != nil || checked.GetContext().GetTenantId() == "" {
		return nil, ErrNoViewer
	}
	if advice := checked.GetRefusal(); advice != "" {
		log.Printf("PERMISSIVE (%s/%s=warn): let through %s, which the authority refused: %s", EnforcementGroup, EnforcementKey, route, advice)
	}
	return checked.GetContext(), nil
}

// principalsOf is whom a Work Context the authority answered is for: its
// organization, its owner, and the actor chain in order, the current actor
// last; with no actor in the chain the owner acts.
func principalsOf(wc *authorityv1.WorkContextV1) (WorkContextPrincipals, []string) {
	principals := WorkContextPrincipals{OrgID: wc.GetTenantId(), OwnerPrincipalID: wc.GetOwnerPrincipalId(), CurrentActorPrincipalID: wc.GetOwnerPrincipalId()}
	var actors []string
	for _, actor := range wc.GetActorChain() {
		actors = append(actors, actor.GetPrincipalId())
	}
	if len(actors) > 0 {
		principals.CurrentActorPrincipalID = actors[len(actors)-1]
	}
	return principals, actors
}

// issueChild asks the authority for a child of the viewer's Work Context
// through one of this module's bindings: the audience is the binding's, and the
// scopes the binding's invoke ceiling narrowed to what was asked and to what
// the person holds there.
func (h *hostAuthority) issueChild(ctx context.Context, parent, binding string, scopes []workContextScope) (string, time.Time, WorkContextPrincipals, error) {
	credential, err := h.credential()
	if err != nil {
		return "", time.Time{}, WorkContextPrincipals{}, err
	}
	req := &authorityv1.IssueRequest{
		As:                 &authorityv1.IssueRequest_ParentToken{ParentToken: parent},
		Actor:              &authorityv1.WorkloadCredential{Credential: credential},
		OperationBindingId: binding,
	}
	for _, scope := range scopes {
		req.Scopes = append(req.Scopes, &authorityv1.WorkScopeV1{ResourceKind: scope.ResourceKind, Actions: scope.Actions, ResourceIds: scope.ResourceIDs})
	}
	return h.issue(ctx, req)
}

// issueForBinding asks the authority for this module's own Work Context
// through one of its declared bindings, in the viewer's organization: the
// binding's headless scopes, with no person in it.
func (h *hostAuthority) issueForBinding(ctx context.Context, organization, binding string) (string, time.Time, WorkContextPrincipals, error) {
	credential, err := h.credential()
	if err != nil {
		return "", time.Time{}, WorkContextPrincipals{}, err
	}
	return h.issue(ctx, &authorityv1.IssueRequest{
		As:                 &authorityv1.IssueRequest_Workload{Workload: &authorityv1.WorkloadCredential{Credential: credential}},
		OrganizationId:     organization,
		OperationBindingId: binding,
	})
}

func (h *hostAuthority) issue(ctx context.Context, req *authorityv1.IssueRequest) (string, time.Time, WorkContextPrincipals, error) {
	ctx, cancel := context.WithTimeout(ctx, authorityCallTimeout)
	defer cancel()
	issued, err := h.authority.Issue(ctx, req)
	if err != nil {
		refusal := &WorkContextRefusal{Audience: req.GetAudience(), StatusCode: refusalStatus(err), code: connect.Code(status.Code(err))}
		// The authority's reason for refusing the ask is the refusal's; a
		// failure to reach it is nobody's refusal, and its text, which can name
		// an address, is not kept.
		if refusal.StatusCode < http.StatusInternalServerError {
			refusal.Reason = status.Convert(err).Message()
		}
		return "", time.Time{}, WorkContextPrincipals{}, refusal
	}
	principals, _ := principalsOf(issued.GetContext())
	expires := time.Unix(issued.GetExpiresAtUnix(), 0)
	lifetime := time.Until(expires)
	if issued.GetToken() == "" || lifetime < workContextMinimumLifetime {
		return "", time.Time{}, WorkContextPrincipals{}, fmt.Errorf("the authority issued no usable Work Context for %q", req.GetAudience())
	}
	lead := workContextRenewal
	if half := lifetime / 2; half < lead {
		lead = half
	}
	return issued.GetToken(), expires.Add(-lead), principals, nil
}

func (h *hostAuthority) Close() error { return h.conn.Close() }

// refusalStatus is the HTTP status an authority refusal answers a page with.
func refusalStatus(err error) int {
	switch status.Code(err) {
	case codes.Unauthenticated:
		return http.StatusUnauthorized
	case codes.PermissionDenied, codes.NotFound, codes.FailedPrecondition:
		return http.StatusForbidden
	case codes.Unavailable, codes.DeadlineExceeded:
		return http.StatusServiceUnavailable
	}
	return http.StatusBadGateway
}

// ForParent is the viewer's own call to a module: a child of the Work Context
// the edge sent this request with, through one of this module's declared
// bindings. The authority derives the audience from the binding and grants
// within the binding's invoke ceiling and what the person holds there; scopes
// narrow it further. The binding is the ceiling, so there is no ceiling of this
// runtime's own to hold the ask to.
func (g *Gateway) ForParent(ctx context.Context, binding string, scopes ...Scope) (*Gateway, error) {
	if g.host == nil || g.parentContext == "" {
		return nil, errors.New("ForParent is issued by the authority interface, as a child of the Work Context the edge sends a request with; this request carries none")
	}
	acting := *g
	wire := askedScopesOf(scopes)
	sum := sha256.Sum256([]byte(g.parentContext))
	key, _ := json.Marshal(wire)
	acting.delegation = &delegation{key: "parent\x00" + hex.EncodeToString(sum[:]) + "\x00" + binding + "\x00" + string(key), ask: issueAsk{organization: g.orgID, binding: binding, scopes: wire, child: true}}
	if _, err := acting.workContext(ctx); err != nil {
		return nil, g.surfaced(err)
	}
	return &acting, nil
}

// WorkContext is the Work Context this gateway acts under, issued (and renewed)
// for ForParent's or ForBinding's ask: what a caller presents to the module it
// reaches itself, over gRPC through the hop. The gateway a handler is given
// acts under the edge's context, which is never forwarded as it is.
func (g *Gateway) WorkContext(ctx context.Context) (string, error) {
	if g.delegation == nil {
		return "", errors.New("this gateway acts under no Work Context of its own: call ForParent or ForBinding first")
	}
	return g.workContext(ctx)
}

// ForBinding is this module's own work: a Work Context through one of its
// declared bindings, in the viewer's organization, carrying the binding's
// headless scopes and no person.
func (g *Gateway) ForBinding(ctx context.Context, binding string) (*Gateway, error) {
	if g.host == nil {
		return nil, errors.New("ForBinding is issued by the authority interface; this gateway was built outside a boot")
	}
	if g.orgID == "" {
		return nil, &ClientError{StatusCode: http.StatusConflict, Message: "no organization selected"}
	}
	acting := *g
	acting.delegation = &delegation{key: "binding\x00" + g.orgID + "\x00" + binding, ask: issueAsk{organization: g.orgID, binding: binding}}
	if _, err := acting.workContext(ctx); err != nil {
		return nil, g.surfaced(err)
	}
	return &acting, nil
}
