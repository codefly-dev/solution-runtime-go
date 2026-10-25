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
	"strings"
	"time"

	"connectrpc.com/connect"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	hop "github.com/codefly-dev/authority/libraries/hop/go"
	"github.com/codefly-dev/sdk-go/workcontext"
	"google.golang.org/grpc"
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

// ErrAuthorityUnavailable is a request the authority could not be asked about:
// it did not answer, or failed. Nobody refused it, so it is not answered as a
// sign-in (401) but 503, by this name; the transport's own text, which can
// name an address, goes to the log.
var ErrAuthorityUnavailable = errors.New("the authority could not be reached to check this request; try again")

// hostAuthority is the runtime's connection to the authority interface.
type hostAuthority struct {
	conn      *grpc.ClientConn
	authority authorityv1.AuthorityServiceClient
	// principal is this module's: the audience a context the edge sends it is
	// addressed to.
	principal string
	// outbound is the hop library's issue, over the authority's generated
	// client, with this workload's credential as the run attests it, read on
	// every call so a rotation takes effect. Every Work Context this runtime
	// acts under is asked through it.
	outbound hop.Outbound
	// advisory is hop/ENFORCEMENT=warn: the route check is asked as advice,
	// and a route the call does not hold is let through with the authority's
	// reason logged. A Work Context the authority does not check is refused
	// either way.
	advisory bool
}

// dialAuthority connects to the authority at endpoint. Every person's Work
// Context and this workload's credential travel on it, so where it may go is
// the SDK's one rule for a credential's destination, as for every relayed
// module (dialModule): https anywhere; cleartext to a loopback host on a local
// run, or to an in-cluster address the mesh carries.
func dialAuthority(endpoint string, transport workcontext.TransportSource, tokenFile, principal string, advisory bool) (*hostAuthority, error) {
	target := strings.TrimSpace(endpoint)
	for _, scheme := range []string{"http://", "tcp://"} {
		target = strings.TrimPrefix(target, scheme)
	}
	if target == "" {
		return nil, fmt.Errorf("%s/%s names no address", AuthorityInterfaceGroup, AuthorityEndpointKey)
	}
	conn, err := dialModule(target, transport, AuthorityInterfaceGroup+"/"+AuthorityEndpointKey)
	if err != nil {
		return nil, fmt.Errorf("%s/%s: %w", AuthorityInterfaceGroup, AuthorityEndpointKey, err)
	}
	authority := authorityv1.NewAuthorityServiceClient(conn)
	return &hostAuthority{
		conn:      conn,
		authority: authority,
		principal: principal,
		advisory:  advisory,
		outbound:  hop.Outbound{Authority: authority, Credential: hop.FileCredential(tokenFile)},
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
	if err != nil {
		log.Printf("the authority's Check of %q failed: %v", route, err)
		return nil, ErrAuthorityUnavailable
	}
	if checked.GetContext().GetTenantId() == "" {
		return nil, fmt.Errorf("%w: the authority named no organization for it", ErrNoViewer)
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

// issueChild asks the authority, through the hop library's Outbound, for a
// child of the viewer's Work Context through one of this module's bindings:
// the audience is the binding's, and the scopes the binding's invoke ceiling
// narrowed to what was asked and to what the person holds there.
func (h *hostAuthority) issueChild(ctx context.Context, parent, binding string, scopes []workContextScope) (string, time.Time, WorkContextPrincipals, error) {
	asked := make([]*authorityv1.WorkScopeV1, 0, len(scopes))
	for _, scope := range scopes {
		asked = append(asked, &authorityv1.WorkScopeV1{ResourceKind: scope.ResourceKind, Actions: scope.Actions, ResourceIds: scope.ResourceIDs})
	}
	ctx, cancel := context.WithTimeout(ctx, authorityCallTimeout)
	defer cancel()
	return held(h.outbound.IssueForParent(ctx, parent, binding, hop.Scopes(asked...)))
}

// issueForBinding asks the authority, through Outbound, for this module's own
// Work Context through one of its declared bindings, in the viewer's
// organization: the binding's headless scopes, with no person in it.
func (h *hostAuthority) issueForBinding(ctx context.Context, organization, binding string) (string, time.Time, WorkContextPrincipals, error) {
	ctx, cancel := context.WithTimeout(ctx, authorityCallTimeout)
	defer cancel()
	return held(h.outbound.IssueForModule(ctx, organization, binding))
}

// held is an issue as the gateway's cache holds it: the token, the instant to
// renew it by, and whom the authority issued it for; or the authority's
// refusal, answered with its status and reason.
func held(issued hop.Issued, err error) (string, time.Time, WorkContextPrincipals, error) {
	if err != nil {
		var carrier interface{ GRPCStatus() *status.Status }
		if !errors.As(err, &carrier) {
			// Not the authority's answer: the credential could not be read,
			// which names its own cause.
			return "", time.Time{}, WorkContextPrincipals{}, err
		}
		st := carrier.GRPCStatus()
		refusal := &WorkContextRefusal{StatusCode: refusalStatus(st.Err()), code: connect.Code(st.Code())}
		// The authority's reason for refusing the ask is the refusal's; a
		// failure to reach it is nobody's refusal, and its text, which can name
		// an address, is not kept.
		if refusal.StatusCode < http.StatusInternalServerError {
			refusal.Reason = st.Message()
		}
		return "", time.Time{}, WorkContextPrincipals{}, refusal
	}
	principals, _ := principalsOf(issued.Context)
	lifetime := time.Until(issued.ExpiresAt)
	if issued.Token == "" || lifetime < workContextMinimumLifetime {
		return "", time.Time{}, WorkContextPrincipals{}, errors.New("the authority issued no usable Work Context")
	}
	lead := workContextRenewal
	if half := lifetime / 2; half < lead {
		lead = half
	}
	return issued.Token, issued.ExpiresAt.Add(-lead), principals, nil
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
