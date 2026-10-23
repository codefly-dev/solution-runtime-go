package solution

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	grpcmetadata "google.golang.org/grpc/metadata"
)

// The authority interface (codefly-dev/authority): the authority gateway on a
// laptop, the host in a cell. When the composition names one
// (authority/endpoint), the runtime asks it everything it otherwise asks the
// saas gateway: who a request's bearer is (session Current) and the Work
// Context a call to a module carries (authority Issue). No gateway stands in
// front of the page, so nothing is read from a header the request wrote, and
// the runtime mints nothing.
const (
	// AuthorityInterfaceGroup and AuthorityEndpointKey name where the
	// composition says which authority answers.
	AuthorityInterfaceGroup = "authority"
	AuthorityEndpointKey    = "endpoint"
	// authorityCallTimeout bounds one call to the authority.
	authorityCallTimeout = 10 * time.Second
)

// ErrNoViewer is a request whose bearer the authority does not know.
var ErrNoViewer = errors.New("the authority knows no session for this bearer")

// hostAuthority is the runtime's connection to the authority interface.
type hostAuthority struct {
	conn      *grpc.ClientConn
	authority authorityv1.AuthorityServiceClient
	session   sessionv1.SessionServiceClient
	// credential is this workload's credential as the run attests it, read on
	// every call so a rotation takes effect.
	credential func() (string, error)
}

// dialAuthority connects to the authority at endpoint. The connection is
// in-cell transport, which the mesh carries; the runtime terminates no TLS to
// it.
func dialAuthority(endpoint, tokenFile string) (*hostAuthority, error) {
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
		session:   sessionv1.NewSessionServiceClient(conn),
		credential: func() (string, error) {
			raw, err := os.ReadFile(tokenFile)
			if err != nil || strings.TrimSpace(string(raw)) == "" {
				return "", fmt.Errorf("this workload's credential at %s is missing or empty (declare module-identity)", tokenFile)
			}
			return strings.TrimSpace(string(raw)), nil
		},
	}, nil
}

// withBearer carries the request's bearer on a call to the authority.
func withBearer(ctx context.Context, bearer string) context.Context {
	return grpcmetadata.AppendToOutgoingContext(ctx, "authorization", bearer)
}

// viewer asks the authority who bearer is.
func (h *hostAuthority) viewer(ctx context.Context, bearer string) (*sessionv1.Session, error) {
	ctx, cancel := context.WithTimeout(ctx, authorityCallTimeout)
	defer cancel()
	sess, err := h.session.Current(withBearer(ctx, bearer), &sessionv1.CurrentRequest{})
	if err != nil || sess.GetOrganizationId() == "" {
		return nil, ErrNoViewer
	}
	return sess, nil
}

// issueForViewer asks the authority for the viewer's Work Context at one
// audience, within the scopes asked: what ForModule's gateway carries.
func (h *hostAuthority) issueForViewer(ctx context.Context, bearer string, ask startTaskRequest) (string, time.Time, WorkContextPrincipals, error) {
	req := &authorityv1.IssueRequest{
		As:       &authorityv1.IssueRequest_Person{Person: &authorityv1.PersonSession{}},
		Audience: ask.Audience,
	}
	for _, scope := range ask.AuthorityScopes {
		req.Scopes = append(req.Scopes, &authorityv1.WorkScopeV1{ResourceKind: scope.ResourceKind, Actions: scope.Actions})
	}
	return h.issue(withBearer(ctx, bearer), req)
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
		return "", time.Time{}, WorkContextPrincipals{}, &WorkContextRefusal{Audience: req.GetAudience(), StatusCode: refusalStatus(err)}
	}
	wc := issued.GetContext()
	principals := WorkContextPrincipals{OrgID: wc.GetTenantId(), OwnerPrincipalID: wc.GetOwnerPrincipalId(), CurrentActorPrincipalID: wc.GetOwnerPrincipalId()}
	if chain := wc.GetActorChain(); len(chain) > 0 {
		principals.CurrentActorPrincipalID = chain[len(chain)-1].GetPrincipalId()
	}
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

// WorkContext is the Work Context this gateway acts under, issued (and renewed)
// for ForModule's or ForBinding's ask: what a caller presents to a module it
// reaches itself, over gRPC through the hop for example.
func (g *Gateway) WorkContext(ctx context.Context) (string, error) {
	if g.delegation == nil && g.carriedContext == "" {
		return "", errors.New("this gateway acts under no Work Context: call ForModule or ForBinding first")
	}
	return g.workContext(ctx)
}

// ForBinding is ForModule for this module's own work: a Work Context through
// one of its declared bindings, in the viewer's organization, carrying the
// binding's headless scopes and no person. Only the authority issues one.
func (g *Gateway) ForBinding(ctx context.Context, binding string) (*Gateway, error) {
	if g.host == nil {
		return nil, errors.New("ForBinding is issued by the authority interface; this composition names none (authority/endpoint)")
	}
	if g.orgID == "" {
		return nil, &ClientError{StatusCode: http.StatusConflict, Message: "no organization selected"}
	}
	acting := *g
	acting.delegation = &delegation{key: "binding\x00" + g.orgID + "\x00" + binding, ask: startTaskRequest{OrgID: g.orgID, Binding: binding}}
	if _, err := acting.workContext(ctx); err != nil {
		return nil, g.surfaced(err)
	}
	return &acting, nil
}
