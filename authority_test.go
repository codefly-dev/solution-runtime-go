package solution

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// interfaceAuthority answers the authority interface: it checks one known Work
// Context, the one the edge sends a request with for the page, and records
// every issue it is asked.
type interfaceAuthority struct {
	authorityv1.UnimplementedAuthorityServiceServer
	mu     sync.Mutex
	issued []*authorityv1.IssueRequest
}

// edgeContext is the person's Work Context the edge sends the page.
const edgeContext = "edge-context-for-the-page"

func (a *interfaceAuthority) Check(_ context.Context, r *authorityv1.CheckRequest) (*authorityv1.CheckResponse, error) {
	if r.GetToken() != edgeContext || r.GetAudience() != "page" {
		return nil, status.Error(codes.Unauthenticated, "not a context for this audience")
	}
	return &authorityv1.CheckResponse{Context: &authorityv1.WorkContextV1{TenantId: "org-from-the-authority", OwnerPrincipalId: "person-1", SessionId: "session-1", Audience: "page"}}, nil
}

func (a *interfaceAuthority) Issue(_ context.Context, r *authorityv1.IssueRequest) (*authorityv1.IssueResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.issued = append(a.issued, proto.Clone(r).(*authorityv1.IssueRequest))
	if r.GetOperationBindingId() == "refused" {
		return nil, status.Error(codes.PermissionDenied, "person-1 holds nothing through that binding")
	}
	return &authorityv1.IssueResponse{
		Token:         "issued-" + r.GetOperationBindingId(),
		ExpiresAtUnix: time.Now().Add(5 * time.Minute).Unix(),
		Context:       &authorityv1.WorkContextV1{TenantId: "org-from-the-authority", OwnerPrincipalId: "person-1"},
	}, nil
}

func (a *interfaceAuthority) asked() []*authorityv1.IssueRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*authorityv1.IssueRequest(nil), a.issued...)
}

// authorityServer is a Server composed with the stand-in authority, as a
// composition naming authority/endpoint composes it.
func authorityServer(t *testing.T) (*Server, *interfaceAuthority) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	stand := &interfaceAuthority{}
	g := grpc.NewServer()
	authorityv1.RegisterAuthorityServiceServer(g, stand)
	go func() { _ = g.Serve(l) }()
	t.Cleanup(g.Stop)
	credential := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(credential, []byte("workload-credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	host, err := dialAuthority("grpc://"+l.Addr().String(), credential, "page")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	return &Server{manifest: Manifest{ID: "page"}, host: host}, stand
}

// Who a request is for is the authority's Check of the Work Context the edge
// sent it with: a header the request wrote about itself names nothing, a
// context the authority does not check is refused before the handler runs, and
// a bearer alone is no viewer, since no session bearer reaches the page.
func TestUnderTheAuthorityTheViewerIsTheEdgesWorkContext(t *testing.T) {
	s, _ := authorityServer(t)
	var seen *Gateway
	handler := s.wrapRequest(func(_ *http.Request, gw *Gateway) (any, error) {
		seen = gw
		return map[string]string{"ok": "yes"}, nil
	})
	request := httptest.NewRequest(http.MethodGet, "/v1/page/types", nil)
	request.Header.Set(WorkContextHeader, edgeContext)
	request.Header.Set(orgHeader, "org-the-caller-wrote")
	answer := httptest.NewRecorder()
	handler(answer, request)
	if answer.Code != http.StatusOK || seen == nil || seen.OrgID() != "org-from-the-authority" || seen.sessionID != "session-1" || seen.parentContext != edgeContext {
		t.Fatalf("answered %d with %+v", answer.Code, seen)
	}
	for name, header := range map[string]http.Header{
		"no Work Context":        {},
		"a forged Work Context":  {http.CanonicalHeaderKey(WorkContextHeader): {"forged"}},
		"a session bearer alone": {"Authorization": {"Bearer viewer-session"}},
	} {
		request := httptest.NewRequest(http.MethodGet, "/v1/page/types", nil)
		request.Header = header
		answer := httptest.NewRecorder()
		handler(answer, request)
		if answer.Code != http.StatusUnauthorized {
			t.Errorf("%s answered %d", name, answer.Code)
		}
	}
}

// ForParent's Work Context is a child of the edge's, issued by the authority
// through the named binding with this workload as actor, held until it is due
// for renewal; ForBinding's is this module's own, in the viewer's organization.
// A person's call never goes by ForModule under the authority.
func TestUnderTheAuthorityEveryWorkContextIsIssued(t *testing.T) {
	s, stand := authorityServer(t)
	gw := s.gatewayFor(http.Header{})
	gw.parentContext, gw.orgID, gw.sessionID = edgeContext, "org-from-the-authority", "session-1"
	ctx := context.Background()

	viewer, err := gw.ForParent(ctx, "documents-read", Scope{ResourceKind: "documents", Actions: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := viewer.WorkContext(ctx)
	if err != nil || token != "issued-documents-read" {
		t.Fatalf("child token %q: %v", token, err)
	}
	if again, _ := viewer.WorkContext(ctx); again != token || len(stand.asked()) != 1 {
		t.Fatalf("a held Work Context was issued again: %d issues", len(stand.asked()))
	}
	asked := stand.asked()[0]
	if asked.GetParentToken() != edgeContext || asked.GetActor().GetCredential() != "workload-credential" || asked.GetOperationBindingId() != "documents-read" ||
		asked.GetAudience() != "" || len(asked.GetScopes()) != 1 || asked.GetScopes()[0].GetResourceKind() != "documents" {
		t.Fatalf("child issue asked %v", asked)
	}

	own, err := gw.ForBinding(ctx, "records-types")
	if err != nil {
		t.Fatal(err)
	}
	if token, err := own.WorkContext(ctx); err != nil || token != "issued-records-types" {
		t.Fatalf("binding token %q: %v", token, err)
	}
	asked = stand.asked()[1]
	if asked.GetWorkload().GetCredential() != "workload-credential" || asked.GetOrganizationId() != "org-from-the-authority" || asked.GetOperationBindingId() != "records-types" {
		t.Fatalf("binding issue asked %v", asked)
	}

	if _, err := gw.ForParent(ctx, "refused", Scope{ResourceKind: "documents", Actions: []string{"read"}}); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a refused issue was not a refusal: %v", err)
	}
	gw.ceilings = map[string][]Scope{}
	if _, err := gw.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}}); err == nil || !strings.Contains(err.Error(), "ForParent") {
		t.Fatalf("ForModule under the authority: %v", err)
	}
	if _, err := gw.WorkContext(ctx); err == nil {
		t.Fatal("a gateway with no ask handed out a Work Context")
	}
	// A request the edge did not send carries no parent to issue a child of.
	bare := s.gatewayFor(http.Header{})
	if _, err := bare.ForParent(ctx, "documents-read"); err == nil {
		t.Fatal("ForParent issued a child of no context")
	}
}

// A composition that names the authority needs no saas gateway and no broker
// credential; one that names neither still refuses to start.
func TestAConfigNamingTheAuthorityNeedsNoGateway(t *testing.T) {
	cfg := config{port: "8080", profile: "local", authorityEndpoint: "127.0.0.1:1", requiresAuthority: true}
	if err := cfg.validate(); err != nil {
		t.Fatalf("a composition naming the authority was refused: %v", err)
	}
	cfg.authorityEndpoint = ""
	if err := cfg.validate(); err == nil || !strings.Contains(err.Error(), "gateway") {
		t.Fatalf("a composition naming neither started: %v", err)
	}
}

// ForBinding is the authority's alone.
func TestForBindingWithoutTheAuthorityIsRefused(t *testing.T) {
	gw := newGateway("https://gateway.test", "Bearer viewer-session", "org", "session")
	if _, err := gw.ForBinding(context.Background(), "records-types"); err == nil || !strings.Contains(err.Error(), "authority/endpoint") {
		t.Fatalf("ForBinding without the authority: %v", err)
	}
}
