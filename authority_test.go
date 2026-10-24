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
	sessionv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/session/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpcmetadata "google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// interfaceAuthority answers the session and authority interfaces for one known
// bearer, and records every issue it is asked.
type interfaceAuthority struct {
	sessionv1.UnimplementedSessionServiceServer
	authorityv1.UnimplementedAuthorityServiceServer
	mu     sync.Mutex
	issued []*authorityv1.IssueRequest
	bearer []string
}

const sessionBearer = "Bearer viewer-session"

func authorityBearerOf(ctx context.Context) string {
	md, _ := grpcmetadata.FromIncomingContext(ctx)
	if values := md.Get("authorization"); len(values) == 1 {
		return values[0]
	}
	return ""
}

func (a *interfaceAuthority) Current(ctx context.Context, _ *sessionv1.CurrentRequest) (*sessionv1.Session, error) {
	if authorityBearerOf(ctx) != sessionBearer {
		return nil, status.Error(codes.Unauthenticated, "no session")
	}
	return &sessionv1.Session{SessionId: "session-1", PersonId: "person-1", OrganizationId: "org-from-the-authority"}, nil
}

func (a *interfaceAuthority) Issue(ctx context.Context, r *authorityv1.IssueRequest) (*authorityv1.IssueResponse, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.issued = append(a.issued, proto.Clone(r).(*authorityv1.IssueRequest))
	a.bearer = append(a.bearer, authorityBearerOf(ctx))
	if r.GetAudience() == "refused" {
		return nil, status.Error(codes.PermissionDenied, "person-1 holds nothing there")
	}
	return &authorityv1.IssueResponse{
		Token:         "issued-" + r.GetAudience() + r.GetOperationBindingId(),
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
	sessionv1.RegisterSessionServiceServer(g, stand)
	authorityv1.RegisterAuthorityServiceServer(g, stand)
	go func() { _ = g.Serve(l) }()
	t.Cleanup(g.Stop)
	credential := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(credential, []byte("workload-credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	host, err := dialAuthority("grpc://"+l.Addr().String(), credential)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	return &Server{manifest: Manifest{ID: "page"}, host: host}, stand
}

// Who a request is for is the authority's answer about its bearer: a header the
// request wrote names nothing, and a bearer the authority does not know is
// refused before the handler runs.
func TestUnderTheAuthorityTheViewerIsTheSessionTheBearerBelongsTo(t *testing.T) {
	s, _ := authorityServer(t)
	var seen *Gateway
	handler := s.wrapRequest(func(_ *http.Request, gw *Gateway) (any, error) {
		seen = gw
		return map[string]string{}, nil
	})
	request := httptest.NewRequest(http.MethodGet, "/v1/page/types", nil)
	request.Header.Set("authorization", sessionBearer)
	request.Header.Set(orgHeader, "org-the-caller-wrote")
	request.Header.Set(sessionHeader, "session-the-caller-wrote")
	answer := httptest.NewRecorder()
	handler(answer, request)
	if answer.Code != http.StatusOK || seen == nil || seen.OrgID() != "org-from-the-authority" || seen.sessionID != "session-1" {
		t.Fatalf("answered %d with org %q", answer.Code, seen.OrgID())
	}
	seen = nil
	forged := httptest.NewRequest(http.MethodGet, "/v1/page/types", nil)
	forged.Header.Set("authorization", "Bearer not-a-session")
	forged.Header.Set(orgHeader, "org-the-caller-wrote")
	answer = httptest.NewRecorder()
	handler(answer, forged)
	if answer.Code != http.StatusUnauthorized || seen != nil {
		t.Fatalf("an unknown bearer answered %d and reached the handler: %v", answer.Code, seen != nil)
	}
}

// ForModule's Work Context is the viewer's, issued by the authority with the
// viewer's bearer, and held until it is due for renewal; ForBinding's is this
// module's own, issued with its workload credential in the viewer's
// organization through the named binding.
func TestUnderTheAuthorityEveryWorkContextIsIssued(t *testing.T) {
	s, stand := authorityServer(t)
	gw := s.gatewayFor(http.Header{"Authorization": {sessionBearer}})
	gw.orgID, gw.sessionID = "org-from-the-authority", "session-1"
	ctx := context.Background()

	viewer, err := gw.ForModule(ctx, "records", Scope{ResourceKind: "records.types", Actions: []string{"read"}})
	if err != nil {
		t.Fatal(err)
	}
	token, err := viewer.WorkContext(ctx)
	if err != nil || token != "issued-records" {
		t.Fatalf("viewer token %q: %v", token, err)
	}
	if again, _ := viewer.WorkContext(ctx); again != token || len(stand.asked()) != 1 {
		t.Fatalf("a held Work Context was issued again: %d issues", len(stand.asked()))
	}
	asked := stand.asked()[0]
	if asked.GetPerson() == nil || asked.GetAudience() != "records" || stand.bearer[0] != sessionBearer ||
		len(asked.GetScopes()) != 1 || asked.GetScopes()[0].GetResourceKind() != "records.types" {
		t.Fatalf("viewer issue asked %v with bearer %q", asked, stand.bearer[0])
	}

	// The published contract's ceilings govern what a viewer is asked for; a
	// binding ask names no scopes and is held to the binding by the authority.
	gw.ceilings = map[string][]Scope{
		"records": {{ResourceKind: "records.types", Actions: []string{"read"}}},
		"refused": {{ResourceKind: "documents", Actions: []string{"read"}}},
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

	if _, err := gw.ForModule(ctx, "refused", Scope{ResourceKind: "documents", Actions: []string{"read"}}); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("a refused issue was not a refusal: %v", err)
	}
	if _, err := gw.WorkContext(ctx); err == nil {
		t.Fatal("a gateway with no ask handed out a Work Context")
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
	gw := newGateway("https://gateway.test", sessionBearer, "org", "session")
	if _, err := gw.ForBinding(context.Background(), "records-types"); err == nil || !strings.Contains(err.Error(), "authority/endpoint") {
		t.Fatalf("ForBinding without the authority: %v", err)
	}
}

// Under the authority, a solution that publishes no ceiling (a module page) is
// bounded by the authority alone; an empty ask is still refused before it
// reaches the authority, and a solution that publishes ceilings stays held to
// them.
func TestUnderTheAuthorityAnUnpublishedCeilingIsTheAuthoritys(t *testing.T) {
	s, stand := authorityServer(t)
	gw := s.gatewayFor(http.Header{"Authorization": {sessionBearer}})
	gw.orgID, gw.sessionID = "org-from-the-authority", "session-1"
	gw.ceilings = map[string][]Scope{}
	ctx := context.Background()
	viewer, err := gw.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
	if err != nil {
		t.Fatalf("a page's viewer read was refused locally: %v", err)
	}
	if token, err := viewer.WorkContext(ctx); err != nil || token != "issued-documents" || len(stand.asked()) != 1 {
		t.Fatalf("the authority was not asked: %q, %v", token, err)
	}
	if _, err := gw.ForModule(ctx, "documents"); err == nil {
		t.Fatal("an ask for nothing reached the authority")
	}
	gw.ceilings = map[string][]Scope{"records": {{ResourceKind: "records.types", Actions: []string{"read"}}}}
	if _, err := gw.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}}); err == nil {
		t.Fatal("a solution publishing ceilings asked outside them")
	}
}
