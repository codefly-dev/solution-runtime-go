package solution

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	codefly "github.com/codefly-dev/sdk-go"
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
	mu      sync.Mutex
	issued  []*authorityv1.IssueRequest
	checked []*authorityv1.CheckRequest
	// held, when set, is what robin's child holds of the page's delivered
	// route policy: the rows the CLI derives, "<VERB> <template>". A checked
	// method no row matches is refused with the authority's reason, or, on an
	// advisory check, answered beside the context.
	held []string
	// step, when set, answers a Check at the install step's method: the
	// authority's dedicated step verifier.
	step func(*authorityv1.CheckRequest) (*authorityv1.CheckResponse, error)
}

// edgeContext is the person's Work Context the edge sends the page.
const edgeContext = "edge-context-for-the-page"

// malformedContext is a Work Context the authority refuses as malformed
// (InvalidArgument).
const malformedContext = "malformed-context"

// solutionContext is a person's Work Context at the page as a solution: the
// installation's roles, each selected to the installation's principal.
const solutionContext = "person-through-the-installation"

// installationPrincipal is the principal solutionContext's scopes select.
const installationPrincipal = "installation-principal"

// robinChild is a module's tool call to the page: Maya's Work Context, issued
// by the authority as a child through robin's declared binding, robin acting,
// addressed to the page.
const robinChild = "robin-child-for-the-page"

func (a *interfaceAuthority) Check(_ context.Context, r *authorityv1.CheckRequest) (*authorityv1.CheckResponse, error) {
	a.mu.Lock()
	a.checked = append(a.checked, proto.Clone(r).(*authorityv1.CheckRequest))
	held, step := a.held, a.step
	a.mu.Unlock()
	if r.GetMethod() == installationStepMethod {
		if step == nil {
			return nil, status.Error(codes.PermissionDenied, "not this installation's setup credential")
		}
		return step(r)
	}
	if r.GetToken() == malformedContext {
		return nil, status.Error(codes.InvalidArgument, "the Work Context is not a token the authority can read")
	}
	var wc *authorityv1.WorkContextV1
	switch {
	case r.GetAudience() != "page":
	case r.GetToken() == edgeContext:
		wc = &authorityv1.WorkContextV1{TenantId: "org-from-the-authority", OwnerPrincipalId: "person-1", SessionId: "session-1", Audience: "page"}
	case r.GetToken() == solutionContext:
		wc = &authorityv1.WorkContextV1{TenantId: "org-from-the-authority", OwnerPrincipalId: "person-1", SessionId: "session-1", Audience: "page",
			AuthorityScopes: []*authorityv1.WorkScopeV1{{ResourceKind: "pages", Actions: []string{"read", "write"}, ResourceOwnerId: installationPrincipal}}}
	case r.GetToken() == robinChild:
		wc = &authorityv1.WorkContextV1{TenantId: "org-from-the-authority", OwnerPrincipalId: "maya", Audience: "page",
			ActorChain: []*authorityv1.WorkActorV1{{PrincipalId: "robin", PrincipalKind: "module"}}}
	}
	if wc == nil {
		return nil, status.Error(codes.Unauthenticated, "not a context for this audience")
	}
	if r.GetMethod() != "" && held != nil {
		matched, ambiguous := heldRoute(held, r.GetMethod())
		if ambiguous != "" {
			return nil, status.Error(codes.PermissionDenied, ambiguous)
		}
		if matched {
			return &authorityv1.CheckResponse{Context: wc}, nil
		}
		refusal := "page requires pages:write for " + r.GetMethod() + ", which the call does not hold (it holds pages:read)"
		if !r.GetAdvisory() {
			return nil, status.Error(codes.PermissionDenied, refusal)
		}
		return &authorityv1.CheckResponse{Context: wc, Refusal: refusal}, nil
	}
	return &authorityv1.CheckResponse{Context: wc}, nil
}

// heldRoute is the authority's reading (state.admitMethod) of a checked
// method against the held rows: a row named exactly is that row; otherwise a
// request "<VERB> <path>" is matched against every "<VERB> <template>",
// "{name}" standing for one segment and a trailing "{name=**}" for the rest
// of the path, and two templates matching one path is refused as ambiguous,
// never guessed between. matched reports a held row; ambiguous, when set, is
// the authority's refusal.
func heldRoute(held []string, method string) (matched bool, ambiguous string) {
	if slices.Contains(held, method) {
		return true, ""
	}
	var found []string
	for _, row := range held {
		if routeRowMatches(row, method) {
			found = append(found, row)
		}
	}
	if len(found) > 1 {
		return false, method + " matches more than one declared route (" + strings.Join(found, ", ") + ")"
	}
	return len(found) == 1, ""
}

// routeRowMatches is the authority's routeOf for one row: a request "<VERB>
// <path>" against a declared row "<VERB> <template>", "{name}" standing for
// one non-empty segment and a last "{name=**}" for the rest of the path.
func routeRowMatches(row, request string) bool {
	verb, template, _ := strings.Cut(row, " ")
	got, path, _ := strings.Cut(request, " ")
	if verb != got {
		return false
	}
	want, have := strings.Split(template, "/"), strings.Split(path, "/")
	if last := want[len(want)-1]; strings.HasPrefix(last, "{") && strings.HasSuffix(last, "=**}") {
		if len(have) < len(want) || strings.Join(have[len(want)-1:], "/") == "" {
			return false
		}
		want, have = want[:len(want)-1], have[:len(want)-1]
	}
	if len(want) != len(have) {
		return false
	}
	for i, segment := range want {
		if !(strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") && have[i] != "") && segment != have[i] {
			return false
		}
	}
	return true
}

func (a *interfaceAuthority) checks() []*authorityv1.CheckRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]*authorityv1.CheckRequest(nil), a.checked...)
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

// interfaceAuthorityAt serves the stand-in authority on loopback and returns its
// address, as a composition names it in authority/endpoint.
func interfaceAuthorityAt(t *testing.T) (*interfaceAuthority, string) {
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
	return stand, l.Addr().String()
}

// authorityServer is a Server composed with the stand-in authority, as a
// composition naming authority/endpoint composes it.
func authorityServer(t *testing.T) (*Server, *interfaceAuthority) {
	t.Helper()
	stand, address := interfaceAuthorityAt(t)
	credential := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(credential, []byte("workload-credential"), 0o600); err != nil {
		t.Fatal(err)
	}
	host, err := dialAuthority("grpc://"+address, meshTransport{local: true}, credential, "page", false)
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
	handler := s.wrapRequest("GET /v1/page/types", func(_ *http.Request, gw *Gateway) (any, error) {
		seen = gw
		return map[string]string{"ok": "yes"}, nil
	})
	request := httptest.NewRequest(http.MethodGet, "/v1/page/types", nil)
	request.Header.Set(WorkContextHeader, edgeContext)
	request.Header.Set("x-org-id", "org-the-caller-wrote")
	answer := httptest.NewRecorder()
	handler(answer, request)
	if answer.Code != http.StatusOK || seen == nil || seen.OrgID() != "org-from-the-authority" || seen.parentContext != edgeContext {
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
func TestUnderTheAuthorityEveryWorkContextIsIssued(t *testing.T) {
	s, stand := authorityServer(t)
	gw := s.newGateway()
	gw.parentContext, gw.orgID = edgeContext, "org-from-the-authority"
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
	if _, err := gw.WorkContext(ctx); err == nil {
		t.Fatal("a gateway with no ask handed out a Work Context")
	}
	// A request the edge did not send carries no parent to issue a child of.
	bare := s.newGateway()
	if _, err := bare.ForParent(ctx, "documents-read"); err == nil {
		t.Fatal("ForParent issued a child of no context")
	}
}

// ForBinding is the authority's alone: a gateway built outside a boot has no
// authority to issue it.
func TestForBindingWithoutTheAuthorityIsRefused(t *testing.T) {
	gw := &Gateway{orgID: "org", contexts: newWorkContextCache()}
	if _, err := gw.ForBinding(context.Background(), "records-types"); err == nil || !strings.Contains(err.Error(), "authority") {
		t.Fatalf("ForBinding without the authority: %v", err)
	}
}

// An ask's scopes are copied when it is made: a caller writing through its own
// slice afterwards changes neither the cache key nor what the next issue asks.
func TestAnAskCannotBeEditedAfterItIsMade(t *testing.T) {
	s, stand := authorityServer(t)
	gw := s.newGateway()
	gw.parentContext, gw.orgID = edgeContext, "org-from-the-authority"
	actions := []string{"read"}
	viewer, err := gw.ForParent(context.Background(), "documents-read", Scope{ResourceKind: "documents", Actions: actions})
	if err != nil {
		t.Fatal(err)
	}
	actions[0] = "delete"
	for key, cached := range viewer.contexts.minted {
		cached.reuseUntil = time.Time{}
		viewer.contexts.minted[key] = cached
	}
	if _, err := viewer.WorkContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	asked := stand.asked()
	if len(asked) != 2 || asked[1].GetScopes()[0].GetActions()[0] != "read" {
		t.Fatalf("the renewed issue asked %v, want the read the ask was made with", asked[len(asked)-1].GetScopes())
	}
}

// Row 6: a module calls the page as a tool with the authority-issued child of
// the person's Work Context (owner Maya, actor robin, audience the page). The
// page admits it, and its handler sees Maya as the viewer and robin as the
// module acting for her, both from the authority's Check and never from
// anything the request wrote. A forged or missing context is refused 401.
func TestUnderTheAuthorityAModulesToolCallActsForThePerson(t *testing.T) {
	s, _ := authorityServer(t)
	var principals WorkContextPrincipals
	var actors []string
	ran := 0
	handler := s.wrapRequest("GET /v1/page/pages/{page_id}", func(r *http.Request, gw *Gateway) (any, error) {
		ran++
		var err error
		principals, err = gw.WorkContextPrincipals(r.Context())
		actors = gw.ActorChain()
		return map[string]string{"ok": "yes"}, err
	})
	request := httptest.NewRequest(http.MethodGet, "/v1/page/pages/p-1", nil)
	request.Header.Set(WorkContextHeader, robinChild)
	answer := httptest.NewRecorder()
	handler(answer, request)
	want := WorkContextPrincipals{OrgID: "org-from-the-authority", OwnerPrincipalID: "maya", CurrentActorPrincipalID: "robin"}
	if answer.Code != http.StatusOK || principals != want || !slices.Equal(actors, []string{"robin"}) {
		t.Fatalf("answered %d (%s); the handler saw %+v acting through %v", answer.Code, answer.Body, principals, actors)
	}

	// The person on the page acts for themselves: no module in the chain.
	request = httptest.NewRequest(http.MethodGet, "/v1/page/pages/p-1", nil)
	request.Header.Set(WorkContextHeader, edgeContext)
	answer = httptest.NewRecorder()
	handler(answer, request)
	want = WorkContextPrincipals{OrgID: "org-from-the-authority", OwnerPrincipalID: "person-1", CurrentActorPrincipalID: "person-1"}
	if answer.Code != http.StatusOK || principals != want || len(actors) != 0 {
		t.Fatalf("answered %d; the handler saw %+v acting through %v", answer.Code, principals, actors)
	}

	ran = 0
	for name, header := range map[string]http.Header{
		"no Work Context":              {},
		"a forged Work Context":        {http.CanonicalHeaderKey(WorkContextHeader): {"forged-child"}},
		"an actor the request claimed": {"X-Codefly-Actor": {"robin"}, "X-Codefly-Owner": {"maya"}},
	} {
		request := httptest.NewRequest(http.MethodGet, "/v1/page/pages/p-1", nil)
		request.Header = header
		answer := httptest.NewRecorder()
		handler(answer, request)
		if answer.Code != http.StatusUnauthorized {
			t.Errorf("%s answered %d", name, answer.Code)
		}
	}
	if ran != 0 {
		t.Fatalf("the handler ran %d times for a request the authority did not check", ran)
	}
}

// Row 7: the Check names the operation a request was dispatched to, "<VERB>
// <template>" exactly as the CLI's route-policy row for it is spelled, so the
// authority applies the page's delivered per-route policy to the operation
// that runs, whatever the request's own path reads as. A route the call does
// not hold is refused with the authority's own reason, before the handler
// runs.
func TestUnderTheAuthorityTheCheckNamesTheRoute(t *testing.T) {
	s, stand := authorityServer(t)
	stand.held = []string{"GET /v1/page/pages/{page_id}"}
	ran := 0
	handler := func(*http.Request, *Gateway) (any, error) {
		ran++
		return map[string]string{"ok": "yes"}, nil
	}
	read := s.wrapRequest("GET /v1/page/pages/{page_id}", handler)
	write := s.wrapRequest("POST /v1/page/pages", handler)

	request := httptest.NewRequest(http.MethodGet, "/v1/page/pages/p-1?revision=3", nil)
	request.Header.Set(WorkContextHeader, robinChild)
	answer := httptest.NewRecorder()
	read(answer, request)
	if answer.Code != http.StatusOK || ran != 1 {
		t.Fatalf("a held route answered %d (%s)", answer.Code, answer.Body)
	}
	checked := stand.checks()
	if len(checked) != 1 || checked[0].GetMethod() != "GET /v1/page/pages/{page_id}" || checked[0].GetAudience() != "page" || checked[0].GetAdvisory() {
		t.Fatalf("the check asked %v", checked)
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/page/pages", strings.NewReader(`{}`))
	request.Header.Set(WorkContextHeader, robinChild)
	answer = httptest.NewRecorder()
	write(answer, request)
	if answer.Code != http.StatusForbidden || ran != 1 || !strings.Contains(answer.Body.String(), "page requires pages:write for POST /v1/page/pages") {
		t.Fatalf("a route the call does not hold answered %d (%s), handler ran %d times", answer.Code, answer.Body, ran)
	}
}

// Under hop/ENFORCEMENT=warn the runtime asks the authority's advisory Check, as
// a permissive hop does: a route the call does not hold goes through with the
// authority's reason logged; a Work Context the authority does not check is
// still refused.
func TestUnderAdvisoryEnforcementARefusedRouteIsLoggedAndLetThrough(t *testing.T) {
	s, stand := authorityServer(t)
	s.host.advisory = true
	stand.held = []string{"GET /v1/page/pages/{page_id}"}
	logged := &strings.Builder{}
	log.SetOutput(logged)
	defer log.SetOutput(os.Stderr)
	handler := s.wrapRequest("POST /v1/page/pages", func(*http.Request, *Gateway) (any, error) {
		return map[string]string{"ok": "yes"}, nil
	})

	request := httptest.NewRequest(http.MethodPost, "/v1/page/pages", strings.NewReader(`{}`))
	request.Header.Set(WorkContextHeader, robinChild)
	answer := httptest.NewRecorder()
	handler(answer, request)
	if answer.Code != http.StatusOK {
		t.Fatalf("an advisory refusal answered %d (%s)", answer.Code, answer.Body)
	}
	if checked := stand.checks(); len(checked) != 1 || !checked[0].GetAdvisory() || checked[0].GetMethod() != "POST /v1/page/pages" {
		t.Fatalf("the check asked %v", checked)
	}
	if !strings.Contains(logged.String(), "POST /v1/page/pages") || !strings.Contains(logged.String(), "page requires pages:write") {
		t.Fatalf("the advisory was not logged: %q", logged.String())
	}

	request = httptest.NewRequest(http.MethodPost, "/v1/page/pages", strings.NewReader(`{}`))
	request.Header.Set(WorkContextHeader, "forged-child")
	answer = httptest.NewRecorder()
	handler(answer, request)
	if answer.Code != http.StatusUnauthorized {
		t.Fatalf("a forged context under advisory enforcement answered %d", answer.Code)
	}
}

// hop/ENFORCEMENT is the composition's one switch for a permissive run: warn
// makes the runtime's route check advisory, as it does the hop's; anything else
// enforces.
func TestHopEnforcementWarnMakesTheRouteCheckAdvisory(t *testing.T) {
	for value, advisory := range map[string]bool{"warn": true, " WARN ": true, "enforce": false, "": false} {
		t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__HOP__ENFORCEMENT", value)
		if err := codefly.LoadEnvironmentVariables(); err != nil {
			t.Fatal(err)
		}
		if got := loadConfig(context.Background(), nil).routeAdvisory; got != advisory {
			t.Errorf("hop/ENFORCEMENT=%q: advisory %v, want %v", value, got, advisory)
		}
	}
	t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })
}

// r1 F5: an authority status outside the sign-in and permission classes was
// answered 503 "try again" with its reason only in the log. A malformed
// request (InvalidArgument) is a permanent refusal: it is answered 400 with
// the authority's reason, to a REST caller and a relayed Connect call alike,
// and an outage is still 503.
func TestAMalformedRequestIsRefusedWithTheAuthoritysReason(t *testing.T) {
	s, _ := authorityServer(t)
	ran := false
	handler := s.wrapRequest("GET /v1/page/types", func(*http.Request, *Gateway) (any, error) { ran = true; return nil, nil })
	request := httptest.NewRequest(http.MethodGet, "/v1/page/types", nil)
	request.Header.Set(WorkContextHeader, malformedContext)
	answer := httptest.NewRecorder()
	handler(answer, request)
	if answer.Code != http.StatusBadRequest || ran || !strings.Contains(answer.Body.String(), "not a token the authority can read") {
		t.Fatalf("a malformed request answered %d %s (handler ran: %v)", answer.Code, answer.Body, ran)
	}
	if _, err := s.viewerGateway(context.Background(), malformedContext, "GET /v1/page/types"); !errors.Is(err, ErrRequestInvalid) || errors.Is(err, ErrAuthorityUnavailable) {
		t.Fatalf("viewerGateway = %v, want ErrRequestInvalid", err)
	}
	if got := refusalStatus(status.Error(codes.Unavailable, "down")); got != http.StatusServiceUnavailable {
		t.Fatalf("an outage maps to %d, want 503", got)
	}
}

// A child names the owner its parent's effective scopes select: the current
// actor's granted scopes, or the authority scopes when no actor has hopped.
// The authority holds the child within what that owner holds, so an owner-blind
// ask would read as every owner's resources. Scopes selecting no owner name
// none; scopes selecting two owners name none either, rather than picking one.
func TestTheSelectedOwnerIsTheOneTheEffectiveScopesSelect(t *testing.T) {
	scope := func(owner string) *authorityv1.WorkScopeV1 {
		return &authorityv1.WorkScopeV1{ResourceKind: "pages", Actions: []string{"read"}, ResourceOwnerId: owner}
	}
	for name, c := range map[string]struct {
		wc   *authorityv1.WorkContextV1
		want string
	}{
		"no scopes":          {&authorityv1.WorkContextV1{}, ""},
		"owner-blind scopes": {&authorityv1.WorkContextV1{AuthorityScopes: []*authorityv1.WorkScopeV1{scope("")}}, ""},
		"one owner":          {&authorityv1.WorkContextV1{AuthorityScopes: []*authorityv1.WorkScopeV1{scope("p"), scope(""), scope("p")}}, "p"},
		"two owners":         {&authorityv1.WorkContextV1{AuthorityScopes: []*authorityv1.WorkScopeV1{scope("p"), scope("q")}}, ""},
		"the current actor's, not the owner's": {&authorityv1.WorkContextV1{
			AuthorityScopes: []*authorityv1.WorkScopeV1{scope("p")},
			ActorChain: []*authorityv1.WorkActorV1{
				{PrincipalId: "first", GrantedScopes: []*authorityv1.WorkScopeV1{scope("q")}},
				{PrincipalId: "robin", GrantedScopes: []*authorityv1.WorkScopeV1{scope("r")}},
			}}, "r"},
		"an actor granted no owner": {&authorityv1.WorkContextV1{
			AuthorityScopes: []*authorityv1.WorkScopeV1{scope("p")},
			ActorChain:      []*authorityv1.WorkActorV1{{PrincipalId: "robin", GrantedScopes: []*authorityv1.WorkScopeV1{scope("")}}}}, ""},
	} {
		if got := selectedOwner(c.wc); got != c.want {
			t.Errorf("%s: selected %q, want %q", name, got, c.want)
		}
	}
}

// Every scope of a child of a person's context at an installation names the
// installation's principal, the owner the authority checked that context's
// scopes are selected to; a child of a context selecting no owner names none,
// and a gateway built outside a request names none either.
func TestAChildNamesTheOwnerItsParentIsSelectedTo(t *testing.T) {
	s, stand := authorityServer(t)
	ctx := context.Background()
	ask := []Scope{{ResourceKind: "documents", Actions: []string{"read"}}, {ResourceKind: "documents.collection", Actions: []string{"create"}, ResourceIDs: []string{"c-1"}}}
	for _, c := range []struct{ parent, want string }{{solutionContext, installationPrincipal}, {edgeContext, ""}} {
		gw, err := s.viewerGateway(ctx, c.parent, "")
		if err != nil {
			t.Fatal(err)
		}
		child, err := gw.ForParent(ctx, "documents", ask...)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := child.WorkContext(ctx); err != nil {
			t.Fatal(err)
		}
		asked := stand.asked()
		scopes := asked[len(asked)-1].GetScopes()
		if asked[len(asked)-1].GetParentToken() != c.parent || len(scopes) != 2 {
			t.Fatalf("a child of %s was asked %v", c.parent, asked[len(asked)-1])
		}
		for _, scope := range scopes {
			if scope.GetResourceOwnerId() != c.want {
				t.Errorf("a child of %s asked %v, want owner %q", c.parent, scope, c.want)
			}
		}
		if ids := scopes[1].GetResourceIds(); !slices.Equal(ids, []string{"c-1"}) {
			t.Errorf("a child of %s lost the ids it asked for: %v", c.parent, ids)
		}
	}
	bare := s.newGateway()
	bare.parentContext = solutionContext
	child, err := bare.ForParent(ctx, "documents", ask...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := child.WorkContext(ctx); err != nil {
		t.Fatal(err)
	}
	asked := stand.asked()
	for _, scope := range asked[len(asked)-1].GetScopes() {
		if scope.GetResourceOwnerId() != "" {
			t.Errorf("a gateway with no checked viewer named owner %q", scope.GetResourceOwnerId())
		}
	}
}
