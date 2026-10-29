package solution

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	authorityv1 "github.com/codefly-dev/authority/libraries/authority-client/go/gen/host/authority/v1"
	"github.com/codefly-dev/sdk-go/workcontext"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// stepCredential is the setup-only credential the authority issued for one
// pending attempt: installation inst-1 at revision 3 in org-1, consent receipt
// receipt-1, addressed to the page.
const stepCredential = "installation-step-credential"

// verifiedStep is what the authority's step verifier answers for
// stepCredential, edited by each case that needs it to disagree.
func verifiedStep(edit func(*authorityv1.WorkContextV1)) func(*authorityv1.CheckRequest) (*authorityv1.CheckResponse, error) {
	return func(r *authorityv1.CheckRequest) (*authorityv1.CheckResponse, error) {
		if r.GetToken() != stepCredential {
			return nil, status.Error(codes.Unauthenticated, "the credential does not verify")
		}
		org := "org-1"
		wc := &authorityv1.WorkContextV1{
			Audience: r.GetAudience(), TenantId: org, OrganizationId: &org, OwnerPrincipalId: "installation-agent", TaskId: "receipt-1",
			Seal:            &authorityv1.WorkSealV1{InstallationId: "inst-1", InstallationRevision: 3},
			AuthorityScopes: []*authorityv1.WorkScopeV1{{ResourceKind: "installations", Actions: []string{"install"}, ResourceIds: []string{"inst-1"}}},
		}
		if edit != nil {
			edit(wc)
		}
		return &authorityv1.CheckResponse{Context: wc}, nil
	}
}

func stepRequest(credentials ...string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, installationPath,
		strings.NewReader(`{"installation_id":"inst-1","organization_id":"org-1","revision":3,"scope":[{"resourceKind":"pages","actions":["read"]}]}`))
	for _, credential := range credentials {
		r.Header.Add(workcontext.HeaderName, credential)
	}
	r.Header.Set(workcontext.InstallationIDHeaderName, "inst-1")
	r.Header.Set(workcontext.InstallationRevisionHeaderName, "3")
	return r
}

// installServer is a Server under the stand-in authority whose step records
// every installation it runs.
func installServer(t *testing.T) (*Server, *interfaceAuthority, *[]Installation) {
	t.Helper()
	s, stand := authorityServer(t)
	stand.step = verifiedStep(nil)
	var mu sync.Mutex
	var ran []Installation
	s.OnInstall(func(_ context.Context, installation Installation) error {
		mu.Lock()
		defer mu.Unlock()
		ran = append(ran, installation)
		return nil
	})
	return s, stand, &ran
}

func install(s *Server, r *http.Request) *httptest.ResponseRecorder {
	answer := httptest.NewRecorder()
	s.handleInstallation(answer, r)
	return answer
}

// The step runs only once the authority's step verifier has verified the
// attempt, and runs with exactly what it verified, receipt included. The check
// is never advisory, even under hop/ENFORCEMENT=warn, because it is not a
// route check.
func TestAnInstallStepRunsOnlyWhatTheAuthorityVerified(t *testing.T) {
	s, stand, ran := installServer(t)
	s.host.advisory = true
	if answer := install(s, stepRequest(stepCredential)); answer.Code != http.StatusNoContent {
		t.Fatalf("a verified step answered %d: %s", answer.Code, answer.Body)
	}
	want := Installation{ID: "inst-1", OrganizationID: "org-1", Revision: 3, Receipt: "receipt-1"}
	if len(*ran) != 1 || (*ran)[0] != want {
		t.Fatalf("the step ran with %+v, want once with %+v", *ran, want)
	}
	checks := stand.checks()
	if len(checks) != 1 || checks[0].GetMethod() != "POST /_codefly/installations" || checks[0].GetAudience() != "page" ||
		checks[0].GetToken() != stepCredential || checks[0].GetAdvisory() {
		t.Fatalf("the authority was asked %v, want one non-advisory check of the credential at the step's method", checks)
	}
}

// Every refusal is answered before the step runs, and an attempt the authority
// did not verify for exactly this installation is never acknowledged.
func TestAnInstallStepTheAuthorityDoesNotVerifyNeverRuns(t *testing.T) {
	for name, c := range map[string]struct {
		request func() *http.Request
		step    func(*authorityv1.CheckRequest) (*authorityv1.CheckResponse, error)
		status  int
	}{
		"no credential":           {request: func() *http.Request { return stepRequest() }, status: http.StatusUnauthorized},
		"two credentials":         {request: func() *http.Request { return stepRequest(stepCredential, stepCredential) }, status: http.StatusUnauthorized},
		"a credential that fails": {request: func() *http.Request { return stepRequest("forged") }, status: http.StatusUnauthorized},
		"no installation carriers": {request: func() *http.Request {
			r := stepRequest(stepCredential)
			r.Header.Del(workcontext.InstallationIDHeaderName)
			return r
		}, status: http.StatusBadRequest},
		"carriers naming another revision": {request: func() *http.Request {
			r := stepRequest(stepCredential)
			r.Header.Set(workcontext.InstallationRevisionHeaderName, "2")
			return r
		}, status: http.StatusBadRequest},
		"a body with an unknown field": {request: func() *http.Request {
			r := stepRequest(stepCredential)
			r.Body = io.NopCloser(strings.NewReader(`{"installation_id":"inst-1","organization_id":"org-1","revision":3,"activate":true}`))
			return r
		}, status: http.StatusBadRequest},
		"the authority refuses the attempt": {step: func(*authorityv1.CheckRequest) (*authorityv1.CheckResponse, error) {
			return nil, status.Error(codes.PermissionDenied, "not this installation's setup credential")
		}, status: http.StatusConflict},
		"the attempt changed": {step: func(*authorityv1.CheckRequest) (*authorityv1.CheckResponse, error) {
			return nil, status.Error(codes.FailedPrecondition, "installation step attempt changed")
		}, status: http.StatusServiceUnavailable},
		"the authority is unreachable": {step: func(*authorityv1.CheckRequest) (*authorityv1.CheckResponse, error) {
			return nil, status.Error(codes.Unavailable, "down")
		}, status: http.StatusServiceUnavailable},
		"sealed to another installation": {step: verifiedStep(func(wc *authorityv1.WorkContextV1) { wc.Seal.InstallationId = "inst-2" }), status: http.StatusConflict},
		"sealed to another revision":     {step: verifiedStep(func(wc *authorityv1.WorkContextV1) { wc.Seal.InstallationRevision = 4 }), status: http.StatusConflict},
		"verified in another org": {step: verifiedStep(func(wc *authorityv1.WorkContextV1) {
			other := "org-2"
			wc.OrganizationId = &other
		}), status: http.StatusConflict},
		"addressed to another module": {step: verifiedStep(func(wc *authorityv1.WorkContextV1) { wc.Audience = "documents" }), status: http.StatusConflict},
		"no consent receipt":          {step: verifiedStep(func(wc *authorityv1.WorkContextV1) { wc.TaskId = "" }), status: http.StatusConflict},
		"an ordinary capability": {step: verifiedStep(func(wc *authorityv1.WorkContextV1) {
			wc.AuthorityScopes = append(wc.AuthorityScopes, &authorityv1.WorkScopeV1{ResourceKind: "pages", Actions: []string{"read"}})
		}), status: http.StatusConflict},
	} {
		t.Run(name, func(t *testing.T) {
			s, stand, ran := installServer(t)
			if c.step != nil {
				stand.step = c.step
			}
			request := stepRequest(stepCredential)
			if c.request != nil {
				request = c.request()
			}
			if answer := install(s, request); answer.Code != c.status {
				t.Errorf("answered %d (%s), want %d", answer.Code, strings.TrimSpace(answer.Body.String()), c.status)
			}
			if len(*ran) != 0 {
				t.Errorf("the step ran: %+v", *ran)
			}
		})
	}
}

// One attempt runs once: a repeat is answered from memory, but only after the
// authority verified the repeat too, so a remembered acknowledgement is never
// an answer to an attempt that no longer stands. Another receipt for the same
// installation is another attempt.
func TestAnInstallAttemptRunsOnceAndARepeatIsStillVerified(t *testing.T) {
	s, stand, ran := installServer(t)
	for range 2 {
		if answer := install(s, stepRequest(stepCredential)); answer.Code != http.StatusNoContent {
			t.Fatalf("answered %d", answer.Code)
		}
	}
	if len(*ran) != 1 {
		t.Fatalf("one attempt ran the step %d times", len(*ran))
	}
	stand.step = func(*authorityv1.CheckRequest) (*authorityv1.CheckResponse, error) {
		return nil, status.Error(codes.FailedPrecondition, "installation has no current consented pending attempt")
	}
	if answer := install(s, stepRequest(stepCredential)); answer.Code != http.StatusServiceUnavailable {
		t.Fatalf("a remembered attempt the authority no longer verifies answered %d", answer.Code)
	}
	stand.step = verifiedStep(func(wc *authorityv1.WorkContextV1) { wc.TaskId = "receipt-2" })
	if answer := install(s, stepRequest(stepCredential)); answer.Code != http.StatusNoContent || len(*ran) != 2 || (*ran)[1].Receipt != "receipt-2" {
		t.Fatalf("another receipt answered %d and ran %+v", answer.Code, *ran)
	}
}

// Concurrent deliveries of one attempt run the step once and every one of them
// gets its answer.
func TestConcurrentDeliveriesOfOneAttemptRunTheStepOnce(t *testing.T) {
	s, stand := authorityServer(t)
	stand.step = verifiedStep(nil)
	var runs atomic.Int32
	started, release := make(chan struct{}, 4), make(chan struct{})
	s.OnInstall(func(context.Context, Installation) error {
		runs.Add(1)
		started <- struct{}{}
		<-release
		return nil
	})
	var wg sync.WaitGroup
	answers := make([]int, 4)
	for i := range answers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			answers[i] = install(s, stepRequest(stepCredential)).Code
		}()
	}
	// The first delivery is inside the step; the others reach it and wait.
	<-started
	close(release)
	wg.Wait()
	if runs.Load() != 1 {
		t.Errorf("the step ran %d times", runs.Load())
	}
	for _, code := range answers {
		if code != http.StatusNoContent {
			t.Errorf("a delivery answered %d", code)
		}
	}
}

// A solution that declares no step is not installable: an acknowledgement is
// what activates the installation, and nothing set it up.
func TestWithoutADeclaredStepNothingIsAcknowledged(t *testing.T) {
	s, stand := authorityServer(t)
	stand.step = verifiedStep(nil)
	answer := install(s, stepRequest(stepCredential))
	if answer.Code != http.StatusConflict || !strings.Contains(answer.Body.String(), "declares no install step") {
		t.Fatalf("a solution with no step answered %d: %s", answer.Code, answer.Body)
	}
}

// A refusal carries only its public reason and is not remembered, so the
// host's retry runs the step again; any other failure is retryable and says
// nothing about why.
func TestARefusalIsPublicAndRetriedAndAFailureSaysNothing(t *testing.T) {
	s, stand := authorityServer(t)
	stand.step = verifiedStep(nil)
	answers := []error{
		RefuseInstall("the workspace quota is exhausted\n"),
		errors.New("dial tcp 10.0.0.7:5432: connection refused"),
		nil,
	}
	var ranWithViewer error
	s.OnInstall(func(ctx context.Context, _ Installation) error {
		_, ranWithViewer = ViewerFromContext(ctx)
		next := answers[0]
		answers = answers[1:]
		return next
	})
	refused := install(s, stepRequest(stepCredential))
	var reason struct{ Reason string }
	if refused.Code != http.StatusConflict || json.Unmarshal(refused.Body.Bytes(), &reason) != nil || reason.Reason != "the workspace quota is exhausted" {
		t.Fatalf("a refusal answered %d: %s", refused.Code, refused.Body)
	}
	failed := install(s, stepRequest(stepCredential))
	if failed.Code != http.StatusServiceUnavailable || strings.Contains(failed.Body.String(), "10.0.0.7") {
		t.Fatalf("a failure answered %d: %s", failed.Code, failed.Body)
	}
	if answer := install(s, stepRequest(stepCredential)); answer.Code != http.StatusNoContent {
		t.Fatalf("the retry after a refusal and a failure answered %d", answer.Code)
	}
	if ranWithViewer == nil {
		t.Error("the step had a viewer gateway: a pending installation holds nothing a step could act under")
	}
}

// The step is served on the listener a boot serves, where the host's delivery
// posts it.
func TestTheInstallStepIsServedByTheBoot(t *testing.T) {
	server := New(Manifest{ID: testSolutionID})
	var ran atomic.Int32
	server.OnInstall(func(context.Context, Installation) error { ran.Add(1); return nil })
	solution := boot(t, server)
	solution.authority.mu.Lock()
	solution.authority.step = verifiedStep(nil)
	solution.authority.mu.Unlock()
	request := stepRequest(stepCredential)
	served, err := http.NewRequest(http.MethodPost, solution.base+installationPath, request.Body)
	if err != nil {
		t.Fatal(err)
	}
	served.Header = request.Header
	answer, err := solution.client.Do(served)
	if err != nil {
		t.Fatal(err)
	}
	_ = answer.Body.Close()
	if answer.StatusCode != http.StatusNoContent || ran.Load() != 1 {
		t.Fatalf("the served step answered %d and ran %d times", answer.StatusCode, ran.Load())
	}
}
