package solution

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	corework "github.com/codefly-dev/core/workcontext"
	"github.com/codefly-dev/sdk-go/workcontext"
)

func TestSharedCredentialsSelectOrganisationAndInstallation(t *testing.T) {
	const orgA = "11111111-1111-4111-8111-111111111111"
	const orgB = "22222222-2222-4222-8222-222222222222"
	installations := map[string]string{orgA: "install-a", orgB: "install-b"}
	issuers := map[string]*hostMint{}
	for org, id := range installations {
		issuer := &hostMint{installation: id}
		issuer.prepareAuthority(t)
		issuers[org] = issuer
	}
	var mu sync.Mutex
	calls := map[string]int{}
	refuseA := false
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		if r.URL.Path != credentialMintPath || json.NewDecoder(r.Body).Decode(&body) != nil ||
			len(body) != 2 || body["prefix"] != testSolutionID || issuers[body["organization_id"]] == nil {
			http.Error(w, "invalid selector", http.StatusBadRequest)
			return
		}
		org := body["organization_id"]
		mu.Lock()
		calls[org]++
		n, refuse := calls[org], refuseA && org == orgA
		mu.Unlock()
		if refuse {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		token, _, err := issuers[org].authority.Start(r.Context(), corework.StartInput{
			TenantID: corework.FixtureTenant, OwnerPrincipalID: corework.FixturePrincipal,
			OwnerPrincipalKind: "human", TaskID: fmt.Sprintf("scoped-%s-%d", org, n),
			Audience: testAudience, OrganizationID: org, InstallationID: installations[org],
			TTL: time.Minute,
		})
		if err != nil {
			t.Errorf("fixture mint: %v", err)
			w.WriteHeader(500)
			return
		}
		writeJSON(w, 200, map[string]any{"token": token, "expiresAt": time.Now().Add(2 * time.Second).UTC()})
	}))
	defer broker.Close()
	authorityValues(t)
	s := New(Manifest{ID: testSolutionID})
	s.cfg.mintURL, s.cfg.gatewayURL = broker.URL+credentialMintPath, broker.URL
	s.cfg.transport.local = true
	s.cfg.brokerInternalToken = "broker-perimeter-token"
	s.cfg.projectedTokenPath = filepath.Join(t.TempDir(), "projection")
	writeFile(t, s.cfg.projectedTokenPath, "projected-token")
	if err := s.openAuthority(t.Context()); err != nil {
		t.Fatal(err)
	}
	get := func(org string) error {
		h := http.Header{}
		h.Set(orgHeader, org)
		h.Set("X-Codefly-Installation-Id", installations[org])
		credential, err := s.gatewayFor(h).workload(t.Context())
		if err == nil {
			err = matchCredentialScope(credential, credentialScope{org, installations[org]})
		}
		return err
	}
	var wg sync.WaitGroup
	for range 12 {
		for _, org := range []string{orgA, orgB} {
			wg.Go(func() {
				if err := get(org); err != nil {
					t.Errorf("scoped work: %v", err)
				}
			})
		}
	}
	wg.Wait()
	mu.Lock()
	if calls[orgA] != 1 || calls[orgB] != 1 {
		t.Errorf("calls = %v; want one per organisation", calls)
	}
	refuseA = true
	mu.Unlock()
	// Let both broker-reported lifetimes expire without health renewing them.
	// The next work call must re-read the same broker through the held clients.
	time.Sleep(2100 * time.Millisecond)
	if err := get(orgA); err == nil {
		t.Fatal("revoked A acquired a credential")
	}
	if err := get(orgB); err != nil {
		t.Fatalf("A's refusal affected B: %v", err)
	}
	mu.Lock()
	if calls[orgA] != 2 || calls[orgB] != 2 {
		t.Errorf("renewal calls = %v; want two per organisation", calls)
	}
	mu.Unlock()
	if status, _ := healthStatus(t, s); status != http.StatusOK {
		t.Fatalf("health = %d", status)
	}
}

func TestViewerEntryAndInstallAcknowledgementNeverAcquire(t *testing.T) {
	var calls int
	s := New(Manifest{ID: testSolutionID}).Credential(credentialSourceFunc(func(context.Context) (workcontext.Credential, error) {
		calls++
		return workcontext.Credential{}, workcontext.ErrMintRefused
	}))
	wentry := httptest.NewRecorder()
	rentry := httptest.NewRequest("GET", "/entry", nil)
	rentry.Header = workHeaders()
	s.wrapRequest(func(*http.Request, *Gateway) (any, error) { return "ok", nil })(wentry, rentry)
	if wentry.Code != 200 {
		t.Fatal("plain entry refused")
	}
	s.OnInstall(func(context.Context, Installation) error { return nil })
	w := httptest.NewRecorder()
	s.handleInstallation(w, installRequest(t, installBody))
	if w.Code != http.StatusNoContent || calls != 0 {
		t.Fatalf("install = %d, mints = %d", w.Code, calls)
	}
}

type credentialSourceFunc func(context.Context) (workcontext.Credential, error)

func (f credentialSourceFunc) Credential(ctx context.Context) (workcontext.Credential, error) {
	return f(ctx)
}

// These helpers set up the real scoped controller for tests which need to
// inspect its flight/backoff state. Acquisition still runs production code.
func scopeController(t *testing.T, s *Server) *credentialController {
	t.Helper()
	key := credentialScope{testOrganization, testInstallation}
	s.scopedMu.Lock()
	defer s.scopedMu.Unlock()
	if s.scoped == nil {
		s.scoped = make(map[credentialScope]*scopedCredential)
	}
	if entry := s.scoped[key]; entry != nil {
		return entry.controller
	}
	source, err := s.installationCredentialSource(key)
	if err != nil {
		t.Fatal(err)
	}
	c := &credentialController{nextCredential: source}
	s.scoped[key] = &scopedCredential{controller: c, used: time.Now()}
	return c
}
func testWorkCredential(s *Server, ctx context.Context) error {
	_, err := s.acquireForInstallation(ctx, testOrganization, testInstallation)
	return err
}
func declaredWorkServer(t *testing.T) *Server {
	t.Helper()
	s := New(Manifest{ID: testSolutionID}).Consumes(passthroughModule()).Contract(ModuleContract{Ceilings: map[string]map[string][]Scope{
		localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
	}})
	s.cfg.profile = localProfile
	s.principal = testPrincipal
	contract, err := s.resolveContract()
	if err != nil {
		t.Fatal(err)
	}
	s.contract, s.contractResolved = contract, true
	return s
}
func workHeaders() http.Header {
	h := http.Header{}
	h.Set("Authorization", viewerBearer())
	h.Set(orgHeader, testOrganization)
	h.Set(sessionHeader, "session-1")
	h.Set(workcontext.InstallationIDHeaderName, testInstallation)
	return h
}

func TestScopedCredentialsRefuseAnotherOrganisationOrInstallation(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	credential := mintedCredential(t, mint, "scoped")
	for _, scope := range []credentialScope{
		{"22222222-2222-4222-8222-222222222222", testInstallation},
		{testOrganization, "another-installation"},
	} {
		s := New(Manifest{ID: testSolutionID}).Credential(stubCredentialSource{credential: credential})
		if _, err := s.acquireForInstallation(t.Context(), scope.organization, scope.installation); !errors.Is(err, ErrCredentialRefused) {
			t.Fatalf("wrong scope accepted: %v", err)
		}
		if err := testWorkCredential(s, t.Context()); err != nil {
			t.Fatalf("wrong-scope refusal poisoned correct scope: %v", err)
		}
	}
}

func TestUndeclaredModuleWorkNeverAcquires(t *testing.T) {
	var calls atomic.Int32
	s := declaredWorkServer(t).Credential(countingIdleSource{calls: &calls})
	if _, err := s.gatewayFor(workHeaders()).ForModule(t.Context(), "undeclared", Scope{ResourceKind: "anything", Actions: []string{"read"}}); err == nil {
		t.Fatal("undeclared work accepted")
	}
	if calls.Load() != 0 {
		t.Fatal("undeclared request minted")
	}
}

func TestScopedAcquisitionRecoversAfterConsentChanges(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	credential := mintedCredential(t, mint, "recover")
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		var refused atomic.Bool
		refused.Store(true)
		s := New(Manifest{ID: testSolutionID}).Credential(credentialSourceFunc(func(context.Context) (workcontext.Credential, error) {
			calls.Add(1)
			if refused.Load() {
				return workcontext.Credential{}, workcontext.ErrMintRefused
			}
			return credential, nil
		}))
		if err := testWorkCredential(s, t.Context()); !errors.Is(err, ErrCredentialRefused) {
			t.Fatalf("refusal=%v", err)
		}
		refused.Store(false)
		if err := testWorkCredential(s, t.Context()); err == nil {
			t.Fatal("refusal backoff was bypassed")
		}
		if calls.Load() != 1 {
			t.Fatal("backoff minted")
		}
		time.Sleep(credentialAskBackoffCeiling + time.Second)
		if calls.Load() != 1 {
			t.Fatal("idle recovery minted")
		}
		if err := testWorkCredential(s, t.Context()); err != nil {
			t.Fatalf("renewed consent stayed refused: %v", err)
		}
		if calls.Load() != 2 {
			t.Fatalf("recovery calls=%d", calls.Load())
		}
	})
}

func TestScopeLimitRetainsDetachedAcquisitions(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		s := New(Manifest{ID: testSolutionID}).Credential(credentialSourceFunc(func(context.Context) (workcontext.Credential, error) {
			calls.Add(1)
			<-release
			return workcontext.Credential{}, workcontext.ErrMintUnavailable
		}))
		var waiters sync.WaitGroup
		for i := range maxCredentialScopes {
			waiters.Go(func() { _, _ = s.acquireForInstallation(t.Context(), testOrganization, fmt.Sprintf("install-%d", i)) })
		}
		synctest.Wait()
		time.Sleep(routeCredentialTimeout + time.Millisecond)
		waiters.Wait()
		if calls.Load() != maxCredentialScopes {
			t.Fatalf("started=%d", calls.Load())
		}
		if _, err := s.acquireForInstallation(t.Context(), testOrganization, "overflow"); !errors.Is(err, ErrCredentialUnavailable) {
			t.Fatalf("capacity=%v", err)
		}
		if calls.Load() != maxCredentialScopes {
			t.Fatal("detached flight evicted; unbounded acquisitions")
		}
		close(release)
		synctest.Wait()
		_, _ = s.acquireForInstallation(t.Context(), testOrganization, "after-idle")
		if calls.Load() != maxCredentialScopes+1 || len(s.scoped) != maxCredentialScopes {
			t.Fatal("idle scope was not evicted at fixed capacity")
		}
	})
}

func TestCancelledWaiterDoesNotCancelSharedAcquisition(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		var calls atomic.Int32
		s := New(Manifest{ID: testSolutionID}).Credential(credentialSourceFunc(func(ctx context.Context) (workcontext.Credential, error) {
			calls.Add(1)
			select {
			case <-release:
				return workcontext.Credential{}, workcontext.ErrMintRefused
			case <-ctx.Done():
				t.Error("waiter cancelled shared ask")
				return workcontext.Credential{}, ctx.Err()
			}
		}))
		ctx, cancel := context.WithCancel(t.Context())
		result := make(chan error, 1)
		go func() { result <- testWorkCredential(s, ctx) }()
		synctest.Wait()
		cancel()
		if err := <-result; !errors.Is(err, ErrCredentialUnavailable) {
			t.Fatalf("cancel=%v", err)
		}
		close(release)
		synctest.Wait()
		if err := testWorkCredential(s, t.Context()); !errors.Is(err, ErrCredentialRefused) {
			t.Fatalf("late refusal lost: %v", err)
		}
		if calls.Load() != 1 {
			t.Fatal("cancelled waiter caused another acquisition")
		}
	})
}
