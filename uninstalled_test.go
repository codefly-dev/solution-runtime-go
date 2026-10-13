package solution

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/codefly-dev/sdk-go/workcontext"
)

// postInstall sends one well-formed install step to a booted runtime as the
// admitted caller, and returns the status it answered.
func postInstall(t *testing.T, b *booted) int {
	t.Helper()
	r := installRequest(t, installBody)
	r.URL.Scheme, r.URL.Host = "http", strings.TrimPrefix(b.base, "http://")
	r.RequestURI = ""
	resp, err := b.client.Do(r)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

func healthOf(t *testing.T, b *booted) int {
	t.Helper()
	resp, err := b.client.Get(b.base + HealthPath)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestAnUninstalledSolutionServesItsInstallStepAndThenHoldsACredential is the
// order an installation actually happens in, against a host that behaves as
// the real one does: it answers 412 while nothing has installed the solution,
// delivers the install step, and issues only once that step was acknowledged.
//
// A runtime that needs its execution credential to answer the step can never
// be installed by such a host — each waits for the other — and one whose
// health fails while uninstalled is restarted for not being installed.
func TestAnUninstalledSolutionServesItsInstallStepAndThenHoldsACredential(t *testing.T) {
	var active atomic.Bool
	var steps atomic.Int32
	host := newHostMint(t, &hostMint{answer: func() int {
		if active.Load() {
			return 0
		}
		return http.StatusPreconditionFailed
	}})
	s := New(Manifest{ID: testSolutionID}).OnInstall(func(context.Context, Installation) error {
		steps.Add(1)
		return nil
	})
	b := boot(t, s, host)
	t.Cleanup(b.client.CloseIdleConnections)
	b.client.Timeout = 5 * time.Second

	if !s.uninstalled() {
		t.Fatal("a boot the host answered 412 does not read as uninstalled")
	}
	if _, held := s.heldCredential(); held {
		t.Fatal("an uninstalled boot holds a credential")
	}
	asked := host.count()

	// Healthy, and answered from what the host already said.
	for range 3 {
		if status := healthOf(t, b); status != http.StatusOK {
			t.Fatalf("health while uninstalled = %d, want 200: a failing probe has the orchestrator restart a solution for not being installed", status)
		}
	}
	if got := host.count(); got != asked {
		t.Fatalf("three probes asked the host %d more time(s); a probe of an uninstalled solution asks nobody", got-asked)
	}

	// The step is delivered while the host still answers 412, exactly as the
	// host orders it, and the host activates only after reading the answer.
	if status := postInstall(t, b); status != http.StatusNoContent {
		t.Fatalf("install step while uninstalled = %d, want 204: the host issues nothing until this step is acknowledged, so refusing it is a solution nobody can install", status)
	}
	if steps.Load() != 1 {
		t.Fatalf("the install step ran %d time(s), want 1", steps.Load())
	}
	time.Sleep(100 * time.Millisecond)
	active.Store(true)

	// Held promptly — well inside the idle cadence, because the acknowledged
	// step is what says the credential is now worth asking for.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, held := s.heldCredential(); held {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("no credential held %s after the install step was acknowledged and the host began issuing", 10*time.Second)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if s.uninstalled() {
		t.Fatal("a runtime holding a credential still reads as uninstalled")
	}
	if status := healthOf(t, b); status != http.StatusOK {
		t.Fatalf("health once installed = %d, want 200", status)
	}
}

// TestARefusalAfterAnUninstalledBootEndsTheProcess: the host admitted this
// workload at boot and judges it differently when next asked. That answer has
// to end the process the way it does on every other path; an ask made around
// the controller logged it and left a process serving on a refused build.
func TestARefusalAfterAnUninstalledBootEndsTheProcess(t *testing.T) {
	var refuse atomic.Bool
	host := newHostMint(t, &hostMint{answer: func() int {
		if refuse.Load() {
			return http.StatusForbidden
		}
		return http.StatusPreconditionFailed
	}})
	s := New(Manifest{ID: testSolutionID}).OnInstall(func(context.Context, Installation) error { return nil })
	b := boot(t, s, host)
	t.Cleanup(b.client.CloseIdleConnections)
	b.client.Timeout = 5 * time.Second

	refuse.Store(true)
	if status := postInstall(t, b); status != http.StatusNoContent {
		t.Fatalf("install step = %d, want 204", status)
	}
	err, ended := b.ended(10 * time.Second)
	if !ended {
		t.Fatal("the host refused this execution's credential after an uninstalled boot and the process kept serving")
	}
	if err == nil || !strings.Contains(err.Error(), "stopped serving") {
		t.Fatalf("serve returned %v; a refusal is reported as the reason the process ended", err)
	}
}

// TestAnInstalledRuntimeStillHoldsTheInstallStepToItsCredential: the exemption
// is for the one state that needs it. A runtime whose credential the host has
// stopped issuing for any other reason answers the step as it answers a viewer.
func TestAnInstalledRuntimeStillHoldsTheInstallStepToItsCredential(t *testing.T) {
	var steps atomic.Int32
	s, _, _ := brokerFixture(t)
	s.OnInstall(func(context.Context, Installation) error { steps.Add(1); return nil })
	s.noteCredentialAnswer(&brokerMintError{class: brokerTransport})
	s.credentialMu.Lock()
	s.credentialQuietUntil = time.Now().Add(time.Minute)
	s.credentialMu.Unlock()
	if s.uninstalled() {
		t.Fatal("a host that cannot be reached reads as an uninstalled solution")
	}
	w := httptest.NewRecorder()
	s.handleInstallation(w, installRequest(t, installBody))
	if w.Code != http.StatusServiceUnavailable || steps.Load() != 0 {
		t.Fatalf("install step with no obtainable credential = %d after %d run(s), want 503 and none", w.Code, steps.Load())
	}
}

// Advancing beyond both the former polling and renewal intervals must make no
// acquisition. The same controller is then exercised by a real request.
func TestIdleRuntimeAndHealthNeverMint(t *testing.T) {
	for _, uninstalled := range []bool{false, true} {
		t.Run(map[bool]string{false: "registered", true: "uninstalled"}[uninstalled], func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				var calls atomic.Int32
				s := New(Manifest{ID: testSolutionID})
				s.credential = countingIdleSource{calls: &calls}
				if uninstalled {
					s.noteCredentialAnswer(&brokerMintError{class: brokerAwaitingInstallation})
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				go s.awaitInstallation(ctx)
				for range 120 {
					time.Sleep(30 * time.Second)
					if status, _ := healthStatus(t, s); status != http.StatusOK {
						t.Fatalf("idle health = %d", status)
					}
				}
				if got := calls.Load(); got != 0 {
					t.Fatalf("one idle hour produced %d credential acquisitions", got)
				}
				if err := s.actingForAViewer(ctx); err == nil {
					t.Fatal("actual work was not refused without a credential")
				}
				if got := calls.Load(); got != 1 {
					t.Fatalf("actual work made %d acquisitions, want 1", got)
				}
			})
		})
	}
}

type countingIdleSource struct{ calls *atomic.Int32 }

func (s countingIdleSource) Credential(context.Context) (workcontext.Credential, error) {
	s.calls.Add(1)
	return workcontext.Credential{}, workcontext.ErrMintUnavailable
}

// TestTheAskerSurvivesATransientAnswerWhileUninstalled: one answer that
// judges nothing — the host restarting, a pass in flight — leaves the solution
// exactly as uninstalled as it was. An asker that stopped there left the first
// credential waiting for the host's next install delivery.
func TestTheAskerSurvivesATransientAnswerWhileUninstalled(t *testing.T) {
	var phase atomic.Int32 // 0: installed nowhere, 1: one transient answer, 2: issuing
	host := newHostMint(t, &hostMint{answer: func() int {
		switch phase.Load() {
		case 0:
			return http.StatusPreconditionFailed
		case 1:
			phase.Store(2)
			return http.StatusServiceUnavailable
		}
		return 0
	}})
	s := New(Manifest{ID: testSolutionID}).OnInstall(func(context.Context, Installation) error { return nil })
	b := boot(t, s, host)
	t.Cleanup(b.client.CloseIdleConnections)
	b.client.Timeout = 5 * time.Second

	if status := postInstall(t, b); status != http.StatusNoContent {
		t.Fatalf("install step = %d, want 204", status)
	}
	phase.Store(1)
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, held := s.heldCredential(); held {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no credential held %s after one transient answer: the asker stopped, and nothing but the host's next install delivery would start it again", 10*time.Second)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// TestABootWaitsForAProjectionThatIsNotThereYet: the platform projects the
// token, and a process can be running before it has. Nothing is sent without
// one, so the boot waits inside its window instead of ending on a state the
// platform is about to leave.
func TestABootWaitsForAProjectionThatIsNotThereYet(t *testing.T) {
	host := newHostMint(t, &hostMint{})
	s := New(Manifest{ID: testSolutionID})
	bootEnvironment(t, host)
	tokenFile := os.Getenv(ProjectedTokenFileEnvironmentVariable)
	projected, err := os.ReadFile(tokenFile)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(tokenFile); err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(300 * time.Millisecond)
		_ = os.WriteFile(tokenFile, projected, 0o600)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	ln, err := takeListener(s).start(ctx)
	if err != nil {
		t.Fatalf("a boot whose projected token arrived a moment late was refused: %v", err)
	}
	_ = ln.Close()
	if _, held := s.heldCredential(); !held {
		t.Fatal("the boot came up holding no credential")
	}
	if got := host.count(); got != 1 {
		t.Fatalf("the host was asked %d time(s); nothing is sent without a token, so exactly one ask reaches it", got)
	}
}
