package solution

import (
	"context"
	"io"
	"net/http"
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

// Installation acknowledgement carries its own capability. It never acquires a
// workload credential; only later module work does, against current consent.
func TestInstallationAcknowledgementDoesNotAcquire(t *testing.T) {
	var active atomic.Bool
	var steps atomic.Int32
	host := newHostMint(t, &hostMint{answer: func() int {
		if active.Load() {
			return 0
		}
		return http.StatusPreconditionFailed
	}})
	s := declaredWorkServer(t).OnInstall(func(context.Context, Installation) error { steps.Add(1); return nil })
	b := boot(t, s, host)
	if host.count() != 0 || healthOf(t, b) != 200 {
		t.Fatal("idle boot consulted issuer")
	}
	if status := postInstall(t, b); status != 204 || steps.Load() != 1 {
		t.Fatalf("install = %d", status)
	}
	if host.count() != 0 {
		t.Fatal("acknowledgement minted")
	}
	active.Store(true)
	if err := testWorkCredential(s, t.Context()); err != nil {
		t.Fatal(err)
	}
	if host.count() != 1 || healthOf(t, b) != 200 {
		t.Fatal("first installed work did not acquire")
	}
}

func TestIdleRuntimeAndHealthNeverMint(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		var calls atomic.Int32
		s := New(Manifest{ID: testSolutionID}).Credential(countingIdleSource{calls: &calls})
		for range 120 {
			time.Sleep(30 * time.Second)
			if status, _ := healthStatus(t, s); status != 200 {
				t.Fatalf("health=%d", status)
			}
		}
		if calls.Load() != 0 {
			t.Fatal("idle health minted")
		}
		if err := testWorkCredential(s, t.Context()); err == nil {
			t.Fatal("unavailable source accepted")
		}
		if calls.Load() != 1 {
			t.Fatalf("actual work made %d acquisitions", calls.Load())
		}
	})
}

type countingIdleSource struct{ calls *atomic.Int32 }

func (s countingIdleSource) Credential(context.Context) (workcontext.Credential, error) {
	s.calls.Add(1)
	return workcontext.Credential{}, workcontext.ErrMintUnavailable
}

func TestMissingProjectionDoesNotDelayBootAndWorkRecovers(t *testing.T) {
	host := newHostMint(t, &hostMint{})
	s := declaredWorkServer(t)
	bootEnvironment(t, host)
	path := os.Getenv(ProjectedTokenFileEnvironmentVariable)
	projected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	ln, err := takeListener(s).start(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	if host.count() != 0 {
		t.Fatal("boot attempted mint")
	}
	if err := testWorkCredential(s, t.Context()); err == nil {
		t.Fatal("work accepted without projection")
	}
	if host.count() != 0 {
		t.Fatal("missing projection sent mint")
	}
	if err := os.WriteFile(path, projected, 0600); err != nil {
		t.Fatal(err)
	}
	// Retry only after the request-driven backoff; no timer mints by itself.
	c := scopeController(t, s)
	c.credentialMu.Lock()
	quiet := c.credentialQuietUntil
	c.credentialMu.Unlock()
	time.Sleep(time.Until(quiet) + time.Millisecond)
	if err := testWorkCredential(s, t.Context()); err != nil {
		t.Fatal(err)
	}
	if host.count() != 1 {
		t.Fatalf("mints=%d", host.count())
	}
}
