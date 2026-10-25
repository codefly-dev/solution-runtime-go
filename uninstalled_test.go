package solution

import (
	"context"
	"io"
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
