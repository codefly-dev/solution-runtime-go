//go:build composition

package scenarios

import (
	"sync"
	"syscall"
	"testing"
	"time"
)

// The authority gone, nothing is answered on what was allowed a moment ago.
// TestComposedTheAuthorityStoppedTheRelayFailsClosed holds the outage that
// answers nothing (a timeout); this one ends the authority's process, so its
// address refuses. Carol's Work Context reads through the backend and her
// session through the edge; the authority is killed; the same token and the
// same session are unavailable, at once, and answer nothing of the document.
//
// It is the last scenario of the run, in the last file, because nothing
// starts the authority again: the scenario library stops a whole run or
// nothing (the same STOPGAP as the stopped scenario's).
func TestComposedTheAuthorityGoneTheRelayFailsClosed(t *testing.T) {
	userTeam(t)
	d := write(t, people.Admin, "authority-gone")
	carol := signIn(t, people.User)
	token, err := carol.issued(t)
	if err != nil {
		t.Fatal(err)
	}
	got, err := presents(t, token, d)
	answered(t, "Carol's Work Context, sent to the backend with the authority up", got, err, d)
	got, err = carol.through(d)
	answered(t, "Carol's session, through the edge with the authority up", got, err, d)

	for _, pid := range listeners(t, delivered(t, "authority", "local", "grpc")) {
		if err := syscall.Kill(pid, syscall.SIGKILL); err != nil {
			t.Fatalf("end the authority (pid %d): %v", pid, err)
		}
	}

	var held, edge answer
	var heldErr, edgeErr error
	var wg sync.WaitGroup
	wg.Add(2)
	began := time.Now()
	go func() { defer wg.Done(); held, heldErr = presents(t, token, d) }()
	go func() { defer wg.Done(); edge, edgeErr = carol.through(d) }()
	wg.Wait()
	failedClosed(t, "gone", d, held, heldErr, edge, edgeErr)
	t.Logf("the two calls were refused in %s", time.Since(began).Round(time.Millisecond))
}
