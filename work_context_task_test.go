package solution

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

// Two Task ids in the shape accounts admits. The first is mixed-case on purpose:
// accounts admits either case and signs the id as given, so a runtime that
// canonicalised it would name a different boundary than the solution asked for.
const (
	askTask   = "A13EC6C4-e43a-5694-911e-63db3dbbf283"
	otherTask = "5b0e3c1d-7f2a-4c8e-9d61-0a4b2c3d4e5f"
)

var readDocuments = Scope{ResourceKind: "documents", Actions: []string{"read"}}

// receivedMints returns every StartTask the gateway has received so far. The
// fake records a mint before answering it, so once the handler has returned
// every mint it made is here.
func receivedMints(gw *workContextGateway) []mintRequest {
	var mints []mintRequest
	for {
		select {
		case mint := <-gw.mints:
			mints = append(mints, mint)
		default:
			return mints
		}
	}
}

// runViewerRequest serves one viewer request through handler and fails the test
// unless the solution answered 200.
func runViewerRequest(t *testing.T, gw *workContextGateway, handler Handler) {
	t.Helper()
	solution := serveHandler(t, gw.URL, handler)
	resp := viewerRequest(t, solution.URL)
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("solution answered %d, want 200", resp.StatusCode)
	}
}

// TestForTaskSendsTheNamedTaskVerbatim is the point of ForTask: every mint of
// one Task, in this request and in a later one, names that Task exactly as the
// solution spelled it, while the session stays the viewer's own.
func TestForTaskSendsTheNamedTaskVerbatim(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	read := func(ctx context.Context, g *Gateway) (any, error) {
		docs, err := g.ForTask(ctx, Task{ID: askTask}, "documents", readDocuments)
		if err != nil {
			return nil, err
		}
		return getThrough(ctx, docs)
	}
	// Two viewer requests: each gets its own cache, so each mints.
	runViewerRequest(t, gw, read)
	runViewerRequest(t, gw, read)

	mints := receivedMints(gw)
	if len(mints) != 2 {
		t.Fatalf("received %d mints across two requests, want 2", len(mints))
	}
	for i, mint := range mints {
		if mint.TaskID != askTask {
			t.Errorf("mint %d task = %q, want %q verbatim", i, mint.TaskID, askTask)
		}
		if mint.SessionID != viewerSession {
			t.Errorf("mint %d session = %q, want the viewer's %q", i, mint.SessionID, viewerSession)
		}
	}
	for range 2 {
		if call := <-gw.calls; call.WorkContext == "" {
			t.Error("module read carried no work context")
		}
	}
}

// TestForTaskNeverSharesAContextBetweenTasks keys the cache by the Task. Two
// Tasks asking the identical audience and scopes are two capabilities, and each
// derived gateway presents its own; shared, a read meant for one Task would be
// admitted under the other's boundary.
func TestForTaskNeverSharesAContextBetweenTasks(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	runViewerRequest(t, gw, func(ctx context.Context, g *Gateway) (any, error) {
		first, err := g.ForTask(ctx, Task{ID: askTask}, "documents", readDocuments)
		if err != nil {
			return nil, err
		}
		second, err := g.ForTask(ctx, Task{ID: otherTask}, "documents", readDocuments)
		if err != nil {
			return nil, err
		}
		if _, err := getThrough(ctx, first); err != nil {
			return nil, err
		}
		return getThrough(ctx, second)
	})

	mints := receivedMints(gw)
	if len(mints) != 2 {
		t.Fatalf("received %d mints for two Tasks, want 2 — the cache handed one Task's capability to the other", len(mints))
	}
	if mints[0].TaskID != askTask || mints[1].TaskID != otherTask {
		t.Errorf("mints named tasks %q then %q, want %q then %q", mints[0].TaskID, mints[1].TaskID, askTask, otherTask)
	}
	first, second := <-gw.calls, <-gw.calls
	if first.WorkContext != "context-documents.1" || second.WorkContext != "context-documents.2" {
		t.Errorf("reads carried %q then %q, want each Task's own capability (context-documents.1, context-documents.2)", first.WorkContext, second.WorkContext)
	}
}

// TestForTaskReusesTheContextOfTheSameTask keeps the audited-mint economy of
// ForModule: within one request, one Task's ask mints once however many times it
// is derived and read through.
func TestForTaskReusesTheContextOfTheSameTask(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	runViewerRequest(t, gw, func(ctx context.Context, g *Gateway) (any, error) {
		for range 3 {
			docs, err := g.ForTask(ctx, Task{ID: askTask}, "documents", readDocuments)
			if err != nil {
				return nil, err
			}
			if _, err := getThrough(ctx, docs); err != nil {
				return nil, err
			}
		}
		return "done", nil
	})

	if got := gw.mintCount(); got != 1 {
		t.Errorf("minted %d capabilities for one Task's ask derived 3 times, want 1", got)
	}
	for range 3 {
		if call := <-gw.calls; call.WorkContext != "context-documents.1" {
			t.Errorf("read carried %q, want the one capability minted for the Task", call.WorkContext)
		}
	}
}

// TestForTaskRefusesATaskIDAccountsWouldNot refuses, before any request, every
// id outside the hyphenated UUID form accounts validates. The looser forms are
// ones a general UUID parser accepts, so a check built on one would send them
// on to be refused there. An empty id is refused rather than read as "draw
// one": a solution that meant to name its Task and named nothing must not get a
// fresh Task per mint, which is exactly the failure ForTask exists to end.
func TestForTaskRefusesATaskIDAccountsWouldNot(t *testing.T) {
	for _, id := range []string{
		"",
		"ask-42",
		"a13ec6c4e43a5694911e63db3dbbf283",
		"{a13ec6c4-e43a-5694-911e-63db3dbbf283}",
		"urn:uuid:a13ec6c4-e43a-5694-911e-63db3dbbf283",
		" a13ec6c4-e43a-5694-911e-63db3dbbf283",
		"a13ec6c4-e43a-5694-911e-63db3dbbf28g",
	} {
		t.Run(id, func(t *testing.T) {
			gw := newWorkContextGateway(t, &workContextGateway{})
			var mintErr error
			runViewerRequest(t, gw, func(ctx context.Context, g *Gateway) (any, error) {
				_, mintErr = g.ForTask(ctx, Task{ID: id}, "documents", readDocuments)
				return "done", nil
			})
			if mintErr == nil || !strings.Contains(mintErr.Error(), "hyphenated UUID") {
				t.Errorf("ForTask(%q) error = %v, want a refusal naming the UUID form", id, mintErr)
			}
			if mints := receivedMints(gw); len(mints) != 0 {
				t.Errorf("ForTask(%q) sent %d StartTask requests, want 0 — the id must be refused here", id, len(mints))
			}
		})
	}
}

// TestForTaskSendsTheTTLWhenGiven passes the lifetime through to accounts, which
// already accepts it, and sends nothing for zero so the issuer's default holds.
// ForModule, which asks no lifetime, sends none. Each ask runs in its own
// request so each mints regardless of how the cache keys them.
func TestForTaskSendsTheTTLWhenGiven(t *testing.T) {
	for _, tc := range []struct {
		name   string
		derive func(context.Context, *Gateway) (*Gateway, error)
		want   *int32
	}{
		{"ForTask with a lifetime", func(ctx context.Context, g *Gateway) (*Gateway, error) {
			return g.ForTask(ctx, Task{ID: askTask, TTLSeconds: 120}, "documents", readDocuments)
		}, ptr(int32(120))},
		{"ForTask without one", func(ctx context.Context, g *Gateway) (*Gateway, error) {
			return g.ForTask(ctx, Task{ID: askTask}, "documents", readDocuments)
		}, nil},
		{"ForModule", func(ctx context.Context, g *Gateway) (*Gateway, error) {
			return g.ForModule(ctx, "documents", readDocuments)
		}, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw := newWorkContextGateway(t, &workContextGateway{})
			runViewerRequest(t, gw, func(ctx context.Context, g *Gateway) (any, error) {
				return tc.derive(ctx, g)
			})
			mints := receivedMints(gw)
			if len(mints) != 1 {
				t.Fatalf("received %d mints, want 1", len(mints))
			}
			if got := mints[0].TTLSeconds; ttlOf(got) != ttlOf(tc.want) {
				t.Errorf("mint sent ttlSeconds %v, want %v", ttlOf(got), ttlOf(tc.want))
			}
		})
	}
}

func ptr[T any](v T) *T { return &v }

func ttlOf(ttl *int32) any {
	if ttl == nil {
		return "absent"
	}
	return *ttl
}

// TestForModuleStillNamesAFreshTaskPerMint pins that ForModule's behaviour is
// unchanged by ForTask: a re-mint within one request names a new Task, never
// the previous mint's.
func TestForModuleStillNamesAFreshTaskPerMint(t *testing.T) {
	gw := newWorkContextGateway(t, &workContextGateway{})
	runViewerRequest(t, gw, func(ctx context.Context, g *Gateway) (any, error) {
		docs, err := g.ForModule(ctx, "documents", readDocuments)
		if err != nil {
			return nil, err
		}
		lapseCachedCapabilities(g)
		return getThrough(ctx, docs)
	})

	mints := receivedMints(gw)
	if len(mints) != 2 {
		t.Fatalf("received %d mints, want 2 (the first and the re-mint after it lapsed)", len(mints))
	}
	for i, mint := range mints {
		if !taskIDShape.MatchString(mint.TaskID) {
			t.Errorf("mint %d task = %q, want a drawn UUID", i, mint.TaskID)
		}
	}
	if mints[0].TaskID == mints[1].TaskID {
		t.Errorf("re-mint reused task %q, want a fresh one per mint", mints[0].TaskID)
	}
}
