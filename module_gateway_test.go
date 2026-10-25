package solution

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/codefly-dev/sdk-go/workcontext"
)

// The host gateway's stand-in, for the tests of ForModule and the execution
// credential: the accounts mint, and a module answering behind it.

// moduleGateway stands in for the host gateway: the accounts mint, and the
// module behind /v1/things.
type moduleGateway struct {
	*httptest.Server
	status int
	reply  string
	// deny, when set, is an action the viewer does not hold: a mint asking for
	// it is refused the way accounts refuses one — with 403.
	deny string
	// conflict, when set, is an action whose mint is answered with 409 rather
	// than 403: the status that means "the state you were sealed to has moved"
	// for a capability and "this viewer lacks that authority" for a viewer,
	// which is the ambiguity nothing in this runtime may resolve by guessing.
	//
	// It exists because a test named after a CONFLICT was driving `deny` and
	// therefore asserting against a 403. A 409-specific regression — inferring
	// supersession and poisoning the process — would have survived it, which a
	// reviewer caught twice before it was fixed.
	conflict string

	mu    sync.Mutex
	mints []mintRequest
	calls []*http.Request
	bodys []string
}

func newModuleGateway(t *testing.T, status int, reply string) *moduleGateway {
	t.Helper()
	g := &moduleGateway{status: status, reply: reply}
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		defer g.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		if r.URL.Path == workContextStartTaskProcedure {
			var mint mintRequest
			_ = json.Unmarshal(body, &mint)
			mint.Bearer = r.Header.Get("authorization")
			mint.WorkContext = r.Header.Get(workcontext.HeaderName)
			g.mints = append(g.mints, mint)
			for _, scope := range mint.AuthorityScopes {
				for _, action := range scope.Actions {
					if g.conflict != "" && action == g.conflict {
						writeJSON(w, http.StatusConflict, map[string]any{
							"code":    "aborted",
							"message": "the state this capability was sealed to has moved",
						})
						return
					}
					if g.deny != "" && action == g.deny {
						writeJSON(w, http.StatusForbidden, map[string]any{
							"code":    "permission_denied",
							"message": "owner is not allowed " + scope.ResourceKind + ":" + action + " at requested scope",
						})
						return
					}
				}
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"token": capability("context-" + mint.Audience + ".1"), "orgId": mint.OrgID,
				"ownerPrincipalId": "viewer", "currentActorPrincipalId": "viewer",
				"expiresAt": time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339Nano),
			})
			return
		}
		g.calls = append(g.calls, r.Clone(r.Context()))
		g.bodys = append(g.bodys, string(body))
		w.WriteHeader(g.status)
		_, _ = io.WriteString(w, g.reply)
	}))
	t.Cleanup(g.Close)
	return g
}

// observedMints is every mint this fake gateway was asked for.
func (g *moduleGateway) observedMints() []mintRequest {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]mintRequest{}, g.mints...)
}

// attestingSource is an execution credential from a fake host, for a test that
// is about something other than the mint.
func attestingSource(t *testing.T) CredentialSource {
	t.Helper()
	mint := newHostMint(t, &hostMint{})
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected")
	return mintClientFor(t, mint, tokenFile)
}
