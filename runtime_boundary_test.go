package solution

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestHostRuntimeBoundaryAuthenticatesMintOnlyAndRefusesDowngrade(t *testing.T) {
	for _, refuse := range []bool{false, true} {
		t.Run(map[bool]string{false: "bound mint", true: "exchange refused"}[refuse], func(t *testing.T) {
			var mints, reads atomic.Int32
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case solutionRegistrationTokenPath:
					if r.Header.Get(solutionSecretHeader) != "test-secret" {
						t.Error("exchange missing solution secret")
					}
					if r.Header.Get("authorization") != "" {
						t.Error("viewer bearer leaked to registration exchange")
					}
					if refuse {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					writeJSON(w, 200, map[string]any{"token": "signed-registration", "expiresAt": time.Now().Add(time.Minute)})
				case workContextStartTaskProcedure:
					mints.Add(1)
					var ask startTaskRequest
					if err := json.NewDecoder(r.Body).Decode(&ask); err != nil {
						t.Error(err)
					}
					if ask.TaskID != "" || ask.OrgID != viewerOrg || ask.SessionID != viewerSession {
						t.Errorf("wrong mint identity: %+v", ask)
					}
					if r.Header.Get(solutionRegistrationHeader) != "signed-registration" || r.Header.Get("authorization") != "Bearer viewer-token" {
						t.Error("mint lacks independent solution and viewer credentials")
					}
					if r.Header.Get(solutionSecretHeader) != "" {
						t.Error("raw registration secret leaked to mint")
					}
					writeJSON(w, 200, map[string]any{"token": "signed.context", "expiresAt": time.Now().Add(time.Minute), "orgId": viewerOrg, "ownerPrincipalId": "viewer", "actorPrincipalId": "viewer"})
				case "/data":
					reads.Add(1)
					if r.Header.Get(solutionRegistrationHeader) != "" || r.Header.Get(solutionSecretHeader) != "" {
						t.Error("registration credential leaked to module")
					}
					writeJSON(w, 200, map[string]bool{"ok": true})
				default:
					t.Errorf("unexpected path %s", r.URL.Path)
					w.WriteHeader(404)
				}
			}))
			defer upstream.Close()
			s := New(Manifest{ID: "example", UseHostRuntimeBoundary: true})
			s.cfg = config{gatewayURL: upstream.URL, solutionTokenURL: upstream.URL + solutionRegistrationTokenPath, solutionSecret: "test-secret", internalToken: "test-internal"}
			page := httptest.NewServer(s.wrap(func(ctx context.Context, g *Gateway) (any, error) {
				scoped, err := g.ForModule(ctx, "records", Scope{ResourceKind: "records.rows", Actions: []string{"read"}})
				if err != nil {
					return nil, err
				}
				req, _ := http.NewRequestWithContext(ctx, "GET", upstream.URL+"/data", nil)
				response, err := scoped.HTTPClient().Do(req)
				if err != nil {
					return nil, err
				}
				defer drainAndClose(response)
				return true, nil
			}))
			defer page.Close()
			response := viewerRequest(t, page.URL)
			defer drainAndClose(response)
			if refuse {
				if response.StatusCode == 200 || mints.Load() != 0 || reads.Load() != 0 {
					t.Fatal("credential refusal downgraded to ordinary access")
				}
			} else if response.StatusCode != 200 || mints.Load() != 1 || reads.Load() != 1 {
				t.Fatalf("status=%d mints=%d reads=%d", response.StatusCode, mints.Load(), reads.Load())
			}
		})
	}
}
