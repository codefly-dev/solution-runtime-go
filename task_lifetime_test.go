package solution

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/codefly-dev/core/solution/manifest"
	"github.com/codefly-dev/sdk-go/workcontext"
)

func TestForModuleLifetimeWireAndCache(t *testing.T) {
	var asks []startTaskRequest
	var ttlFields []bool
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var wire map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&wire); err != nil {
			t.Error(err)
		}
		body, err := json.Marshal(wire)
		if err != nil {
			t.Error(err)
		}
		var ask startTaskRequest
		if err := json.Unmarshal(body, &ask); err != nil {
			t.Error(err)
		}
		_, explicit := wire["ttlSeconds"]
		ttlFields = append(ttlFields, explicit)
		asks = append(asks, ask)
		writeJSON(w, 200, map[string]any{"token": capability("lifetime-issued"), "expiresAt": time.Now().Add(15 * time.Minute), "orgId": ask.OrgID, "ownerPrincipalId": "viewer", "currentActorPrincipalId": "viewer"})
	}))
	defer issuer.Close()
	srv := serveHandler(t, issuer.URL, func(ctx context.Context, g *Gateway) (any, error) {
		scope := Scope{ResourceKind: "runtime.tasks", Actions: []string{"create"}}
		if _, err := g.ForModule(ctx, "runtime", scope); err != nil {
			return nil, err
		}
		for range 2 {
			if _, err := g.ForModuleWithLifetime(ctx, "runtime", 601*time.Second, scope); err != nil {
				return nil, err
			}
		}
		if _, err := g.ForModuleWithLifetime(ctx, "runtime", 602*time.Second, scope); err != nil {
			return nil, err
		}
		if _, err := g.ForModuleWithLifetime(ctx, "records", 601*time.Second, Scope{ResourceKind: "records.records", Actions: []string{"read"}}); err != nil {
			return nil, err
		}
		return "ok", nil
	})
	resp := viewerRequest(t, srv.URL)
	defer drainAndClose(resp)
	if resp.StatusCode != 200 {
		t.Fatalf("handler status %d", resp.StatusCode)
	}
	if len(asks) != 4 {
		t.Fatalf("mint count %d, want four distinct scoped/lifetime asks", len(asks))
	}
	for i, want := range []int32{0, 601, 602, 601} {
		if asks[i].TTLSeconds != want {
			t.Fatalf("ask %d ttl %d want %d", i, asks[i].TTLSeconds, want)
		}
		if ttlFields[i] != (want != 0) {
			t.Fatalf("ask %d explicit TTL field %t, want %t", i, ttlFields[i], want != 0)
		}
	}
	for _, a := range asks {
		if a.OrgID != viewerOrg || a.SessionID != viewerSession || a.TaskID == "" || a.InstallationID != testInstallation {
			t.Fatal("viewer boundaries lost")
		}
	}
	if asks[3].Audience != "records" || asks[3].AuthorityScopes[0].ResourceKind != "records.records" {
		t.Fatal("authority scopes conflated")
	}
}

func TestForModuleLifetimeIssuerRefusal(t *testing.T) {
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ask startTaskRequest
		_ = json.NewDecoder(r.Body).Decode(&ask)
		if ask.TTLSeconds != 901 {
			t.Errorf("issuer got ttl %d", ask.TTLSeconds)
		}
		writeJSON(w, 403, map[string]string{"code": "permission_denied", "message": "requested lifetime exceeds issuer maximum"})
	}))
	defer issuer.Close()
	var got error
	srv := serveHandler(t, issuer.URL, func(ctx context.Context, g *Gateway) (any, error) {
		_, got = g.ForModuleWithLifetime(ctx, "runtime", 901*time.Second, Scope{ResourceKind: "runtime.tasks", Actions: []string{"create"}})
		return nil, got
	})
	resp := viewerRequest(t, srv.URL)
	defer drainAndClose(resp)
	var refusal *WorkContextRefusal
	if !errors.As(got, &refusal) || refusal.StatusCode != 403 || refusal.Message != "requested lifetime exceeds issuer maximum" {
		t.Fatalf("issuer refusal lost: %v", got)
	}
}

func TestForModuleLifetimeInvalid(t *testing.T) {
	t.Setenv(manifest.APIConsumesEnvironmentVariable, consumesThings)
	mint := newHostMint(t, &hostMint{})
	var invalidErrors []error
	var invalidMintCount int
	var validError error
	solution := boot(t, New(Manifest{ID: testSolutionID}).
		Consumes(passthroughModule()).
		Contract(ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
		}}).
		Handle("/lifetime", func(ctx context.Context, gw *Gateway) (any, error) {
			scope := Scope{ResourceKind: "things", Actions: []string{"read"}}
			for _, duration := range []time.Duration{-time.Second, time.Millisecond, time.Duration(1<<31) * time.Second} {
				_, err := gw.ForModuleWithLifetime(ctx, "things", duration, scope)
				invalidErrors = append(invalidErrors, err)
			}
			invalidMintCount = len(mint.observedStartTasks())
			// The same installed viewer gateway must actually mint a valid ask.
			_, validError = gw.ForModuleWithLifetime(ctx, "things", 601*time.Second, scope)
			return "ok", nil
		}), mint)
	request, err := http.NewRequest(http.MethodGet, solution.base+"/lifetime", nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("authorization", viewerBearer())
	request.Header.Set(orgHeader, "org-1")
	request.Header.Set(sessionHeader, "session-1")
	request.Header.Set(workcontext.InstallationIDHeaderName, testInstallation)
	resp, err := solution.client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	drainAndClose(resp)
	for index, err := range invalidErrors {
		if err == nil || !strings.Contains(err.Error(), "nonnegative whole seconds fitting int32") {
			t.Errorf("invalid duration %d did not reach lifetime guard: %v", index, err)
		}
	}
	if len(invalidErrors) != 3 || invalidMintCount != 0 || validError != nil || len(mint.observedStartTasks()) != 1 {
		t.Fatalf("same viewer fixture: invalid outcomes=%d invalid issuer calls=%d valid error=%v total issuer calls=%d, want3 guarded errors,0 invalid mints and only1 valid mint", len(invalidErrors), invalidMintCount, validError, len(mint.observedStartTasks()))
	}
}

func TestForModuleLifetimeDoesNotReuseAuthorityBelowRequestedLife(t *testing.T) {
	mints := 0
	issuer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ask startTaskRequest
		if err := json.NewDecoder(r.Body).Decode(&ask); err != nil {
			t.Error(err)
			return
		}
		if ask.TTLSeconds != 601 {
			t.Errorf("requested lifetime %d, want 601", ask.TTLSeconds)
		}
		mints++
		writeJSON(w, 200, map[string]any{"token": capability("bounded-life"), "expiresAt": time.Now().Add(601 * time.Second), "orgId": ask.OrgID, "ownerPrincipalId": "viewer", "currentActorPrincipalId": "viewer"})
	}))
	defer issuer.Close()
	srv := serveHandler(t, issuer.URL, func(ctx context.Context, g *Gateway) (any, error) {
		scope := Scope{ResourceKind: "runtime.tasks", Actions: []string{"create"}}
		if _, err := g.ForModuleWithLifetime(ctx, "runtime", 601*time.Second, scope); err != nil {
			return nil, err
		}
		// The issuer's 601-second answer is now shorter than a 600-second
		// operation. This elapsed ruler exercises the real request cache.
		time.Sleep(2 * time.Second)
		if _, err := g.ForModuleWithLifetime(ctx, "runtime", 601*time.Second, scope); err != nil {
			return nil, err
		}
		return "ok", nil
	})
	resp := viewerRequest(t, srv.URL)
	defer drainAndClose(resp)
	if resp.StatusCode != http.StatusOK || mints != 2 {
		t.Fatalf("elapsed explicit lifetime: status=%d issuer mints=%d, want 200 and 2", resp.StatusCode, mints)
	}
}
