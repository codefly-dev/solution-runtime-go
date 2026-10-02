package solution

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"

	"github.com/codefly-dev/sdk-go/workcontext"
	"testing"
)

// trap is a destination this runtime must never dial: it records anything that
// reaches it, so a test can assert absence rather than infer it.
type trap struct {
	*httptest.Server
	mu   sync.Mutex
	hits []http.Header
}

func newTrap(t *testing.T) *trap {
	t.Helper()
	tr := &trap{}
	tr.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tr.mu.Lock()
		tr.hits = append(tr.hits, r.Header.Clone())
		tr.mu.Unlock()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(tr.Close)
	return tr
}

func (tr *trap) received() []http.Header {
	tr.mu.Lock()
	defer tr.mu.Unlock()
	return append([]http.Header(nil), tr.hits...)
}

// TestACredentialBearingRequestIsNeverRedirected is the blocker a second
// reviewer found, and every piece of it looked right on its own.
//
// The boot's outbound client did set CheckRedirect. gatewayFor copied only its
// .Transport, so every gateway client was an http.Client literal with Go's
// default policy: follow up to ten hops. Go copies the original request's
// headers onto a redirected request and strips only Authorization,
// WWW-Authenticate and Cookie — so the viewer's capability and the installation
// headers travelled, and on the mint this workload's own credential in
// x-codefly-work-context travelled with them. bearerTransport then set the
// bearer again on the redirected hop, putting back the one header Go strips.
// A 307 re-sends the body too.
//
// So one `307 Location: http://elsewhere/` from the gateway, from accounts, or
// from any module the gateway relays handed a third party the viewer's unscoped
// bearer, the capability minted for them, and this workload's credential — in
// cleartext, because nothing about an http:// hop involves the TLS
// configuration that protects the first one.
//
// The assertion is absence at the destination, on every credential-bearing
// path, with the trap on plain http so a followed hop is unmistakable.
func TestACredentialBearingRequestIsNeverRedirected(t *testing.T) {
	for _, tc := range []struct {
		name string
		// redirect reports whether this request is the one to bounce
		redirect func(*http.Request) bool
	}{
		{"the viewer's mint is redirected", func(r *http.Request) bool {
			return r.URL.Path == workContextStartTaskProcedure
		}},
		{"the module call is redirected", func(r *http.Request) bool {
			return r.URL.Path != workContextStartTaskProcedure
		}},
		{"every hop is redirected", func(*http.Request) bool { return true }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tr := newTrap(t)
			var gw *httptest.Server
			gw = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.redirect(r) {
					// 307 keeps the method and re-sends the body, which is the
					// worst case: the mint's own payload is replayed too.
					http.Redirect(w, r, tr.URL+"/stolen", http.StatusTemporaryRedirect)
					return
				}
				if r.URL.Path == workContextStartTaskProcedure {
					writeJSON(w, http.StatusOK, map[string]any{
						"token": capability("context-things.1"), "orgId": "org-1",
						"expiresAt": "2099-01-01T00:00:00Z",
					})
					return
				}
				writeJSON(w, http.StatusOK, map[string]any{"entry_id": "e1"})
			}))
			t.Cleanup(gw.Close)

			mint := newHostMint(t, &hostMint{})
			tokenFile := filepath.Join(t.TempDir(), "token")
			writeFile(t, tokenFile, "projected")
			server := New(Manifest{ID: testSolutionID}).Credential(mintClientFor(t, mint.URL, tokenFile))
			server.cfg.gatewayURL = gw.URL

			header := http.Header{}
			header.Set("authorization", "Bearer viewer-secret")
			header.Set(orgHeader, "org-1")
			header.Set(sessionHeader, "session-1")

			// The call may fail or succeed depending on which hop bounced; what
			// it must never do is reach the trap.
			moduleGW, err := server.gatewayFor(header).ForModule(context.Background(), "things",
				Scope{ResourceKind: "things", Actions: []string{"read"}})
			if err == nil && moduleGW != nil {
				type empty struct{}
				_, _ = Unary[empty, empty](context.Background(), moduleGW, "/things.v1.Things/Read", &empty{})
			}

			hits := tr.received()
			if len(hits) != 0 {
				var leaked []string
				for _, h := range hits {
					for _, name := range []string{"authorization", workcontext.HeaderName, orgHeader, sessionHeader} {
						if v := h.Get(name); v != "" {
							leaked = append(leaked, name+"="+v)
						}
					}
				}
				t.Fatalf("a redirected credential-bearing request reached a third party %d time(s), carrying [%s]: the viewer's bearer, their capability and this workload's own credential must never follow a Location",
					len(hits), strings.Join(leaked, " "))
			}
		})
	}
}

// TestEveryGatewayClientRefusesAForeignDestination is the belt to the braces of
// the test above: the redirect policy lives on the client, so the transport is
// where a client built without it is still stopped.
//
// Both of the clients a gateway hands out are checked, because the bug was that
// they were http.Client literals built in two places while only a third place
// carried the policy.
func TestEveryGatewayClientRefusesAForeignDestination(t *testing.T) {
	tr := newTrap(t)
	gw := newModuleGateway(t, http.StatusOK, `{"entry_id":"e1"}`)
	server := New(Manifest{ID: testSolutionID})
	server.cfg.gatewayURL = gw.URL
	header := http.Header{}
	header.Set("authorization", "Bearer viewer-secret")
	header.Set(orgHeader, "org-1")
	header.Set(sessionHeader, "session-1")
	gateway := server.gatewayFor(header)

	for _, tc := range []struct {
		name   string
		client *http.Client
	}{
		{"HTTPClient", gateway.HTTPClient()},
		{"bearerClient", gateway.bearerClient()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request, err := http.NewRequest(http.MethodGet, tr.URL+"/stolen", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp, err := tc.client.Do(request)
			if err == nil {
				_ = resp.Body.Close()
				t.Fatalf("%s dialled a destination that is not its gateway", tc.name)
			}
			if !strings.Contains(err.Error(), "refusing to send a credential-bearing request") {
				t.Errorf("%s refused with %v, want the refusal naming what these headers carry", tc.name, err)
			}
			if got := tr.received(); len(got) != 0 {
				t.Errorf("%s reached the foreign destination %d time(s)", tc.name, len(got))
			}
		})
	}
}

// TestASameOriginRedirectIsNotFollowedEither isolates the redirect policy from
// the origin pin.
//
// The cross-origin test above passes if *either* mechanism holds, which is what
// defence in depth means and also what makes it a poor test of either one: with
// CheckRedirect removed, the transport's pin still refuses the foreign hop, so
// the test stays green while the policy it is named after is gone. (Found by
// mutating it, which is the only reason I know.)
//
// Here the Location is on the gateway's own origin, so the pin permits it and
// only the client's policy can stop the hop. A same-origin redirect is also the
// case that is not merely theoretical: a gateway behind an ingress that
// normalises a path answers 307 to itself, and following it would re-send the
// mint's body and re-present every credential for no reason — the runtime
// should see the 3xx and report it, not chase it.
func TestASameOriginRedirectIsNotFollowedEither(t *testing.T) {
	var hops struct {
		mu    sync.Mutex
		paths []string
	}
	record := func(p string) {
		hops.mu.Lock()
		defer hops.mu.Unlock()
		hops.paths = append(hops.paths, p)
	}

	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		record(r.URL.Path)
		if r.URL.Path == workContextStartTaskProcedure {
			// Same origin, different path: the pin allows it.
			http.Redirect(w, r, "/relocated"+workContextStartTaskProcedure, http.StatusTemporaryRedirect)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"token": capability("context-things.1"), "orgId": "org-1",
			"expiresAt": "2099-01-01T00:00:00Z",
		})
	}))
	t.Cleanup(gw.Close)

	mint := newHostMint(t, &hostMint{})
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected")
	server := New(Manifest{ID: testSolutionID}).Credential(mintClientFor(t, mint.URL, tokenFile))
	server.cfg.gatewayURL = gw.URL

	header := http.Header{}
	header.Set("authorization", "Bearer viewer-secret")
	header.Set(orgHeader, "org-1")
	header.Set(sessionHeader, "session-1")
	if _, err := server.gatewayFor(header).ForModule(context.Background(), "things",
		Scope{ResourceKind: "things", Actions: []string{"read"}}); err == nil {
		t.Error("ForModule reported success on a mint that answered 307: the redirect was followed and its answer taken as the capability")
	}

	hops.mu.Lock()
	defer hops.mu.Unlock()
	for _, path := range hops.paths {
		if strings.HasPrefix(path, "/relocated") {
			t.Fatalf("the mint followed a same-origin 307 to %q, re-sending its body and re-presenting the viewer's bearer and this workload's credential: a 3xx is an answer to report, not a hop to take (hops: %v)",
				path, hops.paths)
		}
	}
	if len(hops.paths) != 1 {
		t.Errorf("the mint made %d requests (%v), want exactly 1: the 307 must end the exchange", len(hops.paths), hops.paths)
	}
}
