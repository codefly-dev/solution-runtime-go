package solution

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"testing/synctest"
	"time"

	"github.com/codefly-dev/sdk-go/workcontext"
)

const installBody = `{"installation_id":"installation-1","organization_id":"organization-1","revision":7,"scope":[{"resourceKind":"documents","actions":["create"],"resourceIds":["collection-1"]}]}`

func installFixture() Installation {
	return Installation{
		ID: "installation-1", OrganizationID: "organization-1", Revision: 7,
		Scope: []Scope{{ResourceKind: "documents", Actions: []string{"create"}, ResourceIDs: []string{"collection-1"}}},
	}
}

func installRequest(t *testing.T, body string) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, installationPath, strings.NewReader(body))
	if err := workcontext.Attach(r, capability("install-step")); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestInstallBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
		ok   bool
	}{
		{"valid", installBody, true},
		{"exact bound", installBody + strings.Repeat(" ", installationMaxBytes-len(installBody)), true},
		{"unknown field", strings.TrimSuffix(installBody, "}") + `,"unexpected":true}`, false},
		{"unknown scope field", strings.Replace(installBody, `"actions"`, `"unexpected"`, 1), false},
		{"oversized object", strings.Replace(installBody, "installation-1", strings.Repeat("i", installationMaxBytes), 1), false},
		{"oversized trailing whitespace", installBody + strings.Repeat(" ", installationMaxBytes-len(installBody)+1), false},
		{"trailing object", installBody + `{}`, false},
		{"trailing junk", installBody + `x`, false},
		{"null", `null`, false},
		{"empty", ``, false},
		{"array", `[]`, false},
		{"missing id", strings.Replace(installBody, `"installation-1"`, `""`, 1), false},
		{"missing organization", strings.Replace(installBody, `"organization-1"`, `" "`, 1), false},
		{"zero revision", strings.Replace(installBody, `"revision":7`, `"revision":0`, 1), false},
		{"negative revision", strings.Replace(installBody, `"revision":7`, `"revision":-1`, 1), false},
		{"fractional revision", strings.Replace(installBody, `"revision":7`, `"revision":1.5`, 1), false},
		{"overflow revision", strings.Replace(installBody, `"revision":7`, `"revision":18446744073709551616`, 1), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodPost, installationPath, strings.NewReader(tc.body))
			got, err := decodeInstallation(httptest.NewRecorder(), r)
			if (err == nil) != tc.ok {
				t.Fatalf("decode = %+v, %v; want accepted=%v", got, err, tc.ok)
			}
			if tc.ok && !reflect.DeepEqual(got, installFixture()) {
				t.Fatalf("installation = %+v, want %+v", got, installFixture())
			}
			calls := 0
			s := New(Manifest{ID: testSolutionID}).OnInstall(func(context.Context, Installation) error {
				calls++
				return nil
			})
			w := httptest.NewRecorder()
			s.handleInstallation(w, installRequest(t, tc.body))
			if tc.ok {
				if w.Code != http.StatusNoContent || calls != 1 {
					t.Fatalf("valid body: status=%d, calls=%d", w.Code, calls)
				}
			} else if w.Code != http.StatusBadRequest || w.Body.String() != "invalid installation\n" || calls != 0 {
				t.Fatalf("invalid body: status=%d, body=%q, calls=%d", w.Code, w.Body, calls)
			}
		})
	}
}

func TestInstallOutcomesAndRepeats(t *testing.T) {
	for _, tc := range []struct {
		name   string
		step   func(context.Context, Installation) error
		status int
		body   string
	}{
		{"no step", nil, http.StatusNoContent, ""},
		{"success", func(context.Context, Installation) error { return nil }, http.StatusNoContent, ""},
		{"refusal", func(context.Context, Installation) error {
			return fmt.Errorf("private database diagnostic: %w", RefuseInstall("collection limit reached"))
		}, http.StatusConflict, "{\"reason\":\"collection limit reached\"}\n"},
		{"bare sentinel", func(context.Context, Installation) error {
			return fmt.Errorf("private diagnostic: %w", ErrInstallRefused)
		}, http.StatusConflict, "{\"reason\":\"installation refused\"}\n"},
		{"other error", func(context.Context, Installation) error {
			return errors.New("private database credential")
		}, http.StatusServiceUnavailable, installationFailure + "\n"},
		{"panic", func(context.Context, Installation) error {
			panic("private panic detail")
		}, http.StatusServiceUnavailable, installationFailure + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := New(Manifest{ID: testSolutionID})
			calls := 0
			if tc.step != nil {
				if got := s.OnInstall(func(ctx context.Context, installation Installation) error {
					calls++
					return tc.step(ctx, installation)
				}); got != s {
					t.Fatal("OnInstall is not chainable")
				}
			}
			for range 2 {
				w := httptest.NewRecorder()
				s.handleInstallation(w, installRequest(t, installBody))
				if w.Code != tc.status || w.Body.String() != tc.body {
					t.Fatalf("response = %d %q; want %d %q", w.Code, w.Body, tc.status, tc.body)
				}
				if tc.status == http.StatusConflict && w.Header().Get("Content-Type") != "application/json" {
					t.Fatal("refusal is not JSON")
				}
			}
			// An acknowledgement is answered from memory; a refusal or a
			// transient failure is forgotten, so the host's retry runs the step again.
			want := 1
			if tc.status != http.StatusNoContent {
				want = 2
			}
			if tc.step != nil && calls != want {
				t.Fatalf("step ran %d times, want %d", calls, want)
			}
		})
	}
}

func TestInstallRequiresOneWellFormedCarrierEvenOnRepeats(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(http.Header)
	}{
		{"missing", func(h http.Header) { h.Del(workcontext.HeaderName) }},
		{"empty", func(h http.Header) { h.Set(workcontext.HeaderName, " ") }},
		{"malformed", func(h http.Header) { h.Set(workcontext.HeaderName, "private-malformed-token") }},
		{"duplicate", func(h http.Header) { h.Add(workcontext.HeaderName, h.Get(workcontext.HeaderName)) }},
		{"comma joined", func(h http.Header) {
			h.Set(workcontext.HeaderName, h.Get(workcontext.HeaderName)+","+h.Get(workcontext.HeaderName))
		}},
		{"missing installation", func(h http.Header) { h.Del(workcontext.InstallationIDHeaderName) }},
		{"missing revision", func(h http.Header) { h.Del(workcontext.InstallationRevisionHeaderName) }},
		{"duplicate installation", func(h http.Header) {
			h.Add(workcontext.InstallationIDHeaderName, h.Get(workcontext.InstallationIDHeaderName))
		}},
		{"duplicate revision", func(h http.Header) {
			h.Add(workcontext.InstallationRevisionHeaderName, h.Get(workcontext.InstallationRevisionHeaderName))
		}},
		{"mismatched installation", func(h http.Header) { h.Set(workcontext.InstallationIDHeaderName, "another-installation") }},
		{"mismatched revision", func(h http.Header) { h.Set(workcontext.InstallationRevisionHeaderName, "999") }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := New(Manifest{ID: testSolutionID}).OnInstall(func(context.Context, Installation) error {
				calls++
				return nil
			})
			for _, cached := range []bool{false, true} {
				if cached {
					w := httptest.NewRecorder()
					s.handleInstallation(w, installRequest(t, installBody))
					if w.Code != http.StatusNoContent || calls != 1 {
						t.Fatalf("valid request: status=%d, calls=%d", w.Code, calls)
					}
				}
				before := calls
				r := installRequest(t, installBody)
				tc.edit(r.Header)
				w := httptest.NewRecorder()
				s.handleInstallation(w, r)
				if w.Code != http.StatusUnauthorized || w.Body.String() != "invalid work context\n" || calls != before {
					t.Fatalf("cached=%v: status=%d, body=%q, calls=%d", cached, w.Code, w.Body, calls)
				}
			}
		})
	}
}

func TestInstallStepReceivesCarriedContext(t *testing.T) {
	var calls, outgoing int
	s := New(Manifest{ID: testSolutionID}).OnInstall(func(ctx context.Context, got Installation) error {
		calls++
		if !reflect.DeepEqual(got, installFixture()) {
			t.Errorf("installation = %+v", got)
		}
		gw, err := ViewerFromContext(ctx)
		if err != nil {
			return err
		}
		for range 2 {
			r, err := http.NewRequestWithContext(ctx, http.MethodPost, gw.BaseURL()+"/install-effect", nil)
			if err != nil {
				return err
			}
			resp, err := gw.HTTPClient().Do(r)
			if err != nil {
				return err
			}
			_ = resp.Body.Close()
		}
		return nil
	})
	s.cfg.gatewayURL = "https://host.example"
	s.outbound = &http.Client{Transport: mintRoundTrip(func(r *http.Request) (*http.Response, error) {
		outgoing++
		token, err := workcontext.FromHeaders(r.Header)
		if err != nil || token != capability("install-step") {
			t.Error("outgoing call lost the carried Work Context")
		}
		if r.URL.Path != "/install-effect" {
			t.Errorf("unexpected call: %s", r.URL.Path)
		}
		return &http.Response{StatusCode: http.StatusNoContent, Body: http.NoBody, Header: make(http.Header)}, nil
	})}
	w := httptest.NewRecorder()
	s.handleInstallation(w, installRequest(t, installBody))
	if w.Code != http.StatusNoContent || calls != 1 || outgoing != 2 {
		t.Fatalf("status=%d, steps=%d, outgoing=%d", w.Code, calls, outgoing)
	}
}

// Exercise the production boot and mux, including the listener's caller
// admission. No exported handler or auxiliary listener mounts this route.
func TestInstallWorkloadIdentityListener(t *testing.T) {
	var calls atomic.Int32
	s := New(Manifest{ID: testSolutionID}).OnInstall(func(_ context.Context, installation Installation) error {
		calls.Add(1)
		if installation.Revision == 8 {
			return RefuseInstall("capacity reached")
		}
		return nil
	})
	b := boot(t, s, newHostMint(t, &hostMint{}))
	t.Cleanup(b.client.CloseIdleConnections)
	b.client.Timeout = 5 * time.Second
	for _, revision := range []int{7, 7, 8, 8} {
		r := installRequest(t, strings.Replace(installBody, `"revision":7`, fmt.Sprintf(`"revision":%d`, revision), 1))
		r.URL.Scheme, r.URL.Host = "https", strings.TrimPrefix(b.base, "https://")
		r.RequestURI = ""
		resp, err := b.client.Do(r)
		if err != nil {
			t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			t.Fatal(err)
		}
		if revision == 7 && (resp.StatusCode != http.StatusNoContent || len(body) != 0) {
			t.Fatalf("success = %d %q", resp.StatusCode, body)
		}
		if revision == 8 && (resp.StatusCode != http.StatusConflict || string(body) != "{\"reason\":\"capacity reached\"}\n") {
			t.Fatalf("refusal = %d %q", resp.StatusCode, body)
		}
	}
	// Revision 7 is acknowledged once and then answered from memory; revision 8
	// is refused and not remembered, so its repeat runs the step again.
	if calls.Load() != 3 {
		t.Fatalf("step ran %d times, want 3", calls.Load())
	}
	admitted := calls.Load()
	for _, tc := range []struct {
		name   string
		scheme string
		caller *tls.Certificate
	}{
		{"plaintext", "http", nil},
		{"no client certificate", "https", nil},
		{"another workload under the same anchor", "https", b.cell.identity(t, rivalPrincipal)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &tls.Config{RootCAs: b.cell.roots, MinVersion: tls.VersionTLS13}
			if tc.caller != nil {
				cfg.Certificates = []tls.Certificate{*tc.caller}
			}
			client := &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}, Timeout: 5 * time.Second}
			defer client.CloseIdleConnections()
			r := installRequest(t, installBody)
			r.URL.Scheme, r.URL.Host = tc.scheme, strings.TrimPrefix(b.base, "https://")
			r.RequestURI = ""
			resp, err := client.Do(r)
			if err == nil {
				_ = resp.Body.Close()
				if tc.scheme == "https" || resp.StatusCode != http.StatusBadRequest {
					t.Fatalf("unadmitted caller received HTTP %d", resp.StatusCode)
				}
			}
			if calls.Load() != admitted {
				t.Fatal("unadmitted caller ran the step")
			}
		})
	}
	resp, err := b.client.Get(b.base + installationPath)
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("GET = %d, want 405", resp.StatusCode)
	}
}

func TestInstallRouteIsNotOnDefaultMux(t *testing.T) {
	w := httptest.NewRecorder()
	http.DefaultServeMux.ServeHTTP(w, installRequest(t, installBody))
	if w.Code != http.StatusNotFound {
		t.Fatalf("default mux serves installation route: %d", w.Code)
	}
}

func TestInstallRefusalReasonIsBoundedAndPublic(t *testing.T) {
	for _, tc := range []struct{ input, want string }{
		{"capacity reached", "capacity reached"},
		{strings.Repeat("a", 300), strings.Repeat("a", 256)},
		{"bad\x00\n\r\t\x1b\x7f雪\xffinput", "bad        input"},
		{"\x00\n雪", "installation refused"},
	} {
		err := RefuseInstall(tc.input)
		if !errors.Is(err, ErrInstallRefused) {
			t.Fatal("refusal does not wrap the sentinel")
		}
		s := New(Manifest{ID: testSolutionID}).OnInstall(func(context.Context, Installation) error {
			return errors.Join(errors.New("internal detail"), fmt.Errorf("another private detail: %w", err))
		})
		outcome := s.installOnce(t.Context(), installFixture())
		if outcome.reason != tc.want {
			t.Fatalf("reason = %q, want %q", outcome.reason, tc.want)
		}
		if len(outcome.reason) > 256 {
			t.Fatal("reason exceeds 256 bytes")
		}
		for _, c := range []byte(outcome.reason) {
			if c < 0x20 || c > 0x7e {
				t.Fatalf("non-printable byte %x in reason", c)
			}
		}
	}
}

func TestInstallKeyIncludesIDAndRevision(t *testing.T) {
	calls := 0
	s := New(Manifest{ID: testSolutionID}).OnInstall(func(context.Context, Installation) error {
		calls++
		return nil
	})
	first := installFixture()
	second := first
	second.Revision++
	third := first
	third.ID = "installation-2"
	for _, installation := range []Installation{first, second, third, first, second, third} {
		if got := s.installOnce(t.Context(), installation); got.status != http.StatusNoContent {
			t.Fatalf("outcome = %+v", got)
		}
	}
	if calls != 3 {
		t.Fatalf("step ran %d times, want 3", calls)
	}
}

func TestInstallConcurrentDuplicateWaits(t *testing.T) {
	for _, stepErr := range []error{nil, RefuseInstall("capacity reached"), errors.New("private failure")} {
		synctest.Test(t, func(t *testing.T) {
			var calls atomic.Int32
			release := make(chan struct{})
			s := New(Manifest{ID: testSolutionID}).OnInstall(func(context.Context, Installation) error {
				calls.Add(1)
				<-release
				return stepErr
			})
			answers := make(chan installationOutcome, 8)
			for range cap(answers) {
				go func() { answers <- s.installOnce(t.Context(), installFixture()) }()
			}
			synctest.Wait()
			if calls.Load() != 1 || len(answers) != 0 {
				t.Fatalf("before completion: %d calls, %d answers", calls.Load(), len(answers))
			}
			close(release)
			synctest.Wait()
			if len(answers) != cap(answers) {
				t.Fatalf("only %d duplicates completed", len(answers))
			}
			first := <-answers
			for range cap(answers) - 1 {
				if got := <-answers; got != first {
					t.Fatalf("duplicate = %+v; first = %+v", got, first)
				}
			}
			// Concurrent duplicates share one run. A later repeat is answered from
			// memory only for an acknowledgement; a refusal or failure runs again.
			wantCalls := int32(1)
			if first.status != http.StatusNoContent {
				wantCalls = 2
			}
			if got := s.installOnce(t.Context(), installFixture()); got != first || calls.Load() != wantCalls {
				t.Fatalf("repeat = %+v, calls = %d, want %d", got, calls.Load(), wantCalls)
			}
		})
	}
}

func TestInstallWaitingCancellationDoesNotCancelStep(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		release := make(chan struct{})
		s := New(Manifest{ID: testSolutionID}).OnInstall(func(ctx context.Context, got Installation) error {
			if !reflect.DeepEqual(got, installFixture()) {
				t.Errorf("installation = %+v", got)
			}
			<-release
			return ctx.Err()
		})
		first := make(chan installationOutcome, 1)
		go func() { first <- s.installOnce(t.Context(), installFixture()) }()
		synctest.Wait()
		ctx, cancel := context.WithCancel(t.Context())
		duplicate := make(chan installationOutcome, 1)
		go func() { duplicate <- s.installOnce(ctx, installFixture()) }()
		synctest.Wait()
		cancel()
		synctest.Wait()
		if got := <-duplicate; got.status != http.StatusServiceUnavailable {
			t.Fatalf("cancelled waiter = %+v", got)
		}
		close(release)
		synctest.Wait()
		if got := <-first; got.status != http.StatusNoContent {
			t.Fatalf("first call = %+v", got)
		}
		if got := s.installOnce(t.Context(), installFixture()); got.status != http.StatusNoContent {
			t.Fatalf("repeat inherited a waiter's cancellation: %+v", got)
		}
	})
}

func TestInstallOutcomesAreBounded(t *testing.T) {
	s := New(Manifest{ID: testSolutionID})
	calls := map[string]int{}
	s.OnInstall(func(_ context.Context, installation Installation) error {
		calls[installation.ID]++
		return nil
	})
	install := func(id string) {
		t.Helper()
		if got := s.installOnce(context.Background(), Installation{ID: id, OrganizationID: "org", Revision: 1}); got.status != http.StatusNoContent {
			t.Fatalf("install %s = %d", id, got.status)
		}
	}
	for i := range maxInstallOutcomes + 1 {
		install(fmt.Sprintf("installation-%d", i))
	}
	if len(s.installations) != maxInstallOutcomes || len(s.installCompleted) != maxInstallOutcomes {
		t.Fatalf("kept %d outcomes (%d ordered), want %d", len(s.installations), len(s.installCompleted), maxInstallOutcomes)
	}
	// The oldest was evicted: a repeat runs the step again, which converges.
	install("installation-0")
	if calls["installation-0"] != 2 {
		t.Fatalf("evicted installation ran %d times, want 2", calls["installation-0"])
	}
	// The newest is still answered from memory.
	install(fmt.Sprintf("installation-%d", maxInstallOutcomes))
	if calls[fmt.Sprintf("installation-%d", maxInstallOutcomes)] != 1 {
		t.Fatal("a kept outcome ran its step again")
	}
}

func TestInstallsInFlightAreBounded(t *testing.T) {
	s := New(Manifest{ID: testSolutionID})
	release := make(chan struct{})
	started := make(chan struct{}, maxInstallsInFlight)
	s.OnInstall(func(context.Context, Installation) error {
		started <- struct{}{}
		<-release
		return nil
	})
	done := make(chan installationOutcome, maxInstallsInFlight)
	for i := range maxInstallsInFlight {
		go func() {
			done <- s.installOnce(context.Background(), Installation{ID: fmt.Sprintf("flight-%d", i), OrganizationID: "org", Revision: 1})
		}()
	}
	for range maxInstallsInFlight {
		<-started
	}
	if got := s.installOnce(context.Background(), Installation{ID: "one-too-many", OrganizationID: "org", Revision: 1}); got.status != http.StatusServiceUnavailable {
		t.Fatalf("a step past the in-flight bound = %d, want 503", got.status)
	}
	close(release)
	for range maxInstallsInFlight {
		if got := <-done; got.status != http.StatusNoContent {
			t.Fatalf("an in-flight step = %d", got.status)
		}
	}
	if got := s.installOnce(context.Background(), Installation{ID: "one-too-many", OrganizationID: "org", Revision: 1}); got.status != http.StatusNoContent {
		t.Fatalf("once the flights finished, the refused step = %d, want 204", got.status)
	}
}
