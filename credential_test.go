package solution

import (
	"connectrpc.com/connect"
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codefly-dev/core/solution/manifest"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workcontext"
)

// TestARefusedMintFailsTheBootAndIsNeverRetried is the model's sharpest edge: a
// host that has judged this workload is not a condition to retry. The old
// runtime answered every refusal by beating again, minting a fresh single-use
// token each time, so one undeployable solution produced an audited mint every
// 15 seconds for as long as it ran. This boot reports the refusal and returns,
// which is a non-zero exit for the process that called Serve.
func TestARefusedMintFailsTheBootAndIsNeverRetried(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
	}{
		{"the host refuses this workload's build or identity", http.StatusForbidden},
		{"the host of this generation serves no mint", http.StatusNotFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mint := newHostMint(t, &hostMint{status: tc.status})
			err := bootFails(t, New(Manifest{ID: testSolutionID}), mint)
			if !errors.Is(err, workcontext.ErrMintRefused) {
				t.Fatalf("boot error = %v, want one wrapping %v so a caller can tell a judgement from an outage", err, workcontext.ErrMintRefused)
			}
			if !strings.Contains(err.Error(), mint.URL) {
				t.Errorf("boot error %q does not name the mint endpoint it asked", err)
			}
			if got := mint.count(); got != 1 {
				t.Errorf("the boot asked the host %d times, want exactly 1: a refusal is terminal", got)
			}
		})
	}
}

// TestAnUnavailableMintIsWaitedForWithinABound is the other half, and the half
// the host asked for: a workload may legitimately start before its presence
// generation has been applied, and the issuer answers that — and its own
// unreachable dependencies — with a retryable status. Treating it as terminal
// would make a pod that is one reconcile early fail for a reason that is not
// about it.
func TestAnUnavailableMintIsWaitedForWithinABound(t *testing.T) {
	t.Run("it recovers when the issuer catches up", func(t *testing.T) {
		mint := newHostMint(t, &hostMint{status: http.StatusServiceUnavailable})
		mint.recoverAfter = 2
		server := New(Manifest{ID: testSolutionID})
		server.firstMintWindow = 20 * time.Second
		solution := boot(t, server, mint)
		if status := getStatus(t, solution.client, solution.base+HealthPath); status != http.StatusOK {
			t.Fatalf("health = %d, want 200: the boot waited out an unapplied presence generation", status)
		}
		if got := mint.count(); got < 3 {
			t.Errorf("the host was asked %d times, want the two refusals plus the one that answered", got)
		}
	})

	t.Run("it gives up when the window is spent, and the window is a deadline", func(t *testing.T) {
		mint := newHostMint(t, &hostMint{status: http.StatusServiceUnavailable})
		server := New(Manifest{ID: testSolutionID})
		// Long enough for more than one attempt over TLS, short enough that
		// the test spends the window rather than waiting out the real two
		// minutes.
		server.firstMintWindow = 1500 * time.Millisecond
		started := time.Now()
		err := bootFails(t, server, mint)
		elapsed := time.Since(started)

		if !errors.Is(err, workcontext.ErrMintUnavailable) {
			t.Fatalf("boot error = %v, want one wrapping %v", err, workcontext.ErrMintUnavailable)
		}
		if !strings.Contains(err.Error(), "transient") {
			t.Errorf("boot error %q does not say the cause is transient, which is what makes the exit the orchestrator's to retry", err)
		}
		if got := mint.count(); got < 2 {
			t.Errorf("the host was asked %d times, want more than one: an unavailable mint is waited for, not judged — boot said: %v", got, err)
		}
		// The window bounds the whole operation. It used to be read only
		// between attempts, so an attempt could start at the deadline and run
		// as long as it liked past it.
		if elapsed > 4*server.firstMintWindow {
			t.Errorf("the boot took %s for a %s window: the window is a deadline on the operation, not a stopwatch read between attempts", elapsed.Round(time.Millisecond), server.firstMintWindow)
		}
	})

	t.Run("a source that never answers is cut off by the window", func(t *testing.T) {
		// The sharpest case for the deadline: a source that waits for its
		// context rather than returning. Without the window on the context it
		// is handed, the boot waits in one attempt forever — no listener, no
		// log, and nothing for an orchestrator to act on.
		mint := newHostMint(t, &hostMint{})
		blocking := &blockingCredentialSource{entered: make(chan struct{}, 1)}
		server := New(Manifest{ID: testSolutionID}).Credential(blocking)
		server.firstMintWindow = 400 * time.Millisecond
		started := time.Now()
		err := bootFails(t, server, mint)
		elapsed := time.Since(started)
		if err == nil {
			t.Fatal("the boot came up on a source that never answered")
		}
		if elapsed > 10*server.firstMintWindow {
			t.Fatalf("the boot waited %s on a source that never answers, for a %s window", elapsed.Round(time.Millisecond), server.firstMintWindow)
		}
		select {
		case <-blocking.entered:
		default:
			t.Error("the source was never called, so this test did not exercise the deadline")
		}
		if !blocking.sawCancellation() {
			t.Error("the source's context was never cancelled: the window has to reach the attempt, not just the loop around it")
		}
	})
}

// blockingCredentialSource waits for its context instead of answering: the
// shape of a source talking to something that has stopped responding.
type blockingCredentialSource struct {
	entered   chan struct{}
	mu        sync.Mutex
	cancelled bool
}

func (b *blockingCredentialSource) Credential(ctx context.Context) (workcontext.Credential, error) {
	select {
	case b.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	b.mu.Lock()
	b.cancelled = true
	b.mu.Unlock()
	return workcontext.Credential{}, fmt.Errorf("%w: %w", workcontext.ErrMintUnavailable, ctx.Err())
}

func (b *blockingCredentialSource) sawCancellation() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.cancelled
}

// TestTheProjectedTokenIsReadAtEveryMintNotCachedAtBoot pins the rotation
// property, by forcing a renewal and reading what the second mint presented.
//
// It used to stop after the first mint, which proved nothing: a client that
// read the projection once at boot and kept it forever passed. The platform
// rotates that file under a running process, so a runtime holding the boot-time
// copy renews with a token the issuer stopped honouring long before the process
// stopped running — and the refusal reads as "this build is not approved".
func TestTheProjectedTokenIsReadAtEveryMintNotCachedAtBoot(t *testing.T) {
	// A short credential so the client's own renewal lead is reached inside a
	// test rather than in ten minutes.
	mint := newHostMint(t, &hostMint{ttl: 30 * time.Second})
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "first-projection")
	source := mintClientFor(t, mint.URL, tokenFile)

	first, err := source.Credential(context.Background())
	if err != nil {
		t.Fatalf("first mint: %v", err)
	}
	// Still current: the same credential is handed back and nothing is minted.
	if _, err := source.Credential(context.Background()); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := mint.count(); got != 1 {
		t.Fatalf("the host minted %d times for two calls, want 1: a current credential is reused, never re-minted per call", got)
	}

	// The projection rotates, and the credential enters its renewal lead: the
	// renewal has to present what is on disk now.
	writeFile(t, tokenFile, "rotated-projection")
	mint.ttl = time.Hour
	waitUntilRenewed(t, source, first.Token())

	if got := mint.count(); got != 2 {
		t.Fatalf("the host minted %d times, want 2: the renewal never happened, so this test proves nothing about rotation", got)
	}
	if got := mint.presented[0]; got != "Bearer first-projection" {
		t.Errorf("the first mint presented %q, want the projection as it was then", got)
	}
	if got := mint.presented[1]; got != "Bearer rotated-projection" {
		t.Errorf("the renewal presented %q, want the rotated projection: a token read once at boot is expired long before the process is", got)
	}
}

// waitUntilRenewed calls the source until it hands back a carrier other than
// the one given, or the renewal plainly is not coming.
//
// The client renews at a fraction of the credential's own lifetime, so the wait
// is on the issuer's clock rather than this test's: polling is what a caller
// does anyway (every use goes through Credential), and the assertion is that a
// renewal happens at all, not when.
func waitUntilRenewed(t *testing.T, source CredentialSource, held string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		credential, err := source.Credential(context.Background())
		if err != nil {
			t.Fatalf("renewal: %v", err)
		}
		if credential.Token() != held {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the credential was never renewed: its lifetime entered the renewal lead and the client kept handing back the same carrier")
}

// TestEveryCallerOfOneExecutionSharesOneCarrier is the mint-once assertion that
// a client minting per request would fail.
//
// Comparing what a credential *describes* does not catch that defect: a client
// that mints per request answers the same audience and the same seal every
// time, because the host issues both again. So this compares the credential
// **material** — the carrier itself — across every caller of a concurrent
// burst, and counts what the host was asked. The runtime resolves a credential
// per use (the passthrough calls it on every request, from whatever goroutine
// the server hands it), so the burst is the shape production actually takes.
//
// It matters more than it looks: the saving this whole change buys is one mint
// plus a handful of renewals an hour against the heartbeat's 240. A client that
// silently minted per request would be *worse* than the heartbeat it replaced,
// and every functional test would still pass, because every token it issued
// would be valid.
func TestEveryCallerOfOneExecutionSharesOneCarrier(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected")
	source := mintClientFor(t, mint.URL, tokenFile)

	const callers = 32
	carriers := make([]string, callers)
	seals := make([]workcontext.Seal, callers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			credential, err := source.Credential(context.Background())
			if err != nil {
				t.Errorf("caller %d: %v", i, err)
				return
			}
			carriers[i], seals[i] = credential.Token(), credential.Seal()
		}()
	}
	close(start)
	wg.Wait()

	for i, carrier := range carriers {
		switch {
		case carrier == "":
			t.Fatalf("caller %d obtained no credential", i)
		case carrier != carriers[0]:
			// Naming which part moved rather than printing both carriers: two
			// different capabilities render alike at a glance, so "X vs X" is
			// what a reader would otherwise be left with.
			t.Fatalf("caller %d holds a different carrier from caller 0 (same length: %t, same seal: %t) — one execution holds one credential",
				i, len(carrier) == len(carriers[0]), seals[i] == seals[0])
		}
	}
	if got := mint.count(); got != 1 {
		t.Errorf("the host was asked %d times by %d concurrent callers, want exactly 1", got, callers)
	}
	// The client's own accounting, which is the only place a source that
	// re-dialled the host for the same bytes would be visible at all.
	if client, ok := source.(*workcontext.MintClient); ok {
		if mints, renewals := client.Counts(); mints != 1 || renewals != 0 {
			t.Errorf("the client reports %d mints and %d renewals, want 1 and 0", mints, renewals)
		}
	}
}

// TestABootedRuntimeRegistersNothingWithEveryLegacyKeySet is the cutover
// evidence the earlier version of this test did not provide.
//
// That version called the SDK's mint client directly and asserted no legacy
// header was on the request — which would have stayed green with the whole
// registration path still in the runtime. This one boots the real runtime with
// every deleted configuration key set to a value a host would once have acted
// on, and asserts what the host received: one request, to the mint, and
// nothing resembling a registration.
func TestABootedRuntimeRegistersNothingWithEveryLegacyKeySet(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	// Every key the cutover deleted. If any of them still reaches a code path,
	// the host below sees a second request — or a header it should never be
	// shown again.
	for key, value := range map[string]string{
		"PUBLIC_URL":                              "https://public.example.com",
		"SELF_UPSTREAM":                           "https://self.example.com",
		"HOST_REGISTER_URL":                       "https://host.example.com/api/solutions/register",
		"GATEWAY_REGISTER_URL":                    "https://gateway.example.com/solutions/_register",
		"GATEWAY_MODULE_REGISTER_URL":             "https://gateway.example.com/modules/_register",
		"GATEWAY_MODULE_REGISTRATION_TOKEN_URL":   "https://gateway.example.com/modules/_registration-token",
		"GATEWAY_SOLUTION_REGISTRATION_TOKEN_URL": "https://gateway.example.com/solutions/_registration-token",
		"CODEFLY_INTERNAL_TOKEN":                  "internal-token-that-must-not-travel",
		"CODEFLY__SOLUTION_REGISTRATION_SECRET":   "solution-secret-that-must-not-travel",
		"CODEFLY__MODULE_REGISTRATION_SECRETS":    "things:module-secret-that-must-not-travel",
		"CODEFLY__SOLUTION_REGISTRATION_INTERVAL": "1s",
		"CODEFLY_HOST_FRONTEND":                   "frontend",
	} {
		t.Setenv(key, value)
	}

	t.Setenv(manifest.APIConsumesEnvironmentVariable, consumesThings)
	solution := boot(t, New(Manifest{ID: testSolutionID}).Consumes(passthroughModule()).
		Contract(ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
		}}), mint)

	// A registration heartbeat was 15s; the shortest interval the deleted
	// configuration accepted was 1s, and it is set above. Give any surviving
	// beat several periods to happen.
	time.Sleep(3 * time.Second)
	if status := getStatus(t, solution.client, solution.base+HealthPath); status != http.StatusOK {
		t.Fatalf("health = %d, want 200", status)
	}

	if got := mint.count(); got != 1 {
		t.Errorf("the host received %d requests, want exactly 1 (the mint): anything more is a registration that survived", got)
	}
	for _, header := range []string{
		"x-codefly-internal-token",
		"x-codefly-solution-registration",
		"x-codefly-module-registration",
		"x-codefly-module-secret",
	} {
		if value := mint.headers[0].Get(header); value != "" {
			t.Errorf("the one request this runtime made presented %s=%q: this runtime has no registration credential to present", header, value)
		}
	}
	for _, path := range mint.paths {
		if path != credentialMintPath {
			t.Errorf("the host was asked for %q: the only endpoint this runtime calls on its own behalf is the mint", path)
		}
	}
}

// TestTheMintCarriesThisWorkloadsCredentialForAViewersMint: the mint this
// runtime runs on a viewer's behalf says which module is asking. Without it the
// issuer sees only that somebody holding a viewer's bearer asked, and the
// installation and binding checks at the issuer have nothing to bind to.
func TestTheMintCarriesThisWorkloadsCredentialForAViewersMint(t *testing.T) {
	host := newHostMint(t, &hostMint{})
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected")
	source := mintClientFor(t, host.URL, tokenFile)
	credential, err := source.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	gw := newModuleGateway(t, http.StatusOK, `{"entry_id":"e1"}`)
	server := New(Manifest{ID: testSolutionID}).Credential(source)
	server.cfg.gatewayURL = gw.URL
	header := http.Header{}
	header.Set("authorization", "Bearer viewer")
	header.Set(orgHeader, "org-1")
	header.Set(sessionHeader, "session-1")
	gateway := server.gatewayFor(header)
	if _, err := gateway.ForModule(context.Background(), "things", Scope{ResourceKind: "things", Actions: []string{"read"}}); err != nil {
		t.Fatalf("ForModule: %v", err)
	}
	mints := gw.observedMints()
	if len(mints) != 1 {
		t.Fatalf("observed %d mints, want 1", len(mints))
	}
	if mints[0].Bearer != "Bearer viewer" {
		t.Errorf("the mint presented bearer %q, want the viewer's", mints[0].Bearer)
	}
	if mints[0].WorkContext != credential.Token() {
		t.Errorf("the mint presented work context %q, want this workload's own credential %q", mints[0].WorkContext, credential.Token())
	}
}

// TestAMintIsRefusedWhenThisWorkloadCannotAttest is the blocker this PR was
// first refused for, inverted into a test.
//
// The attestation used to be best-effort: a workload whose renewal the issuer
// had started refusing kept minting viewer capabilities, with no execution
// binding on any of them, and a test asserted that three such mints succeeded.
// That is fail-open in the one case the attestation exists for — the issuer
// stops renewing precisely when the installation has moved, the build is no
// longer approved, or the principal's epoch has advanced — and "the host does
// not require it yet" is a statement about the counterpart's current state
// rather than a property of this runtime.
func TestAMintIsRefusedWhenThisWorkloadCannotAttest(t *testing.T) {
	buf := &syncBuffer{}
	log.SetOutput(buf)
	defer log.SetOutput(os.Stderr)

	refusing := newHostMint(t, &hostMint{status: http.StatusForbidden})
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected")
	gw := newModuleGateway(t, http.StatusOK, `{"entry_id":"e1"}`)
	server := New(Manifest{ID: testSolutionID}).Credential(mintClientFor(t, refusing.URL, tokenFile))
	server.cfg.gatewayURL = gw.URL

	header := http.Header{}
	header.Set("authorization", "Bearer viewer")
	header.Set(orgHeader, "org-1")
	header.Set(sessionHeader, "session-1")
	for range 3 {
		_, err := server.gatewayFor(header).ForModule(context.Background(), "things", Scope{ResourceKind: "things", Actions: []string{"read"}})
		if err == nil {
			t.Fatal("ForModule minted for a viewer while this workload could not attest which module was asking")
		}
		if !errors.Is(err, ErrNotAttested) {
			t.Fatalf("ForModule error = %v, want one wrapping ErrNotAttested", err)
		}
	}
	// Zero mints. Not fewer, not unattested ones: none.
	if got := len(gw.observedMints()); got != 0 {
		t.Errorf("observed %d viewer mints, want 0: a mint this solution cannot attest for must not be sent", got)
	}
	// The refusal reaches a page as this solution's condition, not the
	// viewer's authority failing.
	if code := connect.CodeOf(relayedError(fmt.Errorf("mint: %w", ErrNotAttested))); code != connect.CodeUnavailable {
		t.Errorf("a page sees %v, want unavailable: the viewer's authority is not in question and one renewal fixes it", code)
	}
	// Still throttled: a renewal that is failing fails on every request, so
	// the first occurrence must not be buried under the rest.
	if got := strings.Count(buf.String(), "refusing to mint for a viewer"); got != 1 {
		t.Errorf("the refusal was logged %d times for 3 calls, want 1:\n%s", got, buf.String())
	}
}

// TestAServerWithNoCredentialSourceMintsNothing: the fail-closed rule has no
// hole for a server that was never given a source. A gateway built outside the
// boot — which is what the passthrough test seam does — mints nothing rather
// than minting unattested.
func TestAServerWithNoCredentialSourceMintsNothing(t *testing.T) {
	gw := newModuleGateway(t, http.StatusOK, `{"entry_id":"e1"}`)
	server := New(Manifest{ID: testSolutionID})
	server.cfg.gatewayURL = gw.URL
	header := http.Header{}
	header.Set("authorization", "Bearer viewer")
	header.Set(orgHeader, "org-1")
	header.Set(sessionHeader, "session-1")
	_, err := server.gatewayFor(header).ForModule(context.Background(), "things", Scope{ResourceKind: "things", Actions: []string{"read"}})
	if !errors.Is(err, ErrNotAttested) {
		t.Fatalf("ForModule error = %v, want ErrNotAttested", err)
	}
	if got := len(gw.observedMints()); got != 0 {
		t.Errorf("observed %d mints with no credential source at all, want 0", got)
	}
}

// TestAnAbsentAuthorityValueIsNamed: the three values the platform provisions
// are refused by name. A boot that said only "could not mint" sent whoever read
// it looking through all three.
func TestAnAbsentAuthorityValueIsNamed(t *testing.T) {
	for _, key := range []string{AuthorityPrincipalKey, AuthorityAudienceKey, AuthorityProjectionAudienceKey} {
		t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MODULE_AUTHORITY__"+key, "")
	}
	// The SDK answers from the snapshot it loaded, so an unprovisioned group
	// has to be loaded as unprovisioned.
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })
	_, err := readAuthority(context.Background())
	if err == nil {
		t.Fatal("readAuthority accepted an unprovisioned authority group")
	}
	if !strings.Contains(err.Error(), AuthorityGroup) {
		t.Errorf("refusal %q does not name the %q group a reader has to provision", err, AuthorityGroup)
	}
}

// stubCredentialSource is a consumer-supplied source that holds one credential
// it was handed. It exists for the boot tests, which care about which material
// a selected source needs rather than about minting.
type stubCredentialSource struct{ credential workcontext.Credential }

func (s stubCredentialSource) Credential(context.Context) (workcontext.Credential, error) {
	return s.credential, nil
}

// mintClientFor is the SDK's mint client as the runtime configures it, pointed
// at a fake host over plain HTTP. The runtime has no mint of its own, so this
// is the only client any of these tests exercise.
//
// A boot's own client presents this workload's identity and verifies the host
// against the projected anchor (outboundClient); that path is exercised by the
// boot tests, which stand their fake host up under the cell's anchor. These
// tests drive the client directly, where the question is the mint's behaviour
// rather than who dialled it.
func mintClientFor(t *testing.T, mintURL, tokenFile string) CredentialSource {
	t.Helper()
	client, err := workcontext.NewMintClient(workcontext.MintOptions{
		URL:                mintURL,
		Audience:           testAudience,
		ProjectedToken:     workcontext.ProjectedTokenFile(tokenFile),
		ProjectionAudience: testProjectionAudience,
		HTTPClient:         &http.Client{Transport: unauthenticatedTransport, Timeout: platformRequestTimeout},
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// mintClientVia is mintClientFor with the caller's own HTTP client, for a test
// whose fake host is served over TLS: a credential source is consumer code and
// brings its own transport, so nothing in the runtime hands it one.
func mintClientVia(t *testing.T, mintURL, tokenFile string, client *http.Client) CredentialSource {
	t.Helper()
	source, err := workcontext.NewMintClient(workcontext.MintOptions{
		URL:                mintURL,
		Audience:           testAudience,
		ProjectedToken:     workcontext.ProjectedTokenFile(tokenFile),
		ProjectionAudience: testProjectionAudience,
		HTTPClient:         client,
	})
	if err != nil {
		t.Fatal(err)
	}
	return source
}

// refusingSource is a credential source whose renewal the issuer has started
// refusing for good: the shape the boot already treats as terminal, happening
// after a successful boot instead of during it.
type refusingSource struct{ err error }

func (r refusingSource) Credential(context.Context) (workcontext.Credential, error) {
	return workcontext.Credential{}, r.err
}

// TestATerminalRenewalRefusalEndsTheProcessRatherThanServing503Forever is the
// asymmetry a second reviewer found between the boot and the run.
//
// The boot separates the issuer's two answers and must: a refusal is a
// judgement on this build that no number of attempts changes, an unavailable
// mint is transient. At renewal both were collapsed into ErrNotAttested, which
// reaches a page as unavailable with the note that one renewal fixes it. For a
// refusal nothing fixes it — so the process answered 503 to every request
// forever while /health returned 200, which is the exact shape the
// delivered-presence model replaced the heartbeat to avoid: a solution that
// serves nothing and looks alive.
func TestATerminalRenewalRefusalEndsTheProcessRatherThanServing503Forever(t *testing.T) {
	for _, tc := range []struct {
		name     string
		err      error
		terminal bool
	}{
		{"the host refuses this build", fmt.Errorf("mint: %w", workcontext.ErrMintRefused), true},
		{"the state the credential is sealed to has moved", fmt.Errorf("mint: %w", workcontext.ErrRevoked), true},
		// The control, and the reason this is not just "exit on any error": an
		// issuer that cannot reach its own policy log is behaving correctly,
		// and exiting on it turns a dependency blip into a crash loop.
		{"the issuer is briefly unavailable", fmt.Errorf("mint: %w", workcontext.ErrMintUnavailable), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw := newModuleGateway(t, http.StatusOK, `{"entry_id":"e1"}`)
			server := New(Manifest{ID: testSolutionID}).Credential(refusingSource{err: tc.err})
			server.cfg.gatewayURL = gw.URL

			// Health is honest before anything has failed.
			if status, _ := healthStatus(t, server); status != http.StatusOK {
				t.Fatalf("health = %d before any failure, want 200", status)
			}

			header := http.Header{}
			header.Set("authorization", "Bearer viewer")
			header.Set(orgHeader, "org-1")
			header.Set(sessionHeader, "session-1")
			_, err := server.gatewayFor(header).ForModule(context.Background(), "things",
				Scope{ResourceKind: "things", Actions: []string{"read"}})
			if !errors.Is(err, ErrNotAttested) {
				t.Fatalf("ForModule error = %v, want ErrNotAttested", err)
			}
			if got := len(gw.observedMints()); got != 0 {
				t.Errorf("observed %d viewer mints, want 0", got)
			}

			status, body := healthStatus(t, server)
			if tc.terminal {
				if status != http.StatusServiceUnavailable {
					t.Errorf("health = %d after a refusal the issuer will not reverse, want 503: a 200 invites the host to keep routing to a binding that answers nothing", status)
				}
				if !strings.Contains(body, "refused") {
					t.Errorf("the probe says %q, want it to name the condition", body)
				}
				select {
				case <-server.credentialRefusedC():
				default:
					t.Error("the process was not asked to end: a credential the host has stopped honouring cannot be waited out")
				}
				if stored := server.terminalErr.Load(); stored == nil || !errors.Is(*stored, tc.err) {
					t.Error("the reason this process is ending was not recorded, so its exit would say nothing")
				}
			} else {
				if status != http.StatusOK {
					t.Errorf("health = %d while the issuer is merely unavailable, want 200: this is transient and exiting on it is a crash loop", status)
				}
				select {
				case <-server.credentialRefusedC():
					t.Error("the process was ended on a transient condition")
				default:
				}
			}
		})
	}
}

// healthStatus asks the health route what this process reports.
func healthStatus(t *testing.T, server *Server) (int, string) {
	t.Helper()
	recorder := httptest.NewRecorder()
	server.handleHealth(recorder, httptest.NewRequest(http.MethodGet, HealthPath, nil))
	return recorder.Code, recorder.Body.String()
}
