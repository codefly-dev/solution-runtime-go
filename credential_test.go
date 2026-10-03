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
	"sync/atomic"
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
		// Bounded here, not measured afterwards: against a runtime whose
		// window is not a deadline this call never returns, and every
		// assertion below is unreachable.
		err := bootFailsWithin(t, server, mint, 4*server.firstMintWindow)
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
		err := bootFailsWithin(t, server, mint, 10*server.firstMintWindow)
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
	// Every deleted URL points at the host this test counts requests on, not at
	// example.com. A second reviewer caught that: aimed elsewhere, a surviving
	// registration would have been a connection to a domain that does not
	// resolve and the host would have counted nothing, so the test passed
	// because the old code never minted rather than because nothing registers.
	for key, value := range map[string]string{
		"PUBLIC_URL":                              "https://public.example.com",
		"SELF_UPSTREAM":                           "https://self.example.com",
		"HOST_REGISTER_URL":                       mint.URL + "/api/solutions/register",
		"GATEWAY_REGISTER_URL":                    mint.URL + "/solutions/_register",
		"GATEWAY_MODULE_REGISTER_URL":             mint.URL + "/modules/_register",
		"GATEWAY_MODULE_REGISTRATION_TOKEN_URL":   mint.URL + "/modules/_registration-token",
		"GATEWAY_SOLUTION_REGISTRATION_TOKEN_URL": mint.URL + "/solutions/_registration-token",
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
// Which also says what the tests over it can and cannot prove, and it is worth
// being explicit because a reader naturally assumes otherwise: they pin the
// SDK's *contract* — one carrier per execution, the projected token re-read at
// every mint — and they reach no line of this repository, so no mutation of
// this package's own code can fail them. Their value is that an SDK bump
// changing either property fails here rather than in a deployment. What this
// runtime does with the client is covered by the boot and health tests, which
// drive start() and serve().
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
		// NOT terminal, and the earlier revision of this test asserted the
		// opposite. ErrRevoked does not come back from the mint at all — it is
		// a *callee* refusing a capability sealed to state that has moved — and
		// the SDK's contract for it is a refresh and one retry. Ending the
		// process on it would be ending on a condition the client recovers
		// from. It is handled where it arrives: the far end's 409 drops the
		// capability so the next call mints.
		{"a capability a callee says is superseded", fmt.Errorf("mint: %w", workcontext.ErrRevoked), false},
		// The control, and the reason this is not just "exit on any error": an
		// issuer that cannot reach its own policy log is behaving correctly,
		// and exiting on it turns a dependency blip into a crash loop.
		{"the issuer is briefly unavailable", fmt.Errorf("mint: %w", workcontext.ErrMintUnavailable), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw := newModuleGateway(t, http.StatusOK, `{"entry_id":"e1"}`)
			server := New(Manifest{ID: testSolutionID}).Credential(refusingSource{err: tc.err})
			server.cfg.gatewayURL = gw.URL

			// Health asks the credential, so with a source that refuses it is
			// already unhealthy before any request — which is the point of
			// C5: a solution serving no module calls must not look alive while
			// the issuer has stopped approving its build.
			if status, _ := healthStatus(t, server); status != http.StatusServiceUnavailable {
				t.Errorf("health = %d while the credential cannot be obtained, want 503: the probe is the only channel this runtime has, and lazy renewal means nothing else may ever ask", status)
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
				// Unhealthy, because this process cannot act for a viewer
				// until the credential can be obtained — but NOT ending, which
				// is the distinction that matters: the host stops routing to
				// it, and it recovers when the issuer does. Exiting here would
				// turn a dependency blip into a crash loop.
				if status != http.StatusServiceUnavailable {
					t.Errorf("health = %d while the credential cannot be obtained, want 503", status)
				}
				if strings.Contains(body, "refused") {
					t.Errorf("the probe says %q, which reads as a judgement on this build: this condition is transient", body)
				}
				select {
				case <-server.credentialRefusedC():
					t.Error("the process was ended on a transient condition")
				default:
				}
				if server.terminalErr.Load() != nil {
					t.Error("a transient condition was recorded as the reason this process is ending")
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

// TestHealthIsHonestAboutTheCredential is the other direction of C5, so the
// check above is not just a probe that always fails: a process holding a
// current credential is healthy, and one that holds none at all (a server built
// outside a boot) does not pretend to consult one.
func TestHealthIsHonestAboutTheCredential(t *testing.T) {
	t.Run("a current credential is healthy", func(t *testing.T) {
		mint := newHostMint(t, &hostMint{})
		tokenFile := filepath.Join(t.TempDir(), "token")
		writeFile(t, tokenFile, "projected")
		server := New(Manifest{ID: testSolutionID}).Credential(mintClientFor(t, mint.URL, tokenFile))
		if status, body := healthStatus(t, server); status != http.StatusOK {
			t.Errorf("health = %d (%s) with a credential the issuer mints, want 200", status, body)
		}
		// And asking did not turn the probe into a mint per probe.
		for range 5 {
			healthStatus(t, server)
		}
		if got := mint.count(); got != 1 {
			t.Errorf("six probes produced %d mints, want 1: the client holds one credential and the probe must not become a heartbeat", got)
		}
	})

	t.Run("no credential source at all", func(t *testing.T) {
		server := New(Manifest{ID: testSolutionID})
		if status, _ := healthStatus(t, server); status != http.StatusOK {
			t.Errorf("health = %d on a server with no credential source, want 200: there is nothing to consult, and a gateway built outside a boot mints nothing anyway", status)
		}
	})
}

// failingCredentialSource answers every ask with one error, which is how a
// refused build and an unreachable issuer both look from a route's point of
// view.
type failingCredentialSource struct{ err error }

func (f failingCredentialSource) Credential(context.Context) (workcontext.Credential, error) {
	return workcontext.Credential{}, f.err
}

// TestAPlainHandlerRefusesToActWithoutACredential: a plain handler mints
// nothing, which is exactly why it was the route that never consulted the
// credential — and it still receives a gateway carrying the viewer's bearer.
// With the credential refused, a booted server kept answering 200 and kept
// forwarding that bearer, with the credential consulted zero times.
//
// handleHealth already made this argument in full and it was applied to the
// probe alone: the probe answered honestly while the routes carried on.
func TestAPlainHandlerRefusesToActWithoutACredential(t *testing.T) {
	for _, tc := range []struct {
		name  string
		err   error
		ends  bool
		names error
	}{
		{
			"a refused build",
			fmt.Errorf("%w: this build is not the one the presence document approved", workcontext.ErrMintRefused),
			true, ErrCredentialRefused,
		},
		{
			"an issuer that cannot answer",
			fmt.Errorf("%w: the issuer cannot reach its own dependencies", workcontext.ErrMintUnavailable),
			false, ErrCredentialUnavailable,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reached atomic.Int64
			server := New(Manifest{ID: testSolutionID}).
				Credential(failingCredentialSource{err: tc.err})
			handler := server.wrapRequest(func(*http.Request, *Gateway) (any, error) {
				reached.Add(1)
				return map[string]string{"ok": "yes"}, nil
			})

			request := httptest.NewRequest(http.MethodGet, "/thing", nil)
			request.Header.Set("authorization", "Bearer viewer")
			recorder := httptest.NewRecorder()
			handler(recorder, request)

			if recorder.Code != http.StatusServiceUnavailable {
				t.Errorf("the handler answered %d while this process held no approved credential, want 503: it would forward the viewer's bearer to the gateway under an authority the issuer has withdrawn", recorder.Code)
			}
			if got := reached.Load(); got != 0 {
				t.Errorf("the handler body ran %d times, want 0: the refusal has to come before anything acts for the viewer", got)
			}
			body := recorder.Body.String()
			if !strings.Contains(body, "authority") {
				t.Errorf("the 503 body %q does not say why this solution will not act", body)
			}
			// And it carries nothing the source said. The error wraps whatever
			// came back — a mint URL, the issuer's own text, a dial failure
			// naming an internal address — and this gate wrote it into the
			// viewer's response verbatim, which is the disclosure
			// handlerErrorResponse exists to prevent. A new gate in front of
			// the handler put a path *around* the sanitization.
			for _, leaked := range []string{"issuer", "presence document", "dependencies", "mint"} {
				if strings.Contains(body, leaked) {
					t.Errorf("the 503 body %q carries %q from the source's own error", body, leaked)
				}
			}
			// Terminal and transient stay distinguishable: conflating them was
			// a review blocker in both directions.
			if err := server.actingForAViewer(context.Background()); !errors.Is(err, tc.names) {
				t.Errorf("the route's refusal is %v, want one wrapping %v", err, tc.names)
			}
			if ended := server.terminalErr.Load() != nil; ended != tc.ends {
				t.Errorf("the process ending = %v, want %v: a judgement about this build ends it, an issuer that cannot answer right now does not", ended, tc.ends)
			}
		})
	}
}

// TestAPlainHandlerStillServesWithAnApprovedCredential is the survive-control.
// Without it, a route that refuses everything unconditionally passes the test
// above.
func TestAPlainHandlerStillServesWithAnApprovedCredential(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected")
	server := New(Manifest{ID: testSolutionID}).Credential(mintClientFor(t, mint.URL, tokenFile))
	handler := server.wrapRequest(func(*http.Request, *Gateway) (any, error) {
		return map[string]string{"ok": "yes"}, nil
	})
	request := httptest.NewRequest(http.MethodGet, "/thing", nil)
	request.Header.Set("authorization", "Bearer viewer")
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Fatalf("a handler answered %d while this process holds an approved credential, want 200: %s", recorder.Code, recorder.Body.String())
	}
}

// slowCredentialSource answers, eventually. It is the shape of an issuer that
// is reachable and not responding.
type slowCredentialSource struct {
	after      time.Duration
	credential workcontext.Credential
}

func (s slowCredentialSource) Credential(ctx context.Context) (workcontext.Credential, error) {
	select {
	case <-time.After(s.after):
		return s.credential, nil
	case <-ctx.Done():
		return workcontext.Credential{}, ctx.Err()
	}
}

// TestARouteIsNotParkedByASlowCredentialSource: the bound on asking for the
// credential has to be imposed outside the SDK's client, because a context does
// not reach what blocks.
//
// The mint client takes a sync.Mutex and holds it across the network mint, and
// sync.Mutex.Lock ignores contexts — so a caller arriving during a slow renewal
// waits on the lock for as long as the renewal takes, whatever deadline it
// passed in. That made the two-second health deadline advisory, and it would
// have made every route's credential check park behind one slow issuer, which
// is a worse failure than the one the check was added for.
func TestARouteIsNotParkedByASlowCredentialSource(t *testing.T) {
	slow := slowCredentialSource{after: 30 * time.Second}

	t.Run("with no credential in hand, the route refuses promptly", func(t *testing.T) {
		server := New(Manifest{ID: testSolutionID}).Credential(slow)
		started := time.Now()
		done := make(chan error, 1)
		go func() { done <- server.actingForAViewer(context.Background()) }()
		select {
		case err := <-done:
			if err == nil {
				t.Fatal("the route acted for a viewer without this process holding a credential")
			}
			if !errors.Is(err, ErrCredentialUnavailable) {
				t.Errorf("the route refused with %v, want one wrapping %v", err, ErrCredentialUnavailable)
			}
			if elapsed := time.Since(started); elapsed > 20*routeCredentialTimeout {
				t.Errorf("the route took %s to answer for a %s bound: the deadline it passes in does not reach the lock the source holds", elapsed, routeCredentialTimeout)
			}
		case <-time.After(20 * routeCredentialTimeout):
			t.Fatalf("the route was still waiting %s after a %s bound: every request would park behind one slow issuer", 20*routeCredentialTimeout, routeCredentialTimeout)
		}
	})

	// And the other half, which is why a timeout does not simply refuse:
	// renewal begins while a valid credential is still held, so a slow renewal
	// must not 503 every viewer.
	t.Run("with an unexpired credential in hand, the route proceeds", func(t *testing.T) {
		mint := newHostMint(t, &hostMint{})
		held := mintedCredential(t, mint, "held")
		server := New(Manifest{ID: testSolutionID}).Credential(slow)
		server.credentialHeld = held
		done := make(chan error, 1)
		go func() { done <- server.actingForAViewer(context.Background()) }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("a route was refused while this process holds a credential valid for another hour and the source is merely slow: %v", err)
			}
		case <-time.After(20 * routeCredentialTimeout):
			t.Fatal("the route parked despite holding a valid credential")
		}
	})

	// An expired one is not "in hand" at all.
	t.Run("with an expired credential, the route refuses", func(t *testing.T) {
		mint := newHostMint(t, &hostMint{ttl: time.Second})
		expired := mintedCredential(t, mint, "expired")
		server := New(Manifest{ID: testSolutionID}).Credential(slow)
		server.credentialHeld = expired
		// Past its expiry, which is the state a route must not act under.
		for !time.Now().After(expired.ExpiresAt()) {
			time.Sleep(50 * time.Millisecond)
		}
		done := make(chan error, 1)
		go func() { done <- server.actingForAViewer(context.Background()) }()
		select {
		case err := <-done:
			if err == nil {
				t.Error("a route acted for a viewer on an expired credential")
			}
		case <-time.After(20 * routeCredentialTimeout):
			t.Fatal("the route parked")
		}
	})
}

// TestEverySourceIsHeldToTheFrozenAuthority: a supplied credential source
// replaces the mint client, and with it every option mintOptions carries —
// including the Authority the SDK rechecks before each renewal. So the one
// guarantee that stops a drifted authority value being re-sealed into a new
// credential applied to the platform path only, while this package's
// documentation promises it of the process.
func TestEverySourceIsHeldToTheFrozenAuthority(t *testing.T) {
	// Two different credentials, so the second ask reads as a renewal: the
	// token is the generation. They come from a plain-HTTP fake host of this
	// test's own, because the boot's mint is served under the cell's anchor and
	// this is only a way to obtain two real sealed credentials to hand out.
	// Three: the boot consumes the first, the control renewal the second, and
	// the ask after the drift the third.
	fabricator := newHostMint(t, &hostMint{})
	handing := &handingSource{credentials: []workcontext.Credential{
		mintedCredential(t, fabricator, "first"),
		mintedCredential(t, fabricator, "second"),
		mintedCredential(t, fabricator, "third"),
	}}

	mint := newHostMint(t, &hostMint{})
	bootEnvironment(t, mint)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := New(Manifest{ID: testSolutionID}).Credential(handing)
	if _, err := server.start(ctx); err != nil {
		t.Fatalf("boot: %v", err)
	}

	// The control: with the authority as this process froze it, a renewal is
	// handed over.
	if _, err := server.credential.Credential(ctx); err != nil {
		t.Fatalf("a renewal was refused while the authority had not drifted: %v", err)
	}

	// Now an authority-bearing value drifts under the running process, and the
	// next renewal must be refused rather than re-sealed against it.
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MODULE_AUTHORITY__"+AuthorityPrincipalKey,
		"spiffe://codefly.test/ns/solutions/sa/somebody-else")
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	_, err := server.credential.Credential(ctx)
	if err == nil {
		t.Fatal("a renewal proceeded after an authority-bearing value drifted from the one this process froze: that renewal is the one moment the drift would be laundered into a differently-sealed credential")
	}
	if !errors.Is(err, workcontext.ErrMintRefused) {
		t.Errorf("the refusal %v is not reported as a judgement, so the boot and the run would classify it differently", err)
	}
}

// handingSource hands out a prepared sequence of credentials, so a second ask
// reads as a renewal.
type handingSource struct {
	mu          sync.Mutex
	credentials []workcontext.Credential
	at          int
	asks        int
}

func (h *handingSource) Credential(context.Context) (workcontext.Credential, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.asks++
	credential := h.credentials[h.at]
	if h.at < len(h.credentials)-1 {
		h.at++
	}
	return credential, nil
}

// count is how many times this source was reached, which is what shows whether
// a check ran before the ask or after it.
func (h *handingSource) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.asks
}

// mintedCredential is one credential from the fake host, so a test can hand out
// a real sealed one rather than a zero value.
func mintedCredential(t *testing.T, mint *hostMint, projection string) workcontext.Credential {
	t.Helper()
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, projection)
	credential, err := mintClientFor(t, mint.URL, tokenFile).Credential(context.Background())
	if err != nil {
		t.Fatalf("mint a credential for the test: %v", err)
	}
	return credential
}

// unavailableAfter answers normally until `after` asks, then reports the issuer
// unavailable — the shape of a credential inside its renewal window against an
// issuer that has stopped answering.
type unavailableAfter struct {
	mu         sync.Mutex
	credential workcontext.Credential
	asks       int
	after      int
}

func (u *unavailableAfter) Credential(context.Context) (workcontext.Credential, error) {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.asks++
	if u.asks > u.after {
		return workcontext.Credential{}, fmt.Errorf("%w: the issuer cannot answer right now", workcontext.ErrMintUnavailable)
	}
	return u.credential, nil
}

func (u *unavailableAfter) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.asks
}

// TestAStreamOfViewerRequestsDoesNotMintPerRequest is the regression this
// round's own fix introduced, and it is the worst kind this runtime can have.
//
// With the credential inside its renewal window and the issuer answering 503,
// every viewer request asked, every ask minted, and every request answered 503
// — while a perfectly valid credential sat in hand. Forty requests, forty
// audited mints. That is not a smaller version of the heartbeat this runtime
// deleted; it is a larger one, because the heartbeat minted on a timer and this
// minted on traffic. The PR body's own claim is that a client minting per
// request "would be worse than the heartbeat it replaced".
//
// The fast-failure path refused outright while the timeout path, three lines
// below, already served on a held credential. The two disagreed.
func TestAStreamOfViewerRequestsDoesNotMintPerRequest(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	held := mintedCredential(t, mint, "held")
	source := &unavailableAfter{credential: held, after: 1}

	server := New(Manifest{ID: testSolutionID}).Credential(source)
	handler := server.wrapRequest(func(*http.Request, *Gateway) (any, error) {
		return map[string]string{"ok": "yes"}, nil
	})

	// The first request takes the credential, which is valid for a while yet.
	request := httptest.NewRequest(http.MethodGet, "/thing", nil)
	request.Header.Set("authorization", "Bearer viewer")
	first := httptest.NewRecorder()
	handler(first, request)
	if first.Code != http.StatusOK {
		t.Fatalf("the first request answered %d, want 200: %s", first.Code, first.Body.String())
	}

	// Now the issuer stops answering, and forty viewers arrive.
	const viewers = 40
	for range viewers {
		recorder := httptest.NewRecorder()
		handler(recorder, httptest.NewRequest(http.MethodGet, "/thing", nil).WithContext(request.Context()))
		served := httptest.NewRequest(http.MethodGet, "/thing", nil)
		served.Header.Set("authorization", "Bearer viewer")
		recorder = httptest.NewRecorder()
		handler(recorder, served)
		if recorder.Code != http.StatusOK {
			t.Fatalf("a viewer request answered %d while this process held a credential valid until %s: the issuer being unavailable is not a reason to refuse a viewer when the authority to act for them is already in hand",
				recorder.Code, held.ExpiresAt().UTC().Format(time.RFC3339))
		}
	}

	// And the asks were not one per request. One ask failed, which quiets the
	// next ones; the renewal the credential's own expiry dictates is still
	// ahead of us.
	if got := source.count(); got > 4 {
		t.Errorf("the source was asked %d times for %d viewer requests: a runtime that asks — and therefore mints — per request is worse than the heartbeat it replaced, which at least minted on a timer", got, viewers)
	}
}

// TestConcurrentViewerRequestsShareOneCredentialAsk is the other half, and the
// half a sequential test cannot see: without single-flight, N requests arriving
// together each start their own ask, and each ask that reaches a due credential
// mints.
//
// It is the shape production takes — the passthrough calls this from whatever
// goroutine the server hands it — and the saving this whole change buys is one
// mint plus a handful of renewals an hour against the heartbeat's 240.
func TestConcurrentViewerRequestsShareOneCredentialAsk(t *testing.T) {
	// Slow enough that every caller arrives while the first ask is in flight,
	// which is exactly when a per-caller ask would mint again.
	source := &countedSlowSource{after: 400 * time.Millisecond}
	server := New(Manifest{ID: testSolutionID}).Credential(source)

	const callers = 24
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _ = server.credentialWithin(context.Background(), 5*time.Second)
		}()
	}
	close(start)
	wg.Wait()

	if got := source.count(); got != 1 {
		t.Errorf("%d concurrent callers produced %d asks, want 1: each ask that finds the credential due for renewal mints, so one per caller is one audited mint per request", callers, got)
	}
}

// countedSlowSource answers after a delay and counts how many times it was
// reached.
type countedSlowSource struct {
	mu    sync.Mutex
	asks  int
	after time.Duration
	held  workcontext.Credential
}

func (c *countedSlowSource) Credential(ctx context.Context) (workcontext.Credential, error) {
	c.mu.Lock()
	c.asks++
	c.mu.Unlock()
	select {
	case <-time.After(c.after):
	case <-ctx.Done():
		return workcontext.Credential{}, ctx.Err()
	}
	// Deliberately unusable, so the test turns on the ask count alone and not
	// on what came back.
	return c.held, nil
}

func (c *countedSlowSource) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.asks
}

// TestACredentialThatAuthorisesNothingIsRefused: a supplied source may hand
// back the zero credential, or an expired one, and this runtime held it,
// booted, answered /health 200 and acted for viewers under it.
//
// The authority wrapper could not see either: it keys on the token *changing*,
// and a token that is always "" never changes.
func TestACredentialThatAuthorisesNothingIsRefused(t *testing.T) {
	mint := newHostMint(t, &hostMint{ttl: time.Second})
	expiring := mintedCredential(t, mint, "expiring")
	for !time.Now().After(expiring.ExpiresAt()) {
		time.Sleep(50 * time.Millisecond)
	}

	for _, tc := range []struct {
		name       string
		credential workcontext.Credential
		terminal   bool
		// names is the part of the refusal that has to be about this case, so
		// a credential failing several checks at once does not stand in for
		// each of them.
		names string
	}{
		{"the zero credential", workcontext.Credential{}, true, "empty token"},
		{"an expired credential", expiring, false, "expired at"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// At the boot.
			boot := newHostMint(t, &hostMint{})
			server := New(Manifest{ID: testSolutionID}).Credential(stubCredentialSource{credential: tc.credential})
			server.firstMintWindow = 750 * time.Millisecond
			if err := bootFailsWithin(t, server, boot, 10*time.Second); err == nil {
				t.Fatal("the boot accepted a credential that authorises nothing: this process would serve, answer /health 200, and act for viewers under it")
			}

			// And at a route, for a source that only degrades later.
			serving := New(Manifest{ID: testSolutionID}).Credential(stubCredentialSource{credential: tc.credential})
			if err := serving.actingForAViewer(context.Background()); err == nil {
				t.Fatal("a route acted for a viewer under a credential that authorises nothing")
			}
			// And classified: nothing to mint with is a judgement, an expiry
			// that has passed is not.
			err := usableCredential(tc.credential)
			if got := terminalCredentialFailure(err); got != tc.terminal {
				t.Errorf("terminal = %v, want %v for %v: the boot and the run have to classify these the same way", got, tc.terminal, err)
			}
			// Refused for its OWN reason. The zero credential fails three of
			// these checks at once — no token, no seal, no expiry — so
			// asserting only that it is refused left each individual check
			// unprotected: deleting the empty-token check still refused it, on
			// the seal.
			if !strings.Contains(err.Error(), tc.names) {
				t.Errorf("the refusal %q does not name %s, so this case does not cover that check", err, tc.names)
			}
		})
	}
}

// slowThenRefused answers slowly, and then with a judgement — the shape where
// acquisition outlives the caller that started it.
type slowThenRefused struct {
	after time.Duration
	asked chan struct{}
}

func (s *slowThenRefused) Credential(ctx context.Context) (workcontext.Credential, error) {
	select {
	case s.asked <- struct{}{}:
	default:
	}
	select {
	case <-time.After(s.after):
	case <-ctx.Done():
		return workcontext.Credential{}, ctx.Err()
	}
	return workcontext.Credential{}, fmt.Errorf("%w: this build is not the one the presence document approved", workcontext.ErrMintRefused)
}

// TestATerminalRefusalIsRecordedWhereverItLands is the blocker the static round
// six found in this round's own fix.
//
// The ask runs on a context detached from the caller's, so a request that gives
// up does not cancel work other callers are waiting on. That also means the
// answer can arrive after every caller has gone — and a terminal refusal
// classified only by whoever was still waiting was simply discarded. The route
// served on the held credential, nothing recorded the refusal, and the process
// went on acting for viewers after its own source had reported this execution
// refused. The classification belongs to the answer, not to the audience.
func TestATerminalRefusalIsRecordedWhereverItLands(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	held := mintedCredential(t, mint, "held")
	source := &slowThenRefused{after: 750 * time.Millisecond, asked: make(chan struct{}, 1)}

	server := New(Manifest{ID: testSolutionID}).Credential(source)
	server.credentialHeld = held

	// A route asks, times out well before the source answers, and is served
	// from the credential in hand — which is correct.
	if err := server.actingForAViewer(context.Background()); err != nil {
		t.Fatalf("a route was refused while this process held a valid credential and the source was merely slow: %v", err)
	}
	select {
	case <-source.asked:
	case <-time.After(2 * time.Second):
		t.Fatal("the source was never asked, so this test does not exercise the detached ask")
	}

	// The refusal lands with nobody waiting.
	deadline := time.Now().Add(5 * time.Second)
	for server.terminalErr.Load() == nil && time.Now().Before(deadline) {
		time.Sleep(25 * time.Millisecond)
	}
	if server.terminalErr.Load() == nil {
		t.Fatal("this execution's credential was refused and nothing recorded it, because the caller that started the ask had already been served: the process keeps acting for viewers under an authority its own source says is gone, and /health keeps answering 200")
	}

	// And the process now refuses to act, rather than carrying on with the
	// credential it still holds.
	if err := server.actingForAViewer(context.Background()); !errors.Is(err, ErrCredentialRefused) {
		t.Errorf("after a recorded refusal a route answered %v, want one wrapping %v: a held credential does not survive a judgement about the build that holds it", err, ErrCredentialRefused)
	}
}

// TestAWithdrawnAuthorityIsCaughtBeforeTheMint: the recheck ran after the ask,
// so a withdrawn authority was discovered one renewal too late — the mint had
// already happened, sealed to values nobody approved, and the caller that
// triggered it was served.
func TestAWithdrawnAuthorityIsCaughtBeforeTheMint(t *testing.T) {
	fabricator := newHostMint(t, &hostMint{})
	handing := &handingSource{credentials: []workcontext.Credential{
		mintedCredential(t, fabricator, "first"),
		mintedCredential(t, fabricator, "second"),
	}}

	mint := newHostMint(t, &hostMint{})
	bootEnvironment(t, mint)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := New(Manifest{ID: testSolutionID}).Credential(handing)
	if _, err := server.start(ctx); err != nil {
		t.Fatalf("boot: %v", err)
	}
	asksAtBoot := handing.count()

	// The authority drifts, and then something asks.
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MODULE_AUTHORITY__"+AuthorityPrincipalKey,
		"spiffe://codefly.test/ns/solutions/sa/somebody-else")
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	if _, err := server.credential.Credential(ctx); err == nil {
		t.Fatal("an ask proceeded under a drifted authority")
	}
	// And the source was never reached, so nothing was minted under it.
	if got := handing.count(); got != asksAtBoot {
		t.Errorf("the source was asked %d times after the authority drifted (%d at boot): the recheck has to come before the ask, or the credential is already minted and sealed to a value nobody approved by the time the drift is noticed",
			got-asksAtBoot, asksAtBoot)
	}
}

// TestASupersededCredentialIsNotRestoredByTheNextAsk: dropping the belief was
// immediately reversible.
//
// The SDK's client re-mints only at its renewal lead, so the next ask returns
// the same credential the host just refused — and storing it restored the belief
// that it was honoured, undone by the very credential that triggered the
// invalidation.
func TestASupersededCredentialIsNotRestoredByTheNextAsk(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected")
	// The real client, so the cache behaves as it does in production: the same
	// credential comes back until its renewal lead.
	server := New(Manifest{ID: testSolutionID}).Credential(mintClientFor(t, mint.URL, tokenFile))

	if err := server.actingForAViewer(context.Background()); err != nil {
		t.Fatalf("a route was refused with a fresh credential in hand: %v", err)
	}
	held, _ := server.heldCredential()
	if held.Token() == "" {
		t.Fatal("nothing was held after a successful ask")
	}

	// The host says this credential is no longer honoured.
	server.executionCredentialSuperseded()
	if _, ok := server.heldCredential(); ok {
		t.Fatal("the superseded credential is still held")
	}

	// The next ask returns the same one. The belief must not come back.
	_ = server.actingForAViewer(context.Background())
	if again, ok := server.heldCredential(); ok && again.Token() == held.Token() {
		t.Error("the superseded credential was held again after the next ask returned it: the SDK re-mints only at its renewal lead, so the invalidation is undone by the very credential that triggered it unless the token is remembered")
	}
}
