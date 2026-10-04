package solution

import (
	"connectrpc.com/connect"
	"context"
	"crypto/x509"
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
	corework "github.com/codefly-dev/core/workcontext"
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
		{"the projected token is not acceptable", http.StatusUnauthorized},
		// 404 is NOT here any more, and that is sdk-go v0.3.0 inverting the
		// default rather than this test being relaxed.
		//
		// The rule was "429 and 5xx retry, everything else is terminal", which
		// made every status anything between the host and this process might
		// invent into a permanent stop — measured: a 408 from a proxy, with a
		// valid credential in hand, latched for the life of the process, and a
		// 404 from an ingress mid-rollout would do the same. Only 401 and 403
		// latch now, because those are the two the host signs: the projected
		// token is not acceptable, or the build is not approved.
		//
		// An old runtime against a new host still does not recover — it waits
		// out its bounded window and exits non-zero for the orchestrator
		// instead of failing on the first answer. Covered by the unavailable
		// cases, and AGENTS.md says so now.
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
	source := mintClientFor(t, mint, tokenFile)

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
	source := mintClientFor(t, mint, tokenFile)

	const callers = 32
	carriers := make([]string, callers)
	seals := make([]*workcontext.SealedValues, callers)
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
		if counts := client.Counts(); counts.Mints != 1 || counts.Renewals != 0 {
			t.Errorf("the client reports %d mints and %d renewals, want 1 and 0", counts.Mints, counts.Renewals)
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
	source := mintClientFor(t, host, tokenFile)
	credential, err := source.Credential(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	gw := newModuleGateway(t, http.StatusOK, `{"entry_id":"e1"}`)
	server := New(Manifest{ID: testSolutionID}).Credential(source)
	server.cfg.gatewayURL = gw.URL
	header := http.Header{}
	header.Set("authorization", viewerBearer())
	header.Set(orgHeader, "org-1")
	header.Set(sessionHeader, "session-1")
	header.Set(workcontext.InstallationIDHeaderName, testInstallation)
	gateway := server.gatewayFor(header)
	if _, err := gateway.ForModule(context.Background(), "things", Scope{ResourceKind: "things", Actions: []string{"read"}}); err != nil {
		t.Fatalf("ForModule: %v", err)
	}
	mints := gw.observedMints()
	if len(mints) != 1 {
		t.Fatalf("observed %d mints, want 1", len(mints))
	}
	if mints[0].Bearer != viewerBearer() {
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
	server := New(Manifest{ID: testSolutionID}).Credential(mintClientFor(t, refusing, tokenFile))
	server.cfg.gatewayURL = gw.URL

	header := http.Header{}
	header.Set("authorization", viewerBearer())
	header.Set(orgHeader, "org-1")
	header.Set(sessionHeader, "session-1")
	header.Set(workcontext.InstallationIDHeaderName, testInstallation)
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
	header.Set("authorization", viewerBearer())
	header.Set(orgHeader, "org-1")
	header.Set(sessionHeader, "session-1")
	header.Set(workcontext.InstallationIDHeaderName, testInstallation)
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
func mintClientFor(t *testing.T, mint *hostMint, tokenFile string) CredentialSource {
	t.Helper()
	client, err := workcontext.NewMintClient(workcontext.MintOptions{
		URL: mint.URL + credentialMintPath,
		// The audience is named as a pinned value now, not passed as a string
		// beside the pin: a string alongside meant the drift check guarded a
		// value the mint did not use.
		Audience:           workcontext.AuthorityValue{Name: AuthorityGroup, Key: AuthorityAudienceKey},
		Authority:          fixedAuthority{audience: testAudience},
		ProjectedToken:     workcontext.ProjectedTokenFile(tokenFile),
		ProjectionAudience: testProjectionAudience,
		// The roots, and nothing else about the transport. The client builds
		// and owns that now, and refuses a nil pool rather than falling back
		// to whatever the image ships.
		RootCAs: mint.roots(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// fixedAuthority is an AuthorityPin whose values do not drift. The drift
// refusal is exercised by its own tests against the real reader; a fixture
// that drifted would fail every other test for a reason none of them is about.
type fixedAuthority struct{ audience string }

func (fixedAuthority) Recheck(context.Context) error { return nil }

func (a fixedAuthority) Value(name, key string) (string, error) {
	switch {
	case name == AuthorityGroup && key == AuthorityAudienceKey:
		return a.audience, nil
	case name == AuthorityGroup && key == AuthorityProjectionAudienceKey:
		return testProjectionAudience, nil
	case name == AuthorityGroup && key == AuthorityPrincipalKey:
		return testPrincipal, nil
	}
	return "", fmt.Errorf("no pinned authority value %s/%s", name, key)
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
			header.Set("authorization", viewerBearer())
			header.Set(orgHeader, "org-1")
			header.Set(sessionHeader, "session-1")
			header.Set(workcontext.InstallationIDHeaderName, testInstallation)
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
		server := New(Manifest{ID: testSolutionID}).Credential(mintClientFor(t, mint, tokenFile))
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
			request.Header.Set("authorization", viewerBearer())
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
	server := New(Manifest{ID: testSolutionID}).Credential(mintClientFor(t, mint, tokenFile))
	handler := server.wrapRequest(func(*http.Request, *Gateway) (any, error) {
		return map[string]string{"ok": "yes"}, nil
	})
	request := httptest.NewRequest(http.MethodGet, "/thing", nil)
	request.Header.Set("authorization", viewerBearer())
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
		mint := newHostMint(t, &hostMint{})
		tokenFile := filepath.Join(t.TempDir(), "token")
		writeFile(t, tokenFile, "projected")
		// Already past its expiry, which is the state a route must not act
		// under. No waiting: see expiredCredential.
		expired := expiredCredential(t, mint, tokenFile)
		server := New(Manifest{ID: testSolutionID}).Credential(slow)
		server.credentialHeld = expired
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
	if _, err := takeListener(server).start(ctx); err != nil {
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
	credential, err := mintClientFor(t, mint, tokenFile).Credential(context.Background())
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
	request.Header.Set("authorization", viewerBearer())
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
		served.Header.Set("authorization", viewerBearer())
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
	mint := newHostMint(t, &hostMint{})
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected")
	expiring := expiredCredential(t, mint, tokenFile)

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
	if _, err := takeListener(server).start(ctx); err != nil {
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

// TestNothingIsInferredFromAConflictOnAViewersMint replaces the two rounds
// spent building around a signal that was never sound.
//
// A 409 on a viewer's mint may mean the credential this workload presented is
// superseded, or it may mean that viewer lacks the authority they asked for.
// The host does not distinguish the two. A hook that dropped this process's
// belief on that answer, plus a remembered token so the drop would stick,
// turned one viewer's missing permission into a process-wide refusal to act for
// anybody — an escalating response to an ambiguous signal, which is worse than
// no response: before, a 409 cost that one call; after, it cost the process.
func TestNothingIsInferredFromAConflictOnAViewersMint(t *testing.T) {
	// The host refuses every mint with a conflict, which is what a viewer
	// lacking authority looks like from here.
	// Refuses the viewer's mint for want of authority, which is exactly the
	// answer that cannot be told apart from "the credential you presented is
	// superseded".
	gw := newModuleGateway(t, http.StatusOK, `{}`)
	gw.deny = "read"
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected")
	mint := newHostMint(t, &hostMint{})

	server := New(Manifest{ID: testSolutionID}).
		Consumes(passthroughModule()).
		Contract(ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
		}}).
		Credential(mintClientFor(t, mint, tokenFile))
	server.cfg.profile = localProfile
	server.cfg.gatewayURL = gw.URL
	contract, err := server.resolveContract()
	if err != nil {
		t.Fatalf("resolveContract: %v", err)
	}
	server.contract, server.contractResolved = contract, true

	header := http.Header{}
	header.Set("authorization", viewerBearer())
	header.Set(orgHeader, "org-1")
	header.Set(sessionHeader, "session-1")
	header.Set(workcontext.InstallationIDHeaderName, testInstallation)
	if _, err := server.gatewayFor(header).ForModule(context.Background(), "things",
		Scope{ResourceKind: "things", Actions: []string{"read"}}); err == nil {
		t.Fatal("a mint refused with a conflict was reported as a success")
	}

	// That refusal cost the viewer their call and nothing else: this process
	// still holds its credential and still acts for everybody else.
	if _, ok := server.heldCredential(); !ok {
		t.Error("a conflict on one viewer's mint dropped this process's own credential: the host does not say whether the conflict is about this workload's authority or that viewer's, so inferring the former makes one viewer's missing permission a process-wide outage")
	}
	if err := server.actingForAViewer(context.Background()); err != nil {
		t.Errorf("this process stopped acting for viewers after one ambiguous conflict: %v", err)
	}
	if server.terminalErr.Load() != nil {
		t.Error("an ambiguous conflict was recorded as a judgement about this build")
	}
}

// TestAViewersMintGoesThroughTheOneController: the viewer's mint called the
// source directly, so the single-flight, the backoff and the held-credential
// fallback governed every path except the one that mints most.
//
// The controller is only a controller if it owns every acquisition.
func TestAViewersMintGoesThroughTheOneController(t *testing.T) {
	fabricator := newHostMint(t, &hostMint{})
	held := mintedCredential(t, fabricator, "held")
	source := &unavailableAfter{credential: held, after: 1}

	gw := newModuleGateway(t, http.StatusOK, `{"entry_id":"e1"}`)
	server := New(Manifest{ID: testSolutionID}).
		Consumes(passthroughModule()).
		Contract(ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
		}}).
		Credential(source)
	server.cfg.profile = localProfile
	server.cfg.gatewayURL = gw.URL
	contract, err := server.resolveContract()
	if err != nil {
		t.Fatalf("resolveContract: %v", err)
	}
	server.contract, server.contractResolved = contract, true

	header := http.Header{}
	header.Set("authorization", viewerBearer())
	header.Set(orgHeader, "org-1")
	header.Set(sessionHeader, "session-1")
	header.Set(workcontext.InstallationIDHeaderName, testInstallation)
	mintFor := func(t *testing.T) error {
		t.Helper()
		_, err := server.gatewayFor(header).ForModule(context.Background(), "things",
			Scope{ResourceKind: "things", Actions: []string{"read"}})
		return err
	}

	// The first mint takes the credential, which stays valid for a while.
	if err := mintFor(t); err != nil {
		t.Fatalf("the first viewer mint was refused: %v", err)
	}

	// The issuer now fails. Forty viewers arrive, and every one of them is a
	// mint for a *different* task, so the capability cache does not absorb
	// them — only the controller can.
	const viewers = 40
	for i := range viewers {
		header.Set(sessionHeader, fmt.Sprintf("session-%d", i))
		header.Set(workcontext.InstallationIDHeaderName, testInstallation)
		if err := mintFor(t); err != nil {
			t.Fatalf("viewer %d was refused while this process held a credential valid until %s: %v",
				i, held.ExpiresAt().UTC().Format(time.RFC3339), err)
		}
	}
	if got := source.count(); got > 4 {
		t.Errorf("the credential source was reached %d times for %d viewer mints: the viewer's mint is acquiring outside the controller, so the backoff and the held-credential fallback do not apply to the path that mints most", got, viewers)
	}
}

// TestTheBackoffAppliesWhenNothingIsHeld: the quiet window was consulted only
// when a credential WAS in hand, so the one state that should ask least —
// nothing held, issuer failing — asked on every request. The branch meant to
// back off was the branch that hammered.
func TestTheBackoffAppliesWhenNothingIsHeld(t *testing.T) {
	// Fails every time, and holds nothing.
	source := &unavailableAfter{after: 0}
	server := New(Manifest{ID: testSolutionID}).Credential(source)

	const callers = 30
	for range callers {
		if err := server.actingForAViewer(context.Background()); err == nil {
			t.Fatal("a route acted for a viewer with no credential at all")
		}
	}
	if got := source.count(); got > 3 {
		t.Errorf("the source was asked %d times for %d calls with nothing held: each ask that finds a credential due mints, so the state with no credential is the one that must ask least, not most", got, callers)
	}
}

// TestAWaiterReadsItsOwnFlightsResult: waiters read the server's current state
// rather than the flight they waited on, so a caller could act on a later
// flight's answer — or on none, if the next flight had already cleared the
// fields.
func TestAWaiterReadsItsOwnFlightsResult(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	first := mintedCredential(t, mint, "first")
	second := mintedCredential(t, mint, "second")
	if first.Token() == second.Token() {
		t.Fatal("this test needs two distinguishable credentials")
	}

	// Slow, so every caller lands on the SAME flight. With an instant source
	// several flights happen and different answers are correct, which is why
	// the first version of this test was asserting something untrue.
	source := &slowHandingSource{
		handing: &handingSource{credentials: []workcontext.Credential{first, second}},
		after:   300 * time.Millisecond,
	}
	server := New(Manifest{ID: testSolutionID}).Credential(source)

	// Many callers on one flight: every one of them must come back with that
	// flight's credential, not with whatever a later flight stored.
	const callers = 16
	var wg sync.WaitGroup
	got := make([]string, callers)
	start := make(chan struct{})
	for i := range callers {
		wg.Add(1)
		go func(at int) {
			defer wg.Done()
			<-start
			credential, err := server.credentialWithin(context.Background(), 5*time.Second)
			if err == nil {
				got[at] = credential.Token()
			}
		}(i)
	}
	close(start)
	wg.Wait()

	for at, token := range got {
		if token == "" {
			t.Fatalf("caller %d came back with no credential at all: it read shared state a later flight had already cleared", at)
		}
	}
	// One flight, so one answer.
	for at, token := range got {
		if token != got[0] {
			t.Errorf("caller %d came back with a different credential from caller 0, though both waited on the same flight: waiters are reading the server's current state rather than the result of the flight they waited on", at)
		}
	}
}

// slowHandingSource is handingSource with a delay, so concurrent callers all
// join one flight.
type slowHandingSource struct {
	handing *handingSource
	after   time.Duration
}

func (s *slowHandingSource) Credential(ctx context.Context) (workcontext.Credential, error) {
	select {
	case <-time.After(s.after):
	case <-ctx.Done():
		return workcontext.Credential{}, ctx.Err()
	}
	return s.handing.Credential(ctx)
}

// driftingSource changes an authority-bearing value while it is being asked,
// so the drift lands after the pre-ask recheck and before the answer is used.
type driftingSource struct {
	credential workcontext.Credential
	drift      func()
	once       sync.Once
}

func (d *driftingSource) Credential(context.Context) (workcontext.Credential, error) {
	d.once.Do(d.drift)
	return d.credential, nil
}

// TestDriftDuringAnAskIsCaughtAfterIt is the half the pre-ask recheck cannot
// cover, and the half the post-check was skipping.
//
// The post-check was gated on the token changing, so it ran only on a renewal
// that produced a different credential. A drift landing *during* the ask — and
// a first credential, and an ask that returned the one already held — all went
// unchecked until some later renewal happened to change the token.
func TestDriftDuringAnAskIsCaughtAfterIt(t *testing.T) {
	fabricator := newHostMint(t, &hostMint{})
	held := mintedCredential(t, fabricator, "held")

	mint := newHostMint(t, &hostMint{})
	bootEnvironment(t, mint)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// The authority is intact when the ask begins and drifts while it runs, so
	// the pre-ask recheck passes and only the one after it can refuse.
	drifted := make(chan struct{})
	source := &driftingSource{
		credential: held,
		drift: func() {
			t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MODULE_AUTHORITY__"+AuthorityPrincipalKey,
				"spiffe://codefly.test/ns/solutions/sa/somebody-else")
			_ = codefly.LoadEnvironmentVariables()
			close(drifted)
		},
	}

	server := New(Manifest{ID: testSolutionID})
	server.authority = authorityFor(t, ctx)
	server.credential = heldToTheFrozenAuthority(source, server.authority)

	_, err := server.credential.Credential(ctx)
	<-drifted
	if err == nil {
		t.Fatal("a credential obtained while an authority-bearing value drifted mid-ask was handed over: the recheck before the ask cannot see a drift that lands after it, so the one after the ask is what catches this — and gating that on the token changing means a first credential, an unchanged one, and a mid-ask drift all go unchecked")
	}
	if !errors.Is(err, workcontext.ErrMintRefused) {
		t.Errorf("the refusal %v is not reported as a judgement, so the boot and the run would classify it differently", err)
	}
}

// authorityFor is this process's frozen authority, read through the SDK the way
// a boot reads it.
func authorityFor(t *testing.T, ctx context.Context) *codefly.Authority {
	t.Helper()
	server := New(Manifest{ID: testSolutionID})
	if err := server.openAuthority(ctx); err != nil {
		t.Fatalf("open the authority: %v", err)
	}
	return server.authority
}

// TestTheBootsCredentialIsHeldByTheController: the boot obtained the
// credential and nothing held it, so the first route after boot saw an empty
// controller — it asked again, and got none of the backoff or
// held-credential behaviour the controller exists to provide.
//
// "One credential per execution" starts at the boot's own credential or it
// starts one request late.
func TestTheBootsCredentialIsHeldByTheController(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	bootEnvironment(t, mint)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := New(Manifest{ID: testSolutionID})
	ln, err := takeListener(server).start(ctx)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	_ = ln.Close()

	held, ok := server.heldCredential()
	if !ok {
		t.Fatal("the boot obtained a credential and the controller holds nothing: the first route after boot therefore asks again, outside the single-flight and the backoff, which is the per-request minting this controller was built to stop")
	}
	if held.Token() == "" {
		t.Fatal("the controller holds a credential with no token")
	}

	// And the boot's mint is the only one: a route served immediately after
	// boot must not produce a second.
	before := mint.count()
	if err := server.actingForAViewer(ctx); err != nil {
		t.Fatalf("a route was refused immediately after a successful boot: %v", err)
	}
	if got := mint.count(); got != before {
		t.Errorf("the host minted %d more times for the first route after boot: the boot's credential is what that route acts under", got-before)
	}
}

// TestAnAuthorityDriftDuringTheAskIsRefused closes a real gap my own mutation
// ledger found: removing the authority recheck that runs AFTER the ask was
// caught by nothing.
//
// The wrapper rechecks twice, and the two catch different things. The check
// before the ask refuses a value that had already drifted; only the check
// after it refuses a value that drifted *during* the mint — which is the one
// moment a credential could be sealed to values nobody approved and then held
// for its whole life. Every existing test drifted the value before the ask, so
// the pre-check answered all of them and the post-check could be deleted
// silently. That is the sixth time in this review a test has passed through a
// different check than the one it named.
func TestAnAuthorityDriftDuringTheAskIsRefused(t *testing.T) {
	authorityValues(t)
	ctx := context.Background()
	authority, err := readAuthority(ctx)
	if err != nil {
		t.Fatalf("readAuthority: %v", err)
	}

	mint := newHostMint(t, &hostMint{})
	minted := mintedCredential(t, mint, testProjectionAudience)

	// A source that drifts the principal while it is minting: the value is the
	// approved one when the ask begins and another when it returns.
	drifting := &driftingCredentialSource{t: t, credential: minted}

	_, err = heldToTheFrozenAuthority(drifting, authority).Credential(ctx)
	if err == nil {
		t.Fatal("a credential minted while an authority-bearing value drifted was accepted: the credential is sealed to the values it was minted under, so a drift that lands during the ask is laundered into one this process then holds for its whole life — the recheck after the ask is the only thing that sees it")
	}
	if !errors.Is(err, workcontext.ErrMintRefused) {
		t.Errorf("the drift was refused with %v, want ErrMintRefused: a drifted authority is a refusal, never a retry", err)
	}
}

// driftingCredentialSource mints normally and changes an authority-bearing
// value as it does, which is the only way to reach the recheck that runs after
// the ask.
type driftingCredentialSource struct {
	t          *testing.T
	credential workcontext.Credential
}

func (d *driftingCredentialSource) Credential(context.Context) (workcontext.Credential, error) {
	d.t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MODULE_AUTHORITY__"+AuthorityPrincipalKey,
		"spiffe://codefly.test/ns/apps/sa/somebody-else")
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		return workcontext.Credential{}, err
	}
	return d.credential, nil
}

// TestAnAlreadyDriftedAuthorityIsNotMintedAgainst is the pre-ask recheck's own
// property, which the post-ask one masks.
//
// Both rechecks refuse a value that drifted before the ask, so deleting the
// first changed no outcome and no test noticed. What it changes is whether the
// mint happens at all: without it a process whose authority has already
// drifted sends the projected service-account token and spends an audited mint
// to obtain a credential it will then throw away. "Before the ask, because the
// ask is what mints" is the comment on it; this is the test that makes the
// comment load-bearing.
func TestAnAlreadyDriftedAuthorityIsNotMintedAgainst(t *testing.T) {
	authorityValues(t)
	ctx := context.Background()
	authority, err := readAuthority(ctx)
	if err != nil {
		t.Fatalf("readAuthority: %v", err)
	}
	mint := newHostMint(t, &hostMint{})
	minted := mintedCredential(t, mint, testProjectionAudience)

	// Drifted before anything asks.
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MODULE_AUTHORITY__"+AuthorityPrincipalKey,
		"spiffe://codefly.test/ns/apps/sa/somebody-else")
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}

	counted := &countingCredentialSource{credential: minted}
	_, err = heldToTheFrozenAuthority(counted, authority).Credential(ctx)
	if err == nil {
		t.Fatal("a credential was obtained while an authority-bearing value had already drifted")
	}
	if !errors.Is(err, workcontext.ErrMintRefused) {
		t.Errorf("the drift was refused with %v, want ErrMintRefused", err)
	}
	if asks := counted.count(); asks != 0 {
		t.Errorf("the source was asked %d times while the authority had already drifted: the recheck before the ask exists so that no projected token is sent and no audited mint is spent for a credential that cannot be kept", asks)
	}
}

// countingCredentialSource records how many times it was asked, so a test can
// assert that it was not.
type countingCredentialSource struct {
	mu         sync.Mutex
	asks       int
	credential workcontext.Credential
}

func (c *countingCredentialSource) Credential(context.Context) (workcontext.Credential, error) {
	c.mu.Lock()
	c.asks++
	c.mu.Unlock()
	return c.credential, nil
}

func (c *countingCredentialSource) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.asks
}

// TestAViewerMintNamesTheInstallationItActsUnder is the installation seam.
//
// The host requires an installation on every mint (core's StartInput) and
// refuses one naming none. An organization is not a substitute: one org may
// hold several installations, so a capability minted without naming one is
// attributable to the org and to no deployment inside it.
//
// The viewer's installation comes from the SEAL of the capability they arrived
// with, not from the x-codefly-installation-id header beside it. That order is
// the SDK's own rule, in its words: the installation that governs a call is the
// one inside the signature, and a header is caller-controlled while a seal is
// not. This runtime reads neither itself — SealedInstallation is the SDK's.
func TestAViewerMintNamesTheInstallationItActsUnder(t *testing.T) {
	t.Run("the gateway's stamped installation reaches the mint", func(t *testing.T) {
		gw := newWorkContextGateway(t, &workContextGateway{})
		solution := serveHandler(t, gw.URL, func(ctx context.Context, g *Gateway) (any, error) {
			_, err := g.ForModule(ctx, "documents", Scope{ResourceKind: "documents", Actions: []string{"read"}})
			return nil, err
		})
		resp := viewerRequest(t, solution.URL)
		_ = resp.Body.Close()

		if got := gw.mintCount(); got != 1 {
			t.Fatalf("the viewer's mint ran %d times, want 1", got)
		}
		mint := <-gw.mints
		if mint.InstallationID != corework.FixtureInstallation {
			t.Errorf("the mint named installation %q, want %q — the one sealed into the capability the viewer arrived with",
				mint.InstallationID, corework.FixtureInstallation)
		}
	})

	t.Run("a request with no readable installation mints nothing", func(t *testing.T) {
		gw := newWorkContextGateway(t, &workContextGateway{})
		server := New(Manifest{ID: "notes"}).Credential(attestingSource(t))
		server.cfg = config{gatewayURL: gw.URL}

		// Everything a mint needs except an installation: the bearer is an
		// opaque string, which is what a caller arriving without a sealed
		// capability looks like.
		header := http.Header{}
		header.Set("authorization", "Bearer an-opaque-session-token")
		header.Set(orgHeader, viewerOrg)
		header.Set(sessionHeader, viewerSession)
		// No installation, which is the point: the gateway stamped none and no
		// capability was carried.

		_, err := server.gatewayFor(header).ForModule(context.Background(), "documents",
			Scope{ResourceKind: "documents", Actions: []string{"read"}})
		if err == nil {
			t.Fatal("a work context was minted for a request naming no installation: the host refuses such a mint, and an org is not an installation")
		}
		if !strings.Contains(err.Error(), "installation") {
			t.Errorf("the refusal %q does not name what is missing", err)
		}
		// Not a ClientError: no caller can seal an installation, so this is not
		// a status a viewer could act on.
		var client *ClientError
		if errors.As(err, &client) {
			t.Errorf("the refusal carries %d, telling the caller to fix something no caller can seal", client.StatusCode)
		}
		if got := gw.mintCount(); got != 0 {
			t.Errorf("the host saw %d mints for a request naming no installation, want 0", got)
		}
	})

	t.Run("a caller-supplied capability does not decide the installation", func(t *testing.T) {
		// Inbound, x-codefly-work-context is caller-controlled: a browser can
		// send one, and this runtime's standing property is that such a
		// capability authenticates nothing and is never forwarded. Reading the
		// installation out of it would let a caller name the installation
		// their own mint is attributed to.
		header := http.Header{}
		header.Set("authorization", "Bearer an-opaque-session-token")
		header.Set(workcontext.InstallationIDHeaderName, testInstallation)
		header.Set(workcontext.HeaderName, capability("forged-by-the-caller"))
		got, err := viewerInstallation(header)
		if err != nil {
			t.Fatalf("a request carrying a caller-supplied capability was refused: %v", err)
		}
		if got != testInstallation {
			t.Errorf("installation = %q, want the stamped %q", got, testInstallation)
		}

		// And a malformed one cannot decide whether the mint happens either.
		header.Set(workcontext.HeaderName, "not-a-capability-at-all")
		if got, err := viewerInstallation(header); err != nil || got != testInstallation {
			t.Errorf("a caller's malformed capability changed the answer (%q, %v): it is not read at all", got, err)
		}
	})

	t.Run("the stamped header is the source, and absent is a refusal", func(t *testing.T) {
		// The ordinary inbound shape: the gateway stamps identity and this
		// runtime mints the capability itself, so nothing arrives carrying
		// one. There the stamped header is the only source there is.
		header := http.Header{}
		header.Set("authorization", "Bearer an-opaque-session-token")
		header.Set(workcontext.InstallationIDHeaderName, "installation-from-a-header")
		got, err := viewerInstallation(header)
		if err != nil {
			t.Fatalf("a stamped installation was refused with no capability carried: %v", err)
		}
		if got != "installation-from-a-header" {
			t.Errorf("installation = %q, want the stamped one", got)
		}

		// And neither is a refusal that names both carriers.
		bare := http.Header{}
		bare.Set("authorization", "Bearer an-opaque-session-token")
		_, err = viewerInstallation(bare)
		if err == nil {
			t.Fatal("a request naming no installation at all was accepted")
		}
		for _, named := range []string{workcontext.InstallationIDHeaderName, orgHeader, sessionHeader} {
			if !strings.Contains(err.Error(), named) {
				t.Errorf("the refusal %q does not name %s", err, named)
			}
		}
	})
}

// TestARenewalToADifferentInstallationIsRefused: usableCredential refuses a
// credential sealed to NO installation; this refuses one sealed to a DIFFERENT
// installation than the credential this process has been acting under.
//
// That is not a renewal, it is a different identity arriving through the
// renewal path, and every viewer mint names the installation this execution
// acts under — so the mints either side of it would name different deployments
// with nothing recording that they did.
func TestARenewalToADifferentInstallationIsRefused(t *testing.T) {
	authorityValues(t)
	ctx := context.Background()
	authority, err := readAuthority(ctx)
	if err != nil {
		t.Fatalf("readAuthority: %v", err)
	}
	mint := newHostMint(t, &hostMint{})
	first := mintedCredential(t, mint, testProjectionAudience)

	source := &movingInstallationSource{credential: first}
	held := heldToTheFrozenAuthority(source, authority)

	if _, err := held.Credential(ctx); err != nil {
		t.Fatalf("the first credential was refused: %v", err)
	}

	// The same process, renewing, and the host answers with a credential
	// sealed to another installation.
	moved := newHostMint(t, &hostMint{installation: "installation-somewhere-else"})
	source.credential = mintedCredential(t, moved, testProjectionAudience)
	_, err = held.Credential(ctx)
	if err == nil {
		t.Fatal("a renewal sealed to a different installation was accepted: the mints before and after it would name different deployments")
	}
	if !errors.Is(err, workcontext.ErrMintRefused) {
		t.Errorf("the refusal is %v, want ErrMintRefused: the host has answered about a different installation than this build was approved for, which no retry changes", err)
	}
}

// movingInstallationSource hands out whatever credential the test last set, so
// a renewal can answer with one sealed elsewhere.
type movingInstallationSource struct {
	mu         sync.Mutex
	credential workcontext.Credential
}

func (m *movingInstallationSource) Credential(context.Context) (workcontext.Credential, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.credential, nil
}

// expiredCredential is a credential that has already expired in real time,
// without waiting for it.
//
// Minting a short-lived one no longer works: the SDK floors the renewal lead
// at five seconds (minRenewalLeadTime), so it refuses to install a credential
// whose whole remaining lifetime is inside that lead — installing one would
// put the client straight back into a renewal, which is a mint loop and one
// audit event per iteration. That refusal is right, and it means a test cannot
// obtain a nearly-dead credential from the client at all.
//
// So the clock moves instead of the lifetime. MintOptions.Now is the SDK's own
// hook for exactly this: the client mints and installs against a backdated
// clock, where the credential is comfortably valid, and every check in THIS
// runtime reads the real time, where it expired twenty minutes ago.
func expiredCredential(t *testing.T, mint *hostMint, tokenFile string) workcontext.Credential {
	t.Helper()
	// Both clocks move, not one. The ISSUER stamps not-before and expiry, so
	// backdating only the client makes the credential not-yet-valid rather
	// than expired; backdating only the issuer makes the client refuse it as
	// expired on arrival. Both are held twenty minutes back, where the
	// credential is comfortably valid, and every check in THIS runtime reads
	// real time, where it expired ten minutes ago.
	backdated := time.Now().Add(-20 * time.Minute)
	// Its OWN authority, not the shared stand-in. standInAuthority returns a
	// singleton, so setting Now on it would backdate every other test's
	// issuer too — a fixture that poisons the tests around it is worse than
	// the wait this replaces.
	_, key := corework.FixtureKeyPair()
	mint.authority = &corework.Authority{
		Issuer:    corework.FixtureIssuer,
		KeyID:     corework.FixtureKeyID,
		Key:       key,
		Revisions: corework.FixtureRevisions(),
		Seals:     corework.FixtureSeals(),
		Now:       func() time.Time { return backdated },
	}
	mint.ttl = 10 * time.Minute
	client, err := workcontext.NewMintClient(workcontext.MintOptions{
		URL:                mint.URL + credentialMintPath,
		Audience:           workcontext.AuthorityValue{Name: AuthorityGroup, Key: AuthorityAudienceKey},
		Authority:          fixedAuthority{audience: testAudience},
		ProjectedToken:     workcontext.ProjectedTokenFile(tokenFile),
		ProjectionAudience: testProjectionAudience,
		RootCAs:            mint.roots(),
		Now:                func() time.Time { return backdated },
	})
	if err != nil {
		t.Fatal(err)
	}
	credential, err := client.Credential(context.Background())
	if err != nil {
		t.Fatalf("mint a credential against a backdated clock: %v", err)
	}
	if !time.Now().After(credential.ExpiresAt()) {
		t.Fatalf("the credential expires at %s, which is not in the past", credential.ExpiresAt())
	}
	return credential
}

// TestAnExecutionFreeCredentialIsRefusedEverywhere is round eleven's blocker,
// and a regression the sdk-go v0.3.0 migration introduced silently.
//
// usableCredential never checked for a sealed execution and never had to: the
// previous SDK's own reader refused a seal whose build incarnation was zero,
// so a credential reaching it carried one by construction. v0.3.0 moved
// structural validation to core, and core LEGITIMATELY mints a credential
// sealing no execution — for a principal recorded as bearing none, a person at
// a terminal. That is core's own execution-missing shape. The guarantee was
// inherited, the inheritance ended, and nothing here noticed.
//
// Reproduced before it was fixed: the runtime booted on such a credential,
// held it, passed actingForAViewer, and served handlers with a credential
// attesting no approved build.
//
// A workload credential is the one kind that may never be execution-free: its
// purpose is attesting which build is asking, so a host can hold a mint to the
// build its presence document approved.
func TestAnExecutionFreeCredentialIsRefusedEverywhere(t *testing.T) {
	t.Run("the boot refuses it, terminally", func(t *testing.T) {
		mint := newHostMint(t, &hostMint{executionFree: true})
		bootEnvironment(t, mint)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		server := New(Manifest{ID: testSolutionID})
		// Short, so a refusal that were wrongly classified as transient shows
		// up as a bounded wait rather than hanging this test.
		server.firstMintWindow = 2 * time.Second
		ln, err := takeListener(server).start(ctx)
		if ln != nil {
			_ = ln.Close()
		}
		if err == nil {
			t.Fatal("the boot accepted a credential sealing no execution: it attests no approved build, so the host has nothing to hold a mint to and the ceiling it is held to is nobody's")
		}
		if !errors.Is(err, workcontext.ErrMintRefused) {
			t.Errorf("the boot failed with %v, want ErrMintRefused: the issuer will seal the same thing next time, so this is a judgement and not an outage", err)
		}
		if !strings.Contains(err.Error(), "seals no execution") {
			t.Errorf("the refusal %q does not say what is missing", err)
		}
		// Terminal means it asked ONCE. A bounded wait here would be the
		// audited-mint loop this runtime was changed to remove.
		if got := mint.count(); got != 1 {
			t.Errorf("the boot asked the issuer %d times, want exactly 1", got)
		}
	})

	t.Run("no handler runs and no module is called", func(t *testing.T) {
		// The route gate's half: even handed such a credential directly, a
		// route must not act for a viewer and nothing author-written may run.
		mint := newHostMint(t, &hostMint{executionFree: true})
		tokenFile := filepath.Join(t.TempDir(), "token")
		writeFile(t, tokenFile, "projected")
		gw := newWorkContextGateway(t, &workContextGateway{})

		var ran atomic.Bool
		server := New(Manifest{ID: testSolutionID}).
			Credential(mintClientFor(t, mint, tokenFile)).
			HandleRequest("/thing", func(*http.Request, *Gateway) (any, error) {
				ran.Store(true)
				return map[string]string{"ok": "yes"}, nil
			})
		server.cfg = config{gatewayURL: gw.URL}

		header := http.Header{}
		header.Set("authorization", viewerBearer())
		header.Set(orgHeader, viewerOrg)
		header.Set(sessionHeader, viewerSession)
		header.Set(workcontext.InstallationIDHeaderName, testInstallation)

		if err := server.actingForAViewer(context.Background()); err == nil {
			t.Fatal("a route acted for a viewer under a credential sealing no execution")
		} else if !errors.Is(err, ErrCredentialRefused) {
			t.Errorf("the route refused with %v, want one wrapping ErrCredentialRefused", err)
		}
		if ran.Load() {
			t.Error("the handler ran")
		}
		if got := gw.mintCount(); got != 0 {
			t.Errorf("the gateway saw %d viewer mints, want 0", got)
		}
		if got := len(gw.calls); got != 0 {
			t.Errorf("a module was called %d times under a credential attesting no build, want 0", got)
		}
	})

	t.Run("the carrier still accepts it as structurally valid", func(t *testing.T) {
		// The division of labour stays intact. An execution-free capability is
		// not malformed — core mints it on purpose for a principal bearing no
		// execution — so the CARRIER must not refuse it. What refuses it is
		// this runtime holding its OWN credential to a higher bar than it
		// holds a capability it merely carries.
		if _, classified := boundary["execution-missing"]; !classified {
			t.Fatal("core's execution-missing fixture is unclassified, so this says nothing")
		}
		if boundary["execution-missing"] != carried {
			t.Error("the carrier refuses core's execution-missing fixture: a capability core mints legitimately is not the carrier's to reject, and refusing it here would be the silent-downgrade failure this boundary exists to prevent")
		}
	})
}

// TestTheMintIsDialledUnderTheAnchorAsItIsNow is round eleven's item 2, as far
// as it can be taken here.
//
// NewMintClient takes RootCAs as a value and builds its transport from it on
// the spot, so the pool a client is constructed with is the pool it keeps. The
// path this replaced dialled the mint through this runtime's own outbound
// client, whose DialTLSContext re-read the anchor per dial — so removing a
// compromised root took effect on the next dial. v0.3.0 exposes no per-dial
// hook, so the anchor is re-read here and the client rebuilt when it rotated.
func TestTheMintIsDialledUnderTheAnchorAsItIsNow(t *testing.T) {
	t.Run("an unreadable anchor refuses rather than using the last good one", func(t *testing.T) {
		mint := newHostMint(t, &hostMint{})
		tokenFile := filepath.Join(t.TempDir(), "token")
		writeFile(t, tokenFile, "projected")

		var fail atomic.Bool
		source := &anchorFreshSource{
			anchor: func() (*x509.CertPool, error) {
				if fail.Load() {
					return nil, errors.New("the projected bundle is unreadable")
				}
				return mint.roots(), nil
			},
			build: func(pool *x509.CertPool) (CredentialSource, error) {
				return mintClientWithRoots(t, mint, tokenFile, pool), nil
			},
		}

		if _, err := source.Credential(context.Background()); err != nil {
			t.Fatalf("the first ask was refused: %v", err)
		}
		// The anchor goes away. A source that cached the last good pool would
		// go on dialling the mint under trust that no longer exists.
		fail.Store(true)
		_, err := source.Credential(context.Background())
		if err == nil {
			t.Fatal("an ask succeeded while the trust anchor could not be read: dialling under a stale anchor sends the projected service-account token to whatever now answers at that address")
		}
		if !errors.Is(err, workcontext.ErrMintUnavailable) {
			t.Errorf("the refusal is %v, want ErrMintUnavailable: an unreadable bundle is an outage, not a judgement on this build", err)
		}
	})

	t.Run("a rotated anchor rebuilds the client, and an unchanged one does not", func(t *testing.T) {
		mint := newHostMint(t, &hostMint{})
		tokenFile := filepath.Join(t.TempDir(), "token")
		writeFile(t, tokenFile, "projected")

		rotated := newCell(t)
		var useRotated atomic.Bool
		var builds atomic.Int64
		source := &anchorFreshSource{
			anchor: func() (*x509.CertPool, error) {
				if useRotated.Load() {
					return rotated.roots, nil
				}
				return mint.roots(), nil
			},
			build: func(pool *x509.CertPool) (CredentialSource, error) {
				builds.Add(1)
				return mintClientWithRoots(t, mint, tokenFile, pool), nil
			},
		}

		for range 3 {
			if _, err := source.Credential(context.Background()); err != nil {
				t.Fatalf("an ask under the unchanged anchor was refused: %v", err)
			}
		}
		if got := builds.Load(); got != 1 {
			t.Errorf("the client was rebuilt %d times under an unchanged anchor, want 1: rebuilding per ask throws away the one credential per execution", got)
		}

		// Rotation. The next ask has to dial under the new trust, which means
		// a new client, which means the pool is not captured for the life of
		// the process.
		useRotated.Store(true)
		_, _ = source.Credential(context.Background())
		if got := builds.Load(); got != 2 {
			t.Errorf("the client was rebuilt %d times across a rotation, want 2: the SDK fixes its transport at construction, so an unrebuilt client keeps dialling under the old anchor", got)
		}
	})
}

// mintClientWithRoots is mintClientFor against a caller-supplied pool, for a
// test about which anchor the mint is dialled under.
func mintClientWithRoots(t *testing.T, mint *hostMint, tokenFile string, roots *x509.CertPool) CredentialSource {
	t.Helper()
	client, err := workcontext.NewMintClient(workcontext.MintOptions{
		URL:                mint.URL + credentialMintPath,
		Audience:           workcontext.AuthorityValue{Name: AuthorityGroup, Key: AuthorityAudienceKey},
		Authority:          fixedAuthority{audience: testAudience},
		ProjectedToken:     workcontext.ProjectedTokenFile(tokenFile),
		ProjectionAudience: testProjectionAudience,
		RootCAs:            roots,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}
