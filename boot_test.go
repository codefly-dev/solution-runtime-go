package solution

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefly-dev/core/resources"
	corework "github.com/codefly-dev/core/workcontext"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workcontext"
)

// The authority-bearing values every test in this package boots under. They are
// one set on purpose: the SDK pins an authority-bearing value process-wide at
// the first read, so two tests reading the same name with different values
// would have the second refused as a value that drifted — which is the
// behaviour, not a test defect.
const (
	// testSolutionID and testSolutionTitle are a solution's identity in these
	// fixtures. Neutral on purpose: this runtime knows nothing about any
	// specific solution, and a product's name in its fixtures is a name the
	// next reader copies into production.
	testOrganization  = viewerOrg
	testSolutionID    = "widgets-go"
	testSolutionTitle = "Widgets"

	testPrincipal          = "spiffe://codefly.test/ns/solutions/sa/widgets"
	testAudience           = testSolutionID
	testProjectionAudience = "accounts"
)

// testFrontend is the declared frontend file every booted fixture embeds: the
// file FrontendFileName names, as an author writes it.
const testFrontend = "title: " + testSolutionTitle + "\norder: 1\nexposed_module: ./Page\nhost_contract: 1\n"

// The sealed values the stand-in host issues against are core's own conformance
// values: the credential is minted by core's authority from core's fixture
// identities, so the seal this runtime logs and a test asserts is the live one
// that authority holds rather than a number invented here.
const (
	testInstallation = corework.FixtureInstallation
)

// authorityValues provisions the module-authority group the way the platform
// does, through the carriers the SDK reads.
func authorityValues(t *testing.T) {
	t.Setenv("CODEFLY__WORKSPACE_SECRET_CONFIGURATION__MODULE_AUTHORITY__INTERNAL_TOKEN", "broker-perimeter-token")
	t.Helper()
	for key, value := range map[string]string{
		AuthorityPrincipalKey:          testPrincipal,
		AuthorityAudienceKey:           testAudience,
		AuthorityProjectionAudienceKey: testProjectionAudience,
	} {
		t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__MODULE_AUTHORITY__"+key, value)
	}
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })
}

// hostMint stands in for the host's mint endpoint: it reviews the projected
// token the workload presents and answers with a credential sealed to this
// execution, exactly as the real one does — signed, because the SDK's client
// reads the seal out of the signature and not out of the response body.
type hostMint struct {
	*httptest.Server
	authority *corework.Authority

	// status, when non-zero, is answered instead of a credential: 403 for a
	// workload the host refuses, 503 for an issuer that has nothing to mint
	// against yet.
	status int
	// paths records what was asked for, so a surviving registration is
	// visible as the path it would have used.
	paths []string
	// answer, when set, decides each workload mint in place of status and
	// recoverAfter: the status to answer, or zero to issue. It is called on
	// the host's goroutines, so what it reads must be safe to read there.
	answer func() int
	// recoverAfter, when positive, is how many times status is answered before
	// the host starts issuing: an issuer catching up with a presence
	// generation that has just been applied.
	recoverAfter int64
	// ttl is how long the credential it issues is valid.
	ttl time.Duration
	// switchTo and switchAfter make this host answer with a DIFFERENT shape
	// once switchAfter credentials have been minted: the renewal path, driven
	// through the real client rather than by calling the wrapper directly.
	switchTo    *hostMint
	switchAfter int64
	// installation overrides the installation it seals credentials to, so a
	// test can have a renewal answer about a different one. Empty means
	// testInstallation.
	installation string

	mints int64
	// mu guards what serve records. The viewer's mint and this workload's
	// arrive on the same host, and a test that drives concurrent requests
	// reaches it from several goroutines.
	mu sync.Mutex
	// signErr is the fake host failing to produce a credential, which is a
	// defect in the test and not an outcome the runtime should see.
	signErr error
	// presented records the projected token each mint arrived with, so a test
	// can prove a rotated projection is re-read rather than cached, and
	// headers records what else each mint carried.
	presented []string
	headers   []http.Header
}

// prepareAuthority gives this fake mint the issuer its fields describe: core's
// stand-in, or one whose seal source has been moved so it can attest a
// different installation, a different build, or no execution at all.
//
// Separate from newHostMint so ONE mint can hold a second shape and switch to
// it after the first credential — which is what a booted renewal test needs,
// and the only way to exercise the renewal path through the real client.
func (mint *hostMint) prepareAuthority(t *testing.T) {
	t.Helper()
	mint.authority = standInAuthority()
	if mint.installation != "" {
		// An issuer that seals to a different installation, for the renewal
		// refusal. Built from CORE's fixture seal source with one entry
		// overridden rather than from a seal source of this repo's own: the
		// rest of what that fixture configures — epochs, approved builds,
		// bindings — is core's to define, and duplicating it here is how a
		// fixture drifts from the thing it stands in for.
		seals := corework.FixtureSeals()
		// Two fields, because core v0.9.0's Seal is the installation and its
		// revision and nothing else: the principal's epoch and the approved
		// build moved off the installation seal, where they described the
		// OWNER's workload however many delegation hops had been added. The
		// fixture's own epoch and approved-build entries are already in the
		// source this starts from.
		if err := seals.Put(corework.FixturePrincipal, corework.Seal{
			InstallationID:       mint.installation,
			InstallationRevision: corework.FixtureInstallationRevision,
		}); err != nil {
			t.Fatalf("seal the stand-in issuer to %s: %v", mint.installation, err)
		}
		_, key := corework.FixtureKeyPair()
		mint.authority = &corework.Authority{
			Issuer:    corework.FixtureIssuer,
			KeyID:     corework.FixtureKeyID,
			Key:       key,
			Revisions: corework.FixtureRevisions(),
			Seals:     seals,
		}
	}
	if mint.ttl == 0 {
		// Core imposes no maximum lifetime — how long a credential lives is the
		// issuing host's decision, and this runtime's renewal arithmetic simply
		// follows whatever it is handed. Ten minutes keeps a test's renewal
		// behaviour ordinary rather than asserting a cap that does not exist.
		mint.ttl = 10 * time.Minute
	}
}

func newHostMint(t *testing.T, mint *hostMint) *hostMint {
	t.Helper()
	mint.prepareAuthority(t)
	if mint.switchTo != nil {
		mint.switchTo.prepareAuthority(t)
	}
	// Plain HTTP on loopback: what the gateway's workload endpoint is inside a
	// cell, and what the SDK's rule admits on a local run.
	mint.Server = httptest.NewServer(http.HandlerFunc(mint.serve))
	t.Cleanup(mint.Close)
	return mint
}

// installationFor is the installation the shape in force seals to.
func (m *hostMint) installationFor() string {
	if m.switchTo != nil && atomic.LoadInt64(&m.mints) > m.switchAfter {
		return m.switchTo.installation
	}
	return m.installation
}

func (m *hostMint) serve(w http.ResponseWriter, r *http.Request) {
	organization := testOrganization
	m.mu.Lock()
	m.presented = append(m.presented, r.Header.Get("authorization"))
	m.headers = append(m.headers, r.Header.Clone())
	m.paths = append(m.paths, r.URL.Path)
	m.mu.Unlock()
	// The gateway this harness stands in for routes the viewer's mint as well
	// as this workload's, on the same base URL. They are counted apart: one per
	// process start is the claim about the workload credential, and a test about
	// what a handler mints needs to see only the viewer's.
	if r.URL.Path == workContextStartTaskProcedure {
		var mint mintRequest
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &mint)
		writeJSON(w, http.StatusOK, map[string]any{
			"token": capability("context-" + mint.Audience + ".1"), "orgId": mint.OrgID,
			"expiresAt": time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
		})
		return
	}
	if r.URL.Path == "/modules/_work-context" {
		var body map[string]string
		if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" || r.Header.Get("Accept") != "application/json" || r.Header.Get("X-Codefly-Internal-Token") != "broker-perimeter-token" || !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") || json.NewDecoder(r.Body).Decode(&body) != nil || body["prefix"] != testSolutionID || len(body) < 1 || len(body) > 2 {
			http.Error(w, "invalid broker request", http.StatusBadRequest)
			return
		}
		if body["organization_id"] != "" {
			organization = body["organization_id"]
		}
	}
	atomic.AddInt64(&m.mints, 1)
	// recoverAfter 0 means this host never issues; a positive one means it
	// issues once that many asks have been answered with status.
	if m.answer != nil {
		if status := m.answer(); status != 0 {
			w.WriteHeader(status)
			return
		}
	} else if m.status != 0 && (m.recoverAfter == 0 || atomic.LoadInt64(&m.mints) <= m.recoverAfter) {
		w.WriteHeader(m.status)
		return
	}
	issuer := m.authority
	if m.switchTo != nil && atomic.LoadInt64(&m.mints) > m.switchAfter {
		issuer = m.switchTo.authority
	}
	token, _, err := issuer.Start(r.Context(), corework.StartInput{
		TenantID:           corework.FixtureTenant,
		OwnerPrincipalID:   corework.FixturePrincipal,
		OwnerPrincipalKind: "human",
		TaskID:             fmt.Sprintf("workload-execution-%d", atomic.LoadInt64(&m.mints)),
		Audience:           testAudience,
		OrganizationID:     organization,
		InstallationID:     cmp.Or(m.installationFor(), testInstallation),
		TTL:                m.ttl,
	})
	if err != nil {
		m.signErr = err
		http.Error(w, "stand-in issuer: "+err.Error(), http.StatusInternalServerError)
		return
	}
	if r.URL.Path == "/modules/_work-context" {
		writeJSON(w, http.StatusOK, map[string]string{"token": token, "expiresAt": time.Now().Add(m.ttl).UTC().Format(time.RFC3339), "principalId": corework.FixturePrincipal, "tenant": corework.FixtureTenant})
	} else {
		writeJSON(w, http.StatusOK, map[string]string{"work_context": token})
	}
}

func (m *hostMint) count() int64 { return atomic.LoadInt64(&m.mints) }

// observedStartTasks is the viewer mints this host was asked for, which is not
// the same question as count(): that one is this workload's own credential.
func (m *hostMint) observedStartTasks() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	var asked []string
	for _, path := range m.paths {
		if path == workContextStartTaskProcedure {
			asked = append(asked, path)
		}
	}
	return asked
}

// booted is a solution serving on an ephemeral port, with the client that
// trusts its workload identity.
type booted struct {
	server *Server
	base   string
	client *http.Client
	mint   *hostMint
	// stop ends this runtime and waits for serve to return, so a test can
	// observe what a SHUTDOWN does rather than only what a serving process
	// does. It is idempotent, and the cleanup calls it too — a test that stops
	// the runtime itself must not leave a second cancel racing the first.
	stop func()
	// ended waits for serve to return by itself, within a bound, and reports
	// its error and whether it returned at all. Nothing here cancels, which is
	// the difference between observing a process end and watching cleanup end
	// it.
	ended func(time.Duration) (error, bool)
}

// bootEnvironment provisions everything a deployed solution's boot reads — the
// projected token, the resolved gateway, the profile — against the fake host.
//
// Shared by every boot test, including the ones that must fail: a boot refused
// for the reason under test has to be refused with everything else in place,
// or the test is asserting the first missing value instead.
func bootEnvironment(t *testing.T, mint *hostMint) {
	t.Helper()
	authorityValues(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected-token")

	// Bound here and handed to whichever Server this test boots, so the port is
	// never released between being chosen and being served on.
	ln, port := boundPort(t)
	provideListener(t, ln)
	t.Setenv("PORT", port)
	t.Setenv(resources.ServicePrefix, "backend")
	t.Setenv("CODEFLY__ENDPOINT__WIDGETS__BACKEND__HTTP__HTTP", ln.Addr().String())
	// The gateway's workload endpoint, which serves the mint beside every
	// other route: one resolved origin, and the mint address derived on it.
	// Plaintext to loopback, which the SDK's rule admits on a local run — and
	// this process is one, as codefly run makes a developer machine one.
	t.Setenv("GATEWAY_URL", mint.URL)
	t.Setenv(resources.EnvironmentPrefix, "local")
	t.Setenv(ProjectedTokenFileEnvironmentVariable, tokenFile)
	t.Setenv(ContractProfileEnvironmentVariable, localProfile)
	// A test that serves assets provisions the directory before booting, since
	// a boot's configuration is read by the serving goroutine and must not be
	// written after it starts.
	if os.Getenv("ASSETS_DIR") == "" {
		t.Setenv("ASSETS_DIR", t.TempDir())
	}
}

// boot runs the whole boot a deployed solution runs — configuration, the
// contract, the one mint, the TLS listener — on an ephemeral port.
func boot(t *testing.T, server *Server, mint *hostMint) *booted {
	t.Helper()
	return bootComponent(t, server, mint, false)
}

func bootComponent(t *testing.T, server *Server, mint *hostMint, headless bool) *booted {
	t.Helper()
	bootEnvironment(t, mint)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	takeListener(server)
	if headless {
		server.manifest.Frontend = nil
	}
	ln, err := server.start(ctx)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- server.serve(ctx, ln) }()
	var stopped sync.Once
	stop := func() {
		stopped.Do(func() {
			cancel()
			<-served
		})
	}
	t.Cleanup(stop)
	// ended waits for serve to return ON ITS OWN and reports what it returned.
	//
	// It must not cancel: a test asserting that this process ends has to
	// observe it ending by itself, and cleanup cancelling afterwards is
	// exactly how such a test passes against a runtime that never would. The
	// error goes back on the buffered channel so stop() still completes.
	ended := func(within time.Duration) (error, bool) {
		select {
		case err := <-served:
			served <- err
			return err, true
		case <-time.After(within):
			return nil, false
		}
	}
	return &booted{
		stop:   stop,
		ended:  ended,
		server: server,
		base:   "http://127.0.0.1:" + os.Getenv("PORT"),
		// Plain HTTP, as the gateway reaches this solution inside the cell.
		client: &http.Client{Transport: &http.Transport{}},
		mint:   mint,
	}
}

// bootFails runs the same boot and returns what it refused with.
func bootFails(t *testing.T, server *Server, mint *hostMint) error {
	t.Helper()
	return bootFailsWithin(t, server, mint, 30*time.Second)
}

// bootFailsWithin is bootFails with a bound on how long the boot may take to
// fail.
//
// The bound is the point. Several of these tests assert that a window is a
// deadline, and they measured the elapsed time *after* start() returned — so
// against a runtime where the window is not a deadline, start() never returns,
// the assertion is never reached, and the only thing that ends the test is `go
// test -timeout`. That kills the mutant by hanging, which is indistinguishable
// from an infrastructure problem and takes the whole suite's timeout to report.
func bootFailsWithin(t *testing.T, server *Server, mint *hostMint, within time.Duration) error {
	t.Helper()
	bootEnvironment(t, mint)
	type outcome struct {
		ln  net.Listener
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		ln, err := takeListener(server).start(context.Background())
		done <- outcome{ln, err}
	}()
	select {
	case got := <-done:
		if got.ln != nil {
			_ = got.ln.Close()
		}
		if got.err == nil {
			t.Fatal("the boot came up; this helper is for boots that must fail")
		}
		return got.err
	case <-time.After(within):
		// Not t.Fatal: this goroutine is the test's, but the boot's is still
		// running and will outlive the test. Reporting and failing is all that
		// is safe.
		t.Fatalf("the boot neither came up nor failed within %s: a bounded window that does not reach the operation leaves the process with no listener, no log and nothing for an orchestrator to act on, and a test that waits for the harness timeout cannot tell you that", within)
		return nil
	}
}

// TestBootMintsExactlyOnceAndServesPlainHTTP is the acceptance criterion of
// this runtime's whole boot: one mint per process start, zero registrations
// over any interval, and a plain-HTTP listener on the resolved port — the
// cell's mesh carries the hop, and this process presents no identity of its
// own.
func TestBootServesPlainHTTPWithoutMinting(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	solution := boot(t, New(Manifest{ID: testSolutionID}).
		Handle("/thing", func(context.Context, *Gateway) (any, error) { return map[string]string{"ok": "yes"}, nil }), mint)

	for range 5 {
		if status := getStatus(t, solution.client, solution.base+HealthPath); status != http.StatusOK {
			t.Fatalf("health = %d, want 200 answered on the destination the presence document names", status)
		}
		if status := getStatus(t, solution.client, solution.base+"/.well-known/solution.json"); status != http.StatusOK {
			t.Fatalf("served manifest = %d, want 200", status)
		}
	}
	if got := mint.count(); got != 0 {
		t.Fatalf("boot and health minted %d credentials, want zero", got)
	}

}

// TestUnauthenticatedCallIsRefusedNotProxied keeps the boot's serving contract:
// a handler call with no bearer is a 401 from this runtime, never a 502 from
// something downstream.
func TestUnauthenticatedCallIsRefusedNotProxied(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	solution := boot(t, New(Manifest{ID: testSolutionID}).
		Handle("/thing", func(context.Context, *Gateway) (any, error) { return nil, nil }), mint)
	if status := getStatus(t, solution.client, solution.base+"/thing"); status != http.StatusUnauthorized {
		t.Errorf("unauthenticated handler call = %d, want 401", status)
	}
}

// boundPort binds a listener and returns it with its port, so a test hands the
// *listener* to the boot rather than a port number.
//
// This replaces a helper that bound :0, read the port, closed the socket and
// returned the number — a time-of-check/time-of-use race against everything
// else in this suite asking the OS for an ephemeral port, and the cause of the
// intermittent `bind: address already in use` failures that appeared in a
// different test each run. A retry narrowed the window and could not close it:
// the port is released by construction. Nothing is released here.
func boundPort(t *testing.T) (net.Listener, string) {
	t.Helper()
	// On the loopback address the tests dial, not the wildcard. A wildcard
	// bind succeeds on a port another local process holds on 127.0.0.1, and
	// the test's own client then reaches that process instead: "first record
	// does not look like a TLS handshake", from a neighbour.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return ln, port
}

// getStatus GETs target through client and returns the status.
func getStatus(t *testing.T, client *http.Client, target string) int {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode
}

// TestABootRefusesAPlaintextGatewayTheMeshDoesNotCarry: validate() holds the
// gateway URL to the SDK's rule, and start() has to *call* validate() for that
// to mean anything. Removing the call left every boot test passing, because
// none of them boots with a configuration validate() would reject.
//
// The consequence is the whole reason the rule exists: every request to the
// gateway carries the projected service-account token, the viewer's bearer or
// the capability minted for them, and over plaintext to a host the mesh does
// not carry those are readable by anything on the path.
func TestABootRefusesAPlaintextGatewayTheMeshDoesNotCarry(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	bootEnvironment(t, mint)
	// Everything else resolved, and the gateway a plaintext host that is
	// neither loopback nor an in-cluster Service address.
	t.Setenv("GATEWAY_URL", "http://gateway.cell.example:8080")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := New(Manifest{ID: testSolutionID})
	ln, err := takeListener(server).start(ctx)
	if ln != nil {
		_ = ln.Close()
	}
	if err == nil {
		t.Fatal("the boot accepted a plaintext gateway the mesh does not carry: the projected service-account token attesting which workload this is would go out in the clear")
	}
	// From THIS runtime's validate(), naming the value an operator fixes, and
	// with the SDK's rule as the reason: two refusals for one fact is fine,
	// a test that cannot tell which fired is not.
	if !strings.Contains(err.Error(), "GATEWAY_URL") || !strings.Contains(err.Error(), "gateway URL") {
		t.Errorf("the refusal %q is not validate()'s, which names the configuration it is refusing", err)
	}
	if !errors.Is(err, workcontext.ErrInvalid) {
		t.Errorf("the refusal %q does not carry the SDK's rule, so a second copy of it is deciding", err)
	}
	// And it did not reach the mint on the way to refusing.
	if got := mint.count(); got != 0 {
		t.Errorf("the boot minted %d times before refusing the configuration: the refusal has to come before the token is sent anywhere", got)
	}
}

// TestAPlaintextGatewayIsAdmittedExactlyWhereTheSDKsRuleAdmitsIt: https
// anywhere; http to a loopback host on a local run, or to an in-cluster
// Service address when the composition asserts the mesh. Each answer here is
// the SDK's, asked with the assertion as loadConfig read it, and the mint URL
// derived on the same origin is held by the same words at every mint.
func TestAPlaintextGatewayIsAdmittedExactlyWhereTheSDKsRuleAdmitsIt(t *testing.T) {
	base := func(gateway string, transport meshTransport) config {
		return config{brokerInternalToken: "broker-perimeter-token", port: "8080", listenHost: "127.0.0.1", profile: localProfile,
			gatewayURL: gateway, mintURL: gateway + credentialMintPath, transport: transport}
	}
	asserted := meshTransport{value: "true", set: true}
	for _, tc := range []struct {
		name      string
		gateway   string
		transport meshTransport
		admitted  bool
	}{
		{"https anywhere", "https://gateway.cell.example:8443", meshTransport{}, true},
		{"loopback on a local run", "http://127.0.0.1:8080", meshTransport{local: true}, true},
		{"loopback in a deployment", "http://127.0.0.1:8080", meshTransport{}, false},
		{"an in-cluster Service under the assertion", "http://auth-gateway.platform.svc.cluster.local:8080", asserted, true},
		{"an in-cluster Service with no assertion", "http://auth-gateway.platform.svc.cluster.local:8080", meshTransport{}, false},
		{"a host the assertion does not cover", "http://gateway.cell.example:8080", asserted, false},
		{"a misspelled assertion", "http://auth-gateway.platform.svc:8080", meshTransport{value: "yes", set: true}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := base(tc.gateway, tc.transport).validate()
			if tc.admitted && err != nil {
				t.Fatalf("a gateway the SDK's rule admits was refused: %v", err)
			}
			if !tc.admitted && err == nil {
				t.Fatal("a plaintext gateway the SDK's rule refuses was accepted: the credentials on every gateway request would travel in the clear")
			}
			if !tc.admitted && !errors.Is(err, workcontext.ErrInvalid) {
				t.Errorf("the refusal %q is not the SDK's rule", err)
			}
		})
	}
}

// TestTheMintIsConfiguredWithTheFrozenAuthority: the SDK rechecks the authority
// before every renewal, which is the one moment a drifted authority value would
// be laundered into a credential nobody approved. Dropping it leaves the boot
// and the first mint perfect and only renewals wrong, which no test over a
// happy path can see — the mutation survived every one of them.
func TestTheMintIsConfiguredWithTheFrozenAuthority(t *testing.T) {
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

	options := server.mintOptions("projection")
	if options.Authority == nil {
		t.Error("the mint client is configured with no authority to recheck, so a renewal proceeds after the principal, the mint audience or the projection audience has drifted — the one moment that drift would otherwise be caught")
	}
	if options.Authority != server.authority {
		t.Error("the mint client rechecks something other than the reader this boot froze: a second reader is a second answer, and the one that disagrees is the one nobody approved")
	}
	// The audience is NAMED, not resolved here and passed beside the pin. The
	// SDK made that a typed reference because a string passed alongside meant
	// the drift check guarded a value the mint did not use.
	if want := (workcontext.AuthorityValue{Name: AuthorityGroup, Key: AuthorityAudienceKey}); options.Audience != want {
		t.Errorf("the mint reads its audience from %v, want the pinned %v", options.Audience, want)
	}
	if options.URL != server.cfg.mintURL {
		t.Errorf("the mint is configured for %q, not the resolved %q", options.URL, server.cfg.mintURL)
	}
	if options.URL != mint.URL+credentialMintPath {
		t.Errorf("the mint is configured for %q, want the host's broker route on the resolved gateway %q", options.URL, mint.URL+credentialMintPath)
	}
	// The transport rule is asked with the assertion loadConfig read, not
	// with a live accessor and not with a boolean somebody typed.
	if options.Transport != server.cfg.transport {
		t.Error("the mint admits plaintext by something other than the mesh assertion this boot read")
	}
	if options.ProjectedToken == nil {
		t.Fatal("the mint presents no projected token, which is the whole of what attests which workload is asking")
	}
}

// TestACredentialThatCannotBePresentedRefusesTheMint: attestWorkload checks
// that the credential actually attached to the outgoing request. Ignoring that
// error sends the mint with no attestation on it, which the host answers by
// minting for the viewer with nothing saying which module asked — the confused
// deputy this runtime exists to prevent, reached by skipping an error check.
func TestACredentialThatCannotBePresentedRefusesTheMint(t *testing.T) {
	gw := newModuleGateway(t, http.StatusOK, `{"entry_id":"e1"}`)
	server := New(Manifest{ID: testSolutionID}).
		Consumes(passthroughModule()).
		Contract(ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
		}}).
		// A credential that holds no token.
		//
		// WHAT THIS COVERS, NARROWED. The comment said this exercises the
		// Attach error branch, and it does not: usableCredential refuses a
		// zero credential before anything is attached, so removing the Attach
		// error check leaves this test green. A reviewer named that twice and
		// was right both times.
		//
		// What it does cover is the property the test is named for — a
		// credential this runtime cannot present produces no mint, reported as
		// this solution failing to attest itself — reached through the
		// usability check rather than through Attach. The Attach branch itself
		// is unreachable behind that check and is documented as defence in
		// depth in credential.go rather than as covered: reaching it would
		// need a credential that passes usability and then fails to attach,
		// which means inventing a capability shape the SDK does not produce.
		Credential(stubCredentialSource{credential: workcontext.Credential{}})
	server.cfg.profile = localProfile
	server.cfg.gatewayURL = gw.URL
	contract, err := server.resolveContract()
	if err != nil {
		t.Fatalf("resolveContract: %v", err)
	}
	server.contract = contract
	server.contractResolved = true

	header := http.Header{}
	header.Set("authorization", viewerBearer())
	header.Set(orgHeader, testOrganization)
	header.Set(sessionHeader, "session-1")
	header.Set(workcontext.InstallationIDHeaderName, testInstallation)
	_, err = server.gatewayFor(header).ForModule(context.Background(), "things",
		Scope{ResourceKind: "things", Actions: []string{"read"}})
	if err == nil {
		t.Fatal("a mint went out with a credential that could not be presented: the host would mint for the viewer with nothing attesting which module asked")
	}
	if !errors.Is(err, ErrNotAttested) {
		t.Errorf("the refusal %v is not reported as this solution failing to attest itself, which is what decides the status a handler answers", err)
	}
	if got := len(gw.observedMints()); got != 0 {
		t.Errorf("observed %d mints for a credential that could not be attached, want 0", got)
	}
}

// provideListener parks a bound listener for the Server this test is about to
// boot, and takeListener collects it.
//
// A package-level handoff because the environment is how a boot learns its
// port and the Server does not exist yet when bootIdentity runs. Safe without
// locking: every test here calls t.Setenv, which forbids t.Parallel, so they
// run one at a time.
var parkedListener net.Listener

func provideListener(t *testing.T, ln net.Listener) {
	t.Helper()
	parkedListener = ln
	t.Cleanup(func() { parkedListener = nil })
}

// takeListener gives the server the listener bootEnvironment bound, if there
// is one. A test that provisioned its environment some other way gets nil and
// the boot binds for itself.
//
// It also embeds the fixture's declared frontend into a server that declared
// none, the way a solution's go:embed does. Existing fixtures include a page;
// bootComponent explicitly opts out when exercising a headless component.
func takeListener(server *Server) *Server {
	if parkedListener != nil {
		server.boundListener = parkedListener
		parkedListener = nil
	}
	if server.manifest.Frontend == nil {
		server.manifest.Frontend = []byte(testFrontend)
	}
	return server
}

// localRun is the SDK's transport source for a test: a local run that asserts
// no mesh, so the only plaintext the mint client admits is loopback — the rule
// a booted runtime applies to its resolved gateway, answered the way a test's
// environment answers it.
type localRun struct{}

func (localRun) WorkspaceValueIfSet(string, string) (string, bool, error) { return "", false, nil }
func (localRun) IsLocalRun() bool                                         { return true }

func TestHeadlessComponentBootsWithoutAdvertisingAFrontend(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	running := bootComponent(t, New(Manifest{ID: testSolutionID}), mint, true)
	if status := getStatus(t, running.client, running.base+HealthPath); status != http.StatusOK {
		t.Fatalf("headless health: %d", status)
	}
	if status := getStatus(t, running.client, running.base+"/.well-known/solution.json"); status != http.StatusNotFound {
		t.Fatalf("headless component advertised a page: %d", status)
	}
}
