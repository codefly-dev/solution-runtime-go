package solution

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
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
	testSolutionID    = "widgets-go"
	testSolutionTitle = "Widgets"

	testPrincipal          = "spiffe://codefly.test/ns/solutions/sa/widgets"
	testGatewayPrincipal   = "spiffe://codefly.test/ns/platform/sa/gateway"
	testAudience           = testSolutionID
	testProjectionAudience = "accounts"
)

// The sealed values the stand-in host issues against are core's own conformance
// values: the credential is minted by core's authority from core's fixture
// identities, so the seal this runtime logs and a test asserts is the live one
// that authority holds rather than a number invented here.
const (
	testInstallation     = corework.FixtureInstallation
	testBuildIncarnation = uint64(corework.FixtureBuildIncarnation)
)

// authorityValues provisions the module-authority group the way the platform
// does, through the carriers the SDK reads.
func authorityValues(t *testing.T) {
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
	// callers records the SPIFFE identity each request presented, so a test
	// can assert the runtime named itself on the way out as well as in, and
	// paths records what was asked for, so a surviving registration is visible
	// as the path it would have used.
	callers []string
	paths   []string
	// recoverAfter, when positive, is how many times status is answered before
	// the host starts issuing: an issuer catching up with a presence
	// generation that has just been applied.
	recoverAfter int64
	// ttl is how long the credential it issues is valid.
	ttl time.Duration

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

func newHostMint(t *testing.T, mint *hostMint) *hostMint {
	t.Helper()
	mint.authority = standInAuthority()
	if mint.ttl == 0 {
		// Core imposes no maximum lifetime — how long a credential lives is the
		// issuing host's decision, and this runtime's renewal arithmetic simply
		// follows whatever it is handed. Ten minutes keeps a test's renewal
		// behaviour ordinary rather than asserting a cap that does not exist.
		mint.ttl = 10 * time.Minute
	}
	mint.Server = httptest.NewServer(http.HandlerFunc(mint.serve))
	t.Cleanup(mint.Close)
	return mint
}

// serveTLS restarts this host under the cell's anchor, presenting an identity
// of its own and requiring the caller's — which is what the runtime's outbound
// client expects, because an https URL alone says only that the scheme is
// https.
func (m *hostMint) serveTLS(t *testing.T, c *cell) {
	t.Helper()
	m.Close()
	m.Server = httptest.NewUnstartedServer(http.HandlerFunc(m.serve))
	m.Server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*c.identity(t, testGatewayPrincipal)},
		ClientCAs:    c.roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	m.Server.StartTLS()
	t.Cleanup(m.Close)
}

func (m *hostMint) serve(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	m.presented = append(m.presented, r.Header.Get("authorization"))
	m.headers = append(m.headers, r.Header.Clone())
	m.callers = append(m.callers, callerIdentity(r))
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
			"expiresAt": time.Now().Add(m.ttl).UTC().Format(time.RFC3339),
		})
		return
	}
	atomic.AddInt64(&m.mints, 1)
	// recoverAfter 0 means this host never issues; a positive one means it
	// issues once that many asks have been answered with status.
	if m.status != 0 && (m.recoverAfter == 0 || atomic.LoadInt64(&m.mints) <= m.recoverAfter) {
		w.WriteHeader(m.status)
		return
	}
	token, _, err := m.authority.Start(r.Context(), corework.StartInput{
		TenantID:           corework.FixtureTenant,
		OwnerPrincipalID:   corework.FixturePrincipal,
		OwnerPrincipalKind: "human",
		TaskID:             fmt.Sprintf("workload-execution-%d", atomic.LoadInt64(&m.mints)),
		Audience:           testAudience,
		OrganizationID:     corework.FixtureOrganization,
		InstallationID:     testInstallation,
		TTL:                m.ttl,
	})
	if err != nil {
		m.signErr = err
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"work_context": token})
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

// callerIdentity is the SPIFFE ID the caller's own certificate named, or "" on
// a plain connection.
func callerIdentity(r *http.Request) string {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 || len(r.TLS.PeerCertificates[0].URIs) == 0 {
		return ""
	}
	return r.TLS.PeerCertificates[0].URIs[0].String()
}

// cell is one deployment's trust anchor: the root every identity in a test is
// issued under — this workload's, its callers', and the platform hosts it
// dials. One anchor on purpose, because that is the shape the runtime assumes:
// the pair its listener presents and the anchor it verifies peers with are also
// what it presents and verifies on the way out.
type cell struct {
	anchorPEM []byte
	anchor    *x509.Certificate
	anchorKey ed25519.PrivateKey
	roots     *x509.CertPool
}

func newCell(t *testing.T) *cell {
	t.Helper()
	pem, leaf, key := issueAnchor(t)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return &cell{anchorPEM: pem, anchor: leaf, anchorKey: key, roots: roots}
}

// workload writes the X.509-SVID the platform projects for a workload — a leaf
// whose URI SAN is its SPIFFE ID, which is what names a workload in this model
// and what the listener is held to — plus the anchor it was issued under, which
// is also the anchor this listener verifies its callers against.
//
// It returns a caller certificate too, because the listener requires one: a
// test that could reach this solution without presenting an identity would be
// exercising a listener this runtime refuses to start.
func (c *cell) workload(t *testing.T, spiffeID string) (certFile, keyFile, bundleFile string, caller *tls.Certificate, roots *x509.CertPool) {
	t.Helper()
	dir := t.TempDir()
	bundleFile = filepath.Join(dir, "ca.crt")
	writeFile(t, bundleFile, string(c.anchorPEM))

	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	leafPEM, keyPEM, _ := issueLeaf(t, c.anchor, c.anchorKey, spiffeID)
	writeFile(t, certFile, string(leafPEM))
	writeFile(t, keyFile, string(keyPEM))

	return certFile, keyFile, bundleFile, c.identity(t, testGatewayPrincipal), c.roots
}

// identity is a TLS certificate for one SPIFFE ID, for a party in a test that
// serves or dials rather than reading projected files.
func (c *cell) identity(t *testing.T, spiffeID string) *tls.Certificate {
	t.Helper()
	certPEM, keyPEM, _ := issueLeaf(t, c.anchor, c.anchorKey, spiffeID)
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return &pair
}

// workloadIdentity is one workload in a cell of its own, for a test that does
// not need the platform's side of the anchor.
func workloadIdentity(t *testing.T, spiffeID string) (certFile, keyFile, bundleFile string, caller *tls.Certificate, roots *x509.CertPool) {
	t.Helper()
	return newCell(t).workload(t, spiffeID)
}

// issueAnchor is the trust anchor a cell's identities are issued under.
func issueAnchor(t *testing.T) ([]byte, *x509.Certificate, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "codefly.test workload CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), leaf, private
}

// issueLeaf issues one workload identity under the anchor: a leaf whose only
// identity is the SPIFFE ID in its URI SAN.
func issueLeaf(t *testing.T, anchor *x509.Certificate, anchorKey ed25519.PrivateKey, spiffeID string) (certPEM, keyPEM []byte, leaf *x509.Certificate) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id, err := url.Parse(spiffeID)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: spiffeID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		URIs:         []*url.URL{id},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, anchor, public, anchorKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		parsed
}

// booted is a solution serving on an ephemeral port, with the client that
// trusts its workload identity.
type booted struct {
	server *Server
	base   string
	client *http.Client
	mint   *hostMint
}

// bootEnvironment provisions everything a deployed solution's boot reads — the
// projected identity, the anchor, the projected token, the resolved gateway —
// and starts the fake host under that same anchor, because the runtime's
// outbound client presents its identity and verifies the host against it.
//
// Shared by every boot test, including the ones that must fail: a boot refused
// for the reason under test has to be refused with everything else in place,
// or the test is asserting the first missing value instead.
func bootEnvironment(t *testing.T, mint *hostMint) (caller *tls.Certificate, roots *x509.CertPool) {
	t.Helper()
	certFile, keyFile, bundleFile, caller, roots := bootIdentity(t, mint, testPrincipal)
	_, _, _ = certFile, keyFile, bundleFile
	return caller, roots
}

// bootIdentity is bootEnvironment with the projected material exposed, for a
// test that supplies its own IdentitySource and must do so under the *same*
// anchor the fake host is served with — otherwise the boot fails verifying the
// host rather than on the property under test.
func bootIdentity(t *testing.T, mint *hostMint, principal string) (certFile, keyFile, bundleFile string, caller *tls.Certificate, roots *x509.CertPool) {
	t.Helper()
	cell := newCell(t)
	certFile, keyFile, bundleFile, caller, roots = cell.workload(t, principal)
	mint.serveTLS(t, cell)
	authorityValues(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected-token")

	t.Setenv("PORT", freePort(t))
	t.Setenv("GATEWAY_URL", mint.URL)
	// Set explicitly, as a deployment must: nothing derives a mint address
	// from the resolved gateway, because the projected token goes there.
	t.Setenv(CredentialMintURLEnvironmentVariable, mint.URL+credentialMintPath)
	t.Setenv(ProjectedTokenFileEnvironmentVariable, tokenFile)
	t.Setenv(IdentityCertFileEnvironmentVariable, certFile)
	t.Setenv(IdentityKeyFileEnvironmentVariable, keyFile)
	t.Setenv(IdentityTrustBundleFileEnvironmentVariable, bundleFile)
	// Who may call: the gateway, which is the identity cell.workload hands back
	// as the caller. Holding a certificate from the cell's anchor is not the
	// same as being a caller this solution serves, so the admitted set is
	// provisioned rather than derived from the anchor.
	t.Setenv(IdentityAllowedCallersFileEnvironmentVariable, identitiesFile(t, testGatewayPrincipal))
	// And whom this runtime may present credentials to: the same identity, for
	// the mirror-image reason. The fake host serves under it.
	t.Setenv(IdentityMintPeersFileEnvironmentVariable, identitiesFile(t, testGatewayPrincipal))
	t.Setenv(IdentityGatewayPeersFileEnvironmentVariable, identitiesFile(t, testGatewayPrincipal))
	t.Setenv(ContractProfileEnvironmentVariable, localProfile)
	// A test that serves assets provisions the directory before booting, since
	// a boot's configuration is read by the serving goroutine and must not be
	// written after it starts.
	if os.Getenv("ASSETS_DIR") == "" {
		t.Setenv("ASSETS_DIR", t.TempDir())
	}
	return certFile, keyFile, bundleFile, caller, roots
}

// boot runs the whole boot a deployed solution runs — configuration, the
// contract, the one mint, the TLS listener — on an ephemeral port.
func boot(t *testing.T, server *Server, mint *hostMint) *booted {
	t.Helper()
	caller, roots := bootEnvironment(t, mint)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ln, err := server.start(ctx)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- server.serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		<-served
	})
	return &booted{
		server: server,
		base:   "https://127.0.0.1:" + os.Getenv("PORT"),
		// The caller presents its own identity, because the listener requires
		// one: a client that could reach this solution without presenting a
		// certificate would be exercising a listener this runtime refuses to
		// start.
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:      roots,
			Certificates: []tls.Certificate{*caller},
			MinVersion:   tls.VersionTLS13,
		}}},
		mint: mint,
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
		ln, err := server.start(context.Background())
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

// TestBootMintsExactlyOnceAndServesOverTLS is the acceptance criterion of this
// runtime's whole boot: one mint per process start, zero registrations over any
// interval, and a listener that answers only over TLS.
func TestBootMintsExactlyOnceAndServesOverTLS(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	solution := boot(t, New(Manifest{ID: testSolutionID, Title: testSolutionTitle}).
		Handle("/thing", func(context.Context, *Gateway) (any, error) { return map[string]string{"ok": "yes"}, nil }), mint)

	for range 5 {
		if status := getStatus(t, solution.client, solution.base+HealthPath); status != http.StatusOK {
			t.Fatalf("health = %d, want 200 answered on the destination the presence document names", status)
		}
		if status := getStatus(t, solution.client, solution.base+"/.well-known/solution.json"); status != http.StatusOK {
			t.Fatalf("served manifest = %d, want 200", status)
		}
	}
	if got := mint.count(); got != 1 {
		t.Errorf("the host minted %d credentials for one process start, want exactly 1: nothing may mint per request, per beat or per probe", got)
	}
	if want := "Bearer projected-token"; mint.presented[0] != want {
		t.Errorf("the mint was presented %q, want %q — the projected service-account token is what attests which workload this is", mint.presented[0], want)
	}

	// The same port answers no plain-HTTP request: the TLS handshake it expects
	// never happens, so the request is refused before any route is reached. The
	// control is the TLS health check above, which the same port answers 200.
	plain, err := http.Get("http://" + solution.base[len("https://"):] + HealthPath)
	if err == nil {
		defer plain.Body.Close()
		if plain.StatusCode == http.StatusOK {
			t.Error("plain HTTP was served: the listener presents this workload's identity and there is no plain-HTTP listener")
		}
	}
}

// TestABootedRuntimeMintsOnceUnderConcurrentRequests is the mint-once claim
// about *production wiring* rather than about one SDK instance.
//
// The earlier version drove the client directly, which would stay green if the
// runtime created a fresh client per request — the defect that would make this
// change worse than the heartbeat it replaced, since every token such a client
// issues is valid and every functional test passes. So this boots the real
// runtime, drives concurrent requests through its handler, and counts what the
// host was asked.
func TestABootedRuntimeMintsOnceUnderConcurrentRequests(t *testing.T) {
	// The handler has to *use* the credential, or this test is green against a
	// runtime that builds a client per request: a second reviewer pointed out
	// that the previous handler returned a literal, so no request reached the
	// credential source at all and the only mint being counted was the boot's.
	t.Setenv(manifest.APIConsumesEnvironmentVariable, consumesThings)
	mint := newHostMint(t, &hostMint{})
	solution := boot(t, New(Manifest{ID: testSolutionID}).
		Consumes(passthroughModule()).
		Contract(ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read"}}}},
		}}).
		Handle("/thing", func(ctx context.Context, gw *Gateway) (any, error) {
			if _, err := gw.ForModule(ctx, "things", Scope{ResourceKind: "things", Actions: []string{"read"}}); err != nil {
				return nil, err
			}
			return map[string]string{"ok": "yes"}, nil
		}), mint)

	const callers = 16
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			request, err := http.NewRequest(http.MethodGet, solution.base+"/thing", nil)
			if err != nil {
				t.Error(err)
				return
			}
			request.Header.Set("authorization", "Bearer viewer")
			// The identity headers the gateway stamps from the verified bearer;
			// ForModule needs both to mint.
			request.Header.Set(orgHeader, "org-1")
			request.Header.Set(sessionHeader, "session-1")
			resp, err := solution.client.Do(request)
			if err != nil {
				t.Errorf("call: %v", err)
				return
			}
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("handler answered %d, want 200", resp.StatusCode)
			}
		}()
	}
	close(start)
	wg.Wait()

	if got := mint.count(); got != 1 {
		t.Errorf("the host minted %d credentials for one process serving %d concurrent requests, want exactly 1: a runtime that minted per request would be worse than the heartbeat it replaced",
			got, callers)
	}
	// And the requests really did reach the credential: without this the
	// assertion above holds for a runtime whose handler never touches it.
	if got := len(mint.observedStartTasks()); got == 0 {
		t.Error("no viewer mint was attempted, so nothing in this test exercised the credential at all")
	}
	// And the mint named this workload on the way out, not just in its body:
	// the outbound client presents the same identity the listener does.
	if got := mint.callers[0]; got != testPrincipal {
		t.Errorf("the mint was dialled by %q, want this workload's own identity %q", got, testPrincipal)
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

// TestServedContractReportsWhatThisProcessHoldsItselfTo: the published contract
// names the principal the platform provisioned, the profile this process runs
// under, and the ceiling each consumed audience is capped at.
func TestServedContractReportsWhatThisProcessHoldsItselfTo(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	t.Setenv(manifest.APIConsumesEnvironmentVariable, consumesThings)
	server := New(Manifest{ID: testSolutionID}).
		Consumes(passthroughModule()).
		Contract(ModuleContract{Ceilings: map[string]map[string][]Scope{
			localProfile: {"things": {{ResourceKind: "things", Actions: []string{"read", "list"}}}},
		}})
	solution := boot(t, server, mint)

	resp, err := solution.client.Get(solution.base + ContractPath)
	if err != nil {
		t.Fatalf("GET %s: %v", ContractPath, err)
	}
	defer resp.Body.Close()
	var published effectiveContract
	if err := json.NewDecoder(resp.Body).Decode(&published); err != nil {
		t.Fatalf("decode contract: %v", err)
	}
	if published.Principal != testPrincipal {
		t.Errorf("published principal = %q, want the provisioned %q", published.Principal, testPrincipal)
	}
	if published.Profile != localProfile {
		t.Errorf("published profile = %q, want %q", published.Profile, localProfile)
	}
	if len(published.Bindings) != 1 || published.Bindings[0].Audience != "things" {
		t.Fatalf("published bindings = %+v, want the one audience this solution consumes", published.Bindings)
	}
	if got := published.Bindings[0].Ceiling; len(got) != 1 || len(got[0].Actions) != 2 {
		t.Errorf("published ceiling = %+v, want the declared read+list ceiling", got)
	}
	if got := published.Bindings[0].Asked; len(got) != 1 || got[0].Actions[0] != "read" {
		t.Errorf("published ask = %+v, want the single read the declaration asks for", got)
	}
}

// freePort is a port nothing is listening on: the kernel picks one and it is
// released immediately. The runtime refuses port 0 — a kernel-assigned port is
// a solution nobody can route to — so a test that wants an ephemeral port has
// to name a real one.
func freePort(t *testing.T) string {
	t.Helper()
	// Bind, read the port, close, hand it over — which is a time-of-check /
	// time-of-use race, and it is the one that produced the intermittent
	// failures this suite was reporting as an unexplained flake: a test booted
	// and got `bind: address already in use`, in a different test each time.
	// Between the close here and the boot's own bind, anything else asking the
	// OS for an ephemeral port can be handed this one, and this suite stands up
	// httptest servers constantly.
	//
	// Two things narrow it: a port handed out once in this process is never
	// handed out again, and the port is re-bound immediately before being
	// returned to confirm it is still free. Neither makes it impossible — only
	// never closing the listener would, and the boot has to bind it — so the
	// retry is what covers the rest.
	for attempt := range 20 {
		ln, err := net.Listen("tcp", ":0")
		if err != nil {
			t.Fatal(err)
		}
		_, port, err := net.SplitHostPort(ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		if err := ln.Close(); err != nil {
			t.Fatal(err)
		}
		if handedOutPort(port) {
			continue
		}
		// Still free for the bind the boot will actually make, which is on all
		// interfaces (`:port`) and not on loopback: 127.0.0.1:P being free
		// does not mean :P is, and checking the wrong one is how this helper
		// handed out ports that then failed to bind.
		again, err := net.Listen("tcp", ":"+port)
		if err != nil {
			continue
		}
		if err := again.Close(); err != nil {
			t.Fatal(err)
		}
		_ = attempt
		return port
	}
	t.Fatal("could not find a free port that had not already been handed out")
	return ""
}

var (
	handedOutMu    sync.Mutex
	handedOutPorts = map[string]bool{}
)

// handedOutPort records a port and reports whether it had been handed out
// before, so no two tests in this process are given the same one.
func handedOutPort(port string) bool {
	handedOutMu.Lock()
	defer handedOutMu.Unlock()
	if handedOutPorts[port] {
		return true
	}
	handedOutPorts[port] = true
	return false
}

// getStatus GETs target through client and returns the status.
func getStatus(t *testing.T, client *http.Client, target string) int {
	t.Helper()
	resp, err := client.Get(target)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// consumesThings is the api.consumes projection core surfaces for the "things"
// module the passthrough fixtures declare. The key is a wire contract
// (manifest.APIConsumesEnvironmentVariable).
const consumesThings = `[{"id":"thingstore.things","module":"thingstore","service":"things","endpoint":"rest","protocol":"rest","as":"things"}]`

// consumesThingsAndBearer adds a module called with the viewer's bearer, which
// mints nothing — the case a ceiling must refuse an ask for.
const consumesThingsAndBearer = `[{"id":"thingstore.things","module":"thingstore","service":"things","endpoint":"rest","protocol":"rest","as":"things"},{"id":"pagestore.pages","module":"pagestore","service":"pages","endpoint":"rest","protocol":"rest","as":"pages"}]`

// TestTheBootedListenerDropsACallerItNoLongerAdmits drives the production
// serve() path, which is the only place the per-connection watch is installed.
//
// A unit test that builds its own http.Server proves the hook works and not
// that anything installs it: removing `ConnState: watch` from serve() left
// every such test passing. This boots the runtime the way Serve does.
func TestTheBootedListenerDropsACallerItNoLongerAdmits(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	solution := boot(t, New(Manifest{ID: testSolutionID}).
		Handle("/thing", func(context.Context, *Gateway) (any, error) { return map[string]string{"ok": "yes"}, nil }), mint)

	call := func() error {
		request, err := http.NewRequest(http.MethodGet, solution.base+"/thing", nil)
		if err != nil {
			return err
		}
		resp, err := solution.client.Do(request)
		if err != nil {
			return err
		}
		_ = resp.Body.Close()
		return nil
	}

	// The control: an admitted caller is served, and stays served on one busy
	// connection across more than a recheck interval.
	if err := call(); err != nil {
		t.Fatalf("an admitted caller was refused: %v", err)
	}
	quiet := time.Now().Add(2 * inboundTrustRecheckInterval)
	for time.Now().Before(quiet) {
		if err := call(); err != nil {
			t.Fatalf("a request failed while this caller was still admitted, so nothing below is about admission: %v", err)
		}
		time.Sleep(inboundTrustRecheckInterval / 10)
	}

	// The platform removes this caller from the provisioned file. Nothing
	// restarts, and traffic keeps arriving on the connection it already holds.
	callersFile := os.Getenv(IdentityAllowedCallersFileEnvironmentVariable)
	if callersFile == "" {
		t.Fatal("the boot resolved no allowed-callers path, so this test cannot withdraw admission")
	}
	writeFile(t, callersFile, "spiffe://codefly.test/ns/platform/sa/somebody-else\n")

	deadline := time.Now().Add(5 * inboundTrustRecheckInterval)
	for {
		if err := call(); err != nil {
			return // the connection stopped being served, which is the point
		}
		if time.Now().After(deadline) {
			t.Fatalf("this caller was still served %s after it was removed from the provisioned set, on the connection it already held: the booted listener installs no per-connection recheck, so revocation waits for a restart",
				5*inboundTrustRecheckInterval)
		}
		time.Sleep(inboundTrustRecheckInterval / 10)
	}
}

// TestABootWithAnUnusableAdmissionFileIsRefused: the path resolving is not the
// same question as the set being readable, and the second one has to be asked
// at boot rather than at the first handshake.
//
// A provisioned path naming a file that is empty, or absent, would otherwise
// start a listener that refuses every caller and a client that refuses every
// dial, and report it as an admission failure once traffic arrived instead of
// as the provisioning gap it is.
func TestABootWithAnUnusableAdmissionFileIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name     string
		contents string
		write    bool
	}{
		{"a file naming nobody", "\n", true},
		{"a file of comments only", "# the gateway goes here\n", true},
		{"a path with no file behind it", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cell := newCell(t)
			certFile, keyFile, bundleFile, _, _ := cell.workload(t, testPrincipal)
			path := filepath.Join(t.TempDir(), "callers")
			if tc.write {
				writeFile(t, path, tc.contents)
			}
			server := New(Manifest{ID: testSolutionID})
			server.cfg = config{
				port: "8080", gatewayURL: "https://gateway:42152",
				mintURL:            "https://gateway:42152" + credentialMintPath,
				identityCertFile:   certFile,
				identityKeyFile:    keyFile,
				projectedTokenPath: "t",
				trustBundleFile:    bundleFile,
				allowedCallersFile: path,
				mintPeersFile:      identitiesFile(t, testGatewayPrincipal),
				gatewayPeersFile:   identitiesFile(t, testGatewayPrincipal),
				profile:            localProfile,
			}
			err := server.validateSources()
			if err == nil {
				t.Fatal("the boot accepted an admission set it cannot read: the listener would start and refuse every caller, reported as an admission failure rather than as provisioning")
			}
			if !strings.Contains(err.Error(), "not usable at boot") {
				t.Errorf("the refusal %q does not say the provisioned set is unusable, so it reads as a different problem", err)
			}
		})
	}
}

// TestABootRefusesAPlaintextMintBeforeSendingTheToken: validate() refuses a
// plaintext credential mint, and start() has to *call* validate() for that to
// mean anything. Removing the call left every boot test passing, because none
// of them boots with a configuration validate() would reject — they all
// provision a conforming one and then assert on behaviour.
//
// The consequence is the whole reason this runtime refuses a plaintext
// destination at boot: the request to the mint carries the projected
// service-account token that attests which workload this process is, and over
// http that is readable by anything on the path.
func TestABootRefusesAPlaintextMintBeforeSendingTheToken(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	bootEnvironment(t, mint)
	// Everything else resolved, and the mint moved to plaintext.
	plaintext := strings.Replace(mint.URL, "https://", "http://", 1)
	t.Setenv(CredentialMintURLEnvironmentVariable, plaintext+credentialMintPath)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	server := New(Manifest{ID: testSolutionID})
	ln, err := server.start(ctx)
	if ln != nil {
		_ = ln.Close()
	}
	if err == nil {
		t.Fatal("the boot accepted a plaintext credential mint: the projected service-account token attesting which workload this is would go out in the clear")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("the refusal %q does not say the destination has to be https", err)
	}
	// And it did not reach the mint on the way to refusing.
	if got := mint.count(); got != 0 {
		t.Errorf("the boot minted %d times before refusing the configuration: the refusal has to come before the token is sent anywhere", got)
	}
}

// TestServeEndsOnATerminalCredentialRefusal: a refused build is not something
// to keep serving under. serve() watches credentialRefusedC and closes the
// listener; removing that watch left the process serving indefinitely while
// /health answered 503, which is the "answers 503 forever while reporting
// itself healthy" shape inverted — and no committed test observed serve
// returning.
func TestServeEndsOnATerminalCredentialRefusal(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	bootEnvironment(t, mint)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	server := New(Manifest{ID: testSolutionID})
	ln, err := server.start(ctx)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	served := make(chan error, 1)
	go func() { served <- server.serve(ctx, ln) }()

	// The control: it is still serving, so the assertion below is about the
	// refusal and not about a listener that never came up.
	select {
	case err := <-served:
		t.Fatalf("serve returned before anything refused this execution's credential: %v", err)
	case <-time.After(250 * time.Millisecond):
	}

	refusal := fmt.Errorf("%w: this build is not the one the presence document approved", workcontext.ErrMintRefused)
	server.credentialRefused(refusal)

	select {
	case err := <-served:
		if err == nil {
			t.Fatal("serve ended without reporting why: the orchestrator restarts against a judgement, so the reason is what it has to be given")
		}
		if !strings.Contains(err.Error(), "presence document approved") {
			t.Errorf("serve ended with %q, which does not carry the issuer's judgement", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serve did not end after this execution's credential was refused for good: the process keeps serving a binding it has no authority for, and the host keeps routing to it")
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
	ln, err := server.start(ctx)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	_ = ln.Close()

	options := server.mintOptions("audience", "projection")
	if options.Authority == nil {
		t.Error("the mint client is configured with no authority to recheck, so a renewal proceeds after the principal, the mint audience or the projection audience has drifted — the one moment that drift would otherwise be caught")
	}
	if options.Authority != server.authority {
		t.Error("the mint client rechecks something other than the reader this boot froze: a second reader is a second answer, and the one that disagrees is the one nobody approved")
	}
	// The rest of the options are decisions too, and each has been wrong once.
	if options.HTTPClient != server.outbound {
		t.Error("the mint does not use this runtime's authenticated outbound client, so it would not present this workload's identity, would not verify the host against the projected anchor, and would follow a redirect carrying the projected token")
	}
	if options.URL != server.cfg.mintURL {
		t.Errorf("the mint is configured for %q, not the resolved %q", options.URL, server.cfg.mintURL)
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
		// A credential that holds no token: Attach cannot seal a request with
		// it, which is the shape a half-initialised source produces.
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
	header.Set("authorization", "Bearer viewer")
	header.Set(orgHeader, "org-1")
	header.Set(sessionHeader, "session-1")
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

// provisionedWorkloadValue makes the SDK answer for one workload-identity key,
// the way authorityValues does for the authority group.
//
// It exists because a comment in this suite claimed a test could not make the
// SDK's workspace configuration answer. It can, and because it was believed it
// could not, the two-sources rule had no behavioural test and three mutants of
// it survived.
func provisionedWorkloadValue(t *testing.T, key, value string) {
	t.Helper()
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION__WORKLOAD_IDENTITY__"+key, value)
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })
}

// withoutWorkloadValues leaves the SDK with no workspace configuration at all,
// so a lookup errors rather than answering empty.
func withoutWorkloadValues(t *testing.T) {
	t.Helper()
	t.Setenv("CODEFLY__WORKSPACE_CONFIGURATION", "")
	if err := codefly.LoadEnvironmentVariables(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })
}
