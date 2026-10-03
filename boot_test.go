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
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefly-dev/core/solution/manifest"
	corework "github.com/codefly-dev/core/workcontext"
	codefly "github.com/codefly-dev/sdk-go"
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
	// At the path the runtime derives from a resolved gateway, so a test sees
	// the same URL shape a deployment does.
	t.Setenv(CredentialMintURLEnvironmentVariable, mint.URL+credentialMintPath)
	t.Setenv(ProjectedTokenFileEnvironmentVariable, tokenFile)
	t.Setenv(IdentityCertFileEnvironmentVariable, certFile)
	t.Setenv(IdentityKeyFileEnvironmentVariable, keyFile)
	t.Setenv(IdentityTrustBundleFileEnvironmentVariable, bundleFile)
	// Who may call: the gateway, which is the identity cell.workload hands back
	// as the caller. Holding a certificate from the cell's anchor is not the
	// same as being a caller this solution serves, so the admitted set is
	// provisioned rather than derived from the anchor.
	t.Setenv(IdentityAllowedCallersEnvironmentVariable, testGatewayPrincipal)
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
	bootEnvironment(t, mint)
	ln, err := server.start(context.Background())
	if ln != nil {
		_ = ln.Close()
	}
	if err == nil {
		t.Fatal("the boot came up; this helper is for boots that must fail")
	}
	return err
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
	mint := newHostMint(t, &hostMint{})
	solution := boot(t, New(Manifest{ID: testSolutionID}).
		Handle("/thing", func(context.Context, *Gateway) (any, error) { return map[string]string{"ok": "yes"}, nil }), mint)

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
	ln, err := net.Listen("tcp", "127.0.0.1:0")
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
	return port
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
