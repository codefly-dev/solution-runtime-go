package solution

import (
	"cmp"
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
	"net/http/httptrace"
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
	// switchTo and switchAfter make this host answer with a DIFFERENT shape
	// once switchAfter credentials have been minted: the renewal path, driven
	// through the real client rather than by calling the wrapper directly.
	switchTo    *hostMint
	switchAfter int64
	// cell is the anchor this mint's own identity is issued under, and the one
	// a caller's certificate is verified against. Set by every constructor,
	// because the mint endpoint now requires a client certificate and is
	// itself admitted by the SPIFFE ID in its single URI SAN.
	cell *cell
	// caller is the leaf a test's own mint client presents, issued under the
	// same anchor. The booted path presents the runtime's projected pair
	// instead; this is for the unit-level clients.
	caller *tls.Certificate
	// cellRoots is set when serveTLS re-serves this mint under a cell's
	// anchor, so roots() answers that rather than httptest's own certificate.
	cellRoots *x509.CertPool
	// digest and incarnation override the build this host attests, so a test
	// can have a RENEWAL seal a different execution than the first credential.
	digest      string
	incarnation uint64
	// executionFree makes this host mint a credential sealing NO execution,
	// which core allows: the sealed execution became optional because a
	// principal that bears no approved build — a person at a terminal — must
	// not have one invented for it. It is the shape of core's own
	// execution-missing fixture, and it is not a shape a WORKLOAD credential
	// may have.
	executionFree bool
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
	if mint.executionFree {
		// An issuer that mints a credential sealing NO execution, which core
		// permits only for a principal bearing no approved build — a person at
		// a terminal. Built by taking core's fixture seal source and recording
		// the installation seal and epoch WITHOUT an approved build, which is
		// the shape of core's own execution-missing fixture.
		//
		// Core refuses to mint execution-free for a principal that does bear
		// one, which is why this cannot be done by simply omitting the field.
		seals := corework.NewMemorySealSource()
		if err := seals.Put(corework.FixturePrincipal, corework.Seal{
			InstallationID:       testInstallation,
			InstallationRevision: corework.FixtureInstallationRevision,
		}); err != nil {
			t.Fatalf("seal an execution-free issuer: %v", err)
		}
		if err := seals.PutEpoch(corework.FixturePrincipal, corework.FixturePrincipalEpoch); err != nil {
			t.Fatalf("record the principal's epoch: %v", err)
		}
		// Explicitly bearing no execution, which is core's own distinction:
		// a principal with an approved build MUST attest it, one recorded as
		// bearing none legitimately carries no execution, and one core knows
		// nothing about is refused. This is the middle case — a person at a
		// terminal — and it is the shape a WORKLOAD credential must never have.
		if err := seals.PutBearsNoExecution(corework.FixturePrincipal); err != nil {
			t.Fatalf("record the principal as bearing no execution: %v", err)
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
	if mint.digest != "" || mint.incarnation != 0 {
		// An issuer whose APPROVED BUILD has moved, which is the only way it
		// can attest a different one: core refuses to seal an execution the
		// issuer does not approve for that principal. Built from core's own
		// fixture seal source with the approved build overridden.
		seals := corework.FixtureSeals()
		if err := seals.PutApprovedBuild(corework.FixturePrincipal,
			cmp.Or(mint.digest, corework.FixtureImageDigest),
			cmp.Or(mint.incarnation, uint64(corework.FixtureBuildIncarnation))); err != nil {
			t.Fatalf("move the issuer's approved build: %v", err)
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
	// TLS, not plaintext, and under a cell of its own. The SDK's mint client
	// refuses plain HTTP outright — the projected service-account token
	// travels on that request — and httptest's shared certificate carries no
	// SPIFFE ID, so a client that admits the endpoint by identity cannot
	// accept it. A booted test calls serveTLS afterwards to move this host
	// under the boot's anchor instead.
	mint.serveUnder(t, newCell(t))
	return mint
}

// serveUnder serves this fake mint under one cell: its own identity from that
// anchor, and the caller's certificate REQUIRED and verified against it.
//
// Required, not "verified if given". The fixture was weakened to
// VerifyClientCertIfGiven when the SDK owned the whole transport and presented
// nothing, and a reviewer was right that this established the changed
// behaviour rather than closing it: a fake host that tolerates an anonymous
// caller cannot tell a runtime that presents its X.509-SVID from one that does
// not. sdk-go#51 gives the client a ClientCertificate reader, so the fixture
// goes back to demanding what a real mint endpoint demands.
func (m *hostMint) serveUnder(t *testing.T, c *cell) {
	t.Helper()
	m.cell, m.cellRoots = c, c.roots
	m.caller = c.identity(t, testPrincipal)
	m.Server = httptest.NewUnstartedServer(http.HandlerFunc(m.serve))
	m.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{*c.identity(t, testGatewayPrincipal)},
		ClientCAs:    c.roots,
		ClientAuth:   tls.RequireAndVerifyClientCert,
	}
	m.StartTLS()
	t.Cleanup(m.Close)
}

// serveTLS restarts this host under the cell's anchor, presenting an identity
// of its own and requiring the caller's — which is what the runtime's outbound
// client expects, because an https URL alone says only that the scheme is
// https.
// roots is the pool that may sign this fake mint's certificate, which the SDK
// now requires and will not default to the system pool for.
func (m *hostMint) roots() (*x509.CertPool, error) {
	if m.cellRoots != nil {
		return m.cellRoots, nil
	}
	pool := x509.NewCertPool()
	pool.AddCert(m.Certificate())
	return pool, nil
}

func (m *hostMint) serveTLS(t *testing.T, c *cell) {
	t.Helper()
	m.Close()
	m.serveUnder(t, c)
}

// execution is the build this host attests for the credential it mints, or
// nothing at all when the test asks for an execution-free one.
// installationFor is the installation the shape in force seals to.
func (m *hostMint) installationFor() string {
	if m.switchTo != nil && atomic.LoadInt64(&m.mints) > m.switchAfter {
		return m.switchTo.installation
	}
	return m.installation
}

func (m *hostMint) execution() corework.Execution {
	if m.executionFree {
		return corework.Execution{}
	}
	return corework.Execution{
		ImageDigest:      cmp.Or(m.digest, corework.FixtureImageDigest),
		BuildIncarnation: cmp.Or(m.incarnation, uint64(corework.FixtureBuildIncarnation)),
	}
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
	issuer, execution := m.authority, m.execution()
	if m.switchTo != nil && atomic.LoadInt64(&m.mints) > m.switchAfter {
		issuer, execution = m.switchTo.authority, m.switchTo.execution()
	}
	token, _, err := issuer.Start(r.Context(), corework.StartInput{
		TenantID:           corework.FixtureTenant,
		OwnerPrincipalID:   corework.FixturePrincipal,
		OwnerPrincipalKind: "human",
		TaskID:             fmt.Sprintf("workload-execution-%d", atomic.LoadInt64(&m.mints)),
		Audience:           testAudience,
		OrganizationID:     corework.FixtureOrganization,
		InstallationID:     cmp.Or(m.installationFor(), testInstallation),
		TTL:                m.ttl,
		// Core v0.9.0 requires the caller to attest the build it is running:
		// a principal that exercises an approved execution must name the image
		// digest and incarnation, and the issuer checks them against the
		// approved build it holds for that principal. The execution moved off
		// the installation seal, where it described the OWNER's workload
		// however many delegation hops had been added.
		Execution: execution,
	})
	if err != nil {
		m.signErr = err
		http.Error(w, "stand-in issuer: "+err.Error(), http.StatusInternalServerError)
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
	// cell is the CA the listener verifies callers against, for a test that
	// must issue another certificate it will accept.
	cell *cell
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
// projected identity, the anchor, the projected token, the resolved gateway —
// and starts the fake host under that same anchor, because the runtime's
// outbound client presents its identity and verifies the host against it.
//
// Shared by every boot test, including the ones that must fail: a boot refused
// for the reason under test has to be refused with everything else in place,
// or the test is asserting the first missing value instead.
func bootEnvironment(t *testing.T, mint *hostMint) (caller *tls.Certificate, roots *x509.CertPool) {
	t.Helper()
	caller, roots, _ = bootCell(t, mint)
	return caller, roots
}

// bootCell is bootEnvironment with the cell exposed, for a test that must issue
// another certificate under the SAME anchor the listener verifies against — a
// forged leaf from any other cell is refused for its chain, which would answer
// the test before the property under test is reached.
func bootCell(t *testing.T, mint *hostMint) (caller *tls.Certificate, roots *x509.CertPool, cell *cell) {
	t.Helper()
	certFile, keyFile, bundleFile, caller, roots, cell := bootIdentityIn(t, mint, testPrincipal)
	_, _, _ = certFile, keyFile, bundleFile
	return caller, roots, cell
}

// bootIdentity is bootEnvironment with the projected material exposed, for a
// test that supplies its own IdentitySource and must do so under the *same*
// anchor the fake host is served with — otherwise the boot fails verifying the
// host rather than on the property under test.
func bootIdentity(t *testing.T, mint *hostMint, principal string) (certFile, keyFile, bundleFile string, caller *tls.Certificate, roots *x509.CertPool) {
	certFile, keyFile, bundleFile, caller, roots, _ = bootIdentityIn(t, mint, principal)
	return
}

func bootIdentityIn(t *testing.T, mint *hostMint, principal string) (certFile, keyFile, bundleFile string, caller *tls.Certificate, roots *x509.CertPool, issuing *cell) {
	t.Helper()
	cell := newCell(t)
	issuing = cell
	certFile, keyFile, bundleFile, caller, roots = cell.workload(t, principal)
	mint.serveTLS(t, cell)
	authorityValues(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected-token")

	// Bound here and handed to whichever Server this test boots, so the port is
	// never released between being chosen and being served on.
	ln, port := boundPort(t)
	provideListener(t, ln)
	t.Setenv("PORT", port)
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
	return certFile, keyFile, bundleFile, caller, roots, issuing
}

// boot runs the whole boot a deployed solution runs — configuration, the
// contract, the one mint, the TLS listener — on an ephemeral port.
func boot(t *testing.T, server *Server, mint *hostMint) *booted {
	t.Helper()
	caller, roots, cell := bootCell(t, mint)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	ln, err := takeListener(server).start(ctx)
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
		cell: cell,
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
		defer func() { _ = plain.Body.Close() }()
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
			request.Header.Set("authorization", viewerBearer())
			// The identity headers the gateway stamps from the verified bearer;
			// ForModule needs both to mint.
			request.Header.Set(orgHeader, "org-1")
			request.Header.Set(sessionHeader, "session-1")
			request.Header.Set(workcontext.InstallationIDHeaderName, testInstallation)
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
	// The mint is dialled WITH this workload's own certificate, and the
	// identity it presented is asserted.
	//
	// This assertion has now been all three things. It asserted the identity;
	// then the sdk-go v0.3.0 pin took the transport over and presented
	// nothing, so it was changed to require the caller identity be EMPTY and
	// the fake endpoint was weakened to VerifyClientCertIfGiven; a reviewer
	// said that established the changed behaviour rather than closing the
	// finding, and was right. sdk-go#51 gives the client a ClientCertificate
	// reader, so both go back: the endpoint REQUIRES a certificate and this
	// names which one it must be.
	//
	// The projected service-account token is still checked, because it is
	// still what the host validates the projection by — it is simply no longer
	// the whole of what attests who is asking.
	if len(mint.presented) == 0 {
		t.Fatal("the mint saw no authorization header at all, so nothing attested which workload was asking")
	}
	if got := mint.presented[0]; !strings.Contains(got, "projected-token") {
		t.Errorf("the mint was presented %q, want the projected service-account token", got)
	}
	if len(mint.callers) == 0 {
		t.Fatal("the mint endpoint recorded no caller, so the handshake carried no client certificate: the projected token would be the whole of what attests which workload is asking")
	}
	if got := mint.callers[0]; got != testPrincipal {
		t.Errorf("the mint was dialled with client identity %q, want %q: the host holds this process to the identity its presence document approved, and the hop that carries the projected service-account token is the one that must present it", got, testPrincipal)
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
	defer func() { _ = resp.Body.Close() }()
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

// boundPort binds a listener and returns it with its port, so a test hands the
// *listener* to the boot rather than a port number. The test clients dial
// IPv4 loopback; binding that same address prevents a wildcard socket from
// sharing its port with a different namespace's IPv4 listener.
//
// This replaces a helper that bound :0, read the port, closed the socket and
// returned the number — a time-of-check/time-of-use race against everything
// else in this suite asking the OS for an ephemeral port, and the cause of the
// intermittent `bind: address already in use` failures that appeared in a
// different test each run. A retry narrowed the window and could not close it:
// the port is released by construction. Nothing is released here.
func boundPort(t *testing.T) (net.Listener, string) {
	t.Helper()
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

// consumesThings is the api.consumes projection core surfaces for the "things"
// module the passthrough fixtures declare. The key is a wire contract
// (manifest.APIConsumesEnvironmentVariable).
const consumesThings = `[{"id":"thingstore.things","module":"thingstore","service":"things","endpoint":"rest","protocol":"rest","as":"things"}]`

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

	// AUTHORIZED, STATUS-CHECKED, DRAINED, AND ON ONE CONNECTION.
	//
	// This sent no bearer, ignored the status, closed the body without
	// draining it and never looked at reuse — so "an admitted caller is
	// served" was really "the request did not error", which a 401 satisfies,
	// and an undrained body means the connection goes back to nobody rather
	// than to the pool. The claim this control makes is that a handler ran
	// over an existing BUSY connection, and none of those three omissions let
	// it make that claim.
	var reused atomic.Int64
	call := func() (int, error) {
		request, err := http.NewRequest(http.MethodGet, solution.base+"/thing", nil)
		if err != nil {
			return 0, err
		}
		request.Header.Set("authorization", viewerBearer())
		request = request.WithContext(httptrace.WithClientTrace(request.Context(), &httptrace.ClientTrace{
			GotConn: func(info httptrace.GotConnInfo) {
				if info.Reused {
					reused.Add(1)
				}
			},
		}))
		resp, err := solution.client.Do(request)
		if err != nil {
			return 0, err
		}
		status := resp.StatusCode
		drainAndClose(resp)
		return status, nil
	}

	// The control: an admitted caller is SERVED — 200, body drained — and
	// stays served on one busy connection across more than a recheck interval.
	if status, err := call(); err != nil {
		t.Fatalf("an admitted caller was refused: %v", err)
	} else if status != http.StatusOK {
		t.Fatalf("an admitted caller got %d, want 200: a refusal satisfies 'did not error', so without this the control proves nothing about the handler running", status)
	}
	quiet := time.Now().Add(2 * inboundTrustRecheckInterval)
	for time.Now().Before(quiet) {
		status, err := call()
		if err != nil {
			t.Fatalf("a request failed while this caller was still admitted, so nothing below is about admission: %v", err)
		}
		if status != http.StatusOK {
			t.Fatalf("a request answered %d while this caller was still admitted", status)
		}
		time.Sleep(inboundTrustRecheckInterval / 10)
	}
	// ON ONE CONNECTION. The claim is that a handler ran over an existing BUSY
	// connection — not that a fresh connection was made each time, which no
	// per-connection recheck would need to notice.
	if reused.Load() == 0 {
		t.Fatal("not one request reused a connection, so this test never exercised an ESTABLISHED connection: a per-dial check alone would satisfy everything below")
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
		if _, err := call(); err != nil {
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
	ln, err := takeListener(server).start(ctx)
	if ln != nil {
		_ = ln.Close()
	}
	if err == nil {
		t.Fatal("the boot accepted a plaintext credential mint: the projected service-account token attesting which workload this is would go out in the clear")
	}
	if !strings.Contains(err.Error(), "https") {
		t.Errorf("the refusal %q does not say the destination has to be https", err)
	}
	// From THIS runtime's validate(), not from the SDK's own refusal.
	//
	// sdk-go v0.3.0 refuses a plaintext mint URL too, so this test passed with
	// validate()'s check deleted — the mutation ledger caught it. Two
	// refusals for one fact is fine; a test that cannot tell which one fired
	// is not, because the boot's own check is what refuses BEFORE a mint
	// client is built and names the variable an operator has to fix.
	if !strings.Contains(err.Error(), CredentialMintURLEnvironmentVariable) {
		t.Errorf("the refusal %q does not name %s, so it is not this runtime's boot check: the SDK refuses a plaintext mint as well, and a test that accepts either cannot tell whether validate() still does",
			err, CredentialMintURLEnvironmentVariable)
	}
	if !strings.Contains(err.Error(), "credential mint URL") {
		t.Errorf("the refusal %q is not validate()'s, which names the configuration it is refusing", err)
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
	ln, err := takeListener(server).start(ctx)
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
	ln, err := takeListener(server).start(ctx)
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	_ = ln.Close()

	anchor := x509.NewCertPool()
	leafAsked := false
	options := server.mintOptions("projection",
		func() (*x509.CertPool, error) { return anchor, nil },
		func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			leafAsked = true
			return &tls.Certificate{}, nil
		})
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
	// The three readers sdk-go#51 takes in place of a pool by value, each
	// asked DURING the handshake. Checking that they are wired AND that they
	// answer from this boot's own material, because a reader that answers from
	// somewhere else is the defect a pool-by-value could not have.
	if options.TrustAnchor == nil {
		t.Fatal("the mint client is configured with no trust-anchor reader, so the anchor is whatever it was when the client was built and a removed root never stops this process dialling the mint")
	}
	if pool, err := options.TrustAnchor(); err != nil || pool != anchor {
		t.Errorf("the mint's trust-anchor reader answered (%v, %v), want this boot's own pool: the endpoint receiving the projected service-account token is verified against something else", pool, err)
	}
	if options.ClientCertificate == nil {
		t.Fatal("the mint client presents no certificate, so the projected service-account token is the whole of what attests which workload is asking")
	}
	if _, err := options.ClientCertificate(); err != nil {
		t.Errorf("the mint's certificate reader refused: %v", err)
	}
	if !leafAsked {
		t.Error("the mint's certificate reader does not come from this runtime's one long-lived reloader, so a rotated leaf is not what gets presented")
	}
	if options.AdmittedPeers == nil {
		t.Fatal("the mint client admits any peer the anchor signed, and every workload in the trust domain holds one of those: authentication is not authorisation")
	}
	peers, err := options.AdmittedPeers()
	if err != nil {
		t.Fatalf("the mint's admitted-peer reader refused: %v", err)
	}
	if len(peers) == 0 || peers[0] != testGatewayPrincipal {
		t.Errorf("the mint admits %v, want the provisioned %q from MINT_PEERS_FILE", peers, testGatewayPrincipal)
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
	header.Set(orgHeader, "org-1")
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

// takeListener gives the server the listener bootIdentity bound, if there is
// one. A test that provisioned its environment some other way gets nil and the
// boot binds for itself.
func takeListener(server *Server) *Server {
	if parkedListener != nil {
		server.boundListener = parkedListener
		parkedListener = nil
	}
	return server
}

// listenOn binds a listener for this server and returns its port, for a test
// that drives listen() directly rather than booting.
func listenOn(t *testing.T, server *Server) string {
	t.Helper()
	ln, port := boundPort(t)
	server.boundListener = ln
	return port
}

// TestAHandlerCannotRewriteTheIdentityThisConnectionWasAdmittedAs is R8-2,
// reproduced on a booted listener over mTLS.
//
// The pin used to be recorded on the recheck's first tick, a second after the
// connection was accepted. I wrote that the window was sound because "no
// in-process hook can run inside it". That was false: a RequestHandler is an
// in-process hook, it is handed r.TLS, and a tls.ConnectionState shares its
// certificates with the connection. A handler rewriting
// PeerCertificates[0].Raw inside that first second had the pin record the
// rewritten identity, and a caller removed from the admitted set went on being
// served on that connection.
//
// The identity is recorded at the first http.StateActive now, which net/http
// calls after reading a request and before ServeHTTP — ahead of any author
// code, on the first request and every one after.
func TestAHandlerCannotRewriteTheIdentityThisConnectionWasAdmittedAs(t *testing.T) {
	const survivor = "spiffe://codefly.test/ns/platform/sa/somebody-else"
	mint := newHostMint(t, &hostMint{})
	var (
		swapped atomic.Bool
		forged  *x509.Certificate
	)

	server := New(Manifest{ID: testSolutionID}).
		HandleRequest("/thing", func(r *http.Request, _ *Gateway) (any, error) {
			// What a hostile or merely careless handler can reach: the parsed
			// chain behind r.TLS, which is the connection's own.
			if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
				// Forged to the identity that will REMAIN admitted after the
				// withdrawal below, and issued under the anchor this listener
				// verifies against.
				//
				// Rewriting to an identity nobody admits proves nothing: the
				// recheck closes such a connection whichever object it read,
				// so a test doing that passes without the fix. The attack is
				// to name the identity that survives the change.
				r.TLS.PeerCertificates[0].Raw = forged.Raw
				r.TLS.PeerCertificates[0].URIs = forged.URIs
				swapped.Store(true)
			}
			return map[string]string{"ok": "yes"}, nil
		})
	solution := boot(t, server, mint)
	forged = parsedLeaf(t, solution.cell.identity(t, survivor))
	provisioned := os.Getenv(IdentityAllowedCallersFileEnvironmentVariable)
	if provisioned == "" {
		t.Fatal("the boot resolved no allowed-callers path, so this test cannot withdraw admission")
	}

	call := func() error {
		request, err := http.NewRequest(http.MethodGet, solution.base+"/thing", nil)
		if err != nil {
			return err
		}
		// The viewer's bearer, because the route gate answers 401 without one
		// and the handler never runs — which is how the first version of this
		// test "passed" while exercising nothing.
		request.Header.Set("authorization", viewerBearer())
		resp, err := solution.client.Do(request)
		if err != nil {
			return err
		}
		drainAndClose(resp)
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("the solution answered %d", resp.StatusCode)
		}
		return nil
	}

	// One request, which runs the handler and lets it rewrite the chain. The
	// pin was taken before that handler ran.
	if err := call(); err != nil {
		t.Fatalf("an admitted caller was refused: %v", err)
	}
	if !swapped.Load() {
		t.Fatal("the handler never saw a peer chain, so this test exercised nothing")
	}

	// The caller is withdrawn. Whatever the handler wrote, the connection is
	// held to the identity it was admitted as, so the recheck must close it.
	writeFile(t, provisioned, survivor+"\n")

	deadline := time.Now().Add(6 * inboundTrustRecheckInterval)
	for time.Now().Before(deadline) {
		if err := call(); err != nil {
			return // closed, which is the point
		}
		time.Sleep(inboundTrustRecheckInterval / 10)
	}
	t.Fatalf("a de-admitted caller was still served %s after its identity was withdrawn: a handler rewrote the chain the recheck reads, and the identity the connection was admitted as has to be recorded before any handler runs",
		6*inboundTrustRecheckInterval)
}

// TestTheListenerDoesNotNegotiateHTTP2 pins the assumption the recheck's pin
// rests on.
//
// net/http calls the ConnState hook with StateActive before ServeHTTP for
// HTTP/1.x, and passes skipHooks for HTTP/2 — so under h2 the pin would never
// be taken at a request and would fall back to the recheck's first tick, which
// is the window R8-2 exploited. Nothing negotiates h2 here: the served
// configuration advertises no ALPN protocol and serve() uses Serve rather than
// ServeTLS, which is what would configure HTTP/2.
//
// If that changes, this fails rather than the pin quietly stopping happening.
func TestTheListenerDoesNotNegotiateHTTP2(t *testing.T) {
	c := newCell(t)
	certFile, keyFile, bundleFile, _, _ := c.workload(t, testPrincipal)
	server := New(Manifest{ID: testSolutionID})
	server.cfg = config{identityCertFile: certFile, identityKeyFile: keyFile, trustBundleFile: bundleFile,
		allowedCallersFile: identitiesFile(t, testGatewayPrincipal)}
	server.principal = testPrincipal
	config, err := server.serverIdentity()
	if err != nil {
		t.Fatalf("serverIdentity: %v", err)
	}
	for _, proto := range config.NextProtos {
		if proto == "h2" {
			t.Fatal("the listener advertises h2: net/http skips the StateActive ConnState hook for HTTP/2, so the identity a connection was admitted as would no longer be recorded before a handler runs — move the pin before enabling it")
		}
	}
}

// TestABootedRenewalToAnotherExecutionEndsTheProcess is B3: the renewal
// evidence for R9-1, driven through a real boot and the real mint client
// rather than by calling the wrapper directly.
//
// The unit tests prove authorityHeldSource refuses a renewal sealed to no
// execution or to a different one. They do not prove the booted runtime
// classifies that refusal as terminal, stops serving, and ends — which is the
// behaviour an orchestrator depends on and the thing a wrapper test cannot
// see. The executed round validated these in scratch; they belong here.
//
// The issuer answers correctly for the first credential and switches shape
// afterwards. A credential whose whole remaining lifetime sits inside the
// renewal lead cannot be installed at all (the SDK floors that lead at five
// seconds), so the TTL is just above it: the first install succeeds and the
// next ask renews.
func TestABootedRenewalToAnotherExecutionEndsTheProcess(t *testing.T) {
	for _, tc := range []struct {
		name  string
		after *hostMint
	}{
		{"a renewal sealing no execution", &hostMint{executionFree: true}},
		{"a renewal sealing a different build", &hostMint{incarnation: 99}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// The TTL sets the margin between the boot and the renewal, and
			// six seconds was not a margin at all.
			//
			// The SDK floors the renewal lead at five seconds
			// (minRenewalLeadTime), so a six-second credential is due for
			// renewal ONE second after it is issued. The control call below
			// has to land before that, and on a loaded CI runner the boot —
			// cert generation, the TLS listener, the first mint — does not
			// finish within a second, so the control call itself triggered the
			// renewal, the switched issuer answered it, the process went
			// terminal mid-request and the control saw a closed connection.
			// It failed in CI with "the route answered 0 before any renewal"
			// and passes six times out of six locally, which is what a margin
			// that depends on machine speed looks like.
			//
			// Twelve seconds puts the renewal at ~7s and leaves the control
			// call seven seconds of room. The wall-clock cost is the price of
			// a test that does not depend on the boot being fast.
			mint := newHostMint(t, &hostMint{
				ttl:         12 * time.Second,
				switchAfter: 1,
				switchTo:    tc.after,
			})
			var ran atomic.Bool
			solution := boot(t, New(Manifest{ID: testSolutionID}).
				HandleRequest("/thing", func(*http.Request, *Gateway) (any, error) {
					ran.Store(true)
					return map[string]string{"ok": "yes"}, nil
				}), mint)

			// call reports the status, or 0 with the reason the request did
			// not complete. The reason is carried rather than swallowed: this
			// test read a bare 0 as "the listener is gone", and a 0 is also
			// what a refused handshake, a closed connection mid-request and a
			// not-yet-bound port look like — so the one failure this test hit
			// in CI reported only "answered 0" and said nothing about why.
			call := func() (int, error) {
				request, err := http.NewRequest(http.MethodGet, solution.base+"/thing", nil)
				if err != nil {
					t.Fatal(err)
				}
				request.Header.Set("authorization", viewerBearer())
				resp, err := solution.client.Do(request)
				if err != nil {
					return 0, err
				}
				defer drainAndClose(resp)
				return resp.StatusCode, nil
			}

			// The control: the first credential is sound and the route serves.
			if got, err := call(); got != http.StatusOK {
				t.Fatalf("the route answered %d (%v) before any renewal, so nothing below is about the renewal", got, err)
			}
			if !ran.Load() {
				t.Fatal("the handler never ran on the first call")
			}
			ran.Store(false)

			// Past the renewal lead, every ask renews — and the issuer has
			// changed shape.
			//
			// THE ROUTE REFUSING IS NOT THE ASSERTION. This test returned on
			// the first 503 or the first transport error, and a reviewer was
			// right that a runtime refusing the request and then serving 503
			// forever satisfied it — as would an unrelated transient renewal
			// failure, and a transport error was being read as proof the
			// listener had disappeared when it proves only that one request
			// did not complete. Worse, cleanup stops the server itself, so
			// "the process ended" was never observed at all.
			//
			// So the refusal is a waypoint, and what is asserted is: the
			// handler did not run on the refused call, serve returned BY
			// ITSELF, and it returned the terminal reason.
			refused := false
			deadline := time.Now().Add(20 * time.Second)
			for time.Now().Before(deadline) {
				// Reset per call, not once: a call made while the FIRST
				// credential is still valid runs the handler legitimately, so
				// the question is whether the handler ran on the call that was
				// refused — not whether it ran at all during the wait.
				ran.Store(false)
				status, _ := call()
				if status == http.StatusServiceUnavailable || status == 0 {
					if ran.Load() {
						t.Error("the handler ran on the refused call: the refusal has to come before anything author-written")
					}
					refused = true
					break
				}
				time.Sleep(200 * time.Millisecond)
			}
			if !refused {
				t.Fatalf("the route was still answering 200 twenty seconds after the issuer began sealing a different execution: a renewal that replaces this execution is terminal, so the process stops serving and ends for the orchestrator")
			}

			// And the process ends, by itself, with the reason.
			//
			// This is what an orchestrator depends on: a pod that refuses
			// every request but stays up is reported healthy by its
			// supervisor and keeps a routable endpoint, which is the exact
			// failure the health/terminal coupling exists to prevent.
			err, done := solution.ended(20 * time.Second)
			if !done {
				t.Fatal("serve was still running twenty seconds after the renewal was refused: the process refuses every request and never exits, so the orchestrator never restarts it and the host keeps routing to a binding this process has no authority for")
			}
			if err == nil {
				t.Fatal("serve returned without reporting why: the orchestrator restarts against a judgement, so the reason is what it has to be given")
			}
			// The terminal reason, not any error: an unrelated transient
			// failure ending the process would satisfy a nil check and is the
			// crash loop ErrMintUnavailable must never cause.
			if !errors.Is(err, workcontext.ErrMintRefused) {
				t.Errorf("serve ended with %v, which does not wrap ErrMintRefused: a transient answer must not end this process, and only a terminal one may", err)
			}
			if !strings.Contains(err.Error(), "execution") {
				t.Errorf("serve ended with %q, which does not say the execution was replaced", err)
			}
		})
	}
}

// TestTheMintsAnchorIsPassedAsAReaderNotASnapshot is the narrow thing this
// runtime owns about the mint's anchor.
//
// Re-reading it per handshake is the SDK's behaviour and cannot be mutated from
// here. What IS this runtime's is passing the READER through rather than
// resolving it once and handing over the answer — and a mutant that captures
// the pool at construction is invisible to every test that only asks the
// reader what it says now, including the configuration test above.
//
// So the reader's answer is changed between calls, which is what a rotation
// looks like from the SDK's side.
func TestTheMintsAnchorIsPassedAsAReaderNotASnapshot(t *testing.T) {
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

	first, second := x509.NewCertPool(), x509.NewCertPool()
	second.AddCert(mint.Certificate())
	rotated := false
	options := server.mintOptions("projection",
		func() (*x509.CertPool, error) {
			if rotated {
				return second, nil
			}
			return first, nil
		},
		func(*tls.CertificateRequestInfo) (*tls.Certificate, error) { return &tls.Certificate{}, nil })

	if got, _ := options.TrustAnchor(); got != first {
		t.Fatal("the mint's trust-anchor reader does not answer from the reader this runtime passed")
	}
	rotated = true
	got, err := options.TrustAnchor()
	if err != nil {
		t.Fatalf("the mint's trust-anchor reader refused after the rotation: %v", err)
	}
	if got == first {
		t.Error("the mint's trust-anchor reader still answers the pool it first returned: the anchor was resolved once and the ANSWER handed over, so the SDK re-reading per handshake re-reads a snapshot and a removed root never stops this process dialling the endpoint that receives the projected service-account token")
	}
	if got != second {
		t.Errorf("the mint's trust-anchor reader answered %v, want the rotated pool", got)
	}
}
