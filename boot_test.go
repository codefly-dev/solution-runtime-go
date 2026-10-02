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
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/codefly-dev/core/solution/manifest"
	codefly "github.com/codefly-dev/sdk-go"
	"github.com/codefly-dev/sdk-go/workcontext"
)

// The authority-bearing values every test in this package boots under. They are
// one set on purpose: the SDK pins an authority-bearing value process-wide at
// the first read, so two tests reading the same name with different values
// would have the second refused as a value that drifted — which is the
// behaviour, not a test defect.
const (
	testPrincipal          = "spiffe://test/ns/solutions/sa/lastlogin"
	testAudience           = "lastlogin-go"
	testProjectionAudience = "accounts"
	testInstallation       = "inst-7"
	testBuildIncarnation   = "sha256:" + "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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
	signer *workcontext.WorkContextSigner

	// status, when non-zero, is answered instead of a credential: 403 for a
	// workload the host refuses, 503 for an issuer that has nothing to mint
	// against yet.
	status int
	// recoverAfter, when positive, is how many times status is answered before
	// the host starts issuing: an issuer catching up with a presence
	// generation that has just been applied.
	recoverAfter int64
	// ttl is how long the credential it issues is valid.
	ttl time.Duration

	mints int64
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
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mint.signer, err = workcontext.NewWorkContextSigner(workcontext.WorkContextSignerOptions{
		Issuer: "test-host", KeyID: "test-key", PrivateKey: key,
	})
	if err != nil {
		t.Fatal(err)
	}
	if mint.ttl == 0 {
		// The signer caps a Work Context's lifetime at 15 minutes, so a
		// credential is short-lived by construction and renewal is ordinary.
		mint.ttl = 10 * time.Minute
	}
	mint.Server = httptest.NewServer(http.HandlerFunc(mint.serve))
	t.Cleanup(mint.Close)
	return mint
}

func (m *hostMint) serve(w http.ResponseWriter, r *http.Request) {
	atomic.AddInt64(&m.mints, 1)
	m.presented = append(m.presented, r.Header.Get("authorization"))
	m.headers = append(m.headers, r.Header.Clone())
	// recoverAfter 0 means this host never issues; a positive one means it
	// issues once that many asks have been answered with status.
	if m.status != 0 && (m.recoverAfter == 0 || atomic.LoadInt64(&m.mints) <= m.recoverAfter) {
		w.WriteHeader(m.status)
		return
	}
	token, _, err := m.signer.StartTask(workcontext.StartTaskInput{
		Audience:           testAudience,
		TenantID:           "tenant",
		OwnerPrincipalID:   testPrincipal,
		OwnerPrincipalKind: "service",
		TaskID:             fmt.Sprintf("task-%d", atomic.LoadInt64(&m.mints)),
		SessionID:          "session-workload",
		Seal: workcontext.Seal{
			PrincipalEpoch:       1,
			InstallationID:       testInstallation,
			InstallationRevision: 3,
			BuildIncarnation:     testBuildIncarnation,
		},
		TTL: m.ttl,
	})
	if err != nil {
		m.signErr = err
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"work_context": token.Encoded()})
}

func (m *hostMint) count() int64 { return atomic.LoadInt64(&m.mints) }

// workloadIdentity writes an X.509 leaf and key the way the platform projects
// them, and returns their paths plus the pool a client verifies the listener
// with.
func workloadIdentity(t *testing.T) (certFile, keyFile string, roots *x509.CertPool) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "solution"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		IsCA:         true,
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile = filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	writeFile(t, certFile, string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))
	writeFile(t, keyFile, string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})))
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots = x509.NewCertPool()
	roots.AddCert(leaf)
	return certFile, keyFile, roots
}

// booted is a solution serving on an ephemeral port, with the client that
// trusts its workload identity.
type booted struct {
	server *Server
	base   string
	client *http.Client
	mint   *hostMint
}

// boot runs the whole boot a deployed solution runs — configuration, the
// contract, the one mint, the TLS listener — on an ephemeral port.
func boot(t *testing.T, server *Server, mint *hostMint) *booted {
	t.Helper()
	certFile, keyFile, roots := workloadIdentity(t)
	authorityValues(t)
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected-token")

	t.Setenv("PORT", freePort(t))
	t.Setenv("GATEWAY_URL", mint.URL)
	t.Setenv(CredentialMintURLEnvironmentVariable, mint.URL)
	t.Setenv(ProjectedTokenFileEnvironmentVariable, tokenFile)
	t.Setenv(IdentityCertFileEnvironmentVariable, certFile)
	t.Setenv(IdentityKeyFileEnvironmentVariable, keyFile)
	t.Setenv(ContractProfileEnvironmentVariable, localProfile)
	t.Setenv("ASSETS_DIR", t.TempDir())

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
		client: &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}},
		mint:   mint,
	}
}

// TestBootMintsExactlyOnceAndServesOverTLS is the acceptance criterion of this
// runtime's whole boot: one mint per process start, zero registrations over any
// interval, and a listener that answers only over TLS.
func TestBootMintsExactlyOnceAndServesOverTLS(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	solution := boot(t, New(Manifest{ID: "lastlogin-go", Title: "Last Login"}).
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

// TestUnauthenticatedCallIsRefusedNotProxied keeps the boot's serving contract:
// a handler call with no bearer is a 401 from this runtime, never a 502 from
// something downstream.
func TestUnauthenticatedCallIsRefusedNotProxied(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	solution := boot(t, New(Manifest{ID: "lastlogin-go"}).
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
	server := New(Manifest{ID: "lastlogin-go"}).
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
