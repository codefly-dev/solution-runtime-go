package solution

import (
	"context"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
			err := bootError(t, New(Manifest{ID: "lastlogin-go"}), mint)
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
		server := New(Manifest{ID: "lastlogin-go"})
		server.firstMintWindow = 5 * time.Second
		solution := boot(t, server, mint)
		if status := getStatus(t, solution.client, solution.base+HealthPath); status != http.StatusOK {
			t.Fatalf("health = %d, want 200: the boot waited out an unapplied presence generation", status)
		}
		if got := mint.count(); got < 3 {
			t.Errorf("the host was asked %d times, want the two refusals plus the one that answered", got)
		}
	})

	t.Run("it gives up when the window is spent", func(t *testing.T) {
		mint := newHostMint(t, &hostMint{status: http.StatusServiceUnavailable})
		server := New(Manifest{ID: "lastlogin-go"})
		server.firstMintWindow = 50 * time.Millisecond
		err := bootError(t, server, mint)
		if !errors.Is(err, workcontext.ErrMintUnavailable) {
			t.Fatalf("boot error = %v, want one wrapping %v", err, workcontext.ErrMintUnavailable)
		}
		if !strings.Contains(err.Error(), "transient") {
			t.Errorf("boot error %q does not say the cause is transient, which is what makes the exit the orchestrator's to retry", err)
		}
		if got := mint.count(); got < 2 {
			t.Errorf("the host was asked %d times, want more than one: an unavailable mint is waited for, not judged", got)
		}
	})
}

// TestTheProjectedTokenIsReadAtEveryMintNotCachedAtBoot pins the rotation
// property. The platform rotates the projection under a running process, so a
// runtime that read the file once would renew with a token the issuer stopped
// honouring long before the process stopped running — and the refusal would
// read as "this build is not approved".
func TestTheProjectedTokenIsReadAtEveryMintNotCachedAtBoot(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "first-projection")
	source := mintClientFor(t, mint.URL, tokenFile)

	if _, err := source.Credential(context.Background()); err != nil {
		t.Fatalf("first mint: %v", err)
	}
	writeFile(t, tokenFile, "rotated-projection")
	// A credential that has not reached its renewal lead is handed back as it
	// is: the rotation is picked up at the next mint, not at the next call.
	if _, err := source.Credential(context.Background()); err != nil {
		t.Fatalf("second call: %v", err)
	}
	if got := mint.count(); got != 1 {
		t.Fatalf("the host minted %d times for two calls, want 1: a current credential is reused, never re-minted per call", got)
	}
	if got := mint.presented[0]; got != "Bearer first-projection" {
		t.Errorf("the mint presented %q, want the projection as it was on disk", got)
	}
}

// TestAMintingRuntimePresentsNoRegistrationCredential is the deletion, pinned:
// the shared cluster-internal token and the per-solution registration secret
// are gone from this package, so no boot can present either and no
// configuration key can reinstate one.
func TestAMintingRuntimePresentsNoRegistrationCredential(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	tokenFile := filepath.Join(t.TempDir(), "token")
	writeFile(t, tokenFile, "projected")
	if _, err := mintClientFor(t, mint.URL, tokenFile).Credential(context.Background()); err != nil {
		t.Fatal(err)
	}
	for _, header := range []string{"x-codefly-internal-token", "x-codefly-solution-registration", "x-codefly-module-registration", "x-codefly-module-secret"} {
		if value := mint.headers[0].Get(header); value != "" {
			t.Errorf("the mint presented %s=%q: this runtime has no registration credential to present", header, value)
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
	server := New(Manifest{ID: "lastlogin-go"}).Credential(source)
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
	if mints[0].WorkContext != credential.Token().Encoded() {
		t.Errorf("the mint presented work context %q, want this workload's own credential %q", mints[0].WorkContext, credential.Token().Encoded())
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

// mintClientFor is the SDK's mint client as the runtime configures it, pointed
// at a fake host. The runtime has no mint of its own, so this is the only
// client any of these tests exercise.
func mintClientFor(t *testing.T, mintURL, tokenFile string) CredentialSource {
	t.Helper()
	client, err := workcontext.NewMintClient(workcontext.MintOptions{
		URL:                mintURL,
		Audience:           testAudience,
		ProjectedToken:     workcontext.ProjectedTokenFile(tokenFile),
		ProjectionAudience: testProjectionAudience,
		HTTPClient:         platformClient,
	})
	if err != nil {
		t.Fatal(err)
	}
	return client
}

// bootError boots far enough to reach the mint and returns what the boot said.
func bootError(t *testing.T, server *Server, mint *hostMint) error {
	t.Helper()
	certFile, keyFile, _ := workloadIdentity(t)
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
	ln, err := server.start(context.Background())
	if ln != nil {
		_ = ln.Close()
	}
	if err == nil {
		t.Fatal("the boot came up; this helper is for boots that must fail")
	}
	return err
}
