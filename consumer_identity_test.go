package solution

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/codefly-dev/core/resources"
	codefly "github.com/codefly-dev/sdk-go"
)

// testModule is the module every test in this package runs as, pinned once for
// the process the way a Codefly flow pins a service's: the SDK refuses every
// endpoint query until Init has pinned the consumer, and a pin cannot be moved
// afterwards, so there is exactly one for the whole binary. Neutral for the
// same reason testSolutionID is.
const testModule = "widgets"

// TestMain identifies the test process to the SDK before anything resolves.
//
// Not a convenience: since sdk-go v0.3.1 an unpinned process resolves no
// endpoint at all, so without this every test that reads an address would be
// asserting on a refusal it never asked about. The boot pins it too — start()
// calls Init — and that path is what TestABootThatNamesNoModuleIsRefused
// drives.
func TestMain(m *testing.M) {
	if err := os.Setenv(resources.ModulePrefix, testModule); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err := codefly.Init(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "codefly.Init for the test process: %v\n", err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// TestABootThatNamesNoModuleIsRefused: a process the SDK cannot identify does
// not serve, and the refusal says why rather than naming the first endpoint
// that came back empty.
//
// The boot used to call LoadEnvironmentVariables and nothing else. Against
// sdk-go v0.3.1 and later that resolves no endpoint — the gateway, the
// frontend and this service's own port all come back empty — and validate()
// then sent the operator to inspect endpoint provisioning for a variable that
// is not an endpoint at all.
func TestABootThatNamesNoModuleIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name, module string
	}{
		// The process is already pinned to testModule, so an unset carrier
		// is the SDK's drift refusal here; in a fresh process it is
		// ErrConsumerNotIdentified. Both are the same refusal to this boot.
		{"no module named", ""},
		{"a module other than the one this process was pinned to", "someone-else"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(resources.ModulePrefix, tc.module)
			// Every endpoint overridden, so nothing else can be the reason.
			t.Setenv("PORT", "8443")
			t.Setenv("GATEWAY_URL", "https://gateway.cell")
			t.Setenv(CredentialMintURLEnvironmentVariable, "https://gateway.cell"+credentialMintPath)
			t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })

			_, initErr := codefly.Init(context.Background())
			if initErr == nil {
				t.Fatal("codefly.Init accepted a process naming no module, or another one: the SDK's contract this boot relies on has changed")
			}
			cfg := loadConfig(context.Background(), testSolutionID, initErr)
			if cfg.environmentLoadErr != nil {
				t.Errorf("an identity refusal was filed as an environment load failure: %v", cfg.environmentLoadErr)
			}
			err := cfg.validate()
			if err == nil {
				t.Fatal("validate() accepted a boot the SDK could not identify")
			}
			if !strings.Contains(err.Error(), resources.ModulePrefix) {
				t.Errorf("the refusal does not name %s, the variable that fixes it: %v", resources.ModulePrefix, err)
			}
			if !errors.Is(err, resources.ErrConsumerNotIdentified) && !errors.Is(err, codefly.ErrAuthorityValueChanged) {
				t.Errorf("the refusal dropped the SDK's sentinel: %v", err)
			}
		})
	}
}

// TestTheBootIdentifiesItselfToTheSDK drives the same refusal through start(),
// with every other value a boot needs in place and every endpoint overridden.
//
// That is what makes it a test of the boot rather than of validate(): with the
// addresses overridden, a boot that only loaded the carriers — what start()
// did before it called Init — would come up, because nothing it reads in this
// test goes through endpoint resolution. It must not: the SDK's contract is
// that a process failing Init does not serve.
func TestTheBootIdentifiesItselfToTheSDK(t *testing.T) {
	mint := newHostMint(t, &hostMint{})
	t.Setenv(resources.ModulePrefix, "")
	t.Cleanup(func() { _ = codefly.LoadEnvironmentVariables() })

	err := bootFails(t, New(Manifest{ID: testSolutionID}), mint)
	if !strings.Contains(err.Error(), resources.ModulePrefix) {
		t.Errorf("the boot was refused, but not for naming no module: %v", err)
	}
	mint.mu.Lock()
	reached := len(mint.paths)
	mint.mu.Unlock()
	if got := reached; got != 0 {
		t.Errorf("the boot reached the mint %d time(s) before refusing: a process the SDK cannot identify must not present its projected token anywhere", got)
	}
}
