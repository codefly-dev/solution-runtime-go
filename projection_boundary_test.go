package solution

import (
	"context"
	"strings"
	"testing"

	"github.com/codefly-dev/core/solution/manifest"
)

// --- The api.consumes projection is judged at boot, whatever is declared ---
//
// The projection is resolved in loadConfig, and used to be decoded only by the
// code that consumes it. That code returns early for a solution declaring no
// passthrough, so one undecodable value had two answers: refused for a
// solution with a declaration, accepted and served for one without. Resolving
// a value at boot is not the same as judging it, and this is where the second
// half is pinned.

// projectionOf is the projection a composition emits for one consumed target.
func projectionOf(as string) string {
	return `[{"id":"things.` + as + `","module":"things","service":"` + as +
		`","endpoint":"rest","protocol":"rest","as":"` + as + `"}]`
}

// bootableEnvironment sets what loadConfig needs for validate() to get as far
// as the projection, so a test that changes the projection sees validate()
// judge the projection rather than the first unresolved value beside it.
func bootableEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("PORT", "8090")
	t.Setenv("GATEWAY_URL", "https://gateway.cell.test:42152")
	t.Setenv(CredentialMintURLEnvironmentVariable, "https://mint.cell.test/mint")
	t.Setenv(ContractProfileEnvironmentVariable, "test")
	t.Setenv("CODEFLY__RUNTIME_CONTEXT", "")
}

// bootConfig is the config a boot resolves in that environment, asserted to be
// otherwise valid so each case below turns on its projection alone.
func bootConfig(t *testing.T, projection string) config {
	t.Helper()
	bootableEnvironment(t)
	t.Setenv(manifest.APIConsumesEnvironmentVariable, projection)
	return loadConfig(context.Background(), "solution-under-test", nil)
}

// TestProjectionIsRefusedBeforeServingWhateverIsDeclared: a projection that
// will not decode fails the boot, with no passthrough declared — the case that
// used to reach no check at all.
func TestProjectionIsRefusedBeforeServingWhateverIsDeclared(t *testing.T) {
	// A control first: the same environment with a good projection must boot,
	// or every refusal below could be about something else entirely.
	if err := bootConfig(t, projectionOf("things")).validate(); err != nil {
		t.Fatalf("the test environment does not boot with a usable projection, so no refusal below can be attributed to the projection: %v", err)
	}

	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"truncated json", `[{"id":"a","module":"m"`},
		{"an object where a list belongs", `{"as":"things"}`},
		{"a scalar", `5`},
		{"a field of the wrong type", `[{"as":5}]`},
		{"not json at all", `nope`},
		{"a trailing comma", `[{"as":"things"},]`},
		{"two documents", `[] []`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := bootConfig(t, tc.raw).validate()
			if err == nil {
				t.Fatalf("validate() accepted the projection %q: a value nothing decodes is a value nothing refuses", tc.raw)
			}
			// The refusal has to name what to go and fix. The projection is
			// the composition's output, not an operator's setting, so the
			// variable carrying it is the only handle there is.
			if !strings.Contains(err.Error(), manifest.APIConsumesEnvironmentVariable) {
				t.Errorf("refusal does not name %s: %v", manifest.APIConsumesEnvironmentVariable, err)
			}
		})
	}
}

// And the inverse. A solution that consumes nothing is the common case and
// must be unaffected, and whitespace means "nothing" rather than "malformed" —
// refusing a render's bare newline would fail a boot over nothing.
func TestAUsableOrAbsentProjectionIsNotRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"unset", ""},
		{"whitespace only", "  \n "},
		{"an empty list", `[]`},
		{"json null", `null`},
		{"one target", projectionOf("things")},
		{"several targets", `[{"id":"a.b","module":"a","service":"b","endpoint":"rest","protocol":"rest","as":"b"},` +
			`{"id":"c.d","module":"c","service":"d","endpoint":"rest","protocol":"rest","as":"d"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := bootConfig(t, tc.raw)
			if cfg.apiConsumesErr != nil {
				t.Fatalf("projection %q did not decode: %v", tc.raw, cfg.apiConsumesErr)
			}
			if err := cfg.validate(); err != nil {
				t.Fatalf("validate() refused the usable projection %q: %v", tc.raw, err)
			}
		})
	}
}

// TestADeclaredPassthroughIsCheckedAgainstTheProjection proves the agreement
// check itself, on a declaration that is otherwise valid.
//
// The earlier version of this test declared a module with no methods, which
// resolvePassthrough refuses before any projection is consulted — and that
// refusal happened to contain the alias the assertion looked for, so the test
// passed without the agreement check running at all. Removing the check left
// it green. Both directions are asserted here, from one declaration that
// differs only in whether the projection lists it.
func TestADeclaredPassthroughIsCheckedAgainstTheProjection(t *testing.T) {
	declared := passthroughModule() // valid: an as, scopes, and a resolvable method

	t.Run("listed in the projection", func(t *testing.T) {
		s := New(Manifest{ID: "solution-under-test", Title: "Solution Under Test"})
		s.consumed = []ConsumedModule{declared}
		s.cfg = bootConfig(t, projectionOf(declared.As))
		if _, err := s.validatePassthrough(); err != nil {
			t.Fatalf("a declared module the projection lists was refused: %v", err)
		}
	})

	t.Run("absent from the projection", func(t *testing.T) {
		s := New(Manifest{ID: "solution-under-test", Title: "Solution Under Test"})
		s.consumed = []ConsumedModule{declared}
		s.cfg = bootConfig(t, projectionOf("something-else"))
		_, err := s.validatePassthrough()
		if err == nil {
			t.Fatal("a declared module absent from the projection was accepted")
		}
		// Specifically the agreement refusal, not resolvePassthrough's: the
		// declaration above is valid, so nothing earlier can refuse it, and
		// the message has to be the one about api.consumes.
		if !strings.Contains(err.Error(), "api.consumes") || !strings.Contains(err.Error(), declared.As) {
			t.Errorf("refusal is not the projection-agreement one: %v", err)
		}
	})
}

// TestTheSeamJudgesItsOwnProjection: the test seam supplies the projection
// instead of resolving it, so it decodes there what loadConfig decodes at a
// boot — otherwise a consumer's test would accept what a boot refuses.
//
// The refusal must be the DECODE refusal. Asserting only that an error came
// back proved nothing: with the seam's decode removed, the projection is
// simply empty, the declared module is then absent from it, and the agreement
// check refuses — a different refusal, for a different reason, that this test
// happily counted as success. A mutation that deleted the decode left it
// green, which is the defect it now fails on.
func TestTheSeamJudgesItsOwnProjection(t *testing.T) {
	s := New(Manifest{ID: "solution-under-test", Title: "Solution Under Test"})
	s.consumed = []ConsumedModule{passthroughModule()}
	_, err := passthroughSeam(s, "https://gateway.cell.test", `{"not":"a list"}`)
	if err == nil {
		t.Fatal("the seam accepted a projection a boot would refuse")
	}
	if !strings.Contains(err.Error(), "cannot be checked against api.consumes") {
		t.Errorf("the seam refused for some other reason than the projection failing to decode: %v", err)
	}
}

// And the seam accepts the projection it should: the same declaration, listed.
// Without this, the test above is satisfied by a seam that refuses everything.
func TestTheSeamAcceptsAProjectionThatListsTheDeclaration(t *testing.T) {
	s := New(Manifest{ID: "solution-under-test", Title: "Solution Under Test"})
	s.consumed = []ConsumedModule{passthroughModule()}
	if _, err := passthroughSeam(s, "https://gateway.cell.test", projectionOf(passthroughModule().As)); err != nil {
		t.Fatalf("the seam refused a projection that lists the declared module: %v", err)
	}
}
