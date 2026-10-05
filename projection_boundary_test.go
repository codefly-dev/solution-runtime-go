package solution

import (
	"context"
	"strings"
	"testing"

	"github.com/codefly-dev/core/solution/manifest"
)

// bootableEnvironment sets the carriers loadConfig needs to produce a config
// validate() accepts, so a test can change one value and see validate() judge
// that value rather than the first unresolved thing beside it.
func bootableEnvironment(t *testing.T) {
	t.Helper()
	t.Setenv("PORT", "8090")
	t.Setenv("GATEWAY_URL", "http://gateway:42152")
	t.Setenv("HOST_REGISTER_URL", "http://frontend:21931/api/solutions/register")
	t.Setenv("SELF_UPSTREAM", "http://backend.svc.cluster.local:8080")
	t.Setenv(SolutionRegistrationSecretEnvironmentVariable, "s3cret")
	t.Setenv("CODEFLY__RUNTIME_CONTEXT", "")
}

// TestProjectionIsRefusedBeforeServingWhateverIsDeclared proves the boot
// refuses a projection it cannot decode even when the solution declares no
// passthrough.
//
// The projection used to be parsed only by the code that consumed it, so the
// value reached no check at all on a solution that declared no Consumes: it
// booted, served, and was judged by nothing. validate() now decides it, which
// is what "resolved in loadConfig, checked in validate()" has to mean for a
// value to be covered by it.
func TestProjectionIsRefusedBeforeServingWhateverIsDeclared(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"truncated json", `[{"id":"a","module":"m"`},
		{"an object where a list belongs", `{"as":"documents"}`},
		{"a scalar", `5`},
		{"a field of the wrong type", `[{"as":5}]`},
		{"not json at all", `nope`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bootableEnvironment(t)
			t.Setenv(manifest.APIConsumesEnvironmentVariable, tc.raw)

			cfg := loadConfig(context.Background(), "solution-under-test")
			err := cfg.validate()
			if err == nil {
				t.Fatalf("validate() accepted the projection %q; a value nothing decodes is a value nothing refuses", tc.raw)
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

// And the inverse: a projection that decodes, or none at all, is not refused.
// A solution that consumes nothing is the common case and must be unaffected,
// and a render emitting whitespace for an unset value means "nothing", not
// "malformed" — refusing that would fail a boot over a newline.
func TestAUsableOrAbsentProjectionIsNotRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"unset", ""},
		{"whitespace only", "  \n "},
		{"an empty list", `[]`},
		{"json null", `null`},
		{"one target", consumesDocuments},
		{"several targets", `[{"id":"a.b","module":"a","service":"b","endpoint":"rest","protocol":"rest","as":"b"},` +
			`{"id":"c.d","module":"c","service":"d","endpoint":"rest","protocol":"rest","as":"d"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bootableEnvironment(t)
			t.Setenv(manifest.APIConsumesEnvironmentVariable, tc.raw)

			cfg := loadConfig(context.Background(), "solution-under-test")
			if cfg.apiConsumesErr != nil {
				t.Fatalf("projection %q did not decode: %v", tc.raw, cfg.apiConsumesErr)
			}
			if err := cfg.validate(); err != nil {
				t.Fatalf("validate() refused the usable projection %q: %v", tc.raw, err)
			}
		})
	}
}

// TestADeclaredPassthroughStillChecksAgainstTheProjection proves the boot
// check that was already there is unchanged: a declared module absent from the
// projection is still refused, and the refusal still names it.
func TestADeclaredPassthroughStillChecksAgainstTheProjection(t *testing.T) {
	bootableEnvironment(t)
	t.Setenv(manifest.APIConsumesEnvironmentVariable, consumesDocuments)

	s := New(Manifest{ID: "solution-under-test", Title: "Solution Under Test"})
	s.consumed = []ConsumedModule{{As: "nothing-consumes-this", ViewerBearer: true}}
	s.cfg = loadConfig(context.Background(), s.manifest.ID)

	_, err := s.validatePassthrough()
	if err == nil {
		t.Fatal("validatePassthrough() accepted a module the projection does not list")
	}
	if !strings.Contains(err.Error(), "nothing-consumes-this") {
		t.Errorf("refusal does not name the declared module: %v", err)
	}
}
