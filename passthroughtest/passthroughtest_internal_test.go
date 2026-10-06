package passthroughtest

import (
	"strings"
	"testing"
)

// TestTheSeamRefusesANonTestBinary is the behavioural half of the seam's gate.
//
// This package is importable by any module — unlike internal/seam, which Go
// keeps inside this one — so Handler and Start were an exported, production
// reachable path to a handler holding a real execution credential, having
// skipped validate(), the mTLS boot, the caller allow-list, the ceiling and
// authenticated outbound. Taking a testing.TB does not prevent that: the
// unexported method stops a type declaring the interface, not one embedding
// it, so a few lines of production code satisfy it.
func TestTheSeamRefusesANonTestBinary(t *testing.T) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("the seam did not refuse a non-test binary: a deployment importing this package builds a credential-bearing handler with none of the boot behind it")
		}
		message, ok := recovered.(string)
		if !ok {
			t.Fatalf("the refusal panicked with %T, which says nothing to whoever hits it", recovered)
		}
		for _, named := range []string{"test binary", "credential", "solution.Serve"} {
			if !strings.Contains(message, named) {
				t.Errorf("the refusal does not mention %q, so it does not say what was wrong or what to do instead: %s", named, message)
			}
		}
	}()
	refuseOutsideTest(false)
}

// And it does not refuse the only callers it has. Every legitimate use of this
// package is a test, which is what makes testing.Testing() the right gate here
// and the wrong one for the root package.
func TestTheSeamAdmitsATestBinary(t *testing.T) {
	refuseOutsideTest(true)
	if !testing.Testing() {
		t.Fatal("testing.Testing() is false inside a test, so the gate this package relies on does not mean what it is used for")
	}
}
