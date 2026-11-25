//go:build !composition

package scenarios

import "testing"

// Every scenario here is behind the build tag `composition`. Without it the
// package would hold no test, and `go test` would say so and exit 0: a gate
// that ran nothing and passed. This is the test that exists without the tag.
func TestComposedScenariosNeedTheCompositionTag(t *testing.T) {
	t.Fatal("no scenario ran: this package is built with -tags composition (cd composed && make scenarios)")
}
