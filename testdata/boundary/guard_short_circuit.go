package passthroughtest

import (
	seam "github.com/codefly-dev/solution-runtime-go/internal/seam"
	"net/http"
	"testing"
)

func mustBeATest() { refuseOutsideTest(testing.Testing()) }
func refuseOutsideTest(isTest bool) {
	if !isTest {
		panic("test binary required")
	}
}
func helper() bool                  { mustBeATest(); return true }
func Routes() (http.Handler, error) { _ = false && helper(); return seam.Passthrough(nil, "", "") }
