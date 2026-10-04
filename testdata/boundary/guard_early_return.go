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
func Routes(skip bool) (http.Handler, error) {
	if skip {
		return seam.Passthrough(nil, "", "")
	}
	mustBeATest()
	return seam.Passthrough(nil, "", "")
}
