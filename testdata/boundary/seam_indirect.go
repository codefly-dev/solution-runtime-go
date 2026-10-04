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
func Routes() (http.Handler, error) { return helper() }
func helper() (http.Handler, error) { return seam.Passthrough(nil, "", "") }
