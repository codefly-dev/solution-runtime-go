package solution

import (
	"go/types"
	"testing"

	"golang.org/x/tools/go/packages"
)

func TestZZLoad(t *testing.T) {
	cfg := &packages.Config{Mode: packages.NeedName | packages.NeedSyntax | packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedImports}
	pkgs, err := packages.Load(cfg, ".", "./passthroughtest")
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pkgs {
		t.Logf("%s types=%v errors=%d syntax=%d", p.PkgPath, p.Types != nil, len(p.Errors), len(p.Syntax))
		for _, e := range p.Errors[:min(2, len(p.Errors))] {
			t.Logf("   err: %v", e)
		}
	}
	// can we resolve the SDK alias to core's generated type?
	for _, p := range pkgs {
		if p.Types == nil {
			continue
		}
		for _, imp := range p.Types.Imports() {
			if imp.Path() == "github.com/codefly-dev/sdk-go/workcontext" {
				o := imp.Scope().Lookup("SealedValues")
				t.Logf("SealedValues -> %s", types.TypeString(types.Unalias(o.Type()), nil))
				c := imp.Scope().Lookup("Claims")
				t.Logf("Claims       -> %s", types.TypeString(types.Unalias(c.Type()), nil))
			}
		}
	}
}
