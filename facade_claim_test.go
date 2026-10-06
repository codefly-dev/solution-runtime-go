package solution

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// --- A solution claims no module's facade route ---
//
// Two invariants (SA-F-GWREGISTRY):
//
//   - a facade route for a module is claimed only by the module that serves
//     it, under a credential bound to that module;
//   - a solution holds no credential that decides where another module's
//     traffic is routed.
//
// So the package carries neither a module route-claim surface nor a credential
// for one. That a given boot claims nothing is checked elsewhere, against a
// running server; what is checked here is that the capability is not present
// to be reached, which no single boot can show.
//
// The shapes are named by this test alone, because a test that cannot write a
// shape down cannot assert its absence.
var claimShapes = map[string]string{
	"/modules/_register":                   "the gateway's module route-claim path",
	"/modules/_registration-token":         "the exchange that credentials a module route claim",
	"X-Codefly-Module-Secret":              "the header carrying a module's route-claim secret",
	"X-Codefly-Module-Registration":        "the header carrying a module route-claim credential",
	"CODEFLY__MODULE_REGISTRATION_SECRETS": "the carrier delivering another module's route-claim secret",
}

// TestNoModuleFacadeClaimOnTheSDKSurface evaluates the package's constant
// string expressions and refuses any that is one of those shapes.
//
// It evaluates rather than matches text. A wire shape is the same shape
// however Go spells it — split across a concatenation, wrapped in parentheses,
// assembled from named constants declared elsewhere in the package, or any
// mixture — and a guard that compares source text is a guard against one
// spelling. Everything the compiler folds to a constant string is folded here
// the same way, then compared on the value.
//
// Folding also absorbs case and the separators inside these names, because
// those are free to move without changing what reaches the wire.
func TestNoModuleFacadeClaimOnTheSDKSurface(t *testing.T) {
	pkg := parseConstantExpressions(t)
	if len(pkg.values) == 0 {
		t.Fatal("no constant strings evaluated: this guard is inert")
	}

	var found []string
	for _, got := range pkg.values {
		for shape, what := range claimShapes {
			if strings.Contains(foldShape(got.value), foldShape(shape)) {
				found = append(found, got.where+": the expression evaluates to "+strconv.Quote(got.value)+
					", which is "+what+" ("+shape+")")
			}
		}
	}
	sort.Strings(found)
	for _, f := range found {
		t.Errorf("%s\na solution claims no module's facade route and holds no credential that could: routing is decided by the module that serves the route, under a credential bound to it", f)
	}
}

// constantString is one evaluated constant string expression and where it is.
type constantString struct {
	value string
	where string
}

// constantPackage is the package's constant strings: named, so an expression
// referring to one can be evaluated, and positional, so every expression that
// produces one can be reported where it is written.
type constantPackage struct {
	named  map[string]string
	values []constantString
}

// parseConstantExpressions evaluates every constant string expression in the
// package's non-test sources.
//
// Two passes, because a constant may be defined in terms of another and the
// files are read in directory order: the first resolves named constants to a
// fixpoint, the second evaluates every expression in the package against them.
func parseConstantExpressions(t *testing.T) constantPackage {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	fset := token.NewFileSet()
	var files []*ast.File
	for _, entry := range entries {
		name := entry.Name()
		// Test sources are exempt: the shapes are written down here on
		// purpose, which is what lets this assert their absence elsewhere.
		if filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, file)
	}
	if len(files) == 0 {
		t.Fatal("no package sources parsed: this guard is inert")
	}

	pkg := constantPackage{named: map[string]string{}}
	// Fixpoint: each round resolves the constants whose definitions became
	// evaluable in the last one, so `const a = b + "x"` resolves whatever
	// order the declarations appear in.
	for round := 0; round < 10; round++ {
		learned := 0
		for _, file := range files {
			for _, decl := range file.Decls {
				gen, ok := decl.(*ast.GenDecl)
				if !ok || gen.Tok != token.CONST {
					continue
				}
				for _, spec := range gen.Specs {
					value, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range value.Names {
						if i >= len(value.Values) {
							continue
						}
						if _, known := pkg.named[name.Name]; known {
							continue
						}
						if got, ok := pkg.evaluate(value.Values[i]); ok {
							pkg.named[name.Name] = got
							learned++
						}
					}
				}
			}
		}
		if learned == 0 {
			break
		}
	}

	// Every expression, not only the named ones: a claim is as likely to be
	// built inline at its call site as bound to a constant first.
	for _, file := range files {
		for _, decl := range file.Decls {
			ast.Inspect(decl, func(n ast.Node) bool {
				expr, ok := n.(ast.Expr)
				if !ok {
					return true
				}
				if got, ok := pkg.evaluate(expr); ok && got != "" {
					pkg.values = append(pkg.values, constantString{
						value: got,
						where: fset.Position(expr.Pos()).String(),
					})
					// The whole expression evaluated, so its parts add
					// nothing but noise.
					return false
				}
				return true
			})
		}
	}
	return pkg
}

// evaluate folds one expression to the constant string it produces, if it
// produces one: a literal, a parenthesised expression, a `+` of two such, or a
// name bound to one. Anything else — a call, a variable, a conversion — is not
// a constant and is reported as such rather than guessed at.
func (p constantPackage) evaluate(expr ast.Expr) (string, bool) {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind != token.STRING {
			return "", false
		}
		value, err := strconv.Unquote(e.Value)
		if err != nil {
			return "", false
		}
		return value, true
	case *ast.ParenExpr:
		return p.evaluate(e.X)
	case *ast.BinaryExpr:
		if e.Op != token.ADD {
			return "", false
		}
		left, okL := p.evaluate(e.X)
		right, okR := p.evaluate(e.Y)
		if !okL || !okR {
			return "", false
		}
		return left + right, true
	case *ast.Ident:
		value, ok := p.named[e.Name]
		return value, ok
	}
	return "", false
}

// foldShape removes what spelling may change without changing the wire shape:
// case, and the separators these paths, headers and carriers are punctuated
// with.
func foldShape(s string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(s) {
		switch r {
		case '-', '_', '/', '.', ' ', '\t':
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}
