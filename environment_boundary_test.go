package solution

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// retiredServeTimeRead named the one function that used to read the
// environment outside boot resolution: it parsed the consumed-API projection
// when the server started, so a malformed value disabled the consumed-module
// federation with a log line while the solution served on. It registered a
// facade route for each consumed module, which is not a solution's to claim,
// and went with that capability — so the exception it was went with it too.
const retiredServeTimeRead = "registerConsumedAPIs"

// AGENTS.md tells an agent that configuration is resolved in one place and
// refused at boot, with no exception. Prose cannot notice an exception
// appearing underneath it, and an agent-context file is followed literally, so
// the claim is pinned here: every environment read sits in loadConfig's call
// tree, where validate() governs the result.
func TestEnvironmentIsReadOnlyWhereAgentsFileSaysItIs(t *testing.T) {
	pkg := parsePackage(t)
	boot := pkg.reachableFrom("loadConfig")

	var undocumented []string
	for _, fn := range pkg.environmentReaders() {
		if !boot[fn] {
			undocumented = append(undocumented, fn)
		}
	}
	if len(undocumented) > 0 {
		t.Errorf("these functions read the environment outside loadConfig's call tree: %s\n"+
			"AGENTS.md states that boot configuration is resolved in loadConfig and refused by validate(), with no exception. "+
			"Either resolve the value in loadConfig, or document the new exception in AGENTS.md and here — a value read after boot is never refused, it degrades while the solution serves.",
			strings.Join(undocumented, ", "))
	}
}

// And the exception stays retired on both sides. A package that reintroduces
// the serve-time read, or an AGENTS.md that still describes one, puts the
// agent-context file back out of step with the code it governs.
func TestTheServeTimeEnvironmentExceptionStaysRetired(t *testing.T) {
	pkg := parsePackage(t)
	for _, fn := range pkg.environmentReaders() {
		if fn == retiredServeTimeRead {
			t.Errorf("%s reads the environment again: its value would be resolved at serve time and never refused by validate()", retiredServeTimeRead)
		}
	}

	agents, err := os.ReadFile("AGENTS.md")
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	if strings.Contains(string(agents), retiredServeTimeRead) {
		t.Errorf("AGENTS.md still names %q, an exception this package no longer has: describe the single boot-resolution rule instead", retiredServeTimeRead)
	}
}

// pkgFuncs is the package's functions, the calls between them, and which of
// them read the process environment.
type pkgFuncs struct {
	calls map[string][]string
	reads map[string]bool
}

func (p pkgFuncs) environmentReaders() []string {
	names := make([]string, 0, len(p.reads))
	for name := range p.reads {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (p pkgFuncs) reachableFrom(root string) map[string]bool {
	seen := map[string]bool{root: true}
	queue := []string{root}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, callee := range p.calls[current] {
			if !seen[callee] {
				seen[callee] = true
				queue = append(queue, callee)
			}
		}
	}
	return seen
}

func parsePackage(t *testing.T) pkgFuncs {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	fset := token.NewFileSet()
	decls := map[string]*ast.FuncDecl{}
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			if fn, ok := decl.(*ast.FuncDecl); ok && fn.Body != nil {
				decls[fn.Name.Name] = fn
			}
		}
	}

	pkg := pkgFuncs{calls: map[string][]string{}, reads: map[string]bool{}}
	for name, fn := range decls {
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if readsEnvironment(call) {
				pkg.reads[name] = true
			}
			if callee, ok := calleeName(call); ok && decls[callee] != nil {
				pkg.calls[name] = append(pkg.calls[name], callee)
			}
			return true
		})
	}
	if len(pkg.reads) == 0 {
		t.Fatal("no environment reads found at all: this guard is inert")
	}
	return pkg
}

func readsEnvironment(call *ast.CallExpr) bool {
	selector, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}
	pkg, ok := selector.X.(*ast.Ident)
	if !ok || pkg.Name != "os" {
		return false
	}
	return selector.Sel.Name == "Getenv" || selector.Sel.Name == "LookupEnv" || selector.Sel.Name == "Environ"
}

// calleeName is the called function's own name, whether it is called plainly
// or as a method on a receiver. Names are unique enough in this package to
// identify the declaration.
func calleeName(call *ast.CallExpr) (string, bool) {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return fn.Name, true
	case *ast.SelectorExpr:
		return fn.Sel.Name, true
	}
	return "", false
}
