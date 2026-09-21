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

// serveTimeEnvironmentRead is the one function that reads the environment
// outside boot resolution: the consumed-API projection is parsed when the
// server starts, never reaches validate(), and a malformed value disables the
// federation with a log line instead of refusing the boot.
const serveTimeEnvironmentRead = "registerConsumedAPIs"

// AGENTS.md tells an agent that configuration is resolved in one place and
// refused at boot, naming the single serve-time exception and the silent
// failure it produces. Prose cannot notice a second exception appearing
// underneath it, and an agent-context file is followed literally, so the claim
// is pinned here: every environment read must sit in loadConfig's call tree,
// where validate() governs the result, or be the documented exception.
func TestEnvironmentIsReadOnlyWhereAgentsFileSaysItIs(t *testing.T) {
	pkg := parsePackage(t)
	boot := pkg.reachableFrom("loadConfig")

	var undocumented []string
	for _, fn := range pkg.environmentReaders() {
		if !boot[fn] && fn != serveTimeEnvironmentRead {
			undocumented = append(undocumented, fn)
		}
	}
	if len(undocumented) > 0 {
		t.Errorf("these functions read the environment outside loadConfig's call tree: %s\n"+
			"AGENTS.md states that boot configuration is resolved in loadConfig and refused by validate(), with %q as the only exception. "+
			"Either resolve the value in loadConfig, or document the new exception in AGENTS.md — a value read after boot is never refused, it degrades while the solution serves.",
			strings.Join(undocumented, ", "), serveTimeEnvironmentRead)
	}
}

// The documented exception has to keep being one. If it stops reading the
// environment, or starts being called during boot resolution, AGENTS.md
// describes a hazard that no longer exists where it says it does.
func TestServeTimeEnvironmentReadIsStillTheException(t *testing.T) {
	pkg := parsePackage(t)

	reads := false
	for _, fn := range pkg.environmentReaders() {
		if fn == serveTimeEnvironmentRead {
			reads = true
		}
	}
	if !reads {
		t.Errorf("%s no longer reads the environment, so AGENTS.md documents an exception that does not exist: remove it there and here",
			serveTimeEnvironmentRead)
	}
	if pkg.reachableFrom("loadConfig")[serveTimeEnvironmentRead] {
		t.Errorf("%s is now reachable from loadConfig, so its value is resolved at boot: AGENTS.md describes it as read at serve time and unseen by validate()",
			serveTimeEnvironmentRead)
	}

	agents, err := os.ReadFile("AGENTS.md")
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	if !strings.Contains(string(agents), serveTimeEnvironmentRead) {
		t.Errorf("AGENTS.md does not name %q, the one configuration read that is not refused at boot", serveTimeEnvironmentRead)
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
