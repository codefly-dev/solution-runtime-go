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

// AGENTS.md tells an agent that configuration is resolved in one place and
// refused at boot, with no exception. Prose cannot notice an exception
// appearing underneath it, and an agent-context file is followed literally, so
// the claim is pinned here: every environment read must sit in loadConfig's
// call tree, where validate() governs the result.
//
// There used to be one exception, and deleting it is part of this runtime
// ceasing to register itself. registerConsumedAPIs read the api.consumes
// projection at serve time to register each consumed module's upstream with
// the gateway; a malformed projection disabled the whole federation with a log
// line while the solution served on, so every consumed facade 404'd at the
// gateway and the solution looked healthy. Nothing registers now — the routes
// are delivered — and the projection is resolved at boot like everything else,
// so the refusal is a refusal and not a log line.
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
			"Either resolve the value in loadConfig, or document the new exception in AGENTS.md — a value read after boot is never refused, it degrades while the solution serves.",
			strings.Join(undocumented, ", "))
	}
}

// AGENTS.md has to keep saying so. A file that stopped describing the boundary
// would leave the next agent to infer it from whichever call site they opened
// first, which is how the serve-time exception came to exist.
func TestTheEnvironmentBoundaryIsDocumented(t *testing.T) {
	agents, err := os.ReadFile("AGENTS.md")
	if err != nil {
		t.Fatalf("read AGENTS.md: %v", err)
	}
	for _, claim := range []string{"loadConfig", "validate()"} {
		if !strings.Contains(string(agents), claim) {
			t.Errorf("AGENTS.md does not name %q, half of where configuration is resolved and refused", claim)
		}
	}
	if strings.Contains(string(agents), "registerConsumedAPIs") {
		t.Error("AGENTS.md still names registerConsumedAPIs, the serve-time exception this runtime deleted along with its registrations")
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
