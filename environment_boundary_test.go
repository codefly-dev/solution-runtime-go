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

// And the read has to happen at boot, not merely be written there.
//
// Static reachability is not the claim AGENTS.md makes, and the difference was
// exploitable without meaning to: a closure *defined* inside loadConfig that
// reads the environment is in loadConfig's call tree for this gate's purposes
// while running per handshake, long after validate() has had its say. Two of
// them existed, resolving the caller and peer admission sets, and the gate
// reported the boundary intact — the reads were lexically where the rule wanted
// them and temporally nowhere near it. A value genuinely resolved at boot does
// not need a closure to do it, so the whole shape is refused rather than
// inspected for intent.
func TestNoClosureDefersAnEnvironmentReadPastBoot(t *testing.T) {
	// Indirectly too. The closures this gate exists to catch did not call
	// os.Getenv: they called workloadPath, which calls env, which does — so a
	// rule that looked only for a direct read would have passed the exact code
	// it was written for. A probe below pins that.
	readers := parsePackage(t).environmentReachers()
	fset := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if filepath.Ext(name) != ".go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, line := range deferredEnvironmentReads(fset, file, readers) {
			t.Errorf("%s:%d defines a function literal that reads the environment: a read inside a closure happens when the closure is called, which is not boot, so validate() never governs it. Resolve the value in loadConfig's own body and carry the result.",
				name, line)
		}
		for _, line := range environmentValuesEscaping(fset, file, readers) {
			t.Errorf("%s:%d takes a reference to a configuration resolver without calling it: a method value or a function value is the same deferred read as a closure, with none of the syntax, so it happens whenever the value is called rather than at boot.",
				name, line)
		}
	}
}

// deferredEnvironmentReads is every environment read inside a function literal
// in one file, by line.
//
// Separated from the test so the gate can be run against a file the test
// writes. A gate that only ever sees conforming code reports success whether
// or not it works, which is how the shape it exists to catch got in.
func deferredEnvironmentReads(fset *token.FileSet, file *ast.File, readers map[string]bool) []int {
	var lines []int
	ast.Inspect(file, func(node ast.Node) bool {
		lit, ok := node.(*ast.FuncLit)
		if !ok {
			return true
		}
		ast.Inspect(lit.Body, func(inner ast.Node) bool {
			call, ok := inner.(*ast.CallExpr)
			if !ok {
				return true
			}
			if readsEnvironment(call) {
				lines = append(lines, fset.Position(call.Pos()).Line)
				return true
			}
			if callee, ok := calleeName(call); ok && readers[callee] {
				lines = append(lines, fset.Position(call.Pos()).Line)
			}
			return true
		})
		return true
	})
	return lines
}

// environmentValuesEscaping is every *reference* to a configuration resolver
// that is taken without being called — a method value or a function value,
// which is the same deferred read as a closure with none of the syntax.
//
// `cfg.resolve = s.readTheSet` reads the environment whenever `resolve` is
// called, and the closure gate sees no function literal at all. A review drove
// exactly that shape past both gates.
func environmentValuesEscaping(fset *token.FileSet, file *ast.File, readers map[string]bool) []int {
	var lines []int
	ast.Inspect(file, func(node ast.Node) bool {
		switch held := node.(type) {
		// A call's own Fun is a call, not an escaping reference — but its
		// arguments are.
		case *ast.CallExpr:
			for _, arg := range held.Args {
				lines = append(lines, referencedReaders(fset, arg, readers)...)
			}
		case *ast.AssignStmt:
			for _, rhs := range held.Rhs {
				lines = append(lines, referencedReaders(fset, rhs, readers)...)
			}
		// `var r = env`, which is an assignment with no AssignStmt.
		case *ast.ValueSpec:
			for _, value := range held.Values {
				lines = append(lines, referencedReaders(fset, value, readers)...)
			}
		// `return workloadPath`, handing the reader to a caller.
		case *ast.ReturnStmt:
			for _, result := range held.Results {
				lines = append(lines, referencedReaders(fset, result, readers)...)
			}
		// `config{resolve: workloadPath}`, which is how the shape this gate
		// exists for was actually written.
		case *ast.CompositeLit:
			for _, element := range held.Elts {
				if pair, ok := element.(*ast.KeyValueExpr); ok {
					lines = append(lines, referencedReaders(fset, pair.Value, readers)...)
					continue
				}
				lines = append(lines, referencedReaders(fset, element, readers)...)
			}
		}
		return true
	})
	return lines
}

// referencedReaders is the lines at which expr names a reader without calling
// it.
func referencedReaders(fset *token.FileSet, expr ast.Expr, readers map[string]bool) []int {
	var lines []int
	switch named := expr.(type) {
	case *ast.Ident:
		if readers[named.Name] {
			lines = append(lines, fset.Position(named.Pos()).Line)
		}
	case *ast.SelectorExpr:
		if readers[named.Sel.Name] {
			lines = append(lines, fset.Position(named.Pos()).Line)
		}
	}
	return lines
}

// environmentReachers is the package's configuration resolvers: the functions
// that read the environment themselves, and the ones whose whole job is to call
// those (workloadPath over env).
//
// One hop, not the transitive closure. The closure marks most of the package —
// enough of it that this gate failed two function literals doing nothing but
// holding a certificate to a principal — and a rule with false positives gets
// relaxed rather than obeyed. One hop is what the shape under test needed: the
// closures called workloadPath, which calls env, which reads. A resolver added
// later is caught the same way, because a new resolver reading the environment
// is itself a direct reader.
func (p pkgFuncs) environmentReachers() map[string]bool {
	reaches := map[string]bool{}
	for name := range p.reads {
		reaches[name] = true
	}
	for caller, callees := range p.calls {
		for _, callee := range callees {
			if p.reads[callee] {
				reaches[caller] = true
				break
			}
		}
	}
	return reaches
}

// TestTheClosureGateCatchesTheShapeThatEvadedIt runs the gate against the two
// closures that passed the boundary check while reading the environment per
// handshake — they resolved the caller and peer admission sets — and against
// the conforming shape, so the gate is not simply refusing every closure.
func TestTheClosureGateCatchesTheShapeThatEvadedIt(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
		caught bool
	}{
		{
			"the admission-set resolver as it was written",
			`package solution
func loadConfig() config {
	return config{
		resolveAllowedCallers: func() string {
			return workloadPath(ctx, IdentityAllowedCallersEnvironmentVariable, WorkloadIdentityAllowedCallersKey)
		},
	}
}`,
			true,
		},
		{
			"a closure reading the environment directly",
			`package solution
func f() func() string {
	return func() string { return os.Getenv("ANYTHING") }
}`,
			true,
		},
		{
			"the SDK accessor called directly in a closure, the exact N1 shape",
			`package solution
func loadConfig() config {
	return config{
		resolve: func() string {
			v, _ := codefly.For(ctx).WorkspaceConfiguration("workload-identity", "ALLOWED_CALLERS")
			return v
		},
	}
}`,
			true,
		},
		{
			"codefly.Environment() in a closure",
			`package solution
func f() func() string {
	return func() string { return codefly.Environment() }
}`,
			true,
		},
		{
			"a closure that reads a file, which is what a live value needs",
			`package solution
func f() func() ([]byte, error) {
	return func() ([]byte, error) { return os.ReadFile(path) }
}`,
			false,
		},
		{
			"a read in a function body, where boot can govern it",
			`package solution
func loadConfig() config {
	return config{port: env("PORT", "")}
}`,
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "probe.go", tc.source, 0)
			if err != nil {
				t.Fatalf("parse the probe: %v", err)
			}
			// The helpers the real closures reached the environment through.
			found := len(deferredEnvironmentReads(fset, file, map[string]bool{"workloadPath": true, "env": true})) > 0
			if found != tc.caught {
				if tc.caught {
					t.Error("the gate did not see an environment read deferred into a closure, so a value read per handshake can be written as if it were resolved at boot")
				} else {
					t.Error("the gate flagged a closure that reads no environment: resolving a value from a file per use is how a live value is supposed to work here, and refusing it would refuse the fix")
				}
			}
		})
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
	// os.Getenv and friends.
	if pkg, ok := selector.X.(*ast.Ident); ok && (pkg.Name == "os" || pkg.Name == "syscall") {
		switch selector.Sel.Name {
		// ExpandEnv reads every variable it finds in the string, and
		// syscall.Getenv is the same read one package down; the rule named
		// neither.
		case "Getenv", "LookupEnv", "Environ", "ExpandEnv":
			return true
		}
	}
	// And the SDK's own readers, which is the gap that mattered: the rule
	// matched only `os.*`, so a closure calling
	// codefly.For(ctx).WorkspaceConfiguration(...) passed — and that is the
	// *precise* shape of the defect the whole round-four finding was about.
	// A gate that misses the exact code it was written for is worse than no
	// gate, because it reports the boundary intact.
	switch selector.Sel.Name {
	case "WorkspaceConfiguration", "Environment", "Endpoint", "Secret":
		return true
	}
	// Not LoadEnvironmentVariables: that is the loader, and start() calling it
	// before loadConfig is the documented shape rather than a read to govern.
	// Not For() either — it returns the query; the read is the accessor called
	// on it, which the names above cover.
	return false
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

// TestTheGateCatchesAReaderTakenAsAValue: a method value or a function value is
// the same deferred read as a closure, with none of the syntax — and a review
// drove exactly that past both gates.
func TestTheGateCatchesAReaderTakenAsAValue(t *testing.T) {
	readers := map[string]bool{"workloadPath": true, "env": true, "readTheSet": true}
	for _, tc := range []struct {
		name   string
		source string
		caught bool
	}{
		{
			"a method value assigned for later",
			`package solution
func (s *Server) wire() {
	s.cfg.resolve = s.readTheSet
}`,
			true,
		},
		{
			"a function value assigned for later",
			`package solution
func wire() config {
	c := config{}
	c.resolve = workloadPath
	return c
}`,
			true,
		},
		{
			"a reader passed as an argument, to be called later",
			`package solution
func wire() {
	hold(workloadPath)
}`,
			true,
		},
		{
			"a composite-literal field, which is how the real one was written",
			`package solution
func loadConfig() config {
	return config{resolve: workloadPath}
}`,
			true,
		},
		{
			"returned to a caller",
			`package solution
func resolver() func() string { return workloadPath }`,
			true,
		},
		{
			"a package-level var holding the reader",
			`package solution
var resolve = env`,
			true,
		},
		{
			"handed to a goroutine",
			`package solution
func wire() { go readTheSet() }`,
			false,
		},
		{
			"calling it, which is a read at boot and fine",
			`package solution
func loadConfig() config {
	return config{port: env("PORT", "")}
}`,
			false,
		},
		{
			"assigning its result, which is also fine",
			`package solution
func loadConfig() config {
	c := config{}
	c.port = workloadPath(ctx, "A", "B")
	return c
}`,
			false,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "probe.go", tc.source, 0)
			if err != nil {
				t.Fatalf("parse the probe: %v", err)
			}
			found := len(environmentValuesEscaping(fset, file, readers)) > 0
			if found != tc.caught {
				if tc.caught {
					t.Error("the gate did not see a configuration resolver taken as a value: it is called whenever the value is called, which is not boot, and no function literal appears for the closure gate to find")
				} else {
					t.Error("the gate flagged a resolver that is called rather than referenced, which is a read at boot and exactly what the rule wants")
				}
			}
		})
	}
}
