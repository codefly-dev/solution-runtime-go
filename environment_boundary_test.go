package solution

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
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

// And a helper that boot resolution uses must not also be used after it.
//
// The gate above asks only whether an environment reader sits in loadConfig's
// call tree. A helper can sit there and be called from serving code as well,
// and then it passes: `env` is reachable from loadConfig, so a serve-time call
// to `env` reads the environment after validate() has had its say while every
// boot-reachability check stays green.
//
// ON THE TYPE CHECKER, and over function VALUES, because the two things this
// gate must follow are exactly the two a name-matching graph loses:
//
//   - `(env)(...)` is a call to env that no callee-NAME walker sees, because
//     the callee is a parenthesised expression rather than an identifier;
//   - a handler mounted on the mux is never "called" anywhere. `handleHealth`
//     is passed to HandleFunc as a value and invoked by net/http per request,
//     so a graph built from call expressions contains no edge to it at all —
//     and a read inside it happens on every request, which is as far from boot
//     as a read gets.
//
// So calls are resolved through types.Info, and a function mentioned as a
// VALUE is an edge too: if serving code can hand it to something, something
// can call it. Roots are `serve` plus every exported declaration, to a fixed
// point — a library's exported surface is callable by a consumer at any time,
// and a list of two names was a list an author adds to without noticing.
func TestNoEnvironmentReadIsReachableAfterBoot(t *testing.T) {
	for _, pkg := range gatePackages(t, nil) {
		if pkg.PkgPath != "github.com/codefly-dev/solution-runtime-go" {
			continue
		}
		graph := newCallGraph(pkg)
		reached, unresolved := graph.servingSurface()

		// Fail closed: a serving edge this gate could not resolve is a part of
		// the surface it did not walk, and silence about it would be the same
		// silent pass the name-matching graph gave.
		for _, edge := range unresolved {
			t.Errorf("%s: a call on the serving surface goes through a value this gate cannot resolve, so what it reaches was never walked. Call the function directly, or give it a type this gate can follow.", edge)
		}

		var afterBoot []string
		for name := range reached {
			if graph.readsEnvironment[name] {
				afterBoot = append(afterBoot, name)
			}
		}
		sort.Strings(afterBoot)
		if len(afterBoot) > 0 {
			t.Errorf("these environment readers are reachable from the post-boot surface without passing through loadConfig: %s\n"+
				"A value read after boot is never refused by validate(): it changes what a running solution does, with nothing judging it. "+
				"Resolve it in loadConfig and carry the resolved value, rather than reading the environment where it is used.",
				strings.Join(afterBoot, ", "))
		}

		// Inertness checks: the gate must know about env, must have found the
		// serving root, and must have walked a served handler — the edge kind
		// the previous version did not have at all.
		if !graph.readsEnvironment["env"] {
			t.Fatal("env is not recorded as an environment reader: this gate is inert")
		}
		if !graph.declared["serve"] {
			t.Fatal("serve is not in the call graph: this gate is inert")
		}
		if !reached["handleHealth"] {
			t.Fatal("handleHealth is not reachable from the serving surface, so mounted handlers are not being followed: this gate is inert")
		}
	}
}

// callGraph is this package's functions, the edges between them resolved by
// the type checker, and which of them read the environment.
type callGraph struct {
	pkg *packages.Package
	// edges maps a function's name to everything it calls or hands out.
	edges map[string]map[string]bool
	// readsEnvironment marks the functions whose own body reads the environment.
	readsEnvironment map[string]bool
	// declared is every function this package defines.
	declared map[string]bool
	// unresolvedIn records, per function, a call whose callee the type
	// checker could not type at all — the only edge this gate refuses.
	unresolvedIn map[string][]string
	// valueTaken is every package function whose value is taken somewhere, and
	// signatureOf its signature. An indirect call is resolved against these:
	// a call through a func-typed value can only land on a function of that
	// exact signature whose value somebody took.
	valueTaken  map[string]bool
	signatureOf map[string]string
}

// newCallGraph builds the graph from resolved types rather than from names.
func newCallGraph(pkg *packages.Package) *callGraph {
	g := &callGraph{
		pkg:              pkg,
		edges:            map[string]map[string]bool{},
		readsEnvironment: map[string]bool{},
		declared:         map[string]bool{},
		unresolvedIn:     map[string][]string{},
		valueTaken:       map[string]bool{},
		signatureOf:      map[string]string{},
	}
	for _, file := range pkg.Syntax {
		if strings.HasSuffix(filepath.Base(pkg.Fset.Position(file.Pos()).Filename), "_test.go") {
			continue
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil || fn.Body == nil {
				continue
			}
			name := fn.Name.Name
			g.declared[name] = true
			if obj, ok := pkg.TypesInfo.Defs[fn.Name].(*types.Func); ok {
				g.signatureOf[name] = obj.Type().String()
			}
			g.scan(name, fn.Body)
		}
	}
	return g
}

// scan records every edge out of one function body: what it calls, and what it
// hands out as a value. A function literal's body belongs to the function that
// writes it, since that is who can invoke it.
func (g *callGraph) scan(from string, body ast.Node) {
	if g.edges[from] == nil {
		g.edges[from] = map[string]bool{}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			g.scanCall(from, node)
		case *ast.Ident:
			// A function named as a VALUE: handed to HandleFunc, stored, or
			// wrapped. Whoever receives it can call it.
			if obj, ok := g.pkg.TypesInfo.Uses[node].(*types.Func); ok {
				g.edges[from][obj.Name()] = true
				g.valueTaken[obj.Name()] = true
			}
		case *ast.SelectorExpr:
			if obj, ok := g.pkg.TypesInfo.Uses[node.Sel].(*types.Func); ok {
				g.edges[from][obj.Name()] = true
				g.valueTaken[obj.Name()] = true
			}
		}
		return true
	})
}

// scanCall resolves one call. os.Getenv and os.LookupEnv mark the caller as an
// environment reader; a call this gate cannot resolve at all is recorded so the
// walk can fail closed on it.
func (g *callGraph) scanCall(from string, call *ast.CallExpr) {
	fun := unparen(call.Fun)
	switch callee := fun.(type) {
	case *ast.Ident:
		if obj := g.pkg.TypesInfo.Uses[callee]; obj != nil {
			if _, isFunc := obj.(*types.Func); isFunc {
				g.edges[from][obj.Name()] = true
				return
			}
			// A func-typed variable, field or parameter: resolve it by type
			// rather than stopping here.
			if isFuncTyped(obj.Type()) {
				g.resolveIndirect(from, call, obj.Type())
			}
			return
		}
		// A builtin or an unresolved name: builtins cannot read the
		// environment, so nothing to record.
	case *ast.SelectorExpr:
		obj := g.pkg.TypesInfo.Uses[callee.Sel]
		fn, isFunc := obj.(*types.Func)
		if !isFunc {
			if obj != nil && isFuncTyped(obj.Type()) {
				g.resolveIndirect(from, call, obj.Type())
			} else if obj == nil {
				g.refuse(from, call, callee.Sel.Name)
			}
			return
		}
		if pkgOf(fn) == "os" && (fn.Name() == "Getenv" || fn.Name() == "LookupEnv") {
			g.readsEnvironment[from] = true
			return
		}
		g.edges[from][fn.Name()] = true
	case *ast.FuncLit:
		// An immediately invoked literal belongs to its writer, which scan
		// already walked.
	}
}

// resolveIndirect follows a call through a func-typed value by TYPE: it can
// only land on a function of that exact signature whose value somebody took,
// so every such function becomes an edge. Resolving rather than exempting is
// the whole point — a callback field is not a place the walk stops, it is a
// place the walk widens to everything that could be in it.
//
// An empty candidate set is a RESOLVED answer, not an unknown one: no function
// of this package with that signature has its value taken anywhere, so the
// call provably cannot land on one, whatever the value came from. That is what
// `cancel` from context.WithCancel is — resolvable to nothing here.
func (g *callGraph) resolveIndirect(from string, call *ast.CallExpr, t types.Type) {
	want := types.Unalias(t).Underlying().String()
	for name, signature := range g.signatureOf {
		if signature == want && g.valueTaken[name] {
			g.edges[from][name] = true
		}
	}
	// A signature the checker could not resolve is the one unknown left.
	if tv, ok := g.pkg.TypesInfo.Types[call.Fun]; !ok || tv.Type == nil || !resolved(tv.Type) {
		g.refuse(from, call, "an unresolved callee type")
	}
}

// refuse records an edge the type checker could not resolve at all. This is
// the fail-closed case and the only one: a call this gate cannot type is a
// part of the serving surface it did not walk, and saying nothing about it
// would be the silent pass the name-matching graph gave.
func (g *callGraph) refuse(from string, call *ast.CallExpr, what string) {
	g.unresolvedIn[from] = append(g.unresolvedIn[from],
		g.pkg.Fset.Position(call.Pos()).String()+" in "+from+" ("+what+")")
}

// servingSurface is everything reachable from the post-boot roots without
// passing through loadConfig, and the unresolved calls found along the way.
func (g *callGraph) servingSurface() (map[string]bool, []string) {
	const bootResolution = "loadConfig"

	roots := []string{"serve"}
	for name := range g.declared {
		if ast.IsExported(name) {
			roots = append(roots, name)
		}
	}
	sort.Strings(roots)

	reached := map[string]bool{}
	var queue []string
	for _, root := range roots {
		if root == bootResolution || reached[root] {
			continue
		}
		reached[root] = true
		queue = append(queue, root)
	}
	var unresolved []string
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		unresolved = append(unresolved, g.unresolvedIn[current]...)
		for callee := range g.edges[current] {
			if callee == bootResolution || reached[callee] {
				continue
			}
			reached[callee] = true
			queue = append(queue, callee)
		}
	}
	sort.Strings(unresolved)
	return reached, unresolved
}

// unparen removes every layer of parentheses, so `(env)(...)` is a call to env
// rather than a call to something this gate has never heard of.
func unparen(expr ast.Expr) ast.Expr {
	for {
		paren, ok := expr.(*ast.ParenExpr)
		if !ok {
			return expr
		}
		expr = paren.X
	}
}

// isFuncTyped reports whether a type is a function type.
func isFuncTyped(t types.Type) bool {
	if t == nil {
		return false
	}
	_, ok := types.Unalias(t).Underlying().(*types.Signature)
	return ok
}

// pkgOf is the import path of the package a function belongs to.
func pkgOf(fn *types.Func) string {
	if fn.Pkg() == nil {
		return ""
	}
	return fn.Pkg().Path()
}

// TestThePostBootGateCatchesTheServedAndParenthesisedReaders drives the gate
// against the shapes that defeated the name-matching graph, compiled into this
// package.
//
// Each is an environment read on the serving surface that a callee-name walker
// rooted at two functions reported nothing about: one because the callee is
// parenthesised, one because the function is never called anywhere — it is
// mounted on the mux and invoked per request — and one because it is reached
// only through a func-typed field.
func TestThePostBootGateCatchesTheServedAndParenthesisedReaders(t *testing.T) {
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "zz_post_boot_fixture.go")

	for _, tc := range []struct {
		name   string
		source string
	}{
		{
			name: "a parenthesised callee on an exported path",
			source: `package solution

func ServedParenthesisedRead() string { return (env)("ANYTHING", "") }
`,
		},
		{
			name: "a reader reached only as a mounted handler value",
			source: `package solution

import "net/http"

func (s *Server) MountFixture(mux *http.ServeMux) {
	mux.HandleFunc("/fixture", fixtureHandler)
}

func fixtureHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("x-fixture", fixtureRead())
}

func fixtureRead() string { return env("ANYTHING", "") }
`,
		},
		{
			name: "a reader reached only through a func-typed field",
			source: `package solution

type fixtureHooks struct{ read func(string, string) string }

func ServedThroughAField() string {
	hooks := fixtureHooks{read: fixtureFieldRead}
	return hooks.read("ANYTHING", "")
}

func fixtureFieldRead(k, d string) string { return env(k, d) }
`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var reported []string
			for _, pkg := range gatePackages(t, map[string][]byte{fixture: []byte(tc.source)}) {
				if pkg.PkgPath != "github.com/codefly-dev/solution-runtime-go" {
					continue
				}
				graph := newCallGraph(pkg)
				reached, _ := graph.servingSurface()
				for name := range reached {
					if graph.readsEnvironment[name] {
						reported = append(reported, name)
					}
				}
			}
			if len(reported) == 0 {
				t.Error("the gate reported no post-boot environment reader for this fixture")
			}
		})
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
