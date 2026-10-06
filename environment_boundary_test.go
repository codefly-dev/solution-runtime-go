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

	"golang.org/x/tools/go/callgraph"
	"golang.org/x/tools/go/callgraph/cha"
	"golang.org/x/tools/go/packages"
	"golang.org/x/tools/go/ssa"
	"golang.org/x/tools/go/ssa/ssautil"
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
	pkgs := gatePackages(t, nil)
	readers := servingReaders(t, pkgs)

	var names []string
	for name := range readers {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		t.Errorf("%s is reachable from the post-boot surface without passing through loadConfig:\n    %s\n"+
			"A value read after boot is never refused by validate(): it changes what a running solution does, with nothing judging it. "+
			"Resolve it in loadConfig and carry the resolved value, rather than reading the environment where it is used.",
			name, readers[name])
	}
}

// And the gate has to be able to see a read at all, or its silence means
// nothing. Three shapes, each the one a previous version of this gate lost:
// an exported function reading directly, a handler reached only as a value
// mounted on a mux, and a method value stored in a package-level struct.
func TestThePostBootGateSeesEveryServingShape(t *testing.T) {
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "zz_post_boot_fixture.go")

	source := `package solution

import "net/http"

// A parenthesised callee on an exported path.
func ServedParenthesisedRead() string { return (env)("ANYTHING", "") }

// A reader reached only as a handler value mounted on a mux, with the handler
// itself never called in this package.
func (s *Server) MountFixture(mux *http.ServeMux) {
	mux.HandleFunc("/fixture", fixtureHandler)
}

func fixtureHandler(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("x-fixture", fixtureMountedRead())
}

func fixtureMountedRead() string { return env("ANYTHING", "") }

// A method value stored in a package-level struct and mounted from there, so
// the only edge to it is through the stored field.
type fixtureReceiver struct{}

func (fixtureReceiver) fixtureServe(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("x-stored", fixtureStoredRead())
}

func fixtureStoredRead() string { return env("ANYTHING", "") }

var fixtureHandlers = struct {
	h func(http.ResponseWriter, *http.Request)
}{h: fixtureReceiver{}.fixtureServe}

func MountStoredFixture(mux *http.ServeMux) {
	mux.HandleFunc("/stored", fixtureHandlers.h)
}

// An exported variable holding a closure that reads.
var ExportedClosure = func() string { return (env)("ANYTHING", "") }
`

	readers := servingReaders(t, gatePackages(t, map[string][]byte{fixture: []byte(source)}))
	if len(readers) == 0 {
		t.Fatal("the gate reported no post-boot reader for a fixture that reads on four serving paths")
	}
	// env is the reader every one of these reaches, so its path has to come
	// back; the path itself is what says WHICH shape was followed.
	if _, ok := readers["env"]; !ok {
		t.Errorf("the gate did not report env: readers=%v", readers)
	}
}

// And os.Environ is a reader too, which is the omission that let an exported
// wrapper of a function using it read changing configuration after boot. It
// has no key to resolve — it reads all of them — so the read itself is the
// finding.
func TestTheWholeEnvironmentCountsAsARead(t *testing.T) {
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "zz_environ_fixture.go")

	source := `package solution

import "context"

// discoverHostModule scans os.Environ, so an exported wrapper of it reads
// changing configuration after boot.
func ExportedLateHost() string {
	return discoverHostModule(context.Background(), "auth-gateway", "rest", "rest")
}
`
	readers := servingReaders(t, gatePackages(t, map[string][]byte{fixture: []byte(source)}))
	if len(readers) == 0 {
		t.Fatal("an exported wrapper of a function scanning the whole environment was not reported")
	}
}

// --- One reader definition, by object identity ---
//
// A reader is an OBJECT, not a spelling. Both gates share this, because the
// two of them disagreeing about what a read is is how a read gets past both:
//
//	read := r2Reader(os.Getenv)
//	read(strings.Join([]string{"CODEFLY", "", "MODULE", ...}, "_"))
//
// recognising readers by callee name sees no read at all — the callee is
// `read` — while a graph that merely records an edge to Getenv never marks it
// as a reader when its value is taken rather than called. So the identity is
// followed wherever it flows: converted, aliased, assigned, stored in a field,
// passed as an argument, returned.
//
// readerNames are the readers by package and name. os.ExpandEnv reads every
// variable named in its argument, syscall.Getenv is the same read one package
// down, and os.Environ reads all of them at once — which is why an exported
// wrapper of a function using it reads changing configuration after boot.
var readerNames = map[string]map[string]bool{
	"os":      {"Getenv": true, "LookupEnv": true, "Environ": true, "ExpandEnv": true},
	"syscall": {"Getenv": true, "Environ": true},
}

// readerPackageOf is the import path a reader package goes by, since SSA names
// a package by path and the syntax names it by identifier.
func readerPackageOf(path string) string { return path }

// sdkReaderNames are the SDK's own accessors, by method name. They are matched
// by name because they are methods on the SDK's query value rather than
// package functions, and the older gate's round-four finding was precisely a
// closure reading configuration through one of them.
var sdkReaderNames = map[string]bool{
	"WorkspaceConfiguration": true, "WorkspaceSecret": true,
	"Environment": true, "Endpoint": true, "Secret": true,
}

// keylessReaders read the whole environment rather than one named variable, so
// there is no key to resolve and nothing to constrain: the read itself is the
// finding when it happens after boot.
var keylessReaders = map[string]bool{"Environ": true, "ExpandEnv": true}

// --- The serving surface, on a sound call graph ---
//
// Reachability is CHA (class hierarchy analysis) over SSA, from
// golang.org/x/tools, rather than a graph this test builds.
//
// Three rounds of hand-written graph each lost one more Go construct: a
// parenthesised callee, a handler mounted as a value, a method value stored in
// a package-level struct, a callback in a variadic option, a func field on an
// interface. Every fix was right and the next construct arrived anyway,
// because a graph assembled from the shapes somebody thought of is a graph
// about those shapes. CHA resolves an indirect call to every type-compatible
// function in the program — an over-approximation, which is the safe
// direction — so there is no "unresolved edge" category left to fail closed
// on: the analysis has an answer for every call site by construction.
//
// What this gate still chooses is the ROOTS. Everything that can run after
// boot: `serve`, which Serve calls once configuration is resolved; every
// exported function and method, this being a library a consumer calls into;
// and the package initializer, where a served callback is stored
// (`var h = struct{f func(...)}{f: method}`) and where an exported
// `var X = func() { ... }` lives. loadConfig is excluded as a NODE, so a
// helper boot shares with serving code is judged by the serving path.

// servingReaders is every environment reader reachable from the post-boot
// roots, named by the function that reads, with the path that reaches it.
func servingReaders(t *testing.T, pkgs []*packages.Package) map[string]string {
	t.Helper()

	prog, _ := ssautil.AllPackages(pkgs, 0)
	prog.Build()
	graph := cha.CallGraph(prog)
	graph.DeleteSyntheticNodes()

	target := ""
	for _, pkg := range pkgs {
		if pkg.PkgPath == "github.com/codefly-dev/solution-runtime-go" {
			target = pkg.PkgPath
		}
	}
	if target == "" {
		t.Fatal("the package under test was not loaded: this gate is inert")
	}

	// Address-taken functions are roots too. A handler mounted on a mux and a
	// closure assigned to an exported variable are never CALLED in this
	// package, so the call graph holds no edge to them — whoever holds the
	// value chooses when it runs, and that is after boot. These two shapes
	// survived a gate that rooted only at named entry points.
	escaping := addressTaken(prog, target)

	var roots []*callgraph.Node
	for fn, node := range graph.Nodes {
		if fn == nil || !inPackage(fn, target) {
			continue
		}
		if isPostBootRoot(fn) || escaping[fn] {
			roots = append(roots, node)
		}
	}
	if len(roots) == 0 {
		t.Fatal("no post-boot roots found: this gate is inert")
	}

	// Breadth-first from the roots, never through loadConfig.
	readers := map[string]string{}
	seen := map[*callgraph.Node]bool{}
	path := map[*callgraph.Node]string{}
	var queue []*callgraph.Node
	for _, root := range roots {
		if seen[root] {
			continue
		}
		seen[root] = true
		path[root] = root.Func.Name()
		queue = append(queue, root)
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		for _, edge := range current.Out {
			next := edge.Callee
			if next == nil || next.Func == nil || seen[next] {
				continue
			}
			if isBootResolution(next.Func) {
				continue
			}
			// A reader is reported only when THIS package's code is what
			// calls it. The walk still goes through dependencies, because a
			// handler this package mounts is invoked by net/http and the path
			// back to it runs through there — but a dependency reading its own
			// configuration is not this package's boundary. Reporting every
			// reader on the path named four that are all somebody else's: the
			// SDK rechecking a rotated value, grpc's resolver, viper's init,
			// none of which this package could resolve in loadConfig.
			if name, ok := environmentReader(next.Func); ok {
				// Only a call that actually names the reader. CHA resolves an
				// indirect call to every type-compatible function in the
				// program, so a callback of shape func(string) (string, bool)
				// resolves to os.LookupEnv whether or not anything ever puts
				// it there — which is exactly what it did here, through
				// namedInJSON's `named` parameter.
				//
				// A reader genuinely held in a value and called through it is
				// not lost by this: that is the identity the key gate follows,
				// precisely, and refuses when its key cannot be resolved. An
				// over-approximated edge proves nothing and the precise gate
				// is the one that owns that shape.
				if inPackage(current.Func, target) && staticCall(edge, next.Func) {
					readers[name] = path[current] + " → " + name
				}
				continue
			}
			seen[next] = true
			path[next] = path[current] + " → " + next.Func.Name()
			queue = append(queue, next)
		}
	}
	return readers
}

// isPostBootRoot reports whether a function can run after boot.
func isPostBootRoot(fn *ssa.Function) bool {
	if fn.Synthetic == "package initializer" || fn.Name() == "init" {
		// Where a package-level callback is stored and where an exported
		// func-valued variable is initialised.
		return true
	}
	if fn.Name() == "serve" {
		return true
	}
	// A method on an exported or unexported receiver is still reachable from a
	// consumer when the method itself is exported.
	return ast.IsExported(fn.Name())
}

// staticCall reports whether an edge is a call that names its callee, rather
// than one CHA resolved from a function type.
func staticCall(edge *callgraph.Edge, callee *ssa.Function) bool {
	if edge.Site == nil {
		return false
	}
	return edge.Site.Common().StaticCallee() == callee
}

// addressTaken is every function of the package whose value is used as a
// value rather than called: stored in a variable or a struct, handed to a
// registration call, closed over. SSA makes this visible — a function
// appearing as an operand anywhere other than a call's static callee is one
// somebody can invoke later.
func addressTaken(prog *ssa.Program, target string) map[*ssa.Function]bool {
	taken := map[*ssa.Function]bool{}
	for fn := range ssautil.AllFunctions(prog) {
		for _, block := range fn.Blocks {
			for _, instruction := range block.Instrs {
				call, isCall := instruction.(ssa.CallInstruction)
				var static *ssa.Function
				if isCall {
					static = call.Common().StaticCallee()
				}
				var operands []*ssa.Value
				operands = instruction.Operands(operands)
				for _, operand := range operands {
					if operand == nil || *operand == nil {
						continue
					}
					referenced, ok := (*operand).(*ssa.Function)
					if !ok || referenced == static {
						continue
					}
					if referenced.Pkg != nil && referenced.Pkg.Pkg.Path() == target {
						taken[referenced] = true
					}
					// An anonymous function's parent is what wrote it; the
					// literal itself is the thing being handed out.
					if referenced.Parent() != nil && referenced.Parent().Pkg != nil &&
						referenced.Parent().Pkg.Pkg.Path() == target {
						taken[referenced] = true
					}
				}
			}
		}
	}
	return taken
}

// inPackage reports whether a function belongs to the package under test.
func inPackage(fn *ssa.Function, path string) bool {
	return fn.Pkg != nil && fn.Pkg.Pkg.Path() == path
}

// isBootResolution reports whether a function IS boot configuration
// resolution, which the walk does not pass through.
func isBootResolution(fn *ssa.Function) bool {
	return fn.Name() == "loadConfig" && fn.Pkg != nil &&
		fn.Pkg.Pkg.Path() == "github.com/codefly-dev/solution-runtime-go"
}

// environmentReader reports whether an SSA function is one of the readers, by
// the SAME definition the key gate uses: package and name for the os and
// syscall readers, method name for the SDK's accessors, and this package's own
// env helper.
func environmentReader(fn *ssa.Function) (string, bool) {
	if fn.Pkg != nil {
		path := fn.Pkg.Pkg.Path()
		if readerNames[path][fn.Name()] {
			return path + "." + fn.Name(), true
		}
		if path == "github.com/codefly-dev/solution-runtime-go" && fn.Name() == "env" {
			return "env", true
		}
	}
	// The SDK's own accessors, matched by the package they belong to as well
	// as the name: a bare name match reported grpc's resolver `Endpoint` as a
	// configuration read, which it is not.
	if fn.Pkg != nil && sdkReaderNames[fn.Name()] && strings.HasPrefix(fn.Pkg.Pkg.Path(), "github.com/codefly-dev/sdk-go") {
		return "the SDK's " + fn.Name(), true
	}
	return "", false
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
