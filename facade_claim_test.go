package solution

import (
	"go/ast"
	"go/constant"
	"go/types"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/tools/go/packages"
)

// --- A solution claims no module's facade route (SP-GW-04, SP-SOL-03) ---
//
// Two invariants:
//
//   - a facade route for a module is claimed only by the module that serves
//     it, under a credential bound to that module;
//   - a solution holds no credential that decides where another module's
//     traffic is routed.
//
// So the package carries neither a module route-claim surface nor a credential
// for one, and no reader of the carrier such a credential arrives in.
//
// ON THE TYPE CHECKER, for the reason typed_boundary_test.go gives: a rule
// that reads syntax is a rule about names, and an author picks the names. The
// first version of this gate evaluated constants by hand — literals,
// parentheses, `+`, and names bound to those — and skipped what it could not
// evaluate. A skip is a silent pass, and this compiles to the forbidden key
// while matching none of its fragments:
//
//	const key = "CODEFLY__MODULE_" + string(rune(82)) + "EGISTRATION_SECRETS"
//
// `string(rune(82))` is a constant conversion, which the hand evaluator did not
// implement. There is no list of expression forms to finish here: the compiler
// has already folded every constant, conversions and concatenation alike, so
// the value is taken from it. That fixture is a compiled negative case below.
var claimShapes = map[string]string{
	"/modules/_register":                   "the gateway's module route-claim path",
	"/modules/_registration-token":         "the exchange that credentials a module route claim",
	"X-Codefly-Module-Secret":              "the header carrying a module's route-claim secret",
	"X-Codefly-Module-Registration":        "the header carrying a module route-claim credential",
	"CODEFLY__MODULE_REGISTRATION_SECRETS": "the carrier delivering another module's route-claim secret",
}

// TestNoModuleFacadeClaimOnTheSDKSurface refuses any constant string in the
// package whose folded value is one of those shapes.
func TestNoModuleFacadeClaimOnTheSDKSurface(t *testing.T) {
	for _, pkg := range gatePackages(t, nil) {
		if findings := claimShapeFindings(t, pkg); len(findings) > 0 {
			for _, finding := range findings {
				t.Errorf("%s\na solution claims no module's facade route and holds no credential that could: a route for a module is claimed by the module that serves it, under a credential bound to that module",
					finding)
			}
		}
	}
}

// claimShapeFindings is every constant expression in pkg whose folded value is
// a claim shape. It is the rule itself, so the negative fixtures below drive
// exactly what the gate drives.
func claimShapeFindings(t *testing.T, pkg *packages.Package) []string {
	t.Helper()

	var findings []string
	evaluated := 0
	for _, file := range pkg.Syntax {
		name := filepath.Base(pkg.Fset.Position(file.Pos()).Filename)
		// Test sources are exempt: the shapes are written down here on
		// purpose, which is what lets this assert their absence elsewhere.
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			expr, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			value, ok := foldedString(pkg, expr)
			if !ok {
				return true
			}
			evaluated++
			for shape, what := range claimShapes {
				if strings.Contains(foldShape(value), foldShape(shape)) {
					findings = append(findings, pkg.Fset.Position(expr.Pos()).String()+
						": the constant "+strconv.Quote(value)+" is "+what+" ("+shape+")")
				}
			}
			// The whole expression folded, so its parts add only noise.
			return false
		})
	}
	if evaluated == 0 {
		t.Fatalf("%s: no constant strings evaluated, so this gate is inert", pkg.PkgPath)
	}
	sort.Strings(findings)
	return findings
}

// foldedString is the constant string an expression evaluates to, as the
// COMPILER folded it. Nothing is reimplemented: `string(rune(82)) + "x"` and a name
// bound to it arrive here already folded, which is the whole reason the hand
// evaluator is gone.
func foldedString(pkg *packages.Package, expr ast.Expr) (string, bool) {
	tv, ok := pkg.TypesInfo.Types[expr]
	if !ok || tv.Value == nil || tv.Value.Kind() != constant.String {
		return "", false
	}
	return constant.StringVal(tv.Value), true
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

// --- An environment read is refused unless its key is a resolved constant ---

// environmentReadFunctions are the ways this package reads the process
// environment. `env` is the package's own helper, which is what a reader
// reaches for: the gate below is about the KEY each one is given.
var environmentReadFunctions = map[string]bool{"Getenv": true, "LookupEnv": true, "env": true}

// TestEveryEnvironmentKeyIsAResolvedConstant refuses an environment read whose
// key cannot be traced to constants.
//
// An unresolved key is a REFUSAL rather than a skip, which is the difference
// between a gate and a suggestion. The gate above judges constants; a key
// computed at run time — joined from a slice, formatted, concatenated with a
// variable — is a key no static rule can judge at all, and letting it through
// is how the one shape that matters arrives.
//
// Traced, not demanded in place. This package names its keys as exported
// constants and passes them to `env` through a parameter or a struct field,
// which is good code and must stay possible: `workloadPath(ctx, override, key)`
// takes the variable name as an argument, and the admission table ranges over a
// literal of them. So a key that does not fold is followed to its sources — the
// arguments at every call site of the enclosing function, the field values of
// the literal being ranged over — and each source must itself resolve. Anything
// that bottoms out in something other than a constant is refused.
//
// The point of tracing rather than relaxing: every constant reached this way is
// also inspected by the gate above, so there is no path to a forbidden key that
// is neither a constant this package declares nor a refusal here.
func TestEveryEnvironmentKeyIsAResolvedConstant(t *testing.T) {
	for _, pkg := range gatePackages(t, nil) {
		if findings := unresolvedKeyFindings(t, pkg); len(findings) > 0 {
			for _, finding := range findings {
				t.Errorf("%s\nan environment key that cannot be traced to constants cannot be judged by any static gate, so it is refused here rather than skipped: name the key as a constant, or pass one in",
					finding)
			}
		}
	}
}

func unresolvedKeyFindings(t *testing.T, pkg *packages.Package) []string {
	t.Helper()

	tracer := newKeyTracer(pkg)
	var findings []string
	for _, file := range pkg.Syntax {
		name := filepath.Base(pkg.Fset.Position(file.Pos()).Filename)
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 || !readsEnvironmentCall(call) {
				return true
			}
			// env's own body reads os.Getenv(key) on its parameter. It is the
			// helper every traced key arrives through, so judging it here
			// would be judging the mechanism rather than any key; its callers
			// are what this gate follows.
			if tracer.insideEnvHelper(call) {
				return true
			}
			if why, ok := tracer.resolves(call.Args[0], 0); !ok {
				findings = append(findings, pkg.Fset.Position(call.Pos()).String()+
					": the key of this environment read does not resolve to constants ("+why+")")
			}
			return true
		})
	}
	sort.Strings(findings)
	return findings
}

// keyTracer follows an environment key back to the constants that reach it.
type keyTracer struct {
	pkg *packages.Package
	// decls is every function in the package by its object, so a parameter can
	// be followed to the call sites that supply it.
	decls map[types.Object]*ast.FuncDecl
	// envHelper is the package's own env helper, whose body is exempt.
	envHelper *ast.FuncDecl
}

func newKeyTracer(pkg *packages.Package) *keyTracer {
	tracer := &keyTracer{pkg: pkg, decls: map[types.Object]*ast.FuncDecl{}}
	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name == nil {
				continue
			}
			if obj := pkg.TypesInfo.Defs[fn.Name]; obj != nil {
				tracer.decls[obj] = fn
			}
			if fn.Name.Name == "env" && fn.Recv == nil {
				tracer.envHelper = fn
			}
		}
	}
	return tracer
}

// insideEnvHelper reports whether a call sits in the env helper's own body.
func (k *keyTracer) insideEnvHelper(call *ast.CallExpr) bool {
	if k.envHelper == nil || k.envHelper.Body == nil {
		return false
	}
	return call.Pos() >= k.envHelper.Body.Pos() && call.End() <= k.envHelper.Body.End()
}

// maxKeyTraceDepth bounds the walk. Nothing here needs more than a couple of
// hops, and a bound is what keeps a cycle from hanging the suite.
const maxKeyTraceDepth = 8

// resolves reports whether every value that can reach expr is a constant,
// and if not, what stopped the trace.
func (k *keyTracer) resolves(expr ast.Expr, depth int) (string, bool) {
	if depth > maxKeyTraceDepth {
		return "the trace is deeper than " + strconv.Itoa(maxKeyTraceDepth) + " hops", false
	}
	if _, folded := foldedString(k.pkg, expr); folded {
		return "", true
	}
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return k.resolves(e.X, depth+1)
	case *ast.Ident:
		return k.resolvesIdent(e, depth)
	case *ast.SelectorExpr:
		return k.resolvesField(e, depth)
	}
	return "it is computed here rather than named", false
}

// resolvesIdent follows a name: a constant resolves, and a parameter resolves
// when every call site supplies something that resolves.
func (k *keyTracer) resolvesIdent(ident *ast.Ident, depth int) (string, bool) {
	obj := k.pkg.TypesInfo.Uses[ident]
	if obj == nil {
		return "its declaration could not be resolved", false
	}
	if _, isConst := obj.(*types.Const); isConst {
		return "", true
	}
	fn, index, ok := k.parameterOf(obj)
	if !ok {
		return "it is a variable, not a constant or a parameter carrying one", false
	}
	sites := k.callSites(fn)
	if len(sites) == 0 {
		// A parameter nothing supplies cannot be judged, and an unjudged key
		// is the thing this gate exists to refuse.
		return "it is a parameter of " + fn.Name.Name + ", which nothing in this package calls", false
	}
	for _, site := range sites {
		if index >= len(site.Args) {
			return "a call to " + fn.Name.Name + " passes too few arguments to judge", false
		}
		if why, ok := k.resolves(site.Args[index], depth+1); !ok {
			return "it is a parameter of " + fn.Name.Name + ", and a caller supplies a value that " + why, false
		}
	}
	return "", true
}

// resolvesField follows a field read, for the shape the admission table uses:
// ranging over a composite literal of constants.
func (k *keyTracer) resolvesField(sel *ast.SelectorExpr, depth int) (string, bool) {
	base, ok := sel.X.(*ast.Ident)
	if !ok {
		return "it is a field of something this gate cannot follow", false
	}
	obj := k.pkg.TypesInfo.Uses[base]
	if obj == nil {
		if def := k.pkg.TypesInfo.Defs[base]; def != nil {
			obj = def
		}
	}
	if obj == nil {
		return "the value it is a field of could not be resolved", false
	}
	literals := k.rangedLiterals(obj)
	if len(literals) == 0 {
		return "it is a field of a value this gate cannot follow to a literal", false
	}
	for _, lit := range literals {
		for _, element := range lit.Elts {
			item, ok := element.(*ast.CompositeLit)
			if !ok {
				return "an element of the ranged literal is not itself a literal", false
			}
			value, ok := k.fieldValue(item, sel.Sel.Name)
			if !ok {
				return "an element of the ranged literal does not set " + sel.Sel.Name, false
			}
			if why, ok := k.resolves(value, depth+1); !ok {
				return "a literal element sets " + sel.Sel.Name + " to a value that " + why, false
			}
		}
	}
	return "", true
}

// parameterOf reports the function a parameter belongs to and its position.
func (k *keyTracer) parameterOf(obj types.Object) (*ast.FuncDecl, int, bool) {
	for fnObj, fn := range k.decls {
		signature, ok := fnObj.Type().(*types.Signature)
		if !ok {
			continue
		}
		params := signature.Params()
		for i := 0; i < params.Len(); i++ {
			if params.At(i) == obj {
				return fn, i, true
			}
		}
	}
	return nil, 0, false
}

// callSites is every call to fn in this package's non-test sources.
func (k *keyTracer) callSites(fn *ast.FuncDecl) []*ast.CallExpr {
	target := k.pkg.TypesInfo.Defs[fn.Name]
	var sites []*ast.CallExpr
	for _, file := range k.pkg.Syntax {
		if strings.HasSuffix(filepath.Base(k.pkg.Fset.Position(file.Pos()).Filename), "_test.go") {
			continue
		}
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			var name *ast.Ident
			switch callee := call.Fun.(type) {
			case *ast.Ident:
				name = callee
			case *ast.SelectorExpr:
				name = callee.Sel
			default:
				return true
			}
			if k.pkg.TypesInfo.Uses[name] == target {
				sites = append(sites, call)
			}
			return true
		})
	}
	return sites
}

// rangedLiterals is every composite literal that obj ranges over.
func (k *keyTracer) rangedLiterals(obj types.Object) []*ast.CompositeLit {
	var literals []*ast.CompositeLit
	for _, file := range k.pkg.Syntax {
		ast.Inspect(file, func(n ast.Node) bool {
			stmt, ok := n.(*ast.RangeStmt)
			if !ok {
				return true
			}
			value, ok := stmt.Value.(*ast.Ident)
			if !ok {
				return true
			}
			if k.pkg.TypesInfo.Defs[value] != obj && k.pkg.TypesInfo.Uses[value] != obj {
				return true
			}
			if lit, ok := stmt.X.(*ast.CompositeLit); ok {
				literals = append(literals, lit)
			}
			return true
		})
	}
	return literals
}

// fieldValue is the value a composite literal gives one named field, keyed or
// positional.
//
// Positional is resolved through the type checker rather than the literal's
// own syntax: the admission table is a slice of an anonymous struct, so its
// elements carry no type of their own to count fields in.
func (k *keyTracer) fieldValue(lit *ast.CompositeLit, field string) (ast.Expr, bool) {
	for _, element := range lit.Elts {
		if kv, ok := element.(*ast.KeyValueExpr); ok {
			if key, ok := kv.Key.(*ast.Ident); ok && key.Name == field {
				return kv.Value, true
			}
		}
	}
	if len(lit.Elts) == 0 {
		return nil, false
	}
	if _, keyed := lit.Elts[0].(*ast.KeyValueExpr); keyed {
		return nil, false
	}
	structType, ok := structTypeOf(k.pkg.TypesInfo.TypeOf(lit))
	if !ok {
		return nil, false
	}
	for i := 0; i < structType.NumFields() && i < len(lit.Elts); i++ {
		if structType.Field(i).Name() == field {
			return lit.Elts[i], true
		}
	}
	return nil, false
}

// structTypeOf unwraps a type to the struct underneath it, through pointers
// and named types alike.
func structTypeOf(t types.Type) (*types.Struct, bool) {
	if t == nil {
		return nil, false
	}
	t = types.Unalias(t)
	if pointer, ok := t.(*types.Pointer); ok {
		t = types.Unalias(pointer.Elem())
	}
	structType, ok := t.Underlying().(*types.Struct)
	return structType, ok
}

// readsEnvironmentCall reports whether a call reads the process environment,
// by the callee's name — os.Getenv, os.LookupEnv, or this package's own env.
func readsEnvironmentCall(call *ast.CallExpr) bool {
	switch fn := call.Fun.(type) {
	case *ast.Ident:
		return environmentReadFunctions[fn.Name]
	case *ast.SelectorExpr:
		return environmentReadFunctions[fn.Sel.Name]
	}
	return false
}

// --- The fixture that escaped, as a compiled negative case ---

// TestTheFacadeGatesCatchTheEscapingFixture drives both gates against the
// sources that defeated the hand evaluator, compiled into this very package.
//
// A fixture that only parsed would prove nothing — it is the compiler's
// folding of `string(rune(82))` and of a constant chain that makes these keys
// real, and a parse-only fixture folds nothing. gatePackages fails the load if
// it does not type-check, so this cannot quietly become a fixture about
// nothing.
//
// All of them in ONE overlay, because each load shells out to the go command:
// the shapes are independent declarations, and the rules return every finding,
// so one compile answers for all of them.
func TestTheFacadeGatesCatchTheEscapingFixture(t *testing.T) {
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "zz_facade_claim_fixture.go")

	source := `package solution

// A constant conversion splicing the carrier's name.
func FacadeCredentialViaConversion() string {
	const key = "CODEFLY__MODULE_" + string(rune(82)) + "EGISTRATION_SECRETS"
	return env(key, "")
}

// A claim path spliced the same way.
const facadeClaimPath = "/modules/" + string(rune(95)) + "register"

func FacadeClaimPath() string { return facadeClaimPath }

// A header assembled through a conversion.
func FacadeSecretHeader() string {
	return "X-Codefly-Module-" + string(rune(83)) + "ecret"
}

// Function-local constants, which a package-level-only collector never saw.
func FacadeClaimLocal(gatewayURL string) string {
	const claim = "/modules/" + "_register"
	return gatewayURL + claim
}

func FacadeCredentialLocal() string {
	const carrier = "CODEFLY__MODULE" + "_REGISTRATION_SECRETS"
	return env(carrier, "")
}

// A chain longer than any iteration limit, declared in reverse so a single
// forward pass resolves none of it.
const (
	chain00 = "/" + chain01
	chain01 = "m" + chain02
	chain02 = "o" + chain03
	chain03 = "d" + chain04
	chain04 = "u" + chain05
	chain05 = "l" + chain06
	chain06 = "e" + chain07
	chain07 = "s" + chain08
	chain08 = "/" + chain09
	chain09 = "_" + chain10
	chain10 = "r" + chain11
	chain11 = "e" + chain12
	chain12 = "g" + chain13
	chain13 = "i" + chain14
	chain14 = "s" + chain15
	chain15 = "t" + chain16
	chain16 = "e" + chain17
	chain17 = "r"
)

func FacadeClaimChain() string { return chain00 }

// And a key that is not constant at all.
func FacadeCredentialViaRuntimeKey(parts []string) string {
	return env(joinedKey(parts), "")
}

func joinedKey(parts []string) string {
	out := ""
	for _, part := range parts {
		out += part
	}
	return out
}
`

	shapes := gateFindings(t, fixture, source, claimShapeFindings)
	for _, want := range []string{
		"CODEFLY__MODULE_REGISTRATION_SECRETS",
		"/modules/_register",
		"X-Codefly-Module-Secret",
	} {
		if !strings.Contains(shapes, want) {
			t.Errorf("the claim-shape gate did not catch %q.\nfindings:\n%s", want, shapes)
		}
	}
	// Every spelling, not just one of each shape: the chain and the local
	// constant both produce the claim path, so two findings name it.
	if strings.Count(shapes, "/modules/_register") < 2 {
		t.Errorf("the claim path was caught in only one spelling.\nfindings:\n%s", shapes)
	}

	keys := gateFindings(t, fixture, source, unresolvedKeyFindings)
	if !strings.Contains(keys, "does not resolve to constants") {
		t.Errorf("the key gate did not catch a runtime-computed key.\nfindings:\n%s", keys)
	}
}

// And the gates must not fire on the package as it is, or the fixtures above
// prove nothing: a gate that fires on everything catches every fixture.
func TestTheFacadeGatesAreSilentOnThisPackage(t *testing.T) {
	for _, pkg := range gatePackages(t, nil) {
		if findings := claimShapeFindings(t, pkg); len(findings) > 0 {
			t.Errorf("%s: the claim-shape gate fires on the package as it is: %s", pkg.PkgPath, strings.Join(findings, "; "))
		}
		if findings := unresolvedKeyFindings(t, pkg); len(findings) > 0 {
			t.Errorf("%s: the key gate fires on the package as it is: %s", pkg.PkgPath, strings.Join(findings, "; "))
		}
	}
}
