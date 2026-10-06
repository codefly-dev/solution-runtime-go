package solution

import (
	"go/ast"
	"go/constant"
	"go/token"
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

// TestEveryEnvironmentKeyIsAResolvedConstant refuses an environment read
// whose key cannot be traced to constants.
//
// BY READER IDENTITY, shared with the post-boot gate, because recognising a
// reader by the callee's name is how this escaped:
//
//	read := r2Reader(os.Getenv)
//	read(strings.Join([]string{"CODEFLY", "", "MODULE", ...}, "_"))
//
// The callee is `read`, so a name rule sees no read at all, and the key — the
// forbidden carrier, assembled at run time — is never examined. The reader is
// an object now, followed wherever its identity flows: converted, aliased,
// assigned, stored in a field, passed as an argument.
//
// An unresolved key is a REFUSAL rather than a skip, which is the difference
// between a gate and a suggestion. Traced, not demanded in place: this package
// names its keys as exported constants and passes them through a parameter or
// a struct field, which is good code and stays possible, so a key that does
// not fold is followed to its sources and anything bottoming out in a computed
// value is refused.
func TestEveryEnvironmentKeyIsAResolvedConstant(t *testing.T) {
	for _, pkg := range gatePackages(t, nil) {
		if pkg.PkgPath != "github.com/codefly-dev/solution-runtime-go" {
			continue
		}
		for _, finding := range unresolvedKeyFindings(t, pkg) {
			t.Errorf("%s\nan environment key that cannot be traced to constants cannot be judged by any static gate, so it is refused here rather than skipped: name the key as a constant, or pass one in",
				finding)
		}
	}
}

// unresolvedKeyFindings is every reader invocation in pkg whose key does not
// resolve. The reader set comes from the call graph, which seeds it with the
// reader objects and grows it through every flow that can carry one.
func unresolvedKeyFindings(t *testing.T, pkg *packages.Package) []string {
	t.Helper()
	identity := newReaderIdentity(pkg)
	if len(identity.readerAliases) == 0 {
		t.Fatal("no readers identified at all: this gate is inert")
	}
	return identity.unresolvedKeys
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

// TestTheKeyGateCatchesAnAliasedReader drives the key gate against the reader
// whose identity is hidden behind a local function type.
//
// This is the shape that defeated recognising readers by callee name: the
// callee is `read`, so no rule about names sees a read, and the key — the
// forbidden carrier assembled at run time — is never examined. No constant
// expression in the fixture contains the complete key either, so the
// claim-shape gate cannot be what catches it. Only the reader's identity can.
func TestTheKeyGateCatchesAnAliasedReader(t *testing.T) {
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "zz_aliased_reader_fixture.go")

	source := `package solution

import (
	"os"
	"strings"
)

type aliasedReader = func(string) string

func AliasedCredential() string {
	read := aliasedReader(os.Getenv)
	return read(strings.Join(
		[]string{"CODEFLY", "", "MODULE", "REGISTRATION", "SECRETS"},
		"_",
	))
}

// And through a struct field, and through a parameter, which are the other
// two ways the identity travels.
type readerBox struct{ read func(string) string }

func AliasedThroughAField(parts []string) string {
	box := readerBox{read: os.Getenv}
	return box.read(strings.Join(parts, "_"))
}

func aliasedThroughAParameter(read func(string) string, parts []string) string {
	return read(strings.Join(parts, "_"))
}

// And parenthesised, which returned false from a rule reading the immediate
// spelling and so skipped the key check entirely.
func AliasedThroughParentheses(parts []string) string {
	return (env)(strings.Join(parts, "_"), "")
}

func AliasedCaller(parts []string) string {
	return aliasedThroughAParameter(os.Getenv, parts)
}
`

	keys := gateFindings(t, fixture, source, unresolvedKeyFindings)
	// One finding per invocation: the alias, the field and the parameter.
	if got := strings.Count(keys, "does not resolve to constants"); got < 4 {
		t.Errorf("the key gate caught %d of the four aliased reader invocations.\nfindings:\n%s", got, keys)
	}
}

// And the gates must not fire on the package as it is, or the fixtures above
// prove nothing: a gate that fires on everything catches every fixture.
func TestTheFacadeGatesAreSilentOnThisPackage(t *testing.T) {
	for _, pkg := range gatePackages(t, nil) {
		if pkg.PkgPath != "github.com/codefly-dev/solution-runtime-go" {
			continue
		}
		if findings := claimShapeFindings(t, pkg); len(findings) > 0 {
			t.Errorf("the claim-shape gate fires on the package as it is: %s", strings.Join(findings, "; "))
		}
		if findings := unresolvedKeyFindings(t, pkg); len(findings) > 0 {
			t.Errorf("the key gate fires on the package as it is: %s", strings.Join(findings, "; "))
		}
	}
}

// --- Reader identity, shared with the post-boot gate ---

// readerIdentity is the set of objects that may hold an environment reader,
// and the reader invocations whose key does not resolve to constants.
//
// A reader is an OBJECT, not a spelling. The gates agreeing about what a read
// is matters because two definitions disagreeing is how a read gets past both:
// a reader converted to a local function type and called through that name is
// invisible to a rule that matches callee names, and its key is then never
// examined at all.
type readerIdentity struct {
	pkg *packages.Package
	// readerAliases is seeded with the reader objects and grown through every
	// flow that can carry one, to a fixpoint.
	readerAliases map[types.Object]bool
	// unresolvedKeys is the findings: a resolved reader invocation whose key
	// is not traceable to constants.
	unresolvedKeys []string
	// invocations is every resolved reader invocation, wherever it is. The
	// post-boot gate uses these rather than its own notion of a reader call:
	// one model, so an alias the key gate resolves is an alias that gate sees
	// too.
	invocations []readerSite
}

// readerSite is one resolved reader invocation.
type readerSite struct {
	pos  token.Pos
	name string
}

func newReaderIdentity(pkg *packages.Package) *readerIdentity {
	r := &readerIdentity{pkg: pkg, readerAliases: map[types.Object]bool{}}
	r.seed()
	for round := 0; round < 16; round++ {
		if !r.grow() {
			break
		}
	}
	r.checkInvocations()
	return r
}

// files is this package's non-test sources.
func (r *readerIdentity) files() []*ast.File {
	var out []*ast.File
	for _, file := range r.pkg.Syntax {
		if strings.HasSuffix(filepath.Base(r.pkg.Fset.Position(file.Pos()).Filename), "_test.go") {
			continue
		}
		out = append(out, file)
	}
	return out
}

// seed puts the reader objects themselves into the set, by the same definition
// the post-boot gate uses: the os and syscall readers, and this package's env.
func (r *readerIdentity) seed() {
	for _, file := range r.files() {
		ast.Inspect(file, func(n ast.Node) bool {
			ident, ok := n.(*ast.Ident)
			if !ok {
				return true
			}
			fn, isFunc := r.pkg.TypesInfo.Uses[ident].(*types.Func)
			if !isFunc || fn.Pkg() == nil {
				return true
			}
			if readerNames[fn.Pkg().Path()][fn.Name()] {
				r.readerAliases[fn] = true
			}
			if fn.Pkg() == r.pkg.Types && fn.Name() == "env" {
				r.readerAliases[fn] = true
			}
			return true
		})
	}
}

// grow adds one round of objects that may hold a reader.
func (r *readerIdentity) grow() bool {
	learned := false
	add := func(obj types.Object) {
		if obj != nil && !r.readerAliases[obj] {
			r.readerAliases[obj] = true
			learned = true
		}
	}
	for _, file := range r.files() {
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.AssignStmt:
				for i, rhs := range node.Rhs {
					if i < len(node.Lhs) && r.holds(rhs) {
						add(r.object(node.Lhs[i]))
					}
				}
			case *ast.ValueSpec:
				for i, value := range node.Values {
					if i < len(node.Names) && r.holds(value) {
						add(r.pkg.TypesInfo.Defs[node.Names[i]])
					}
				}
			case *ast.CompositeLit:
				for _, element := range node.Elts {
					kv, ok := element.(*ast.KeyValueExpr)
					if !ok || !r.holds(kv.Value) {
						continue
					}
					if key, ok := kv.Key.(*ast.Ident); ok {
						add(r.field(node, key.Name))
					}
				}
			case *ast.CallExpr:
				r.intoParameters(node, add)
			}
			return true
		})
	}
	return learned
}

// intoParameters adds a callee's parameters that receive a reader.
func (r *readerIdentity) intoParameters(call *ast.CallExpr, add func(types.Object)) {
	fn, ok := r.object(call.Fun).(*types.Func)
	if !ok || fn.Pkg() != r.pkg.Types {
		return
	}
	decl := r.decl(fn)
	if decl == nil || decl.Type.Params == nil {
		return
	}
	index := 0
	for _, field := range decl.Type.Params.List {
		for _, name := range field.Names {
			if index < len(call.Args) && r.holds(call.Args[index]) {
				add(r.pkg.TypesInfo.Defs[name])
			}
			index++
		}
	}
}

// holds reports whether an expression evaluates to a reader: the object, a
// parenthesisation, a CONVERSION of one — which is the same function wearing a
// different type name — or an object already known to hold one.
func (r *readerIdentity) holds(expr ast.Expr) bool {
	switch e := expr.(type) {
	case *ast.ParenExpr:
		return r.holds(e.X)
	case *ast.Ident, *ast.SelectorExpr:
		return r.readerAliases[r.object(expr)]
	case *ast.CallExpr:
		if tv, ok := r.pkg.TypesInfo.Types[e.Fun]; ok && tv.IsType() && len(e.Args) == 1 {
			return r.holds(e.Args[0])
		}
	}
	return false
}

// checkInvocations requires every resolved reader invocation's key to be
// traceable to constants. A keyless reader reads the whole environment, so
// there is no key: that read is the post-boot gate's finding, not this one's.
func (r *readerIdentity) checkInvocations() {
	tracer := newKeyTracer(r.pkg)
	for _, file := range r.files() {
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			if tv, ok := r.pkg.TypesInfo.Types[call.Fun]; ok && tv.IsType() {
				return true // a conversion, not a call
			}
			callee := r.object(call.Fun)
			if callee == nil || !r.readerAliases[callee] {
				return true
			}
			r.invocations = append(r.invocations, readerSite{pos: call.Pos(), name: readerDisplayName(callee)})
			if fn, ok := callee.(*types.Func); ok && keylessReaders[fn.Name()] {
				return true
			}
			if len(call.Args) == 0 || tracer.insideEnvHelper(call) {
				return true
			}
			if why, ok := tracer.resolves(call.Args[0], 0); !ok {
				r.unresolvedKeys = append(r.unresolvedKeys,
					r.pkg.Fset.Position(call.Pos()).String()+": the key of this environment read does not resolve to constants ("+why+")")
			}
			return true
		})
	}
	sort.Strings(r.unresolvedKeys)
}

// readerDisplayName names a reader for a finding.
func readerDisplayName(obj types.Object) string {
	if fn, ok := obj.(*types.Func); ok && fn.Pkg() != nil {
		if fn.Pkg().Path() == "github.com/codefly-dev/solution-runtime-go" {
			return fn.Name()
		}
		return fn.Pkg().Name() + "." + fn.Name()
	}
	if obj != nil {
		return obj.Name()
	}
	return "an environment reader"
}

// object resolves an expression to the object it names.
func (r *readerIdentity) object(expr ast.Expr) types.Object {
	switch e := unparen(expr).(type) {
	case *ast.Ident:
		if obj := r.pkg.TypesInfo.Uses[e]; obj != nil {
			return obj
		}
		return r.pkg.TypesInfo.Defs[e]
	case *ast.SelectorExpr:
		if selection, ok := r.pkg.TypesInfo.Selections[e]; ok {
			return selection.Obj()
		}
		return r.pkg.TypesInfo.Uses[e.Sel]
	}
	return nil
}

// field is the struct field a composite literal key names.
func (r *readerIdentity) field(lit *ast.CompositeLit, name string) types.Object {
	structType, ok := structTypeOf(r.pkg.TypesInfo.TypeOf(lit))
	if !ok {
		return nil
	}
	for i := 0; i < structType.NumFields(); i++ {
		if structType.Field(i).Name() == name {
			return structType.Field(i)
		}
	}
	return nil
}

// decl is the declaration of one of this package's functions.
func (r *readerIdentity) decl(fn *types.Func) *ast.FuncDecl {
	for _, file := range r.files() {
		for _, d := range file.Decls {
			if decl, ok := d.(*ast.FuncDecl); ok && decl.Name != nil &&
				r.pkg.TypesInfo.Defs[decl.Name] == fn {
				return decl
			}
		}
	}
	return nil
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
