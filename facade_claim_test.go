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
	"sync"
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
	return append(append([]string{}, identity.unresolvedKeys...), identity.unresolved...)
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

import (
	"os"
	"reflect"

	"golang.org/x/sys/unix"
)

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

// The reader's identity hidden behind a local function type: the callee is
// ` + "`read`" + `, so no rule about callee names sees a read at all, and the key is
// never examined.
type aliasedReader = func(string) string

func AliasedCredential(parts []string) string {
	read := aliasedReader(osGetenv)
	return read(joinedKey(parts))
}

// Through a struct field, through a parameter, and parenthesised.
type readerBox struct{ read func(string) string }

func AliasedThroughAField(parts []string) string {
	box := readerBox{read: osGetenv}
	return box.read(joinedKey(parts))
}

func aliasedThroughAParameter(read func(string) string, parts []string) string {
	return read(joinedKey(parts))
}

func AliasedCaller(parts []string) string {
	return aliasedThroughAParameter(osGetenv, parts)
}

func AliasedThroughParentheses(parts []string) string {
	return (env)(joinedKey(parts), "")
}

var osGetenv = os.Getenv

// The ways of moving a function value this analysis does not model. None is
// handled by teaching the model about maps, reflection or instantiation —
// that would leave the NEXT way silent. Each is a reader value in a position
// grow() does not propagate through, so each fails for the same reason, and so
// will the one nobody has thought of.
func EscapeViaMap() string {
	readers := map[string]func(string) string{"get": os.Getenv}
	return readers["get"](joinedKey(nil))
}

func EscapeViaReflect() string {
	return reflect.ValueOf(os.Getenv).Call([]reflect.Value{reflect.ValueOf(joinedKey(nil))})[0].String()
}

func escapeApply[F ~func(string) string](reader F, key string) string { return reader(key) }

func EscapeViaGeneric() string {
	return escapeApply[func(string) string](os.Getenv, joinedKey(nil))
}

func EscapeViaSlice() string {
	readers := []func(string) string{os.Getenv}
	return readers[0](joinedKey(nil))
}

// And a dependency that wraps the syscall layer is a reader by SUMMARY: its
// body is not here, so calling it is modelled as the read it is.
func WrapperRead(parts []string) string {
	value, _ := unix.Getenv(joinedKey(parts))
	return value
}

func joinedKey(parts []string) string {
	out := ""
	for _, part := range parts {
		out += part
	}
	return out
}
`

	// One load for both rules: each shells out to the go command, and the
	// fixture is the same package either way.
	shapes, keys := "", ""
	for _, pkg := range gatePackages(t, map[string][]byte{fixture: []byte(source)}) {
		if pkg.PkgPath != "github.com/codefly-dev/solution-runtime-go" {
			continue
		}
		shapes = strings.Join(claimShapeFindings(t, pkg), "\n")
		keys = strings.Join(unresolvedKeyFindings(t, pkg), "\n")
	}
	for _, want := range []string{
		"CODEFLY__MODULE_REGISTRATION_SECRETS",
		"/modules/_register",
		"X-Codefly-Module-Secret",
	} {
		if !strings.Contains(shapes, want) {
			t.Errorf("the claim-shape gate did not catch %q.\nfindings:\n%s", want, shapes)
		}
	}
	// Every spelling, by DISTINCT finding. Counting occurrences of the string
	// did not require two: one finding names the shape twice, once as the
	// constant's value and once as the shape it matched, so a gate that found
	// the conversion and lost the chain still counted two.
	distinct := map[string]bool{}
	for _, line := range strings.Split(shapes, "\n") {
		if strings.Contains(line, "/modules/_register") {
			distinct[strings.SplitN(line, ":", 4)[0]+":"+strings.SplitN(line, ":", 4)[1]] = true
		}
	}
	if len(distinct) < 2 {
		t.Errorf("the claim path was caught at %d distinct places, want the conversion, the chain and the local constant.\nfindings:\n%s",
			len(distinct), shapes)
	}

	// Four aliased reader invocations: through a conversion, a struct field,
	// a parameter, and parenthesised — plus the runtime-joined key. Each is a
	// spelling that defeated recognising readers by callee name.
	if got := strings.Count(keys, "does not resolve to constants"); got < 5 {
		t.Errorf("the key gate caught %d of the five untraceable-key invocations.\nfindings:\n%s", got, keys)
	}

	// Per escape, by its own source line: an aggregate count lets one stand
	// for another.
	for _, want := range []string{
		"EscapeViaMap", "EscapeViaReflect", "EscapeViaGeneric", "EscapeViaSlice",
	} {
		if !mentionsFunction(t, source, keys, want) {
			t.Errorf("no finding inside %s, so that escape is still silent.\nfindings:\n%s", want, keys)
		}
	}
	// The dependency wrapper is a read by summary, so its runtime key is
	// refused like any other reader's.
	if !mentionsFunction(t, source, keys, "WrapperRead") {
		t.Errorf("a dependency wrapper of the syscall layer was not treated as a reader.\nfindings:\n%s", keys)
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
	// decls caches the declaration of each of this package's functions. The
	// propagation asks for them once per call expression per round, and
	// re-walking every file each time was most of this gate's cost.
	decls map[*types.Func]*ast.FuncDecl
	// unresolved is every reader flow this analysis does not model, and the
	// exhaustion of the fixpoint if it happens. These FAIL the gate.
	//
	// This is the whole shape of the rule. An analysis that skips what it
	// cannot follow reports a boundary intact because it did not look: a map
	// of functions, a reflect.Value.Call, a generic instantiation each carried
	// a reader somewhere this model has no edge for, and each produced
	// silence. Refusing instead means a new way of moving a function value
	// fails the suite until somebody models it or decides it is fine.
	unresolved []string
}

// maxReaderFlowRounds bounds the propagation. Reaching it is a finding rather
// than a stopping condition.
const maxReaderFlowRounds = 64

// readerSite is one resolved reader invocation.
type readerSite struct {
	pos  token.Pos
	name string
}

// readerIdentityCache holds one analysis per loaded package. Several gates ask
// the same package the same question, and the propagation is the expensive
// part of this suite — recomputing it per gate cost ninety seconds.
var (
	readerIdentityMu    sync.Mutex
	readerIdentityCache = map[*packages.Package]*readerIdentity{}
)

func newReaderIdentity(pkg *packages.Package) *readerIdentity {
	readerIdentityMu.Lock()
	defer readerIdentityMu.Unlock()
	if cached, ok := readerIdentityCache[pkg]; ok {
		return cached
	}
	identity := buildReaderIdentity(pkg)
	readerIdentityCache[pkg] = identity
	return identity
}

func buildReaderIdentity(pkg *packages.Package) *readerIdentity {
	return buildReaderIdentityWithin(pkg, maxReaderFlowRounds)
}

// buildReaderIdentityWithin is the analysis with the round budget named, so the
// refusal below can be asked directly. No fixture can exhaust sixty-four
// rounds — that is what a budget is for — and a branch no test reaches is a
// claim, not a guarantee.
func buildReaderIdentityWithin(pkg *packages.Package, rounds int) *readerIdentity {
	r := &readerIdentity{pkg: pkg, readerAliases: map[types.Object]bool{}, decls: map[*types.Func]*ast.FuncDecl{}}
	for _, file := range r.files() {
		for _, d := range file.Decls {
			if decl, ok := d.(*ast.FuncDecl); ok && decl.Name != nil {
				if fn, ok := pkg.TypesInfo.Defs[decl.Name].(*types.Func); ok {
					r.decls[fn] = decl
				}
			}
		}
	}
	r.seed()
	// A fixed point, or a refusal. Stopping silently after a fixed number of
	// rounds is a skip wearing a loop: whatever had not propagated yet simply
	// was not there, and nothing said so.
	settled := false
	for round := 0; round < rounds; round++ {
		if !r.grow() {
			settled = true
			break
		}
	}
	if !settled {
		r.unresolved = append(r.unresolved, "reader flow did not reach a fixed point within "+
			strconv.Itoa(rounds)+" rounds, so what else may hold a reader is unknown")
	}
	r.checkEscapes()
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

// checkEscapes finds every reader VALUE in a position this analysis does not
// model, and reports it.
//
// The modelled flows are the ones grow() propagates through: an assignment to
// a name, a variable specification, a struct literal field, an argument to one
// of this package's own functions, a conversion, and being called. A reader
// anywhere else — a map literal, an argument to a dependency, a generic
// instantiation, a return value, a channel — is a reader this model loses, and
// losing it silently is how a map of functions and a reflect.Value.Call both
// read the environment while both gates reported nothing.
//
// Refusing rather than enumerating is the point. Teaching the model about maps
// and reflection and instantiation would leave the NEXT way of moving a
// function value silent again; refusing means it fails the suite instead,
// until somebody models it or decides it is fine.
func (r *readerIdentity) checkEscapes() {
	for _, file := range r.files() {
		// The stack is kept by hand rather than with a defer in the visitor:
		// a defer per AST node is a defer per node of the whole package, and
		// that alone cost this suite a minute and a half under -race.
		var stack []ast.Node
		ast.Inspect(file, func(n ast.Node) bool {
			if n == nil {
				if len(stack) > 0 {
					stack = stack[:len(stack)-1]
				}
				return true
			}
			var parent ast.Node
			if len(stack) > 0 {
				parent = stack[len(stack)-1]
			}
			stack = append(stack, n)

			expr, ok := n.(ast.Expr)
			if !ok {
				return true
			}
			// A DECLARATION is not a flow: `func env(...)` names the reader,
			// it does not move it. Only a use can carry one somewhere.
			if ident, isIdent := expr.(*ast.Ident); isIdent && r.pkg.TypesInfo.Defs[ident] != nil {
				return true
			}
			if !r.holds(expr) || r.modelledFlow(expr, parent, stack) {
				return true
			}
			r.unresolved = append(r.unresolved,
				r.pkg.Fset.Position(expr.Pos()).String()+": a reader value flows into "+
					describeNode(parent)+", which this analysis does not model, so where it is "+
					"called and with what key is unknown")
			return true
		})
	}
	sort.Strings(r.unresolved)
}

// modelledFlow reports whether a reader expression sits in a position grow()
// propagates through.
func (r *readerIdentity) modelledFlow(expr ast.Expr, parent ast.Node, stack []ast.Node) bool {
	switch p := parent.(type) {
	case nil:
		return false
	case *ast.ParenExpr:
		return true // judged at the enclosing position
	case *ast.SelectorExpr:
		return true // `os.Getenv` is judged as the selector, not as its halves
	case *ast.AssignStmt:
		// Only when the destination is a name this model can mark.
		for i, rhs := range p.Rhs {
			if rhs == expr && i < len(p.Lhs) {
				return r.object(p.Lhs[i]) != nil
			}
		}
		return false
	case *ast.ValueSpec:
		for _, value := range p.Values {
			if value == expr {
				return true
			}
		}
		return false
	case *ast.KeyValueExpr:
		// A struct field is modelled; a map entry is not — the key decides
		// which element a call reads, and that is not resolved here.
		if p.Value != expr {
			return false
		}
		for i := len(stack) - 1; i >= 0; i-- {
			if lit, ok := stack[i].(*ast.CompositeLit); ok {
				_, isStruct := structTypeOf(r.pkg.TypesInfo.TypeOf(lit))
				return isStruct
			}
		}
		return false
	case *ast.CallExpr:
		if p.Fun == expr {
			return true // being called IS the invocation
		}
		// A conversion carries the reader through.
		if tv, ok := r.pkg.TypesInfo.Types[p.Fun]; ok && tv.IsType() {
			return true
		}
		// An argument, only to one of this package's own functions, whose
		// parameter grow() marks. Anything else — a dependency, a generic
		// instantiation whose callee is an IndexExpr, a call through a value —
		// takes the reader somewhere with no body here to follow.
		fn, isFunc := r.object(p.Fun).(*types.Func)
		return isFunc && fn.Pkg() == r.pkg.Types
	}
	return false
}

// describeNode names a syntax position for a finding.
func describeNode(n ast.Node) string {
	switch node := n.(type) {
	case nil:
		return "an unattached position"
	case *ast.CallExpr:
		if ident, ok := unparen(node.Fun).(*ast.Ident); ok {
			return "a call to " + ident.Name
		}
		if selector, ok := unparen(node.Fun).(*ast.SelectorExpr); ok {
			return "a call to " + selector.Sel.Name
		}
		if _, ok := unparen(node.Fun).(*ast.IndexExpr); ok {
			return "a generic instantiation"
		}
		return "a call through a value"
	case *ast.KeyValueExpr:
		return "a keyed composite element"
	case *ast.CompositeLit:
		return "a composite literal"
	case *ast.ReturnStmt:
		return "a return"
	case *ast.SendStmt:
		return "a channel send"
	case *ast.IndexExpr:
		return "an index expression"
	}
	return "an unmodelled position"
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
func (r *readerIdentity) decl(fn *types.Func) *ast.FuncDecl { return r.decls[fn] }

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

// mentionsFunction reports whether any finding falls on a line belonging to
// the named function in the fixture source.
func mentionsFunction(t *testing.T, source, findings, name string) bool {
	t.Helper()
	lines := strings.Split(source, "\n")
	start, end := -1, len(lines)
	for i, line := range lines {
		if strings.HasPrefix(line, "func "+name) || strings.HasPrefix(line, "func "+name+"[") {
			start = i + 1
			continue
		}
		if start > 0 && line == "}" {
			end = i + 1
			break
		}
	}
	if start < 0 {
		t.Fatalf("the fixture has no function %s", name)
	}
	for _, finding := range strings.Split(findings, "\n") {
		parts := strings.Split(finding, ":")
		if len(parts) < 2 {
			continue
		}
		if at, err := strconv.Atoi(parts[1]); err == nil && at >= start && at <= end {
			return true
		}
	}
	return false
}

// The fixpoint's refusal, asked directly.
//
// "Reach a fixed point or refuse exhaustion" is half a rule until the refusing
// half has a test, and no fixture can supply one against the real budget: the
// budget exists precisely so that nothing in a real package reaches it. So the
// budget is named, and the branch is asked at one round against a fixture whose
// reader identities need several — the chain is declared in REVERSE, so a
// single forward pass resolves one link and no more.
//
// The control is the same fixture at the full budget. Without it this test
// would pass on a tree that reported exhaustion unconditionally, which is the
// mirror of the defect it pins: the previous loop stopped after sixteen rounds
// and said nothing, so a partial reader set and a complete one were
// indistinguishable to every caller.
func TestTheReaderFixpointRefusesExhaustionRatherThanStoppingQuietly(t *testing.T) {
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "zz_reader_chain_fixture.go")

	source := `package solution

import "os"

// Declared in reverse, so each round of the propagation resolves exactly one
// link: four links need four rounds, and one round leaves three unknown.
var chainReader3 = chainReader2
var chainReader2 = chainReader1
var chainReader1 = chainReader0
var chainReader0 = os.Getenv

func ChainedRead() string { return chainReader3("ANYTHING") }
`

	const refusal = "did not reach a fixed point"
	checked := false
	for _, pkg := range gatePackages(t, map[string][]byte{fixture: []byte(source)}) {
		if pkg.PkgPath != "github.com/codefly-dev/solution-runtime-go" {
			continue
		}
		checked = true
		starved := strings.Join(buildReaderIdentityWithin(pkg, 1).unresolved, "\n")
		if !strings.Contains(starved, refusal) {
			t.Errorf("the propagation ran out of rounds and reported no finding, so a partial reader set reads as a complete one.\nfindings:\n%s", starved)
		}
		settled := strings.Join(buildReaderIdentityWithin(pkg, maxReaderFlowRounds).unresolved, "\n")
		if strings.Contains(settled, refusal) {
			t.Errorf("the propagation does not settle within %d rounds on this fixture, so the refusal above proves nothing.\nfindings:\n%s", maxReaderFlowRounds, settled)
		}
	}
	if !checked {
		t.Fatal("the fixture package was not loaded, so neither branch was asked")
	}
}
