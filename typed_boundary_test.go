package solution

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/tools/go/packages"
)

// The boundary gates, on RESOLVED TYPES.
//
// Five review rounds each found one more spelling the syntactic gates did not
// follow: a supplied destination, a zero-value declaration, an assignment
// alias, a function-local type alias, `Decode` instead of `Unmarshal`, an
// unexported struct field, an anonymous struct result, and an SDK alias whose
// name the gate had never heard of. Every fix was correct and the next spelling
// arrived anyway, because a rule that reads syntax is a rule about names and an
// author picks the names.
//
// So these ask the type checker instead. `types.Unalias` makes every alias —
// package-level, function-local, the SDK's own — the same type; `info.TypeOf`
// gives the type of an expression however it was assigned; a struct's fields
// and method set are resolved rather than matched. The name lists are gone,
// and with them the thing each round extended.
//
// Two further rules this buys, which no probe list had:
//
//   - the capability rule keys on core's GENERATED PACKAGE PATH, not on a set
//     of message names, so a message core adds is covered the day it exists;
//   - a handler reachable through an exported METHOD is found, which the field
//     walk could never see.
//
// What type resolution still cannot decide is stated here rather than left for
// a reviewer: a destination whose static type is an INTERFACE (`proto.Message`,
// `any`) is not a capability by its type, and a capability arriving through one
// is invisible to any static rule. That is the residual, it is narrow, and it
// is the same residual core's own verifier has.
//
// The fixtures in TestTheTypedGatesCatchEveryKnownShape are COMPILED against
// this package and the pinned SDK through an overlay. That is deliberate: the
// syntactic probes only parsed their source, so two of them asserted against
// `workcontext.WorkContextV1` — a type the SDK does not export — and supplied
// three rounds of false evidence that the whole-capability rule worked.

// loadedGates caches the unchanged-source load. packages.Load shells out to
// the go command, which costs seconds, and the gates that read the package as
// it is all want the same answer — the sources cannot change inside one run.
// Loading per gate put the suite over CI's five-minute budget.
var (
	loadedGatesOnce sync.Once
	loadedGates     []*packages.Package
	loadedGatesErr  error
)

// gatePackages loads this module's packages with full type information. A nil
// overlay is the package as it is, and is loaded once; an overlay is a
// different package and is loaded on its own.
func gatePackages(t *testing.T, overlay map[string][]byte) []*packages.Package {
	t.Helper()
	if overlay == nil {
		loadedGatesOnce.Do(func() {
			loadedGates, loadedGatesErr = loadGatePackages(nil)
		})
		if loadedGatesErr != nil {
			t.Fatalf("load this module for type-resolved gating: %v", loadedGatesErr)
		}
		return loadedGates
	}
	loaded, err := loadGatePackages(overlay)
	if err != nil {
		t.Fatalf("load this module for type-resolved gating: %v", err)
	}
	return loaded
}

// loadGatePackages is the load itself, returning its complaint rather than
// failing a test, so the cache above can hold the outcome.
func loadGatePackages(overlay map[string][]byte) ([]*packages.Package, error) {
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedImports,
		Overlay: overlay,
	}
	loaded, err := packages.Load(cfg, ".", "./passthroughtest")
	if err != nil {
		return nil, err
	}
	if len(loaded) < 2 {
		return nil, fmt.Errorf("loaded %d packages, want at least the root and passthroughtest: a gate that reads nothing passes", len(loaded))
	}
	for _, pkg := range loaded {
		// A fixture that does not COMPILE cannot supply evidence. This is the
		// check the parse-only probes did not have.
		for _, err := range pkg.Errors {
			return nil, fmt.Errorf("%s does not type-check, so nothing below means anything: %v", pkg.PkgPath, err)
		}
		if pkg.TypesInfo == nil {
			return nil, fmt.Errorf("%s loaded without type information", pkg.PkgPath)
		}
	}
	return loaded, nil
}

// resolved reports whether a type is a real one. go/types gives the INVALID
// type for an expression it could not resolve, and types.Implements says an
// invalid type implements anything.
func resolved(t types.Type) bool {
	if t == nil {
		return false
	}
	basic, ok := types.Unalias(t).(*types.Basic)
	return !ok || basic.Kind() != types.Invalid
}

// namedPath is "<import path>.<Name>" for a named type, after resolving
// aliases. Empty for anything unnamed.
func namedPath(t types.Type) string {
	named, ok := types.Unalias(t).(*types.Named)
	if !ok || named.Obj() == nil || named.Obj().Pkg() == nil {
		return ""
	}
	return named.Obj().Pkg().Path() + "." + named.Obj().Name()
}

// coreWireType reports whether a type is one of core's generated wire messages,
// by the package it comes from.
//
// By PATH, not by a list of message names. The list was the defect: it knew
// WorkContextV1 and WorkSealV1, the SDK exports those as Claims and
// SealedValues, and SealedOperationBinding was missing entirely — three rounds
// of adding names. Everything under core's generated tree is core's encoding,
// which is the actual rule.
func coreWireType(t types.Type) string {
	path := namedPath(t)
	if strings.Contains(path, "/codefly-dev/core/generated/") {
		return path
	}
	return ""
}

// mountableHandlerType reports whether a caller holding this type can serve it
// as-is.
func (g typedGate) mountableHandlerType(t types.Type) bool {
	if !resolved(t) {
		// An unresolved expression — a package name, a callee identifier —
		// has the invalid type, and types.Implements answers TRUE for it.
		// Without this guard every exported function "held a handler".
		return false
	}
	// IMPLEMENTS http.Handler — the actual definition of servable, rather than
	// a list of the types that happen to.
	//
	// The list was still the wrong primitive, and the compiled fixtures caught
	// it on their first run: `type fixtureDefined http.Handler` is a type
	// DEFINITION whose underlying is the interface, so it is mountable and
	// matched no name. Asking the type checker whether it implements the
	// interface covers http.Handler, HandlerFunc, ServeMux, any definition or
	// alias of them, and any type a consumer writes with a ServeHTTP method —
	// which is every spelling there is.
	if g.handler != nil {
		if types.Implements(t, g.handler) || types.Implements(types.NewPointer(t), g.handler) {
			return true
		}
	}
	// A bare func with ServeHTTP's parameters is not an http.Handler, and is
	// one http.HandlerFunc away from being served.
	return servesHTTPSignature(t)
}

// typedGate carries what one LOAD resolved, because a type from one
// packages.Load is not identical to the same type from another: holding
// net/http.Handler in a package-level variable made the compiled-fixture test
// pass alone and fail after the real gates, since types.Implements compared a
// fixture's *http.Request against the previous load's. Per load, passed in.
type typedGate struct {
	handler *types.Interface
	// pkgPath is the package under the gate, so the walk can tell a carrier
	// THIS package declared from another package's own type.
	pkgPath string
}

// gateFor resolves net/http.Handler out of one loaded package.
func gateFor(pkg *packages.Package) typedGate {
	if http := pkg.Imports["net/http"]; http != nil && http.Types != nil {
		if handler := http.Types.Scope().Lookup("Handler"); handler != nil {
			iface, _ := handler.Type().Underlying().(*types.Interface)
			return typedGate{handler: iface, pkgPath: pkg.PkgPath}
		}
	}
	return typedGate{pkgPath: pkg.PkgPath}
}

// handedOutDirectly is what no exported path may RETURN. It is wider than
// mountable, and the difference is load-bearing.
//
// http.RoundTripper belongs here and NOT in mountableHandlerType: returning
// this runtime's transport hands over a credential-bearing round tripper, which
// is worth refusing — but a RoundTripper is not something a caller mounts, and
// treating it as one made every *http.Client "expose a servable handler",
// because http.Client has a Transport field. Gateway.HTTPClient() returns one
// by design: it is how a handler calls a module as the viewer. The first run of
// this typed gate flagged exactly that, which is the recursion working and the
// set being wrong.
func (g typedGate) handedOutDirectly(t types.Type) bool {
	return g.mountableHandlerType(t) || declaredHandlerType(t) ||
		namedPath(t) == "net/http.RoundTripper"
}

// servesHTTPSignature reports whether a type is a function with ServeHTTP's
// parameters, under any name or none.
func servesHTTPSignature(t types.Type) bool {
	signature, ok := types.Unalias(t).Underlying().(*types.Signature)
	if !ok || signature.Params().Len() != 2 {
		return false
	}
	return namedPath(signature.Params().At(0).Type()) == "net/http.ResponseWriter" &&
		namedPath(derefOnce(signature.Params().At(1).Type())) == "net/http.Request"
}

// declaredHandlerType is this package's own Handler/RequestHandler, which a
// consumer WRITES. Handing one back is refused; carrying one in a declaration
// type is how a route is declared, because it needs a *Gateway that only a
// booted request produces.
func declaredHandlerType(t types.Type) bool {
	switch namedPath(t) {
	case "github.com/codefly-dev/solution-runtime-go.Handler",
		"github.com/codefly-dev/solution-runtime-go.RequestHandler":
		return true
	}
	return false
}

// derefOnce strips ONE pointer, for a parameter like *http.Request where the
// level matters.
func derefOnce(t types.Type) types.Type {
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		return pointer.Elem()
	}
	return t
}

// typeWalk is THE traversal, and every rule in this file asks its question
// through it.
//
// Four rounds of gate findings were all the same defect: a walk that
// enumerated the carriers it knew. A struct, then a map, then a signature
// result, then an interface-typed field, then a generic's type argument, then
// a concrete wrapper around a capability. Each fix was correct and the next
// carrier arrived, because the author picks the carrier.
//
// So this reaches a FIXED POINT over resolved types instead: given a type, it
// expands every way a value of that type can hold or hand back another value —
// pointer, slice, array, map key and element, channel, struct field,
// signature result, interface method result, exported method result, a named
// type's underlying type, a generic's type arguments, a type parameter's
// constraint terms — and asks the predicate at every node. There is no list of
// shapes to extend because there is no list.
//
// It FAILS CLOSED in both directions that a traversal can go wrong:
//
//   - A cycle is guarded by identity, not by a depth cap. The previous walks
//     returned false beyond depth 8 and depth 6, so nine nested arrays around
//     an http.Handler escaped both — a traversal that gives up quietly is a
//     gate that can be exhausted by nesting.
//   - What it cannot resolve is REPORTED rather than skipped. An invalid type
//     or a budget exhausted by a pathological graph comes back as `unresolved`,
//     and every caller turns that into a finding. A gate that cannot see is not
//     a gate that passes.
type typeWalk struct {
	gate   typedGate
	match  func(types.Type) bool
	fields fieldPolicy
	// local is this package's path. When foreignOpaque is set, a named type
	// from ANOTHER package is not expanded into its fields.
	//
	// That distinction is the rule, not a concession: what this boundary
	// forbids is THIS package building a carrier for one of core's wire
	// messages. The SDK's own `Credential` transitively contains them — that
	// is its API, and this runtime holds one by design — so expanding every
	// foreign struct flagged `openCredential`, `mcpViewer` and `Credential`
	// itself. A core wire type is still matched directly wherever it appears,
	// however deep, because the match runs before any expansion.
	local         string
	foreignOpaque bool
	// storage restricts expansion to what a value's own memory contains;
	// indirect adds what a decoder allocates through.
	storage  bool
	indirect bool
	// seen keys on the type's own identity, which is what makes a recursive
	// named type terminate.
	seen  map[types.Type]bool
	depth int
	// budget bounds a graph this walk cannot otherwise finish. Exhausting it is
	// an ANSWER — "this could not be decided" — not a false.
	budget     int
	unresolved string
}

// fieldPolicy says which struct fields a value's holder can reach, and — with
// the walk's graph mode — what "carries" means for the question being asked.
type fieldPolicy int

const (
	// reachableFields: exported, or embedded (reachable by its own type name).
	// What a CONSUMER of a handed-out value can read. Used with the EXPOSURE
	// graph, which follows every way a value hands back another value:
	// methods, callable results, interface results, elements, fields.
	reachableFields fieldPolicy = iota
	// everyField: visibility is irrelevant, because allocating a struct
	// allocates its unexported fields too. Used with the STORAGE graph.
	everyField
)

// storageGraph restricts the walk to what a value's own MEMORY contains.
//
// This distinction is the one the first run of the fixed-point walk got wrong,
// and the finding was real: expanding every carrier reported
// `&authorityHeldSource{…}` as constructing a capability, because its
// `CredentialSource` field is an interface whose method returns the SDK's
// credential — which is an alias for one of core's wire messages.
//
// But a method RESULT is not an allocation, and neither is what a pointer, a
// slice, a map or a channel refers to: those are nil in a freshly allocated
// value. Allocating a struct allocates its FIELDS, and allocating an array
// allocates its ELEMENTS, inline. That is the whole of what construction
// means, so that is the whole of what this walk follows — which is both
// narrower and exactly right: `struct{ Seal wc.SealedValues }` allocates a
// seal, and holding a `CredentialSource` does not.
func storageGraph(w *typeWalk) { w.storage = true }

// throughIndirection adds what a DECODER reaches: it allocates through the
// pointers and slices in its destination, which a constructor does not.
func throughIndirection(w *typeWalk) { w.storage, w.indirect = true, true }

func (g typedGate) walk(t types.Type, match func(types.Type) bool, fields fieldPolicy, opts ...func(*typeWalk)) (bool, string) {
	w := &typeWalk{gate: g, match: match, fields: fields, seen: map[types.Type]bool{}, budget: 50000}
	for _, opt := range opts {
		opt(w)
	}
	found := w.reach(t)
	return found, w.unresolved
}

// withinThisPackage stops the walk expanding another package's named types
// into their fields.
func withinThisPackage(path string) func(*typeWalk) {
	return func(w *typeWalk) { w.local, w.foreignOpaque = path, true }
}

func (w *typeWalk) reach(t types.Type) bool {
	if t == nil {
		return false
	}
	if w.budget <= 0 {
		if w.unresolved == "" {
			w.unresolved = "the traversal ran out of budget before it finished, so this type's carriers were never all examined"
		}
		return false
	}
	w.budget--
	if !resolved(t) {
		if w.depth > 0 {
			// Invalid INSIDE a graph: a carrier the gate cannot see into.
			w.unresolved = "go/types could not resolve a type inside this one, so nothing can be decided about what it carries"
		}
		// At the root, an invalid type is an expression that is not a value at
		// all — a package name, a callee identifier. There is nothing to
		// decide, and reporting it would fire on every file.
		return false
	}
	if w.seen[t] {
		return false
	}
	w.seen[t] = true
	w.depth++
	defer func() { w.depth-- }()

	if w.match(t) {
		return true
	}

	// An EXPORTED METHOD handing one back is the same exposure with a call in
	// the way, on the value and on a pointer to it. A method result is not
	// STORAGE, so this is the exposure graph only.
	for _, receiver := range []types.Type{t, types.NewPointer(t)} {
		if w.storage {
			break
		}
		set := types.NewMethodSet(receiver)
		for i := range set.Len() {
			method := set.At(i).Obj()
			if !method.Exported() {
				continue
			}
			signature, ok := method.Type().(*types.Signature)
			if !ok {
				continue
			}
			for r := range signature.Results().Len() {
				if w.reach(signature.Results().At(r).Type()) {
					return true
				}
			}
		}
	}

	// A NAMED type carries its underlying type and its type ARGUMENTS: an
	// instantiated generic holds whatever it was instantiated with.
	if named, ok := types.Unalias(t).(*types.Named); ok {
		if args := named.TypeArgs(); args != nil {
			for i := range args.Len() {
				if w.reach(args.At(i)) {
					return true
				}
			}
		}
		if w.foreignOpaque {
			if pkg := named.Obj().Pkg(); pkg != nil && pkg.Path() != w.local {
				// Another package's type, and not a match itself. Its insides
				// are its own API.
				return false
			}
		}
	}

	under := types.Unalias(t).Underlying()
	if w.storage {
		// Only what the value itself holds.
		switch held := under.(type) {
		case *types.Struct:
			for i := range held.NumFields() {
				field := held.Field(i)
				if w.fields == reachableFields && !field.Exported() && !field.Embedded() {
					continue
				}
				if w.reach(field.Type()) {
					return true
				}
			}
		case *types.Array:
			if w.reach(held.Elem()) {
				return true
			}
		case *types.Pointer:
			if w.indirect && w.reach(held.Elem()) {
				return true
			}
		case *types.Slice:
			if w.indirect && w.reach(held.Elem()) {
				return true
			}
		case *types.Map:
			if w.indirect && (w.reach(held.Key()) || w.reach(held.Elem())) {
				return true
			}
		case *types.TypeParam:
			if constraint := held.Constraint(); constraint != nil && w.reach(constraint) {
				return true
			}
		}
		return false
	}
	switch under := under.(type) {
	case *types.Signature:
		// A CALLABLE hands back whatever it returns. `func() any` is a handler
		// one call away when the body builds one.
		for i := range under.Results().Len() {
			if w.reach(under.Results().At(i).Type()) {
				return true
			}
		}
	case *types.Interface:
		// An interface hands back its methods' results.
		for i := range under.NumMethods() {
			signature, ok := under.Method(i).Type().(*types.Signature)
			if !ok {
				continue
			}
			for r := range signature.Results().Len() {
				if w.reach(signature.Results().At(r).Type()) {
					return true
				}
			}
		}
	case *types.Pointer:
		if w.reach(under.Elem()) {
			return true
		}
	case *types.Slice:
		if w.reach(under.Elem()) {
			return true
		}
	case *types.Array:
		if w.reach(under.Elem()) {
			return true
		}
	case *types.Map:
		// Both halves: a map keyed by a carrier carries it too.
		if w.reach(under.Key()) || w.reach(under.Elem()) {
			return true
		}
	case *types.Chan:
		if w.reach(under.Elem()) {
			return true
		}
	case *types.Struct:
		for i := range under.NumFields() {
			field := under.Field(i)
			if w.fields == reachableFields && !field.Exported() && !field.Embedded() {
				continue
			}
			if w.reach(field.Type()) {
				return true
			}
		}
	case *types.TypeParam:
		// A type parameter carries whatever its constraint admits.
		if terms := under.Constraint(); terms != nil {
			if w.reach(terms) {
				return true
			}
		}
	}
	return false
}

// exposesMountableHandler: does a value of this type IS or CARRY something
// mountable, anywhere in its type graph?
func (g typedGate) exposesMountableHandler(t types.Type) (bool, string) {
	return g.walk(t, g.mountableHandlerType, reachableFields)
}

// opaqueForHandler: does this type carry an interface A HANDLER COULD BE
// STORED IN — the point at which static types stop answering?
//
// It runs through the same walk, so `func() any`, `[]any`, `struct{ H any }`
// and a method returning one are all one case. Reaching callable results is
// what closed the escape: the old predicate had no signature traversal, so a
// `func() any` result skipped the body check entirely.
func (g typedGate) opaqueForHandler(t types.Type) (bool, string) {
	return g.walk(t, func(candidate types.Type) bool {
		iface, ok := types.Unalias(candidate).Underlying().(*types.Interface)
		if !ok || g.handler == nil {
			return false
		}
		// `any` can hold a handler; `error` cannot, and every function returns
		// one. Asking whether http.Handler implements the interface is the
		// type-driven form of "could a handler hide here".
		return types.Implements(g.handler, iface)
	}, reachableFields)
}

// carriesCoreWire: does this type IS or CARRY one of core's wire messages?
//
// Every field counts, exported or not: allocating a struct allocates its
// unexported fields, so `struct{ seal wc.SealedValues }` constructs a seal as
// much as an exported one does. This is what closed the concrete wrapper —
// `new(reviewBox)` where reviewBox holds a SealedValues allocates a capability,
// and pointer-stripping plus a top-level package check could not see it.
// decodesIntoCoreWire is carriesCoreWire for a DESTINATION, which a decoder
// allocates through: a `*struct{ Seal *SealedValues }` destination has a seal
// written into it even though constructing that struct allocates none.
func (g typedGate) decodesIntoCoreWire(t types.Type) (string, string) {
	var carried string
	_, unresolved := g.walk(t, func(candidate types.Type) bool {
		if path := coreWireType(candidate); path != "" {
			carried = path
			return true
		}
		return false
	}, everyField, withinThisPackage(g.pkgPath), throughIndirection)
	return carried, unresolved
}

func (g typedGate) carriesCoreWire(t types.Type) (string, string) {
	var carried string
	_, unresolved := g.walk(t, func(candidate types.Type) bool {
		if path := coreWireType(candidate); path != "" {
			carried = path
			return true
		}
		return false
	}, everyField, withinThisPackage(g.pkgPath), storageGraph)
	return carried, unresolved
}

// TestNoExportedPathHandsOutAServableHandlerByType is the handler-export gate,
// on resolved types.
func TestNoExportedPathHandsOutAServableHandlerByType(t *testing.T) {
	for _, pkg := range gatePackages(t, nil) {
		if strings.HasSuffix(pkg.PkgPath, "/passthroughtest") {
			// passthroughtest is where a consumer's TEST is supposed to get a
			// handler; it refuses a non-test binary instead, which
			// TestTheSeamRefusesANonTestBinary drives.
			continue
		}
		for _, finding := range reportHandlerShapes(t, pkg) {
			t.Error(finding)
		}
	}
}

// reportHandlerShapes is every exported declaration in one package that hands
// out something servable. Factored out so the compiled fixtures below drive
// THIS rule rather than a copy of its reasoning.
func reportHandlerShapes(_ *testing.T, pkg *packages.Package) []string {
	g := gateFor(pkg)
	var findings []string
	report := func(format string, args ...any) {
		findings = append(findings, fmt.Sprintf(format, args...))
	}
	servable := func(where, name string, signature types.Type) {
		fn, ok := signature.(*types.Signature)
		if !ok {
			return
		}
		for i := range fn.Results().Len() {
			result := fn.Results().At(i).Type()
			switch {
			case g.handedOutDirectly(result):
				report("%s exports %s returning %s: a servable handler obtained outside Serve has skipped validate(), the mTLS boot, the caller allow-list, the ceiling and authenticated outbound. Let Serve mount it.",
					where, name, types.TypeString(result, nil))
			case isEmptyInterface(result):
				report("%s exports %s returning the empty interface: nothing can tell from the signature whether what comes back is servable. Declare the concrete type.",
					where, name)
			default:
				exposes, unresolved := g.exposesMountableHandler(result)
				if unresolved != "" {
					// FAIL CLOSED. A traversal that could not finish is not a
					// traversal that found nothing — the previous walks
					// returned false past a depth cap, so nesting escaped
					// them.
					report("%s exports %s returning %s and the gate COULD NOT DECIDE what it carries: %s. Declare a concrete type the gate can resolve.",
						where, name, types.TypeString(result, nil), unresolved)
				}
				if exposes {
					report("%s exports %s returning %s, which exposes a servable handler through a reachable field, element, callable result or method: a caller reaches it and has a handler built without the boot.",
						where, name, types.TypeString(result, nil))
				}
			}
		}
	}
	// A HANDLER FLOWING INTO AN OPAQUE RESULT.
	//
	// `func (s *Server) Routes() struct{ H any } { return struct{ H any }{H:
	// s.wrapRequest(…)} }` cannot be decided from the result type: `any`
	// carries no handler statically, and refusing every interface-typed field
	// would refuse Operation.Request and Operation.Response, which are `any`
	// by design and hold a consumer's message rather than anything built here.
	//
	// So the VALUE is followed instead of the declaration. If an exported
	// function's results contain an interface anywhere — the point at which
	// the type system stops being able to answer — and its body has a value in
	// hand whose type IS mountable, then this function demonstrably builds a
	// handler and hands it out through a hole static types cannot see into.
	// That is the fail-closed direction, and it is narrow: a function whose
	// results are all concrete is judged by the walk, and a function that
	// builds no handler is not judged at all.
	for _, file := range pkg.Syntax {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !fn.Name.IsExported() || fn.Type.Results == nil {
				continue
			}
			g := gateFor(pkg)
			opaque, unresolved := false, ""
			for _, result := range fn.Type.Results.List {
				carries, why := g.opaqueForHandler(pkg.TypesInfo.TypeOf(result.Type))
				opaque = opaque || carries
				if why != "" && unresolved == "" {
					unresolved = why
				}
			}
			if unresolved != "" {
				report("%s exports %s and the gate COULD NOT DECIDE whether its results carry an interface a handler could hide in: %s.",
					pkg.PkgPath, fn.Name.Name, unresolved)
			}
			if !opaque {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				expr, ok := node.(ast.Expr)
				if !ok {
					return true
				}
				held := pkg.TypesInfo.TypeOf(expr)
				if held == nil || !g.mountableHandlerType(held) {
					return true
				}
				report("%s exports %s, whose results carry an interface and whose body holds a %s: a handler built here is handed out through a field or result no static type can see into, and a caller asserts it back out. Let Serve mount it.",
					pkg.PkgPath, fn.Name.Name, types.TypeString(held, nil))
				return false
			})
		}
	}
	scope := pkg.Types.Scope()
	for _, name := range scope.Names() {
		object := scope.Lookup(name)
		if !object.Exported() {
			continue
		}
		switch typed := object.(type) {
		case *types.Func:
			servable(pkg.PkgPath, name, typed.Type())
		case *types.Var, *types.Const:
			exposes, unresolved := g.exposesMountableHandler(object.Type())
			if unresolved != "" {
				report("%s exports %s and the gate COULD NOT DECIDE what its type carries: %s.", pkg.PkgPath, name, unresolved)
			}
			if exposes {
				report("%s exports %s, whose type exposes a servable handler: a caller holding it serves the viewer's bearer and this workload's credential over whatever it is mounted on.",
					pkg.PkgPath, name)
			}
		case *types.TypeName:
			for _, receiver := range []types.Type{object.Type(), types.NewPointer(object.Type())} {
				set := types.NewMethodSet(receiver)
				for i := range set.Len() {
					method := set.At(i).Obj()
					if method.Exported() {
						servable(pkg.PkgPath, name+"."+method.Name(), method.Type())
					}
				}
			}
		}
	}
	return findings
}

func isEmptyInterface(t types.Type) bool {
	iface, ok := types.Unalias(t).Underlying().(*types.Interface)
	return ok && iface.NumMethods() == 0 && iface.IsMethodSet()
}

// TestNoCapabilityIsConstructedOrDecodedByType is the capability gate, on
// resolved types: nothing here allocates one of core's wire messages, and
// nothing decodes into one.
//
// Reading one is untouched — holdSealedIdentity takes a *SealedValues and reads
// it through GetInstallationId — because the rule is on allocation and on
// decode destinations, not on the type appearing.
func TestNoCapabilityIsConstructedOrDecodedByType(t *testing.T) {
	for _, pkg := range gatePackages(t, nil) {
		for _, finding := range reportCapabilityShapes(t, pkg) {
			t.Error(finding)
		}
	}
}

// reportCapabilityShapes is every construction of, and decode into, one of
// core's wire messages in one package. The fixtures below drive this rule.
func reportCapabilityShapes(_ *testing.T, pkg *packages.Package) []string {
	var findings []string
	report := func(format string, args ...any) {
		findings = append(findings, fmt.Sprintf(format, args...))
	}
	info := pkg.TypesInfo
	g := gateFor(pkg)
	// Every instantiation in the package, walked for what its type arguments
	// CARRY — not merely what they are. A generic's `new(T)` sees a type
	// parameter, so the instantiation is where the concrete type exists; and
	// `alloc[box, *box]()` carries the capability one field inside box, which
	// is where two type parameters and an alias hid it.
	for ident, instance := range info.Instances {
		if instance.TypeArgs == nil {
			continue
		}
		for i := range instance.TypeArgs.Len() {
			path, unresolved := g.carriesCoreWire(instance.TypeArgs.At(i))
			if unresolved != "" {
				report("%s instantiates %s and the gate COULD NOT DECIDE what the type argument carries: %s.", pkg.PkgPath, ident.Name, unresolved)
				continue
			}
			if path != "" {
				report("%s instantiates %s with a type carrying %s: a generic over one of core's wire messages allocates and decodes one wherever it is used, and the allocation site sees only a type parameter. Read the seal through Credential.Seal().",
					pkg.PkgPath, ident.Name, path)
			}
		}
	}
	for _, file := range pkg.Syntax {
		// Per declaration, so a finding names the function it is in. An
		// assertion per SHAPE is possible then, where a count over the whole
		// file let a missing rule hide behind the other shapes' findings —
		// which is exactly what mutant T6 showed: dropping `Decode` from the
		// matcher removed one finding and the count still passed.
		for _, decl := range file.Decls {
			where := pkg.PkgPath
			if fn, ok := decl.(*ast.FuncDecl); ok {
				where += "." + fn.Name.Name
			}
			inspectForCapabilities(g, decl, where, info, report)
		}
	}
	return findings
}

// inspectForCapabilities is the capability rule over one declaration.
// reportCarrier asks one of the carrier walks and turns its answer — including
// "could not decide" — into a finding. Fail-closed is the default: a gate that
// cannot see is not a gate that passes.
func reportCarrier(ask func(types.Type) (string, string), t types.Type, said, where string, report func(string, ...any), args ...any) {
	path, unresolved := ask(t)
	if unresolved != "" {
		report("%s: the gate COULD NOT DECIDE whether %s carries one of core's wire messages: %s. Use a concrete type the gate can resolve.",
			where, types.TypeString(t, nil), unresolved)
		return
	}
	if path == "" {
		return
	}
	report(said, append(args, path)...)
}

func inspectForCapabilities(g typedGate, decl ast.Node, where string, info *types.Info, report func(string, ...any)) {
	// EVERY question here goes through the same fixed-point walk, so a
	// CONCRETE WRAPPER is one case with everything else. `type box struct{
	// Seal wc.SealedValues }` allocated with `new(box)` constructs a
	// capability, and decoding into a `*box` decodes one — pointer-stripping
	// plus a top-level package check saw neither, because the wire type was
	// one field in.
	carries := func(t types.Type, said string, args ...any) {
		reportCarrier(g.carriesCoreWire, t, said, where, report, args...)
	}
	// A DESTINATION is reached through indirection: a decoder allocates
	// through the pointers and slices in it.
	destination := func(t types.Type, said string, args ...any) {
		reportCarrier(g.decodesIntoCoreWire, t, said, where, report, args...)
	}
	ast.Inspect(decl, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.CompositeLit:
			carries(info.TypeOf(typed),
				"%s constructs a value carrying %s: allocating one of core's wire messages is what decoding into it requires, and a second reader of that encoding is this boundary's whole subject. Read the seal through Credential.Seal().",
				where)
		case *ast.ValueSpec:
			if typed.Type == nil {
				return true
			}
			carries(info.TypeOf(typed.Type),
				"%s declares a value carrying %s, whose zero value allocates core's wire message: see Credential.Seal().",
				where)
		case *ast.CallExpr:
			if called, ok := typed.Fun.(*ast.Ident); ok && called.Name == "new" && len(typed.Args) == 1 {
				carries(info.TypeOf(typed.Args[0]),
					"%s allocates a value carrying %s with new(): see Credential.Seal().", where)
				return true
			}
			// A GENERIC is asked at its INSTANTIATION, because `new(T)` sees
			// only a type parameter. The type ARGUMENT is then walked, so
			// `alloc[box, *box]()` is caught through box's own field — two
			// type parameters and an alias deep.
			if ident, ok := typed.Fun.(*ast.Ident); ok {
				if instance, instantiated := info.Instances[ident]; instantiated && instance.TypeArgs != nil {
					for i := range instance.TypeArgs.Len() {
						carries(instance.TypeArgs.At(i),
							"%s instantiates %s with a type carrying %s: a generic over one of core's wire messages allocates and decodes one wherever it is used, and the allocation site sees only a type parameter. Read the seal through Credential.Seal().",
							where, ident.Name)
					}
				}
			}
			if selector, ok := typed.Fun.(*ast.SelectorExpr); ok {
				if instance, instantiated := info.Instances[selector.Sel]; instantiated && instance.TypeArgs != nil {
					for i := range instance.TypeArgs.Len() {
						carries(instance.TypeArgs.At(i),
							"%s instantiates %s with a type carrying %s: see Credential.Seal().",
							where, selector.Sel.Name)
					}
				}
			}
			// HANDING A CAPABILITY TO SOMETHING THAT TAKES IT AS AN OPAQUE
			// MESSAGE is handing it to a codec, and that is decided by the
			// callee's SIGNATURE rather than its name — so a decoder reached
			// through a function variable is one case with a named one.
			// `holdSealedIdentity(seal *workcontext.SealedValues)` takes it
			// CONCRETELY and is the supported way to read one, so it is not
			// flagged.
			if signature, ok := types.Unalias(info.TypeOf(typed.Fun)).(*types.Signature); ok {
				for i, arg := range typed.Args {
					parameter := parameterAt(signature, i)
					if parameter == nil {
						continue
					}
					if _, opaque := types.Unalias(parameter).Underlying().(*types.Interface); !opaque {
						continue
					}
					// The carried path is the LAST argument reportCarrier
					// appends, so it is the last placeholder here. It was
					// second, and the refusal printed
					// `%!s(int=1)` and `%!d(string=…/WorkSealV1)` — a garbled
					// message on the one path whose job is to tell an author
					// exactly what they did.
					destination(info.TypeOf(arg),
						"%s hands a value to something that takes it as an opaque message (parameter %d is an interface), and that value carries %s: that is a codec, whatever the call is spelled like. Read the seal through Credential.Seal().",
						where, i)
				}
			}
			selector, ok := typed.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// Any decoder, by the shape of its name. The DESTINATION decides,
			// and its type is resolved — an assignment, a parameter, a field,
			// a package-level alias and a function-local alias are one case.
			if !strings.Contains(selector.Sel.Name, "Unmarshal") && !strings.Contains(selector.Sel.Name, "Decode") {
				return true
			}
			// The RECEIVER is a destination too: `b.Decode(raw)` on a
			// `*box` decodes into box, and only the arguments were examined.
			destinations := append([]ast.Expr{selector.X}, typed.Args...)
			for _, arg := range destinations {
				destination(info.TypeOf(arg),
					"%s decodes into a value carrying %s: that is a second reader of core's wire encoding, whoever allocated the destination. Read the seal through Credential.Seal().",
					where)
			}
		}
		return true
	})
}

// TestTheTypedGatesCatchEveryKnownShape drives the typed rules against every
// shape five review rounds produced — in fixtures that COMPILE.
//
// The overlay puts the fixture into this very package, so it is type-checked
// against the real `*Server`, the real `Handler`, and the pinned SDK. That is
// the point: the syntactic probes only parsed their text, so two of them
// asserted against `workcontext.WorkContextV1`, a type the SDK does not
// export, and reported for three rounds that the whole-capability rule worked.
// A fixture that does not compile now fails the load, loudly, before any
// assertion runs.
func TestTheTypedGatesCatchEveryKnownShape(t *testing.T) {
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "zz_typed_gate_fixture.go")

	// Every handler-export shape, each in its own exported declaration so the
	// gate names it. R13 G5u, R14 B4, R15 F2 and the earlier rounds' shapes.
	handlers := `package solution

import (
	nh "net/http"
)

type fixtureHidden = nh.Handler
type fixtureDefined nh.Handler
type fixtureChain = fixtureHidden
type fixtureServes func(nh.ResponseWriter, *nh.Request)
type fixtureCarrier struct{ H fixtureHidden }
type fixtureNested struct{ In fixtureCarrier }
type fixtureEmbeds struct{ nh.Handler }

// An embedded type whose own NAME is unexported still promotes its exported
// field, so a caller reaches .H. The field walk's embedded-field clause is
// what covers it: without this shape, mutant T4 (dropping that clause) went
// uncaught, because every other embedded fixture happened to have an exported
// type name. (No backticks here: this comment lives inside a raw string.)
type fixtureEmbedsUnexported struct{ fixtureCarrier }
type fixtureUnexported struct{ H nh.Handler }
type fixtureByMethod struct{}

func (fixtureByMethod) Mux() nh.Handler { return nil }

func (s *Server) FixtureAliasResult() fixtureHidden                 { return nil }
func (s *Server) FixtureDefinedResult() fixtureDefined              { return nil }
func (s *Server) FixtureChainResult() fixtureChain                  { return nil }
func (s *Server) FixtureServesResult() fixtureServes                { return nil }
func (s *Server) FixtureBareHandler() Handler                       { return nil }
func (s *Server) FixtureRequestHandler() RequestHandler             { return nil }
func (s *Server) FixtureCollection() map[string]fixtureHidden       { return nil }
func (s *Server) FixtureCarrier() fixtureCarrier                    { return fixtureCarrier{} }
func (s *Server) FixtureNested() fixtureNested                      { return fixtureNested{} }
func (s *Server) FixtureEmbeds() fixtureEmbeds                      { return fixtureEmbeds{} }
func (s *Server) FixtureEmbedsUnexported() fixtureEmbedsUnexported {
	return fixtureEmbedsUnexported{}
}
func (s *Server) FixtureUnexportedCarrier() fixtureUnexported       { return fixtureUnexported{} }
func (s *Server) FixtureAnonymous() struct{ H nh.Handler }          { return struct{ H nh.Handler }{} }
func (s *Server) FixtureAnonymousAliased() struct{ H fixtureHidden } { return struct{ H fixtureHidden }{} }
func (s *Server) FixtureAnonymousNested() struct{ In struct{ H nh.Handler } } {
	return struct{ In struct{ H nh.Handler } }{}
}
func (s *Server) FixtureAnonymousEmbeds() struct{ nh.Handler }   { return struct{ nh.Handler }{} }
func (s *Server) FixtureAnonymousSlice() []struct{ H nh.Handler } { return nil }
func (s *Server) FixtureByMethod() fixtureByMethod                { return fixtureByMethod{} }
func (s *Server) FixtureAny() any                                 { return nil }
func (s *Server) FixtureRoundTripper() nh.RoundTripper            { return nil }

// The CONTROL: a declaration type, which is how a consumer writes routes.
// Operation.Handler is this package's own Handler, and it needs a *Gateway
// that only a booted request produces — so one carried here is inert, and
// refusing it would refuse the documented API. It must NOT be flagged.
type fixtureDeclaration struct {
	Handler        Handler
	RequestHandler RequestHandler
}

func (s *Server) FixtureDeclaration() []fixtureDeclaration { return nil }
`
	wantFlagged := []string{
		"FixtureAliasResult", "FixtureDefinedResult", "FixtureChainResult", "FixtureServesResult",
		"FixtureBareHandler", "FixtureRequestHandler", "FixtureCollection",
		"FixtureCarrier", "FixtureNested", "FixtureEmbeds", "FixtureUnexportedCarrier",
		"FixtureAnonymous", "FixtureAnonymousAliased", "FixtureAnonymousNested",
		"FixtureAnonymousEmbeds", "FixtureAnonymousSlice", "FixtureEmbedsUnexported",
		"FixtureByMethod", "FixtureAny", "FixtureRoundTripper",
	}
	flagged := gateFindings(t, fixture, handlers, reportHandlerShapes)
	for _, want := range wantFlagged {
		if !strings.Contains(flagged, want) {
			t.Errorf("the handler gate did not flag %s: that shape hands out a handler built without the boot", want)
		}
	}
	// And the one that must NOT be flagged: a struct a consumer DECLARES
	// routes with. Operation.Handler is this package's own Handler, which
	// needs a *Gateway only a booted request produces.
	if strings.Contains(flagged, "FixtureDeclaration") {
		t.Errorf("the handler gate flagged a declaration type, which is the documented way to use this package: %s", flagged)
	}

	// Every capability shape: R13's supplied destination, R14's zero value,
	// R15's assignment and function-local aliases, Decode, and the SDK's real
	// whole-capability alias.
	capabilities := `package solution

import (
	"encoding/json"
	"io"

	"google.golang.org/protobuf/proto"
	wc "github.com/codefly-dev/sdk-go/workcontext"
)

type fixtureSeal = wc.SealedValues

func fixtureSupplied(raw []byte, dst *wc.SealedValues) error { return proto.Unmarshal(raw, dst) }
func fixtureZeroValue(raw []byte) error {
	var dst wc.SealedValues
	return proto.Unmarshal(raw, &dst)
}
func fixtureAssigned(raw []byte, dst *wc.SealedValues) error {
	target := dst
	return proto.Unmarshal(raw, target)
}
func fixtureTwoHops(raw []byte, dst *wc.SealedValues) error {
	a := dst
	b := a
	return proto.Unmarshal(raw, b)
}
func fixturePackageAlias(raw []byte) error {
	var dst fixtureSeal
	return proto.Unmarshal(raw, &dst)
}
func fixtureLexicalAlias(raw []byte) error {
	type localSeal = wc.SealedValues
	var dst localSeal
	return proto.Unmarshal(raw, &dst)
}
func fixtureWholeCapability(raw []byte) error {
	var dst wc.Claims
	return proto.Unmarshal(raw, &dst)
}
func fixtureOperationBinding(raw []byte, dst *wc.SealedOperationBinding) error {
	return proto.Unmarshal(raw, dst)
}
func fixtureJSONDecode(r io.Reader, dst *wc.SealedValues) error {
	return json.NewDecoder(r).Decode(dst)
}
func fixtureLiteral() *wc.SealedValues { return &wc.SealedValues{} }
func fixtureNew() *wc.Claims           { return new(wc.Claims) }
func fixtureThroughAField(raw []byte, holder *struct{ Seal *wc.SealedValues }) error {
	return proto.Unmarshal(raw, holder.Seal)
}
func fixtureAccessorOnly(seal *wc.SealedValues) string { return seal.GetInstallationId() }
`
	decoded := gateFindings(t, fixture, capabilities, reportCapabilityShapes)
	// ONE ASSERTION PER SHAPE, by the function it is in.
	//
	// This was a count, and mutant T6 showed why that is not enough: dropping
	// `Decode` from the matcher removed one finding out of thirteen and the
	// count still passed. A missing rule hid behind the other shapes.
	for _, want := range []string{
		"fixtureSupplied", "fixtureZeroValue", "fixtureAssigned", "fixtureTwoHops",
		"fixturePackageAlias", "fixtureLexicalAlias", "fixtureWholeCapability",
		"fixtureOperationBinding", "fixtureJSONDecode", "fixtureLiteral",
		"fixtureNew", "fixtureThroughAField",
	} {
		if !strings.Contains(decoded, want) {
			t.Errorf("the capability gate did not flag %s, so that construction or decode shape escapes:\n%s", want, decoded)
		}
	}
	// And the one that must NOT be flagged: reading a seal through the SDK's
	// accessors, which is what credential.go does.
	if strings.Contains(decoded, "fixtureAccessorOnly") {
		t.Errorf("the capability gate flagged reading a seal through Credential.Seal()'s accessors, which is the one supported way to do it:\n%s", decoded)
	}
}

// parameterAt is the type of the parameter one argument lands on, accounting
// for a variadic tail.
func parameterAt(signature *types.Signature, i int) types.Type {
	params := signature.Params()
	if i < params.Len() {
		if signature.Variadic() && i == params.Len()-1 {
			if slice, ok := params.At(i).Type().(*types.Slice); ok {
				return slice.Elem()
			}
		}
		return params.At(i).Type()
	}
	if signature.Variadic() && params.Len() > 0 {
		if slice, ok := params.At(params.Len() - 1).Type().(*types.Slice); ok {
			return slice.Elem()
		}
	}
	return nil
}

// gateFindings loads this package with one extra COMPILED file and returns
// whatever the given rule reports about it.
func gateFindings(t *testing.T, path, source string, rule func(*testing.T, *packages.Package) []string) string {
	t.Helper()
	// A sub-test collects the findings instead of failing: these fixtures are
	// SUPPOSED to be refused.
	var findings []string
	for _, pkg := range gatePackages(t, map[string][]byte{path: []byte(source)}) {
		if pkg.PkgPath != "github.com/codefly-dev/solution-runtime-go" {
			continue
		}
		findings = append(findings, rule(t, pkg)...)
	}
	return strings.Join(findings, "\n") + "\n"
}

// TestTheTypedGateRefusesAFixtureThatDoesNotCompile is the check the syntactic
// probes did not have, and the reason three rounds of evidence were false.
//
// Two of those probes asserted against `workcontext.WorkContextV1`. The SDK
// does not export that name — it exports `Claims` — and because a probe only
// PARSED its fixture, a type that cannot exist reported that the
// whole-capability rule worked. Here a fixture naming a nonexistent type must
// fail the load, so a fixture can never again be evidence for a rule it did
// not reach.
func TestTheTypedGateRefusesAFixtureThatDoesNotCompile(t *testing.T) {
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "zz_typed_gate_noncompiling.go")
	// The exact mistake: a type the pinned SDK does not export.
	source := `package solution

import wc "github.com/codefly-dev/sdk-go/workcontext"

func fixtureNonexistent() *wc.WorkContextV1 { return nil }
`
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedImports,
		Overlay: map[string][]byte{fixture: []byte(source)},
	}
	loaded, err := packages.Load(cfg, ".")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	errors := 0
	for _, pkg := range loaded {
		errors += len(pkg.Errors)
	}
	if errors == 0 {
		t.Fatal("a fixture naming workcontext.WorkContextV1 type-checked, which cannot be: the SDK exports Claims and not that name. If this ever passes, a fixture can assert against a type that does not exist — which is how two probes reported for three rounds that the whole-capability rule worked.")
	}
	// And the gate helper must REFUSE such a load rather than reporting on it.
	//
	// In a goroutine of its own, because gatePackages refuses with t.Fatalf —
	// which is runtime.Goexit, and Goexit cannot be recovered: run inline it
	// terminates this test rather than being observed by it.
	refused := &testing.T{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		gatePackages(refused, map[string][]byte{fixture: []byte(source)})
	}()
	<-done
	if !refused.Failed() {
		t.Error("gatePackages accepted a package that does not type-check, so a non-compiling fixture could still supply findings")
	}
}

// TestTheTypedDecodeGateNeedsNoSpelling pins the shapes round sixteen named,
// where the destination or the callee is written in a way no name-matching
// rule follows.
//
// Each of these was reported as an escape of the syntactic rule, and each is
// one case here rather than a branch: a parenthesized destination and a call
// inside a function literal are resolved by `info.TypeOf`, and a decoder
// reached through a function VARIABLE is caught by the callee's signature —
// it takes the capability as an opaque interface, which is what a codec does.
func TestTheTypedDecodeGateNeedsNoSpelling(t *testing.T) {
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(dir, "zz_typed_spelling_fixture.go")
	source := `package solution

import (
	"google.golang.org/protobuf/proto"
	wc "github.com/codefly-dev/sdk-go/workcontext"
)

// A parenthesized destination.
func fixtureParenthesized(raw []byte, dst *wc.SealedValues) error {
	return proto.Unmarshal(raw, (dst))
}

// The decoder reached through a function VARIABLE, so there is no selector to
// match and no name to read.
func fixtureThroughAVariable(raw []byte, dst *wc.SealedValues) error {
	decode := proto.Unmarshal
	return decode(raw, dst)
}

// Inside a function literal, with its own binding.
func fixtureInsideAClosure(raw []byte) func() error {
	return func() error {
		var dst wc.SealedValues
		return proto.Unmarshal(raw, &dst)
	}
}

// A decoder whose destination parameter is CONCRETE. The signature rule does
// not fire — nothing is being handed over as an opaque message — so this is
// the shape the name check still earns its keep on, and the reason both rules
// exist. A generated UnmarshalVT-style method has exactly this shape.
type fixtureCodec struct{}

func (fixtureCodec) DecodeSeal(raw []byte, dst *wc.SealedValues) error { return nil }

func fixtureConcreteDecoder(raw []byte, dst *wc.SealedValues) error {
	return fixtureCodec{}.DecodeSeal(raw, dst)
}

// The supported read, which must stay unflagged: a concrete parameter, and no
// decoder in sight.
func fixtureSpellingAccessor(seal *wc.SealedValues) string { return seal.GetImageDigest() }
`
	found := gateFindings(t, fixture, source, reportCapabilityShapes)
	for _, want := range []string{
		"fixtureParenthesized", "fixtureThroughAVariable", "fixtureInsideAClosure",
		// Caught by the NAME rule alone: its destination parameter is
		// concrete, so the signature rule has nothing to say about it.
		"fixtureConcreteDecoder",
	} {
		if !strings.Contains(found, want) {
			t.Errorf("the capability gate did not flag %s, so that spelling still escapes:\n%s", want, found)
		}
	}
	if strings.Contains(found, "fixtureSpellingAccessor") {
		t.Errorf("the capability gate flagged a read through the SDK's accessors, which takes the seal as a CONCRETE parameter and is the one supported way to read one:\n%s", found)
	}
}

// TestTheTypedGatesFollowValuesNotShapes pins the confirming round's two gate
// findings, in the reviewer's own shapes.
//
// Both were the class the go/types rebuild was meant to close, and both got
// past it because the traversal was still enumerating shapes it knew — a
// struct, a slice, a map — rather than following every value whose TYPE
// carries a handler or a decoder. An interface-typed field is where the type
// system stops answering, and a generic's allocation site sees a type
// parameter rather than the concrete instantiation.
func TestTheTypedGatesFollowValuesNotShapes(t *testing.T) {
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}

	// A handler built HERE, handed out through `any`. The caller mounts
	// `Routes().H.(http.Handler)` and has the wrapper without the boot.
	opaque := filepath.Join(dir, "zz_typed_opaque_fixture.go")
	handlers := gateFindings(t, opaque, `package solution

import "net/http"

func (s *Server) FixtureOpaqueField() struct{ H any } {
	return struct{ H any }{H: s.wrapRequest(func(*http.Request, *Gateway) (any, error) { return nil, nil })}
}

func (s *Server) FixtureCallableResult() struct{ H func() http.Handler } {
	return struct{ H func() http.Handler }{}
}
`, reportHandlerShapes)
	for _, want := range []string{"FixtureOpaqueField", "FixtureCallableResult"} {
		if !strings.Contains(handlers, want) {
			t.Errorf("the handler gate did not flag %s:\n%s", want, handlers)
		}
	}

	// A generic allocation, and a decoder reached through a function variable
	// whose destination is a DOUBLE pointer.
	generic := filepath.Join(dir, "zz_typed_generic_fixture.go")
	capabilities := gateFindings(t, generic, `package solution

import (
	"encoding/json"

	wc "github.com/codefly-dev/sdk-go/workcontext"
)

func fixtureAlloc[T any]() *T { return new(T) }

func fixtureReadSeal(raw []byte) (*wc.SealedValues, error) {
	dst := fixtureAlloc[wc.SealedValues]()
	decode := json.Unmarshal
	err := decode(raw, &dst)
	return dst, err
}

// The DESTINATION rule on its own. This codec's parameter is concrete, so the
// opaque-parameter rule does not fire and only dereferencing the destination
// all the way down reaches the wire type. Without it the two rules overlapped
// on one fixture and neither was pinned alone.
type fixtureCodec struct{}

func (fixtureCodec) UnmarshalInto(dst **wc.SealedValues) {}

func fixtureHandRoundAboutDestination() {
	dst := fixtureAlloc[wc.SealedValues]()
	var codec fixtureCodec
	codec.UnmarshalInto(&dst)
}
`, reportCapabilityShapes)
	// The instantiation is the construction, and the double-pointer
	// destination is the decode. Both must be named.
	if !strings.Contains(capabilities, "fixtureAlloc") {
		t.Errorf("the capability gate did not flag the generic instantiated with core's wire message, so a generic allocation still escapes:\n%s", capabilities)
	}
	for _, want := range []string{"fixtureReadSeal", "fixtureHandRoundAboutDestination"} {
		if !strings.Contains(capabilities, want) {
			t.Errorf("the capability gate did not flag %s, so a destination behind two pointers still escapes:\n%s", want, capabilities)
		}
	}

	// CONTROLS, because both new rules are the fail-closed kind and a gate
	// nobody can satisfy gets loosened by whoever hits it next.
	controls := filepath.Join(dir, "zz_typed_control_fixture.go")
	clean := gateFindings(t, controls, `package solution

import (
	"net/http"

	wc "github.com/codefly-dev/sdk-go/workcontext"
)

// `+"`error`"+` is an interface, and every function here returns one. A handler
// cannot be stored in it, so it is not a hole a handler hides in — and this
// one BUILDS a mountable value, which is what makes it discriminating: a rule
// that treated every interface as opaque would flag it, and a mutant that
// removes the "a handler could be stored in it" condition is caught here.
// That is Serve's own shape.
func FixtureBuildsAMuxAndReturnsAnError() error {
	mux := http.NewServeMux()
	_ = mux
	return nil
}

// `+"`any`"+` fields that hold a consumer's message, which is Operation.Request
// and Operation.Response. Nothing mountable is built here.
func FixtureDeclaresBodies() struct {
	Request  any
	Response any
} {
	return struct {
		Request  any
		Response any
	}{}
}

// Reading a seal through the SDK's accessors.
func FixtureReadsASeal(seal *wc.SealedValues) string { return seal.GetInstallationId() }
`, reportHandlerShapes)
	if clean != "\n" && strings.TrimSpace(clean) != "" {
		t.Errorf("the handler gate refused shapes that are the documented way to use this package:\n%s", clean)
	}
}

// TestTheTypedGatesReachAFixedPoint pins the confirming round's two escapes,
// in the reviewer's own shapes, plus the exhaustion both earlier walks failed
// open on.
//
// These are not two more carriers added to a list. They are the two the fixed
// point exists for: an interface-typed RESULT (the previous rule closed the
// interface-typed FIELD and had no signature traversal at all) and a CONCRETE
// WRAPPER around a capability, behind two type parameters and an alias method
// (the previous rules stripped pointers and checked the top-level package, so
// a wire type one field in was invisible).
func TestTheTypedGatesReachAFixedPoint(t *testing.T) {
	dir, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}

	// A callable returning an opaque handler, and nine nested arrays.
	callable := filepath.Join(dir, "zz_typed_callable_fixture.go")
	handlers := gateFindings(t, callable, `package solution

import "net/http"

func (s *Server) FixtureCallableOpaque() func() any {
	return func() any {
		return s.wrapRequest(func(*http.Request, *Gateway) (any, error) { return nil, nil })
	}
}

// Depth the old walks failed OPEN on: both returned false past their caps, so
// nesting escaped them. The fixed point has no cap.
func (s *Server) FixtureDeeplyNested() [1][1][1][1][1][1][1][1][1]http.Handler {
	return [1][1][1][1][1][1][1][1][1]http.Handler{}
}
`, reportHandlerShapes)
	for _, want := range []string{"FixtureCallableOpaque", "FixtureDeeplyNested"} {
		if !strings.Contains(handlers, want) {
			t.Errorf("the handler gate did not flag %s:\n%s", want, handlers)
		}
	}

	// A concrete wrapper around a capability, behind two type parameters and
	// an alias method.
	wrapper := filepath.Join(dir, "zz_typed_wrapper_fixture.go")
	capabilities := gateFindings(t, wrapper, `package solution

import (
	"encoding/json"

	wc "github.com/codefly-dev/sdk-go/workcontext"
)

type fixtureBox struct{ Seal wc.SealedValues }
type fixtureBoxAlias = fixtureBox

func fixtureTwoParams[T any, P ~*T]() P { return P(new(T)) }

func (b *fixtureBoxAlias) DecodeFixture(raw []byte) error { return json.Unmarshal(raw, b) }

func fixtureReadWrapped(raw []byte) (string, error) {
	b := fixtureTwoParams[fixtureBoxAlias, *fixtureBoxAlias]()
	err := b.DecodeFixture(raw)
	return b.Seal.GetInstallationId(), err
}

// Even the plain allocation, which the reviewer noted escapes too.
func fixturePlainAllocation() *fixtureBoxAlias { return new(fixtureBoxAlias) }

// A decoder whose own body decodes NOTHING, so the only rule that can catch
// the call below is "the receiver is a destination too". Without it the
// receiver rule rode on the opaque-parameter rule firing inside
// DecodeFixture's body, and neither was pinned alone.
type fixtureReceiverOnly struct{ Seal wc.SealedValues }

func (b *fixtureReceiverOnly) UnmarshalFixture(raw []byte) error {
	b.Seal.InstallationId = string(raw)
	return nil
}

func fixtureDecodeThroughReceiver(raw []byte, b *fixtureReceiverOnly) error {
	return b.UnmarshalFixture(raw)
}

// An UNEXPORTED field is still allocated, so visibility cannot be the rule.
type fixtureHiddenBox struct{ seal wc.SealedValues }

func fixtureAllocateHidden() fixtureHiddenBox { return fixtureHiddenBox{} }
`, reportCapabilityShapes)
	for _, want := range []string{
		"fixtureTwoParams",       // the instantiation, through two type parameters
		"DecodeFixture",          // the receiver as a decode destination
		"fixturePlainAllocation", // new() on a wrapper
		"fixtureAllocateHidden",  // an unexported field
		// The receiver as a destination, with nothing else able to catch it.
		"fixtureDecodeThroughReceiver",
	} {
		if !strings.Contains(capabilities, want) {
			t.Errorf("the capability gate did not flag %s, so a concrete wrapper still hides a capability:\n%s", want, capabilities)
		}
	}

	// CONTROLS. Both walks are fail-closed, and a gate nobody can satisfy gets
	// loosened by whoever hits it next. These are the shapes production
	// actually has.
	controls := filepath.Join(dir, "zz_typed_fixedpoint_control_fixture.go")
	clean := gateFindings(t, controls, `package solution

import (
	"context"

	"github.com/codefly-dev/sdk-go/workcontext"
)

// Holding a source whose method returns the SDK's credential — which is an
// alias for one of core's wire messages — is not constructing one. The first
// run of the fixed point reported authorityHeldSource for exactly this, and
// the finding was mine, not the code's: a method RESULT is not an allocation.
type fixtureHolder struct {
	inner  CredentialSource
	anchor *workcontext.Credential
}

func fixtureHold(s CredentialSource) *fixtureHolder { return &fixtureHolder{inner: s} }

func fixtureReadThrough(ctx context.Context, s CredentialSource) (string, error) {
	held, err := s.Credential(ctx)
	if err != nil {
		return "", err
	}
	return held.Token(), nil
}

// Reading a seal through the SDK's accessors, which is the supported way.
func fixtureReadSealed(seal *workcontext.SealedValues) string { return seal.GetInstallationId() }
`, reportCapabilityShapes)
	if strings.TrimSpace(clean) != "" {
		t.Errorf("the capability gate refused shapes production has: holding the SDK's credential is not constructing core's wire message:\n%s", clean)
	}
}

// TestTheWalkRefusesWhatItCannotFinish pins the fail-closed half of the fixed
// point, which no fixture can reach: the budget is 50,000 nodes and a type
// graph that large cannot be written into a fixture, so the branch is asked
// directly.
//
// It matters because the two walks this replaced failed OPEN past a depth cap
// — they returned false, which reads as "carries nothing" — so a gate could be
// exhausted by nesting. A traversal that gives up has not answered, and the
// difference between those two is why this returns a reason alongside its
// verdict.
func TestTheWalkRefusesWhatItCannotFinish(t *testing.T) {
	pkgs := gatePackages(t, nil)
	if len(pkgs) == 0 {
		t.Fatal("no package loaded")
	}
	g := gateFor(pkgs[0])
	never := func(types.Type) bool { return false }

	// A graph larger than the budget allows.
	deep := types.Type(types.Typ[types.String])
	for range 64 {
		deep = types.NewPointer(deep)
	}
	w := &typeWalk{gate: g, match: never, fields: everyField,
		seen: map[types.Type]bool{}, budget: 8, indirect: true, storage: true}
	if w.reach(deep) {
		t.Fatal("the walk matched nothing and said it found something")
	}
	if w.unresolved == "" {
		t.Error(`the walk ran out of budget and reported nothing: a traversal that could not finish must not read as "carries nothing", which is how a depth cap let nesting escape the two walks this replaced`)
	}

	// An invalid type INSIDE a graph is the same answer. At the root it is not:
	// an expression with no type is not a value to decide about.
	w = &typeWalk{gate: g, match: never, fields: everyField,
		seen: map[types.Type]bool{}, budget: 50000, indirect: true, storage: true}
	w.reach(types.NewPointer(types.Typ[types.Invalid]))
	if w.unresolved == "" {
		t.Error("a type the checker could not resolve, inside a graph, was skipped rather than reported")
	}
}
