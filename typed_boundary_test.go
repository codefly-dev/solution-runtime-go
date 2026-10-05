package solution

import (
	"fmt"
	"go/ast"
	"go/types"
	"path/filepath"
	"strings"
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

// gatePackages loads this module's packages with full type information.
func gatePackages(t *testing.T, overlay map[string][]byte) []*packages.Package {
	t.Helper()
	cfg := &packages.Config{
		Mode: packages.NeedName | packages.NeedFiles | packages.NeedSyntax |
			packages.NeedTypes | packages.NeedTypesInfo | packages.NeedDeps | packages.NeedImports,
		Overlay: overlay,
	}
	loaded, err := packages.Load(cfg, ".", "./passthroughtest")
	if err != nil {
		t.Fatalf("load this module for type-resolved gating: %v", err)
	}
	if len(loaded) < 2 {
		t.Fatalf("loaded %d packages, want at least the root and passthroughtest: a gate that reads nothing passes", len(loaded))
	}
	for _, pkg := range loaded {
		// A fixture that does not COMPILE cannot supply evidence. This is the
		// check the parse-only probes did not have.
		for _, err := range pkg.Errors {
			t.Fatalf("%s does not type-check, so nothing below means anything: %v", pkg.PkgPath, err)
		}
		if pkg.TypesInfo == nil {
			t.Fatalf("%s loaded without type information", pkg.PkgPath)
		}
	}
	return loaded
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
type typedGate struct{ handler *types.Interface }

// gateFor resolves net/http.Handler out of one loaded package.
func gateFor(pkg *packages.Package) typedGate {
	if http := pkg.Imports["net/http"]; http != nil && http.Types != nil {
		if handler := http.Types.Scope().Lookup("Handler"); handler != nil {
			iface, _ := handler.Type().Underlying().(*types.Interface)
			return typedGate{handler: iface}
		}
	}
	return typedGate{}
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

// deref strips EVERY pointer.
//
// The decode rule used derefOnce, so a destination of type **SealedValues —
// which is what `dst := alloc[wc.SealedValues](); decode(raw, &dst)` produces
// — still had a pointer on it when coreWireType asked for its name, and a
// named type behind two pointers has no name at one. Indirection is not a
// shape to enumerate: whatever a value points at, through however many levels,
// is what a decoder writes into.
func deref(t types.Type) types.Type {
	for {
		pointer, ok := types.Unalias(t).(*types.Pointer)
		if !ok {
			return t
		}
		t = pointer.Elem()
	}
}

// exposesMountableHandler reports whether a caller holding this type can reach
// a mountable handler through it — a field, an embedded field, a method, or any
// of those inside a container or an unnamed struct.
//
// Recursive and cycle-guarded. This is what replaces localHandlerTypes and
// carriesAMountableHandler: it needs no declaration to visit, so an anonymous
// struct is no different from a named one, and it reads method sets, which the
// field walk could not.
func (g typedGate) exposesMountableHandler(t types.Type, seen map[types.Type]bool, depth int) bool {
	if t == nil || depth > 8 {
		return false
	}
	if seen == nil {
		seen = map[types.Type]bool{}
	}
	if seen[t] {
		return false
	}
	seen[t] = true

	if g.mountableHandlerType(t) {
		return true
	}
	// An exported method handing one back is the same exposure with a call in
	// the way.
	for _, receiver := range []types.Type{t, types.NewPointer(t)} {
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
				if g.mountableHandlerType(signature.Results().At(r).Type()) {
					return true
				}
			}
		}
	}
	switch under := types.Unalias(t).Underlying().(type) {
	case *types.Signature:
		// A CALLABLE that hands one back. `func() http.Handler` in a field or
		// a result is a handler one call away, and the walk had no signature
		// case at all.
		for i := range under.Results().Len() {
			if g.exposesMountableHandler(under.Results().At(i).Type(), seen, depth+1) {
				return true
			}
		}
	case *types.Pointer:
		return g.exposesMountableHandler(under.Elem(), seen, depth+1)
	case *types.Slice:
		return g.exposesMountableHandler(under.Elem(), seen, depth+1)
	case *types.Array:
		return g.exposesMountableHandler(under.Elem(), seen, depth+1)
	case *types.Map:
		return g.exposesMountableHandler(under.Elem(), seen, depth+1)
	case *types.Chan:
		return g.exposesMountableHandler(under.Elem(), seen, depth+1)
	case *types.Struct:
		for i := range under.NumFields() {
			field := under.Field(i)
			// Reachable: exported, or embedded (reachable by its own name).
			if !field.Exported() && !field.Embedded() {
				continue
			}
			if g.exposesMountableHandler(field.Type(), seen, depth+1) {
				return true
			}
		}
	}
	return false
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
			case g.exposesMountableHandler(result, nil, 0):
				report("%s exports %s returning %s, which exposes a servable handler through a reachable field or method: a caller reaches it and has a handler built without the boot.",
					where, name, types.TypeString(result, nil))
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
			if !resultsHoldAnInterface(gateFor(pkg), pkg.TypesInfo, fn.Type.Results) {
				continue
			}
			g := gateFor(pkg)
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
			if g.exposesMountableHandler(object.Type(), nil, 0) {
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

// resultsHoldAnInterface reports whether a result list contains an interface
// anywhere inside it — directly, or in a field of a struct it returns.
//
// This is the point where the type system stops being able to say what a value
// carries, which is why it is the point where the rule stops trusting types
// and starts looking at what the function actually built.
func resultsHoldAnInterface(g typedGate, info *types.Info, results *ast.FieldList) bool {
	var opaque func(types.Type, int) bool
	opaque = func(t types.Type, depth int) bool {
		if !resolved(t) || depth > 6 {
			return false
		}
		switch under := types.Unalias(t).Underlying().(type) {
		case *types.Interface:
			// Only an interface a HANDLER COULD BE STORED IN. `any` can hold
			// one; `error` cannot, and treating every interface as opaque made
			// every function returning an error qualify — which is all of
			// them. Asking whether http.Handler implements the interface is
			// the type-driven form of "could a handler hide here".
			return g.handler != nil && types.Implements(g.handler, under)
		case *types.Pointer:
			return opaque(under.Elem(), depth+1)
		case *types.Slice:
			return opaque(under.Elem(), depth+1)
		case *types.Array:
			return opaque(under.Elem(), depth+1)
		case *types.Map:
			return opaque(under.Elem(), depth+1)
		case *types.Chan:
			return opaque(under.Elem(), depth+1)
		case *types.Struct:
			for i := range under.NumFields() {
				field := under.Field(i)
				if (field.Exported() || field.Embedded()) && opaque(field.Type(), depth+1) {
					return true
				}
			}
		}
		return false
	}
	for _, result := range results.List {
		if opaque(info.TypeOf(result.Type), 0) {
			return true
		}
	}
	return false
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
	// A GENERIC INSTANTIATED WITH ONE OF CORE'S WIRE MESSAGES.
	//
	// `alloc[wc.SealedValues]()` where `func alloc[T any]() *T { return new(T)
	// }` allocates a capability, and at the `new(T)` the scanner sees a type
	// PARAMETER: there is no concrete type at the allocation site to ask
	// about. The instantiation is where the concrete type appears, and
	// info.Instances records it — so the question is asked where the answer
	// exists rather than where the allocation is written.
	for ident, instance := range info.Instances {
		for i := range instance.TypeArgs.Len() {
			if path := coreWireType(deref(instance.TypeArgs.At(i))); path != "" {
				report("%s instantiates %s with %s: a generic over one of core's wire messages allocates and decodes one wherever it is used, and the allocation site sees only a type parameter. Read the seal through Credential.Seal().",
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
			inspectForCapabilities(decl, where, info, report)
		}
	}
	return findings
}

// inspectForCapabilities is the capability rule over one declaration.
func inspectForCapabilities(decl ast.Node, where string, info *types.Info, report func(string, ...any)) {
	ast.Inspect(decl, func(node ast.Node) bool {
		switch typed := node.(type) {
		case *ast.CompositeLit:
			if path := coreWireType(info.TypeOf(typed)); path != "" {
				report("%s constructs %s: allocating one of core's wire messages is what decoding into it requires, and a second reader of that encoding is this boundary's whole subject. Read the seal through Credential.Seal().",
					where, path)
			}
		case *ast.ValueSpec:
			if typed.Type == nil {
				return true
			}
			if path := coreWireType(info.TypeOf(typed.Type)); path != "" {
				report("%s declares a %s, whose zero value is an allocation of core's wire message: see Credential.Seal().",
					where, path)
			}
		case *ast.CallExpr:
			if called, ok := typed.Fun.(*ast.Ident); ok && called.Name == "new" && len(typed.Args) == 1 {
				if path := coreWireType(info.TypeOf(typed.Args[0])); path != "" {
					report("%s allocates a %s with new(): see Credential.Seal().", where, path)
				}
				return true
			}
			// HANDING A CAPABILITY TO SOMETHING THAT TAKES IT AS AN OPAQUE
			// MESSAGE is handing it to a codec, and that is decided by the
			// callee's SIGNATURE rather than its name.
			//
			// The name check below needs a selector, so a decoder reached
			// through a function variable — `decode := proto.Unmarshal;
			// decode(raw, dst)` — escaped it. This rule needs no spelling at
			// all: it asks what the parameter's type is.
			// `proto.Unmarshal(b []byte, m proto.Message)` takes the
			// capability as an INTERFACE; `holdSealedIdentity(seal
			// *workcontext.SealedValues)` takes it concretely and is the
			// supported way to read one, so it is not flagged.
			if signature, ok := types.Unalias(info.TypeOf(typed.Fun)).(*types.Signature); ok {
				for i, arg := range typed.Args {
					path := coreWireType(deref(info.TypeOf(arg)))
					if path == "" {
						continue
					}
					parameter := parameterAt(signature, i)
					if parameter == nil {
						continue
					}
					if _, opaque := types.Unalias(parameter).Underlying().(*types.Interface); opaque {
						report("%s hands a %s to something that takes it as an opaque message (parameter %d is an interface): that is a codec, whatever the call is spelled like. Read the seal through Credential.Seal().",
							where, path, i)
					}
				}
			}
			selector, ok := typed.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			// Any decoder, by the shape of its name. The DESTINATION is
			// what decides, and its type is resolved — so an assignment, a
			// parameter, a field, a package-level alias and a
			// function-local alias are all one case here, which is why
			// this rule no longer grows a branch per spelling.
			if !strings.Contains(selector.Sel.Name, "Unmarshal") && !strings.Contains(selector.Sel.Name, "Decode") {
				return true
			}
			for _, arg := range typed.Args {
				if path := coreWireType(deref(info.TypeOf(arg))); path != "" {
					report("%s decodes into a %s: that is a second reader of core's wire encoding, whoever allocated the destination. Read the seal through Credential.Seal().",
						where, path)
				}
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
`, reportCapabilityShapes)
	// The instantiation is the construction, and the double-pointer
	// destination is the decode. Both must be named.
	if !strings.Contains(capabilities, "fixtureAlloc") {
		t.Errorf("the capability gate did not flag the generic instantiated with core's wire message, so a generic allocation still escapes:\n%s", capabilities)
	}
	if !strings.Contains(capabilities, "fixtureReadSeal") {
		t.Errorf("the capability gate did not flag the decode into a **SealedValues, so indirection still escapes:\n%s", capabilities)
	}

	// CONTROLS, because both new rules are the fail-closed kind and a gate
	// nobody can satisfy gets loosened by whoever hits it next.
	controls := filepath.Join(dir, "zz_typed_control_fixture.go")
	clean := gateFindings(t, controls, `package solution

import wc "github.com/codefly-dev/sdk-go/workcontext"

// `+"`error`"+` is an interface, and every function here returns one. A handler
// cannot be stored in it, so it is not a hole a handler hides in.
func FixtureReturnsAnError() error { return nil }

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
