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
	if t == nil {
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

func derefOnce(t types.Type) types.Type {
	if pointer, ok := types.Unalias(t).(*types.Pointer); ok {
		return pointer.Elem()
	}
	return t
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
	for _, file := range pkg.Syntax {
		ast.Inspect(file, func(node ast.Node) bool {
			switch typed := node.(type) {
			case *ast.CompositeLit:
				if path := coreWireType(info.TypeOf(typed)); path != "" {
					report("%s constructs %s: allocating one of core's wire messages is what decoding into it requires, and a second reader of that encoding is this boundary's whole subject. Read the seal through Credential.Seal().",
						pkg.PkgPath, path)
				}
			case *ast.ValueSpec:
				if typed.Type == nil {
					return true
				}
				if path := coreWireType(info.TypeOf(typed.Type)); path != "" {
					report("%s declares a %s, whose zero value is an allocation of core's wire message: see Credential.Seal().",
						pkg.PkgPath, path)
				}
			case *ast.CallExpr:
				if called, ok := typed.Fun.(*ast.Ident); ok && called.Name == "new" && len(typed.Args) == 1 {
					if path := coreWireType(info.TypeOf(typed.Args[0])); path != "" {
						report("%s allocates a %s with new(): see Credential.Seal().", pkg.PkgPath, path)
					}
					return true
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
					if path := coreWireType(derefOnce(info.TypeOf(arg))); path != "" {
						report("%s decodes into a %s: that is a second reader of core's wire encoding, whoever allocated the destination. Read the seal through Credential.Seal().",
							pkg.PkgPath, path)
					}
				}
			}
			return true
		})
	}
	return findings
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
		"FixtureAnonymousEmbeds", "FixtureAnonymousSlice",
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
	for _, want := range []string{
		"WorkSealV1", "WorkContextV1", "WorkOperationBindingV1",
	} {
		if !strings.Contains(decoded, want) {
			t.Errorf("the capability gate flagged nothing naming %s, so one of the decode or construction shapes escaped: %s", want, decoded)
		}
	}
	// Twelve shapes construct or decode; the accessor-only one does not.
	if got := strings.Count(decoded, "\n"); got < 12 {
		t.Errorf("the capability gate produced %d findings for 13 shapes, 12 of which must be flagged:\n%s", got, decoded)
	}
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
