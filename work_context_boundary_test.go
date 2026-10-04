package solution

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
)

// There is one implementation of a Work Context — core's — and this runtime is
// not it. This package obtains a capability through the SDK's mint client,
// carries it, and hands it to whatever verifies it; it never signs one, never
// parses one, and never declares the fields of one.
//
// The gate exists because the duplication it prevents already happened once, in
// a module whose only job was to carry these things: a second signed encoding
// grew inside an SDK beside core's, with its own payload struct, its own
// signer, its own verifier and its own error taxonomy, and 3,532 lines had to
// be deleted to get back to one. Every step of that was locally reasonable. The
// cheapest way to not repeat it is to make the first step fail a test here.
//
// What this checks is narrow on purpose: a signing primitive, and a type or
// function of this package's own that claims to be a Work Context. It does not
// forbid encoding/json — this package serves JSON documents for a living — and
// the one capability-shaped JSON this package does touch, the mint endpoint's
// HTTP bodies, lives in the SDK client and not here.
func TestNoWorkContextImplementationGrowsHere(t *testing.T) {
	fset := token.NewFileSet()
	for _, name := range moduleSources(t) {
		file, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			switch path {
			case "crypto/ed25519", "crypto/ecdsa", "crypto/hmac", "crypto/rsa", "crypto/ed25519/internal/edwards25519":
				t.Errorf("%s imports %s: signing a capability is core's, and a runtime that can sign one is a second implementation waiting to happen. Carry the credential the mint client hands you.",
					name, path)
			}
			// Core's generated protobuf package is the other road to a
			// capability's fields: holding basev0 means declaring, building
			// and decoding core's wire types directly, which is a second
			// reader of the encoding whatever it is named. Nothing here needs
			// it — the SDK re-exports the one type this runtime reads as
			// workcontext.SealedValues, and reads it through accessors.
			if strings.Contains(path, "codefly-dev/core/generated/") {
				t.Errorf("%s imports %s: core's generated wire types are how a second reader of the encoding starts. The credential's seal is reached through the SDK's Credential.Seal() accessor, which needs no generated import.",
					name, path)
			}
			// A JOSE or raw-segment path reaches the same place by another
			// road: the 3,532 lines that had to be deleted were a payload
			// struct, a signer, a verifier and an error taxonomy, and none of
			// them needed crypto/ed25519 by name.
			switch {
			case strings.HasPrefix(path, "golang.org/x/crypto"),
				strings.Contains(path, "go-jose"), strings.Contains(path, "jwt"),
				strings.Contains(path, "jws"), strings.Contains(path, "jwk"):
				t.Errorf("%s imports %s: a second signed encoding beside core's is what this boundary exists to prevent, and it does not have to be spelled crypto/ed25519 to be one.",
					name, path)
			}
		}
		// CONSTRUCTING one of core's capability messages, which is what a
		// home-made decode needs and what reading one never does.
		//
		// This is the escape an executed round named and the gates above do
		// not close: `proto.Unmarshal(raw, &workcontext.SealedValues{})`
		// compiles with nothing but the sdk-go import this package already
		// has, because SealedValues is a type ALIAS for core's
		// basev0.WorkSealV1 — so refusing the generated import, refusing a
		// signer and refusing a verifier all pass it. A second reader of the
		// seal does not need to be called a verifier to be one.
		//
		// The rule is on construction rather than on the type name, because
		// the type name appears legitimately: holdSealedIdentity takes a
		// *workcontext.SealedValues and reads it through GetInstallationId.
		// Decoding into one requires allocating it; reading one never does.
		for _, built := range coreCapabilityConstructions(file) {
			t.Errorf("%s constructs %s: allocating one of core's capability messages is what decoding into it requires, and a second decoder of that encoding is this boundary's whole subject. Read the seal through the SDK's Credential.Seal() accessor.",
				name, built)
		}
		// A declaration of this package's own that names itself after the thing
		// core owns. The two this package legitimately has are a refusal it
		// returns to a handler and the principals it reports from a mint
		// answer — neither is a capability, and both are named below so a third
		// has to be argued for rather than appearing.
		allowed := map[string]bool{"WorkContextRefusal": true, "WorkContextPrincipals": true}
		for _, decl := range file.Decls {
			var declared string
			switch node := decl.(type) {
			case *ast.FuncDecl:
				declared = node.Name.Name
			case *ast.GenDecl:
				for _, spec := range node.Specs {
					if typeSpec, ok := spec.(*ast.TypeSpec); ok && strings.Contains(typeSpec.Name.Name, "WorkContext") && !allowed[typeSpec.Name.Name] {
						t.Errorf("%s declares the type %s: a Work Context type in this package is core's type copied. Use the SDK's alias of core's, or carry the capability as the string it travels as.",
							name, typeSpec.Name.Name)
					}
				}
				continue
			}
			if strings.Contains(declared, "SignWorkContext") || strings.Contains(declared, "ParseWorkContext") || strings.Contains(declared, "VerifyWorkContext") {
				t.Errorf("%s declares %s: signing, parsing and verifying a capability are core's. This runtime presents one and lets the far end decide.", name, declared)
			}
		}
	}
}

// And the other half of not being an implementation: this runtime does not
// verify, and that is a design position rather than an omission.
//
// Core's verifier requires four live sources — the authorization revision,
// replay, grants and seals — and refuses everything without them, deliberately,
// so that the strongest check in the model cannot be the easiest to skip. A
// solution runtime holds none of those: it is the party presenting a
// capability, not the party that decides on one. So there is no verifier here
// to configure, and a future change that adds one has to answer where those
// four sources come from.
//
// This is not an exemption from Core's conformance kit. The kit runs — against
// the boundary this package does own, carriage, in
// TestCoreConformanceFixturesThroughTheCarrier — and it is what keeps the line
// below checkable: every fixture whose refusal is a property of the bytes in
// hand is refused here with Core's own sentinel, and every fixture whose
// refusal is a judgement against live state is carried, because claiming that
// judgement without the issuer's four sources is the silent downgrade this
// single-implementation rule exists to prevent.
func TestThisRuntimeVerifiesNothing(t *testing.T) {
	fset := token.NewFileSet()
	for _, name := range moduleSources(t) {
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, reached := range verifiersReachedBy(file) {
			t.Errorf("%s names %s: verifying a capability needs the issuer's live revision, replay, grant and seal sources, which this runtime does not hold. It presents its own credential and lets the component that holds them decide.",
				name, reached)
		}
		if dotted := dotImportedWorkContext(file); dotted != "" {
			// A dot-import makes every name in that package unqualified, so
			// nothing above could find them. It is also not a style this
			// package uses anywhere.
			t.Errorf("%s dot-imports %s: the names a verifier is built from would then be unqualified, which this gate cannot see and a reader cannot either", name, dotted)
		}
	}
}

// verifiersReachedBy is every way one file reaches a Work Context verifier,
// rendered as alias.Name.
//
// Separated from the test so the gate can be run against a file the test
// writes, which is the only way to show it catches an escape rather than
// merely passing over this package's current contents.
func verifiersReachedBy(file *ast.File) []string {
	var reached []string
	for alias := range workContextImports(file) {
		if alias == "." {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := selector.X.(*ast.Ident)
			if !ok || pkg.Name != alias {
				return true
			}
			// Every name a verifier can be reached by: the constructor, the
			// type (so a declared field or variable is caught as well as a
			// call), and the methods. A verifier cannot be obtained without
			// naming one of them through the package it lives in, which is
			// what makes matching on the name sufficient here — the earlier
			// rule matched only the call, so declaring the type and calling
			// a method on the value escaped it.
			//
			// Contains, not HasPrefix: the probe below caught that a prefix
			// rule misses NewVerifier, which is the most ordinary name a
			// verifier constructor can have. Nothing this package legitimately
			// names through these imports contains it.
			if strings.Contains(selector.Sel.Name, "Verif") {
				reached = append(reached, pkg.Name+"."+selector.Sel.Name)
			}
			return true
		})
	}
	return reached
}

// dotImportedWorkContext is the Work Context package this file dot-imports, if
// it does.
func dotImportedWorkContext(file *ast.File) string {
	for alias, path := range workContextImports(file) {
		if alias == "." {
			return path
		}
	}
	return ""
}

// TestTheVerifierGateCatchesASubpackage runs the gate against the escapes it
// has actually been shown to miss.
//
// The rule matched two import paths exactly, and
// core/workcontext/conformance — the published conformance kit this suite
// already uses — is neither of them while exporting Verifier(), which returns
// core's own *workcontext.Verifier. So the single import that hands this
// package a working verifier walked past the gate written to refuse exactly
// that. A gate on an enumerated path is only as good as the enumeration.
func TestTheVerifierGateCatchesASubpackage(t *testing.T) {
	for _, tc := range []struct {
		name   string
		source string
	}{
		{
			"the conformance subpackage under its own name",
			`package solution
import "github.com/codefly-dev/core/workcontext/conformance"
func f() { _ = conformance.Verifier() }`,
		},
		{
			"the conformance subpackage under an alias",
			`package solution
import kit "github.com/codefly-dev/core/workcontext/conformance"
func f() { _ = kit.Verifier() }`,
		},
		{
			"a deeper subpackage nobody has written yet",
			`package solution
import "github.com/codefly-dev/sdk-go/workcontext/whatever/next"
func f() { _ = next.NewVerifier() }`,
		},
		{
			"the package itself, which already failed the gate",
			`package solution
import "github.com/codefly-dev/core/workcontext"
func f() { _ = workcontext.Verifier() }`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "escape.go", tc.source, 0)
			if err != nil {
				t.Fatalf("parse the probe: %v", err)
			}
			if reached := verifiersReachedBy(file); len(reached) == 0 {
				t.Error("the gate did not see a verifier this file reaches, so a file shaped like this could verify a capability here with nothing noticing")
			}
		})
	}

	// And the control: importing the kit without reaching a verifier is not
	// flagged. conformance_test.go does exactly this — it reads core's
	// published fixtures — so a gate that refused the import itself would
	// refuse the thing this suite is built on.
	file, err := parser.ParseFile(token.NewFileSet(), "fine.go", `package solution
import "github.com/codefly-dev/core/workcontext/conformance"
func f() { _ = conformance.Fixtures() }`, 0)
	if err != nil {
		t.Fatalf("parse the control: %v", err)
	}
	if reached := verifiersReachedBy(file); len(reached) != 0 {
		t.Errorf("the gate flagged %v in a file that reaches no verifier: reading core's published fixtures is how this suite gets a capability it did not sign itself", reached)
	}
}

// TestATestingTBParameterIsNotAGate records why the seam's refusal is
// testing.Testing() and not its signature.
//
// testing.TB has an unexported method, which stops a type *declaring* the
// interface — and not a type that EMBEDS it. So a production program can
// satisfy testing.TB in a few lines, which is what the review's reproducer
// did, and a function taking one proves nothing about where it was called
// from.
func TestATestingTBParameterIsNotAGate(t *testing.T) {
	// The point is that this line compiles: a struct embedding testing.TB is a
	// testing.TB anywhere, including in a deployment, so a function taking one
	// proves nothing about where it was called from.
	var satisfied testing.TB = struct{ testing.TB }{}
	_ = satisfied
}

// workContextImports is the local name each Work Context package is imported
// under in one file, which is what the gate above has to match on rather than
// the name this package happens to use.
func workContextImports(file *ast.File) map[string]string {
	imports := map[string]string{}
	for _, imported := range file.Imports {
		path := strings.Trim(imported.Path.Value, `"`)
		// Prefix, not equality, so a *subpackage* is matched too. The rule was
		// written against the two package paths exactly, and
		// core/workcontext/conformance is neither of them while exporting
		// Verifier(), which returns core's own *workcontext.Verifier — so the
		// one import that hands this package a working verifier passed the
		// gate meant to refuse exactly that. A gate on a path is only as good
		// as the paths it enumerates, which is the same defect as an
		// enumerated posture check.
		if !isWorkContextPath(path) {
			continue
		}
		alias := path[strings.LastIndex(path, "/")+1:]
		if imported.Name != nil {
			alias = imported.Name.Name
		}
		if alias == "_" {
			continue
		}
		imports[alias] = path
	}
	return imports
}

// isWorkContextPath reports whether an import path is a Work Context package or
// anything beneath one, in either repository that owns one.
func isWorkContextPath(path string) bool {
	for _, root := range []string{
		"github.com/codefly-dev/core/workcontext",
		"github.com/codefly-dev/sdk-go/workcontext",
	} {
		if path == root || strings.HasPrefix(path, root+"/") {
			return true
		}
	}
	return false
}

// TestNoExportedPathBuildsACredentialBearingHandlerWithoutTheBoot pins the one
// API this round removed.
//
// Server.PassthroughHandler was exported, and that made a usable
// credential-bearing handler reachable without validate(), the mTLS boot, the
// caller allow-list, the published ceiling or authenticated outbound: a
// deployment calling it completed a viewer mint and a module call over
// plaintext and answered 200, with the viewer's bearer and this workload's own
// credential on the wire. It is reachable from package passthroughtest through
// internal/seam now, which Go's internal-package rule keeps inside this module.
//
// The gate is here because the pressure to put it back is real — it is two
// lines and it makes a consumer's test shorter — and because nothing else
// notices an exported identifier reappearing.
// The gate was two shapes too narrow, and both narrowings were about the
// previous round's removal rather than the property it was removed for. It
// skipped passthroughtest/ wholesale, and it matched only an exported func with
// a *receiver* whose name contained "Passthrough" — so passthroughtest.Handler,
// a plain exported function in a skipped file, was a production-importable path
// to the same credential-bearing handler. It now reads every call to the seam
// in the module and requires the calling function to refuse a non-test binary.
func TestNoExportedPathBuildsACredentialBearingHandlerWithoutTheBoot(t *testing.T) {
	reachesTheSeam, refusesANonTestBinary := seamCallGraph(t)
	fset := token.NewFileSet()
	for _, name := range moduleSources(t) {
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, decl := range file.Decls {
			switch declared := decl.(type) {
			case *ast.FuncDecl:
				if strings.Contains(name, "internal/seam") {
					continue
				}
				// Whoever reaches the seam is an exported path to a handler
				// holding a real credential, whatever it is called and whether
				// it hangs off a receiver or not.
				//
				// Transitively. The rule matched only a function that calls
				// seam.Passthrough *directly*, so an exported Handler
				// delegating to an unexported helper — and a root-package
				// wrapper over passthroughSeam — both walked past it. One hop
				// of indirection is the first thing anyone writes.
				if !reachesTheSeam[declared.Name.Name] {
					continue
				}
				if !declared.Name.IsExported() {
					continue
				}
				if !refusesANonTestBinary[declared.Name.Name] {
					t.Errorf("%s exports %s, which builds a passthrough through internal/seam without refusing a non-test binary: that handler holds a real execution credential and skips validate(), the mTLS boot, the caller allow-list, the ceiling and authenticated outbound, so an exported path to it has to call mustBeATest()",
						name, declared.Name.Name)
				}
			case *ast.GenDecl:
				for _, spec := range declared.Specs {
					if typed, ok := spec.(*ast.TypeSpec); ok && typed.Name.Name == "PassthroughEnvironment" {
						t.Errorf("%s exports PassthroughEnvironment, the argument of the constructor this change removed", name)
					}
					// An exported *variable* holding the seam is the same
					// bypass with no function to inspect: `var
					// BuildPassthrough = passthroughSeam` in the root package,
					// or `var Build = seam.Passthrough` in passthroughtest,
					// both passed a gate that only read function bodies.
					value, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, declaredName := range value.Names {
						if !declaredName.IsExported() || i >= len(value.Values) {
							continue
						}
						if named := renderedReference(value.Values[i]); reachesTheSeam[named] || named == "seam.Passthrough" {
							t.Errorf("%s exports the variable %s holding %s: that is a path to a credential-bearing handler with no function body for a gate to read and no refusal in front of it",
								name, declaredName.Name, named)
						}
					}
				}
			}
		}
	}
}

// TestNoExportedPathHandsOutAServableHandler is the type-based half, and the
// half the rule above cannot be.
//
// The rule above keys on reaching internal/seam and on the identifier
// PassthroughEnvironment, which is a rule about this change's own vocabulary:
// an exported `func (s *Server) Mux() http.Handler` returning the very mux
// Serve mounts passes it, because it calls no seam and is not named
// "Passthrough". What makes a bypass a bypass is handing a caller something
// SERVABLE that was built without the boot, so the gate is on the type.
//
// No exported declaration in this module returns one today, which is why this
// can be absolute rather than a list of blessed exceptions. A consumer writes
// Handler and RequestHandler and lets Serve mount them.
func TestNoExportedPathHandsOutAServableHandler(t *testing.T) {
	fset := token.NewFileSet()
	for _, name := range moduleSources(t) {
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		for _, finding := range servableExports(name, file) {
			t.Error(finding)
		}
	}
}

// servableExports is every exported declaration in one file that hands out
// something servable, as the message the gate reports.
//
// Factored out of the test so a probe drives THE RULE rather than a copy of
// its reasoning: a probe that re-implements the check proves only that two
// copies agree, and this gate has been falsified four times by a shape nobody
// had written a probe for. TestTheHandlerGateCatchesEveryEscapeShape is that
// probe.
func servableExports(name string, file *ast.File) (findings []string) {
	report := func(format string, args ...any) {
		findings = append(findings, fmt.Sprintf(format, args...))
	}
	{
		aliases := importedAs(file)
		rendered := func(expr ast.Expr) string { return renderedTypeIn(aliases, expr) }
		serves := func(expr ast.Expr) bool { return servesHTTP(aliases, expr) }
		// An exported struct carrying a servable field is the same re-exposure
		// with a type in the way: `type Mounted struct { Handler http.Handler }`
		// returned from an exported method hands out exactly what a direct
		// result would, and a gate reading only result types walks past it.
		for _, decl := range file.Decls {
			declared, ok := decl.(*ast.GenDecl)
			if !ok || strings.Contains(name, "passthroughtest") || strings.Contains(name, "internal/seam") {
				continue
			}
			for _, spec := range declared.Specs {
				typed, ok := spec.(*ast.TypeSpec)
				if !ok || !typed.Name.IsExported() {
					continue
				}
				// A named type whose underlying type is a map, slice or
				// channel of handlers is the same re-exposure with a name on
				// it.
				if named := rendered(typed.Type); handedOut(named) || serves(typed.Type) {
					report("%s exports the type %s over %s: naming a collection of handlers does not make handing one out any less servable",
						name, typed.Name.Name, named)
					continue
				}
				structure, ok := typed.Type.(*ast.StructType)
				if !ok || structure.Fields == nil {
					continue
				}
				for _, field := range structure.Fields.List {
					named := rendered(field.Type)
					// MOUNTABLE only, and the asymmetry is the rule rather
					// than an exemption. An http.Handler in an exported struct
					// is servable the moment a caller has the struct. This
					// package's own Handler and RequestHandler are not: they
					// take a *Gateway, whose fields are all unexported and
					// which a caller can obtain only from ViewerFromContext
					// inside a booted request or from another Gateway — so one
					// handed out is inert, and it is how a consumer DECLARES a
					// route for Serve to mount (Operation.Handler). Refusing
					// those here would refuse the documented inbound
					// direction; they stay refused as a RESULT below, which is
					// the direction that hands something out.
					if !mountableHandler[named] && !serves(field.Type) {
						continue
					}
					for _, fieldName := range field.Names {
						if fieldName.IsExported() {
							report("%s exports the type %s with a servable field %s %s: a struct is not a gate, and handing one out hands out the handler inside it",
								name, typed.Name.Name, fieldName.Name, named)
						}
					}
				}
			}
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() || fn.Type.Results == nil {
				continue
			}
			// passthroughtest is where a consumer's test is *supposed* to get a
			// handler; it refuses a non-test binary instead, which
			// TestTheSeamRefusesANonTestBinary drives.
			if strings.Contains(name, "passthroughtest") || strings.Contains(name, "internal/seam") {
				continue
			}
			for _, result := range fn.Type.Results.List {
				// A func type whose own signature is ServeHTTP's is a handler
				// however it is spelled, which is the shape `func (s *Server)
				// Routes() func(http.ResponseWriter, *http.Request)` uses to
				// avoid naming http.Handler at all.
				if serves(result.Type) {
					report("%s exports %s returning a function with ServeHTTP's signature: naming the type something else does not make it less servable",
						name, fn.Name.Name)
					continue
				}
				named := rendered(result.Type)
				// The empty interface is refused outright rather than followed.
				// `func (s *Server) Routes() any` hands back whatever it likes
				// and no rule reading signatures can see it; following the
				// returned expressions would make the gate a type checker, and
				// a gate that has to infer is one an author can out-infer.
				// Nothing in this module returns a bare any today, so this is
				// absolute rather than a list of exceptions.
				if named == "any" {
					report("%s exports %s returning the empty interface: this gate reads signatures, so `any` hides whether what comes back is servable. Declare the concrete type.",
						name, fn.Name.Name)
					continue
				}
				if handedOut(named) {
					report("%s exports %s returning %s: a servable handler obtained outside Serve has skipped validate(), the mTLS boot, the caller allow-list, the ceiling and authenticated outbound, and whoever mounts it serves the viewer's bearer and this workload's credential over whatever it is mounted on. Let Serve mount it.",
						name, fn.Name.Name, named)
				}
			}
		}
	}
	return findings
}

// coreCapabilityConstructions is every place a file ALLOCATES one of core's
// capability messages, by rendered type name.
//
// Construction rather than mention, because the mention is legitimate:
// holdSealedIdentity takes a *workcontext.SealedValues and reads it through
// GetInstallationId. Decoding into one requires allocating it; reading one
// never does. Factored out so TestTheCapabilityDecodeGateCatchesTheSDKAlias
// drives this rule rather than a copy of it.
func coreCapabilityConstructions(file *ast.File) []string {
	aliases := importedAs(file)
	var built []string
	ast.Inspect(file, func(node ast.Node) bool {
		var allocated ast.Expr
		switch typed := node.(type) {
		case *ast.CompositeLit:
			allocated = typed.Type
		case *ast.CallExpr:
			if called, ok := typed.Fun.(*ast.Ident); ok && called.Name == "new" && len(typed.Args) == 1 {
				allocated = typed.Args[0]
			}
		}
		if allocated == nil {
			return true
		}
		if rendered := renderedTypeIn(aliases, allocated); coreCapabilityType(rendered) {
			built = append(built, rendered)
		}
		return true
	})
	return built
}

// coreCapabilityType reports whether a rendered type is one of core's
// capability messages, under any of the names it is reachable by: core's own
// generated spelling, and the SDK's aliases for it.
func coreCapabilityType(rendered string) bool {
	if rendered == "" {
		return false
	}
	bare := rendered
	if cut := strings.LastIndex(bare, "."); cut >= 0 {
		bare = bare[cut+1:]
	}
	switch bare {
	case "WorkSealV1", "WorkContextV1", "SealedValues", "WorkContext", "Capability":
		return true
	}
	return false
}

// mountableHandler is what a caller can serve the moment they hold it, keyed
// by IMPORT PATH rather than by the prefix a file happens to spell it with.
var mountableHandler = map[string]bool{
	"net/http.Handler":       true,
	"net/http.HandlerFunc":   true,
	"net/http.ServeMux":      true,
	"net/http.RoundTripper":  true,
	"net/http.ServeMuxEntry": true,
}

// declaredHandler is this package's own pair, which a consumer writes and
// Serve mounts. Handing one BACK is still refused — that is a path to a route
// built outside the boot whatever it needs to run — but carrying one in an
// exported struct is the documented way to declare a route.
var declaredHandler = map[string]bool{"Handler": true, "RequestHandler": true}

// handedOut reports whether a rendered type is one no exported path may return.
func handedOut(rendered string) bool {
	return mountableHandler[rendered] || declaredHandler[rendered]
}

// renderedReference is pkg.Name or Name for an expression that merely refers to
// something, which is what an exported variable's initialiser is.
func renderedReference(expr ast.Expr) string {
	switch named := expr.(type) {
	case *ast.Ident:
		return named.Name
	case *ast.SelectorExpr:
		if pkg, ok := named.X.(*ast.Ident); ok {
			return pkg.Name + "." + named.Sel.Name
		}
	}
	return ""
}

// servesHTTP reports whether a type is a function taking
// (http.ResponseWriter, *http.Request), under this file's import names.
func servesHTTP(aliases map[string]string, expr ast.Expr) bool {
	fn, ok := expr.(*ast.FuncType)
	if !ok || fn.Params == nil || len(fn.Params.List) != 2 {
		return false
	}
	return renderedTypeIn(aliases, fn.Params.List[0].Type) == "net/http.ResponseWriter" &&
		renderedTypeIn(aliases, fn.Params.List[1].Type) == "net/http.Request"
}

// importedAs is the local name each import is reachable under in this file,
// which is what a qualified type's prefix actually means.
//
// The gate keyed on the PREFIX, so `import nh "net/http"` and
// `func (s *Server) Mux() nh.Handler` rendered as "nh.Handler" and matched
// nothing — a one-word rename walked past it. A dot-import lands in the bare
// namespace and is caught by the unqualified names instead.
func importedAs(file *ast.File) map[string]string {
	aliases := map[string]string{}
	for _, imported := range file.Imports {
		path := strings.Trim(imported.Path.Value, `"`)
		name := path
		if cut := strings.LastIndex(path, "/"); cut >= 0 {
			name = path[cut+1:]
		}
		if imported.Name != nil {
			name = imported.Name.Name
		}
		aliases[name] = path
	}
	return aliases
}

// renderedType is renderedTypeIn with no import names resolved, for a probe
// that only needs the unqualified shapes.
func renderedType(expr ast.Expr) string { return renderedTypeIn(nil, expr) }

// renderedTypeIn is <import path>.Name for a qualified type, the bare name for
// an unqualified one, and "any" for the empty interface — with one level of
// pointer, slice, map and channel stripped, which is enough to recognise a
// handler however it is handed back.
//
// It had no *ast.Ident case, and that was not a cosmetic gap: the servable set
// has always named this package's own `Handler` and `RequestHandler`, and
// since a bare identifier rendered as "" those two entries matched nothing a
// gate ever asked about. `func (s *Server) Mux() Handler` passed, and so did
// `map[string]Handler` — the local spelling of the very collection shape a
// previous round added the map case for.
func renderedTypeIn(aliases map[string]string, expr ast.Expr) string {
	switch typed := expr.(type) {
	case *ast.StarExpr:
		return renderedTypeIn(aliases, typed.X)
	case *ast.ArrayType:
		return renderedTypeIn(aliases, typed.Elt)
	case *ast.MapType:
		// A map, channel or slice of handlers hands out handlers. `type Routes
		// map[string]http.Handler` returned from an exported method walked
		// past a rule that looked only at the result type itself and at struct
		// fields.
		return renderedTypeIn(aliases, typed.Value)
	case *ast.ChanType:
		return renderedTypeIn(aliases, typed.Value)
	case *ast.Ident:
		return typed.Name
	case *ast.InterfaceType:
		// The empty interface is how a result hides what it is. `any` is not
		// servable, but nothing can tell from the signature whether what comes
		// back is, which is the point of the refusal below.
		if typed.Methods == nil || len(typed.Methods.List) == 0 {
			return "any"
		}
	case *ast.SelectorExpr:
		pkg, ok := typed.X.(*ast.Ident)
		if !ok {
			return ""
		}
		if path, aliased := aliases[pkg.Name]; aliased {
			return path + "." + typed.Sel.Name
		}
		return pkg.Name + "." + typed.Sel.Name
	}
	return ""
}

// seamCallGraph is, for every function in the module, whether it reaches the
// passthrough seam and whether it refuses a non-test binary — both
// transitively, because one hop of indirection is the first thing anyone
// writes and the previous rule only looked at direct calls.
func seamCallGraph(t *testing.T) (reaches, refuses map[string]bool) {
	t.Helper()
	fset := token.NewFileSet()
	var files []*ast.File
	for _, name := range moduleSources(t) {
		if strings.Contains(name, "internal/seam") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files = append(files, file)
	}
	return seamReachability(files)
}

// seamReachability is seamCallGraph over files already parsed, so a probe can
// supply its own.
func seamReachability(files []*ast.File) (reaches, refuses map[string]bool) {
	calls := map[string][]string{}
	reaches, refuses = map[string]bool{}, map[string]bool{}
	// defeated is every function that swallows a panic or guards a branch it
	// cannot take, whether the refusal it defeats is its own call or one it
	// inherits from a callee. Recording it for EVERY function, not only for
	// the ones calling mustBeATest, is what makes the propagation below
	// honest: the defeat check used to run only where the refusal was called
	// directly, so the same `if false` moved one hop away was inherited as a
	// refusal and passed the gate. Probed both ways in
	// TestTheSeamGateIsNotDefeatedOneHopAway.
	defeated := map[string]bool{}
	for _, file := range files {
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			if defeatsItsOwnRefusal(fn) {
				defeated[fn.Name.Name] = true
			}
			if callsThe(fn, "seam", "Passthrough") {
				reaches[fn.Name.Name] = true
			}
			// A refusal swallowed by recover(), or sitting on a branch that
			// cannot be taken, is not a refusal. Counting the call alone made
			// both of those read as guarded.
			if (callsThe(fn, "", "mustBeATest") || callsThe(fn, "", "refuseOutsideTest")) && !defeated[fn.Name.Name] {
				refuses[fn.Name.Name] = true
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				if callee, ok := calleeName(call); ok {
					calls[fn.Name.Name] = append(calls[fn.Name.Name], callee)
				}
				return true
			})
		}
	}
	// Propagate both properties up the call graph until nothing changes.
	for changed := true; changed; {
		changed = false
		for caller, callees := range calls {
			for _, callee := range callees {
				if reaches[callee] && !reaches[caller] {
					reaches[caller], changed = true, true
				}
				// A caller inherits a callee's refusal only if it does not
				// defeat it. `if false { return guard() }` reaches the seam by
				// its real path and inherited guard()'s refusal, which is the
				// defeat this gate already refused one hop closer in.
				if refuses[callee] && !refuses[caller] && !defeated[caller] {
					refuses[caller], changed = true, true
				}
			}
		}
	}
	return reaches, refuses
}

// defeatsItsOwnRefusal reports whether fn recovers from a panic or guards the
// refusal behind a constant false, either of which makes the call decorative.
func defeatsItsOwnRefusal(fn *ast.FuncDecl) bool {
	defeated := false
	ast.Inspect(fn, func(node ast.Node) bool {
		if call, ok := node.(*ast.CallExpr); ok {
			if named, ok := call.Fun.(*ast.Ident); ok && named.Name == "recover" {
				defeated = true
			}
		}
		if branch, ok := node.(*ast.IfStmt); ok {
			if cond, ok := branch.Cond.(*ast.Ident); ok && cond.Name == "false" {
				defeated = true
			}
		}
		return true
	})
	return defeated
}

// callsThe reports whether fn calls pkg.name, or bare name when pkg is empty.
func callsThe(fn *ast.FuncDecl, pkg, name string) bool {
	found := false
	ast.Inspect(fn, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if pkg == "" {
			if called, ok := call.Fun.(*ast.Ident); ok && called.Name == name {
				found = true
			}
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		qualifier, ok := selector.X.(*ast.Ident)
		if ok && qualifier.Name == pkg && selector.Sel.Name == name {
			found = true
		}
		return true
	})
	return found
}

// moduleSources is every non-test Go source in this module, which is what both
// gates above read.
//
// They read only the root directory until now, and passthroughtest/ is where a
// capability is actually signed — with core's published fixture key, which is
// the right way to do it and exactly the file a second implementation would
// grow in, since it is the one place already holding a signing key. A gate that
// does not look at the directory most likely to break it is a gate that reports
// success for the wrong reason.
func moduleSources(t *testing.T) []string {
	t.Helper()
	var sources []string
	err := filepath.WalkDir(".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// Nothing generated and nothing vendored: those are not this
			// repository's declarations to answer for.
			if name := entry.Name(); path != "." && (name == "vendor" || strings.HasPrefix(name, ".")) {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) == ".go" && !strings.HasSuffix(path, "_test.go") {
			sources = append(sources, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk module sources: %v", err)
	}
	if len(sources) < 2 {
		t.Fatalf("found %d sources to gate, which cannot be right: a gate that reads nothing passes", len(sources))
	}
	return sources
}

// TestTheSeamGateFollowsIndirection: the rule matched only a function calling
// seam.Passthrough *directly*, so an exported wrapper one hop away passed it —
// and one hop of indirection is the first thing anyone writes.
func TestTheSeamGateFollowsIndirection(t *testing.T) {
	parse := func(t *testing.T, source string) []*ast.File {
		t.Helper()
		file, err := parser.ParseFile(token.NewFileSet(), "probe.go", source, 0)
		if err != nil {
			t.Fatalf("parse the probe: %v", err)
		}
		return []*ast.File{file}
	}

	t.Run("an exported path one hop from the seam is seen", func(t *testing.T) {
		reaches, refuses := seamReachability(parse(t, `package solution
func ExportedIndirect() (http.Handler, error) { return viaHelper() }
func viaHelper() (http.Handler, error) { return seam.Passthrough(nil, "", "") }`))
		if !reaches["ExportedIndirect"] {
			t.Error("the gate did not see that ExportedIndirect reaches the seam: it delegates, so a rule matching only direct callers reports an exported path to a credential-bearing handler as if it were not one")
		}
		if refuses["ExportedIndirect"] {
			t.Error("the gate thinks ExportedIndirect refuses a non-test binary, which nothing in it does")
		}
	})

	t.Run("a refusal one hop away is seen too", func(t *testing.T) {
		// Or the gate would flag a path that is in fact guarded, and a rule
		// that cries wolf gets relaxed rather than obeyed.
		_, refuses := seamReachability(parse(t, `package solution
func Guarded() (http.Handler, error) { return guard() }
func guard() (http.Handler, error) { mustBeATest(); return seam.Passthrough(nil, "", "") }`))
		if !refuses["Guarded"] {
			t.Error("the gate did not see that Guarded refuses a non-test binary through its helper")
		}
	})

	t.Run("a function that reaches nothing is not flagged", func(t *testing.T) {
		reaches, _ := seamReachability(parse(t, `package solution
func Unrelated() error { return nil }`))
		if reaches["Unrelated"] {
			t.Error("the gate flagged a function that does not reach the seam")
		}
	})
}

// TestTheHandlerGateCatchesEveryEscapeShape drives servableExports against the
// shapes an executed round listed as walking past it, plus the two that list
// turned out to understate.
//
// A gate cannot be mutation-tested: the harness asks "mutate the code, does
// the suite fail?", and a gate only fails when a counterexample is in the
// tree, which is the thing it exists to stop being there. So its acceptance
// criterion is a probe per shape, and the probes are the record of what it has
// been falsified by — four times now, each time by a shape that was locally
// obvious once someone wrote it down.
func TestTheHandlerGateCatchesEveryEscapeShape(t *testing.T) {
	parse := func(t *testing.T, source string) *ast.File {
		t.Helper()
		file, err := parser.ParseFile(token.NewFileSet(), "probe.go", source, 0)
		if err != nil {
			t.Fatalf("parse the probe: %v", err)
		}
		return file
	}

	caught := []struct{ shape, source string }{
		{
			// The reviewer's shape: declare `any` and no signature rule can
			// see what comes back.
			"a result typed any",
			`package solution
import "net/http"
func (s *Server) Routes() any { return http.NewServeMux() }`,
		},
		{
			// A one-word rename. The gate keyed on the PREFIX "http".
			"an import-aliased http.Handler",
			`package solution
import nh "net/http"
func (s *Server) Mux() nh.Handler { return nil }`,
		},
		{
			// This package's own Handler, which the servable set has always
			// named and never matched, because a bare identifier rendered "".
			"a result typed with this package's own Handler",
			`package solution
func (s *Server) Mux() Handler { return nil }`,
		},
		{
			"a result typed with this package's own RequestHandler",
			`package solution
func (s *Server) Mux() RequestHandler { return nil }`,
		},
		{
			// The map case a previous round added — in the local spelling it
			// did not cover.
			"a map of this package's own handlers",
			`package solution
func (s *Server) Routes() map[string]Handler { return nil }`,
		},
		{
			"a map of http.Handlers",
			`package solution
import "net/http"
func (s *Server) Routes() map[string]http.Handler { return nil }`,
		},
		{
			"a dot-imported Handler",
			`package solution
import . "net/http"
func (s *Server) Mux() Handler { return nil }`,
		},
		{
			"a function with ServeHTTP's signature, named nothing",
			`package solution
import "net/http"
func (s *Server) Routes() func(http.ResponseWriter, *http.Request) { return nil }`,
		},
		{
			"an exported struct carrying a mountable handler",
			`package solution
import "net/http"
type Mounted struct { Handler http.Handler }`,
		},
		{
			"an exported struct carrying an alias-spelled mountable handler",
			`package solution
import nh "net/http"
type Mounted struct { Handler nh.Handler }`,
		},
		{
			"a named collection type over handlers",
			`package solution
import "net/http"
type Routes map[string]http.Handler`,
		},
	}
	for _, probe := range caught {
		t.Run(probe.shape, func(t *testing.T) {
			if findings := servableExports("probe.go", parse(t, probe.source)); len(findings) == 0 {
				t.Errorf("the gate did not catch %s, so an exported path can hand out a handler built without the boot in this shape:\n%s", probe.shape, probe.source)
			}
		})
	}

	// And what it must NOT catch, because a gate nobody can satisfy gets
	// loosened by whoever hits it next.
	passes := []struct{ shape, source string }{
		{
			// The documented inbound direction. Operation is how a consumer
			// DECLARES a route; refusing it here would refuse the API this
			// package exists to offer. It is not mountable: a Handler needs a
			// *Gateway, whose fields are unexported and which comes only from
			// a booted request.
			"an exported struct declaring routes with this package's own handlers",
			`package solution
type Operation struct {
	Handler Handler
	RequestHandler RequestHandler
}`,
		},
		{
			"an exported method returning the declaration type",
			`package solution
func PassthroughOperations(modules ...ConsumedModule) ([]Operation, error) { return nil, nil }`,
		},
		{
			"ordinary exported results",
			`package solution
import "net/http"
func (g *Gateway) BaseURL() string { return "" }
func (g *Gateway) HTTPClient() *http.Client { return nil }
func (s *Server) Serve() error { return nil }`,
		},
		{
			"an interface result that is not the empty one",
			`package solution
func (s *Server) Source() IdentitySource { return nil }`,
		},
	}
	for _, probe := range passes {
		t.Run("passes: "+probe.shape, func(t *testing.T) {
			if findings := servableExports("probe.go", parse(t, probe.source)); len(findings) != 0 {
				t.Errorf("the gate refused %s, which is the documented way to use this package:\n%s\nfindings: %v", probe.shape, probe.source, findings)
			}
		})
	}
}

// TestTheSeamGateIsNotDefeatedOneHopAway is B6: the defeat check ran only where
// mustBeATest was called directly, and the propagation loop then handed the
// refusal to any caller of a refusing callee without asking whether that
// caller defeats it. So the gate caught `if false { mustBeATest() }` and
// passed the same defeat one function away.
func TestTheSeamGateIsNotDefeatedOneHopAway(t *testing.T) {
	parse := func(t *testing.T, source string) []*ast.File {
		t.Helper()
		file, err := parser.ParseFile(token.NewFileSet(), "probe.go", source, 0)
		if err != nil {
			t.Fatalf("parse the probe: %v", err)
		}
		return []*ast.File{file}
	}
	const guard = `
func guard() (http.Handler, error) { mustBeATest(); return seam.Passthrough(nil, "", "") }`

	defeats := []struct{ shape, source string }{
		{
			"the refusal is called directly on a branch that cannot be taken",
			`package solution
func Exported() (http.Handler, error) {
	if false { mustBeATest() }
	return seam.Passthrough(nil, "", "")
}`,
		},
		{
			"the guarded helper is called on a branch that cannot be taken, and the real path is not",
			`package solution
func Exported() (http.Handler, error) {
	if false { return guard() }
	return seam.Passthrough(nil, "", "")
}` + guard,
		},
		{
			"the guarded helper's panic is swallowed by the caller",
			`package solution
func Exported() (h http.Handler, err error) {
	defer func() { recover() }()
	return guard()
}` + guard,
		},
	}
	for _, probe := range defeats {
		t.Run(probe.shape, func(t *testing.T) {
			_, refuses := seamReachability(parse(t, probe.source))
			if refuses["Exported"] {
				t.Errorf("the gate reads Exported as refusing a non-test binary, and it does not — %s:\n%s", probe.shape, probe.source)
			}
		})
	}

	t.Run("passes: a refusal one hop away that nothing defeats", func(t *testing.T) {
		_, refuses := seamReachability(parse(t, `package solution
func Exported() (http.Handler, error) { return guard() }`+guard))
		if !refuses["Exported"] {
			t.Error("the gate stopped seeing a genuine refusal through a helper, which would fail every guarded path in the module")
		}
	})
}

// TestTheCapabilityDecodeGateCatchesTheSDKAlias is F6's fold-in: an executed
// round observed that a home-made WorkSealV1 proto.Unmarshal "would escape the
// gates", and it would have. Every other rule here looks for a signer, a
// verifier, a crypto import or a type of this package's own named after a Work
// Context — and a decode is none of those. It needs no generated import
// either, because the SDK re-exports core's message as an ALIAS, so the one
// import this package already has is enough to allocate one and unmarshal into
// it.
func TestTheCapabilityDecodeGateCatchesTheSDKAlias(t *testing.T) {
	parse := func(t *testing.T, source string) *ast.File {
		t.Helper()
		file, err := parser.ParseFile(token.NewFileSet(), "probe.go", source, 0)
		if err != nil {
			t.Fatalf("parse the probe: %v", err)
		}
		return file
	}

	caught := []struct{ shape, source string }{
		{
			// The shape the round named, through the alias this package
			// already imports.
			"a decode into the SDK's alias for core's seal",
			`package solution
import (
	"google.golang.org/protobuf/proto"
	"github.com/codefly-dev/sdk-go/workcontext"
)
func (s *Server) sealOf(raw []byte) *workcontext.SealedValues {
	seal := &workcontext.SealedValues{}
	_ = proto.Unmarshal(raw, seal)
	return seal
}`,
		},
		{
			"the same decode with new() instead of a literal",
			`package solution
import (
	"google.golang.org/protobuf/proto"
	"github.com/codefly-dev/sdk-go/workcontext"
)
func (s *Server) sealOf(raw []byte) *workcontext.SealedValues {
	seal := new(workcontext.SealedValues)
	_ = proto.Unmarshal(raw, seal)
	return seal
}`,
		},
		{
			"core's own generated spelling, under an import alias",
			`package solution
import pb "github.com/codefly-dev/core/generated/go/codefly/base/v0"
func build() *pb.WorkSealV1 { return &pb.WorkSealV1{} }`,
		},
		{
			"a whole capability, not just its seal",
			`package solution
import "github.com/codefly-dev/sdk-go/workcontext"
func build() any { return &workcontext.WorkContextV1{} }`,
		},
	}
	for _, probe := range caught {
		t.Run(probe.shape, func(t *testing.T) {
			if built := coreCapabilityConstructions(parse(t, probe.source)); len(built) == 0 {
				t.Errorf("the gate did not catch %s, so a second decoder of core's encoding can grow here:\n%s", probe.shape, probe.source)
			}
		})
	}

	t.Run("passes: reading a seal through the accessor", func(t *testing.T) {
		// What credential.go actually does. The type is named, in a parameter
		// and a result, and nothing is allocated — so a rule on the NAME would
		// refuse the supported way to read a seal, and this one does not.
		built := coreCapabilityConstructions(parse(t, `package solution
import "github.com/codefly-dev/sdk-go/workcontext"
func holdSealedIdentity(seal *workcontext.SealedValues) sealedIdentity {
	return sealedIdentity{
		installation: seal.GetInstallationId(),
		digest:       seal.GetImageDigest(),
		incarnation:  seal.GetBuildIncarnation(),
	}
}`))
		if len(built) != 0 {
			t.Errorf("the gate refused reading a seal through the SDK's accessor, which is the one supported way to do it: %v", built)
		}
	})
}
