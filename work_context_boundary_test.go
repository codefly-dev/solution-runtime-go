package solution

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os/exec"
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
	// Every source first: a capability type can be aliased in one file and
	// decoded into in another.
	sources := map[string]*ast.File{}
	for _, name := range moduleSources(t) {
		file, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		sources[name] = file
	}
	localCapability := localCapabilityTypes(sources)
	for name, file := range sources {
		// issuesTLSMaterialOnly relaxes the signing-primitive rule for ONE
		// narrow shape, and the condition is checked rather than asserted.
		//
		// sdk-go#51 holds the mint endpoint to the SPIFFE ID in its single URI
		// SAN, so the fake host in passthroughtest has to issue a certificate
		// carrying one — httptest's shared certificate has no URI SAN at all,
		// and a client with AdmittedPeers refuses it, correctly. The seam's
		// code lives in non-test files because a consumer imports it from
		// their tests, so it cannot hide behind the _test.go exclusion the
		// root package's own cell helpers use.
		//
		// The relaxation is conditional on the file touching NOTHING
		// capability-shaped: issuing TLS material has no business importing a
		// work-context package, and a file that does both is exactly what this
		// gate is for. Every other rule below still applies to it — the
		// capability-message construction rule, the verifier rule, the JOSE
		// rule and the declaration-name rule — and
		// TestTheSigningRelaxationIsConditional pins that.
		issuesTLSMaterialOnly := issuesTLSMaterialOnly(name, file)
		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			switch path {
			case "crypto/ed25519", "crypto/ecdsa", "crypto/hmac", "crypto/rsa", "crypto/ed25519/internal/edwards25519":
				if issuesTLSMaterialOnly {
					continue
				}
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
		for _, built := range coreCapabilityConstructions(file, localCapability) {
			t.Errorf("%s constructs %s: allocating one of core's capability messages is what decoding into it requires, and a second decoder of that encoding is this boundary's whole subject. Read the seal through the SDK's Credential.Seal() accessor.",
				name, built)
		}
		for _, decoded := range capabilityDecodes(file, localCapability) {
			t.Errorf("%s decodes %s: that is a second reader of core's wire encoding, whoever allocated the destination. Read the seal through the SDK's Credential.Seal() accessor.",
				name, decoded)
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
	// Every source first, because a result's type may be declared in another
	// file than the function returning it.
	files := map[string]*ast.File{}
	for _, name := range moduleSources(t) {
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		files[name] = file
	}
	local := localHandlerTypes(files)
	for name, file := range files {
		for _, finding := range servableExports(name, file, local) {
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
func servableExports(name string, file *ast.File, local map[string]bool) (findings []string) {
	report := func(format string, args ...any) {
		findings = append(findings, fmt.Sprintf(format, args...))
	}
	{
		aliases := importedAs(file)
		rendered := func(expr ast.Expr) string { return renderedTypeIn(aliases, expr) }
		serves := func(expr ast.Expr) bool { return servesHTTP(aliases, expr) }
		// handedOut, plus the names this module declares for the same thing.
		handedOut := func(named string) bool { return handedOut(named) || local[named] }
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
					if !mountableHandler[named] && !local[named] && !serves(field.Type) {
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
					continue
				}
				// An ANONYMOUS struct carrying one. There is no declaration
				// for the name-based analysis to visit, so the expression is
				// inspected directly.
				if carriesAMountableHandler(aliases, local, result.Type, 0) {
					report("%s exports %s returning an unnamed type that carries a servable handler in a reachable field: a caller mounts that field and has a handler built without validate(), the mTLS boot, the caller allow-list, the ceiling and authenticated outbound. Let Serve mount it.",
						name, fn.Name.Name)
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
func coreCapabilityConstructions(file *ast.File, local map[string]bool) []string {
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
		case *ast.ValueSpec:
			// `var seal workcontext.SealedValues` — round thirteen's major 3.
			//
			// This rule inspected composite literals and new() only, and I
			// asserted that decoding necessarily passes through one of them.
			// It does not: the zero value is allocated by the declaration, and
			// `proto.Unmarshal(raw, &seal)` then decodes into it with no
			// literal, no new, no generated import, no signing primitive, no
			// verifier and no prohibited declaration name anywhere. The
			// assertion was simply false, and a reviewer produced the four
			// lines that show it.
			//
			// ValueSpec covers both a package-level var and a local one, since
			// a DeclStmt inside a function carries the same node.
			allocated = typed.Type
		}
		if allocated == nil {
			return true
		}
		// Local aliases resolve here as well: `type hiddenSeal =
		// workcontext.SealedValues` renders as its own spelling, which no
		// fixed set contains.
		if rendered := renderedTypeIn(aliases, allocated); coreCapabilityType(rendered) || local[rendered] {
			built = append(built, rendered)
		}
		return true
	})
	return built
}

// capabilityDecodes is every place a file DECODES into one of core's
// capability messages, by the name of the destination.
//
// The construction rule is not enough, and the premise behind it was wrong
// twice. I asserted that decoding requires an allocation; a reviewer showed
// the zero-value declaration, which ValueSpec now covers, and then showed that
// the allocation need not be in the inspected code at all:
//
//	func decodeSeal(raw []byte, dst *workcontext.SealedValues) error {
//		return proto.Unmarshal(raw, dst)
//	}
//
// no literal, no new, no declaration, no generated import, no signing
// primitive, no verifier, no prohibited name. The destination arrives as a
// parameter and the caller allocated it.
//
// So this rule is on the DECODE rather than on the allocation: any call to an
// Unmarshal whose destination is a name bound to a capability type — a
// parameter, a result, a local declaration, or a local alias for one. It stays
// a syntactic rule, which is the honest limit: a destination reached through
// an interface, a field selector or a function call is not resolved here, and
// the construction rule covers the shapes where this package would have had to
// allocate one itself.
func capabilityDecodes(file *ast.File, localCapability map[string]bool) []string {
	aliases := importedAs(file)
	base := func(expr ast.Expr) bool {
		rendered := renderedTypeIn(aliases, expr)
		return coreCapabilityType(rendered) || localCapability[rendered]
	}
	var decoded []string
	for _, decl := range file.Decls {
		capability := base
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		// Every name in this function bound to a capability type.
		bound := map[string]bool{}
		record := func(fields *ast.FieldList) {
			if fields == nil {
				return
			}
			for _, field := range fields.List {
				if !capability(field.Type) {
					continue
				}
				for _, name := range field.Names {
					bound[name.Name] = true
				}
			}
		}
		record(fn.Type.Params)
		record(fn.Type.Results)
		record(fn.Recv)
		// Aliases declared INSIDE the function.
		//
		// localCapabilityTypes reads package-level declarations, so a
		// function-local `type localSeal = workcontext.SealedValues` was a
		// name the scanner had never heard of — and `var dst localSeal`
		// bound nothing. Collected per function because that is the scope the
		// name exists in.
		lexical := map[string]bool{}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			declared, ok := node.(*ast.GenDecl)
			if !ok || declared.Tok != token.TYPE {
				return true
			}
			for _, spec := range declared.Specs {
				typed, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				if rendered := renderedTypeIn(aliases, typed.Type); coreCapabilityType(rendered) || localCapability[rendered] || lexical[rendered] {
					lexical[typed.Name.Name] = true
				}
			}
			return true
		})
		if len(lexical) > 0 {
			outer := capability
			capability = func(expr ast.Expr) bool {
				return outer(expr) || lexical[renderedTypeIn(aliases, expr)]
			}
		}
		// Declarations with an explicit type, and then ASSIGNMENT ALIASES, to
		// a fixpoint.
		//
		// `target := dst` put the destination in a name the scanner had never
		// heard of, with no allocation for the construction rule to catch
		// either. The previous round closed the direct-parameter form and this
		// adjacent one walked straight past it, which is the third time a
		// premise about where the destination comes from has been wrong here.
		//
		// The fixpoint is because an alias can alias an alias. The coverage is
		// bounded deliberately and the bound is stated: a name assigned from
		// another NAME (optionally through & or *) is followed; a destination
		// arriving through a field selector, an index, a function result or an
		// interface is not. Closing those means go/types, which is the honest
		// next step and is named in the gate's own comment rather than left to
		// be discovered.
		for changed := true; changed; {
			changed = false
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				switch typed := node.(type) {
				case *ast.ValueSpec:
					if capability(typed.Type) {
						for _, name := range typed.Names {
							if !bound[name.Name] {
								bound[name.Name], changed = true, true
							}
						}
					}
					// `var target = dst`, which is an assignment in a
					// declaration's clothing.
					for i, name := range typed.Names {
						if i < len(typed.Values) && bound[rootName(typed.Values[i])] && !bound[name.Name] {
							bound[name.Name], changed = true, true
						}
					}
				case *ast.AssignStmt:
					for i, left := range typed.Lhs {
						if i >= len(typed.Rhs) {
							break
						}
						target, ok := left.(*ast.Ident)
						if !ok || bound[target.Name] {
							continue
						}
						if bound[rootName(typed.Rhs[i])] {
							bound[target.Name], changed = true, true
						}
					}
				}
				return true
			})
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			selector, ok := call.Fun.(*ast.SelectorExpr)
			// Unmarshal AND Decode. This matched only "Unmarshal", so
			// `json.NewDecoder(r).Decode(dst)` — an ordinary shape, with the
			// destination a capability — walked past it. The rule is about
			// reading core's encoding into one of core's messages; which
			// decoder library does it is not the question.
			if !ok || (!strings.Contains(selector.Sel.Name, "Unmarshal") && !strings.Contains(selector.Sel.Name, "Decode")) {
				return true
			}
			for _, arg := range call.Args {
				// `dst`, `&dst`, or a capability constructed inline.
				reference := arg
				if unary, ok := arg.(*ast.UnaryExpr); ok {
					reference = unary.X
				}
				if named, ok := reference.(*ast.Ident); ok && bound[named.Name] {
					decoded = append(decoded, fn.Name.Name+" into "+named.Name)
					return false
				}
				if capability(reference) {
					decoded = append(decoded, fn.Name.Name+" into an inline "+renderedTypeIn(aliases, reference))
					return false
				}
			}
			return true
		})
	}
	return decoded
}

// rootName is the identifier an expression ultimately refers to, through any
// number of address-of and dereference operators: `dst`, `&dst` and `*dst` all
// give "dst". Anything else — a selector, an index, a call — gives "", which is
// the bound this scanner states rather than pretends to cover.
func rootName(expr ast.Expr) string {
	for {
		switch typed := expr.(type) {
		case *ast.Ident:
			return typed.Name
		case *ast.UnaryExpr:
			expr = typed.X
		case *ast.StarExpr:
			expr = typed.X
		case *ast.ParenExpr:
			expr = typed.X
		default:
			return ""
		}
	}
}

// localCapabilityTypes is every type name the module declares that resolves to
// one of core's capability messages, so an alias cannot hide the destination.
func localCapabilityTypes(files map[string]*ast.File) map[string]bool {
	local := map[string]bool{}
	under := map[string]string{}
	for _, file := range files {
		aliases := importedAs(file)
		for _, decl := range file.Decls {
			declared, ok := decl.(*ast.GenDecl)
			if !ok || declared.Tok != token.TYPE {
				continue
			}
			for _, spec := range declared.Specs {
				typed, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				under[typed.Name.Name] = renderedTypeIn(aliases, typed.Type)
			}
		}
	}
	for changed := true; changed; {
		changed = false
		for name, target := range under {
			if local[name] {
				continue
			}
			if coreCapabilityType(target) || local[target] {
				local[name], changed = true, true
			}
		}
	}
	return local
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
	// Core's own generated spellings.
	case "WorkContextV1", "WorkSealV1", "WorkOperationBindingV1":
		return true
	// The SDK's exported aliases for them. `Claims` is the whole capability
	// and was MISSING from this list, which is the gap that mattered: the SDK
	// does not export `WorkContextV1` at all, so the probes that claimed to
	// cover the whole-capability case named a type that does not exist. They
	// only parsed their source, so nothing failed and the omission was
	// invisible for three rounds. TestEverySDKCapabilityAliasIsInTheGatesList
	// derives this set from the pinned SDK now.
	case "Claims", "SealedValues", "SealedOperationBinding":
		return true
	// Names this package must never declare for one of its own, kept so a
	// local type called WorkContext or Capability is refused on sight.
	case "WorkContext", "Capability":
		return true
	}
	return false
}

// localHandlerTypes is every type NAME declared in the module that resolves to
// something servable, following chains and across files.
//
// This is round thirteen's G5u, and the coordinator had asked for it by name a
// round earlier:
//
//	type hiddenHandler = http.Handler
//	func (s *Server) Routes() hiddenHandler { ... }
//
// walked past the gate completely. The declaration is unexported, so the rule
// that reports "exports the type X" skipped it; and the result rendered as the
// bare spelling "hiddenHandler", which matched no entry in either set. Adding
// probes for bare `Handler` and `map[string]Handler` did not touch it, because
// those two are names the gate already knew — this one is a name the AUTHOR
// chooses, and there are infinitely many of those. The only rule that holds is
// resolution.
//
// Unexported declarations are READ here even though they are never reported:
// what makes a bypass a bypass is the exported function's result, and the
// unexported alias is just the spelling it reaches that result under.
func localHandlerTypes(files map[string]*ast.File) map[string]bool {
	under := map[string]string{}
	servable := map[string]bool{}
	// fields[name] is every type an exported field of `name` has, by rendered
	// name. A struct that CARRIES a mountable handler in an exported field
	// hands one out as soon as a caller holds the struct, so returning it is
	// returning the handler with a type in the way:
	//
	//	type hidden = http.Handler
	//	type Mounted struct{ H hidden }
	//	func (s *Server) Routes() Mounted { ... }
	//
	// walked past every rule: `hidden` was skipped as an unexported
	// declaration, `H hidden` missed the field predicate because that one
	// matched only the literal mountable set, and `Mounted` was never recorded
	// as servable at all. An unexported struct with an exported handler field
	// is the same shape with one more step.
	fields := map[string][]string{}
	for _, file := range files {
		aliases := importedAs(file)
		for _, decl := range file.Decls {
			declared, ok := decl.(*ast.GenDecl)
			if !ok || declared.Tok != token.TYPE {
				continue
			}
			for _, spec := range declared.Specs {
				typed, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				// A function type with ServeHTTP's signature is a handler
				// under any name, so it is recorded directly rather than by
				// its rendering (which is empty for a func type).
				if servesHTTP(aliases, typed.Type) {
					servable[typed.Name.Name] = true
					continue
				}
				under[typed.Name.Name] = renderedTypeIn(aliases, typed.Type)
				structure, ok := typed.Type.(*ast.StructType)
				if !ok || structure.Fields == nil {
					continue
				}
				for _, field := range structure.Fields.List {
					exported := len(field.Names) == 0 // an embedded field is reachable
					for _, name := range field.Names {
						if name.IsExported() {
							exported = true
						}
					}
					if !exported {
						continue
					}
					if servesHTTP(aliases, field.Type) {
						servable[typed.Name.Name] = true
						continue
					}
					fields[typed.Name.Name] = append(fields[typed.Name.Name], renderedTypeIn(aliases, field.Type))
				}
			}
		}
	}
	// To a fixpoint, because an alias may name an alias and a struct may
	// carry a struct that carries a handler.
	for changed := true; changed; {
		changed = false
		for name, target := range under {
			if servable[name] {
				continue
			}
			if handedOut(target) || servable[target] {
				servable[name], changed = true, true
			}
		}
		for name, carried := range fields {
			if servable[name] {
				continue
			}
			for _, target := range carried {
				// MOUNTABLE only for a field, for the reason the field rule in
				// servableExports gives: this package's own Handler needs a
				// *Gateway that only a booted request produces, so one carried
				// in a declaration type is inert and is how a consumer
				// declares a route.
				if mountableHandler[target] || servable[target] {
					servable[name], changed = true, true
					break
				}
			}
		}
	}
	return servable
}

// carriesAMountableHandler reports whether a type EXPRESSION hands out a
// mountable handler through a field a caller can reach — including an
// anonymous struct, which has no declaration for localHandlerTypes to visit.
//
// That was the hole: localHandlerTypes follows named structs, aliases,
// exported fields and embedding, and
//
//	func (s *Server) Routes() struct{ H http.Handler } { ... }
//
// has no type name at all, so there was nothing to record and renderedTypeIn
// returns "" for it. A caller mounts `Routes().H` and has the wrapper without
// the boot. Recursive, because the struct can nest.
func carriesAMountableHandler(aliases map[string]string, local map[string]bool, expr ast.Expr, depth int) bool {
	if depth > 6 {
		// A type cannot nest in itself without a name, and a name is
		// localHandlerTypes' job; this only bounds a pathological expression.
		return false
	}
	switch typed := expr.(type) {
	case *ast.StarExpr:
		return carriesAMountableHandler(aliases, local, typed.X, depth+1)
	case *ast.ArrayType:
		return carriesAMountableHandler(aliases, local, typed.Elt, depth+1)
	case *ast.MapType:
		return carriesAMountableHandler(aliases, local, typed.Value, depth+1)
	case *ast.ChanType:
		return carriesAMountableHandler(aliases, local, typed.Value, depth+1)
	case *ast.StructType:
		if typed.Fields == nil {
			return false
		}
		for _, field := range typed.Fields.List {
			reachable := len(field.Names) == 0 // embedded: reachable by its own type name
			for _, name := range field.Names {
				if name.IsExported() {
					reachable = true
				}
			}
			if !reachable {
				continue
			}
			rendered := renderedTypeIn(aliases, field.Type)
			if mountableHandler[rendered] || local[rendered] || servesHTTP(aliases, field.Type) {
				return true
			}
			if carriesAMountableHandler(aliases, local, field.Type, depth+1) {
				return true
			}
		}
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
		{
			// G5u, named by the coordinator a round before a reviewer
			// reproduced it. The declaration is unexported, so the rule that
			// reports an exported type skipped it, and the result rendered as
			// a spelling no set could contain.
			"an UNEXPORTED alias for http.Handler, returned by an exported method",
			`package solution
import "net/http"
type hiddenHandler = http.Handler
func (s *Server) Routes() hiddenHandler { return nil }`,
		},
		{
			"an unexported DEFINITION rather than an alias",
			`package solution
import "net/http"
type hiddenHandler http.Handler
func (s *Server) Routes() hiddenHandler { return nil }`,
		},
		{
			"an alias chain, through two unexported names",
			`package solution
import "net/http"
type innerHandler = http.Handler
type hiddenHandler = innerHandler
func (s *Server) Routes() hiddenHandler { return nil }`,
		},
		{
			"an unexported alias for this package's own Handler",
			`package solution
type hiddenHandler = Handler
func (s *Server) Routes() hiddenHandler { return nil }`,
		},
		{
			"an unexported func type with ServeHTTP's signature",
			`package solution
import "net/http"
type hiddenHandler func(http.ResponseWriter, *http.Request)
func (s *Server) Routes() hiddenHandler { return nil }`,
		},
		{
			"a collection of an unexported alias",
			`package solution
import "net/http"
type hiddenHandler = http.Handler
func (s *Server) Routes() map[string]hiddenHandler { return nil }`,
		},
		{
			// Round fourteen's B4: the alias hides inside an exported field,
			// and the struct carrying it is what the exported method returns.
			"an exported struct whose exported field is an aliased handler",
			`package solution
import "net/http"
type hidden = http.Handler
type Mounted struct{ H hidden }
func (s *Server) Routes() Mounted { return Mounted{} }`,
		},
		{
			"an UNEXPORTED struct with an exported handler field, returned by an exported method",
			`package solution
import "net/http"
type mounted struct{ H http.Handler }
func (s *Server) Routes() mounted { return mounted{} }`,
		},
		{
			"a struct carrying a struct that carries a handler",
			`package solution
import "net/http"
type inner struct{ H http.Handler }
type outer struct{ In inner }
func (s *Server) Routes() outer { return outer{} }`,
		},
		{
			"an embedded handler, which has no field name to be unexported",
			`package solution
import "net/http"
type Mounted struct{ http.Handler }
func (s *Server) Routes() Mounted { return Mounted{} }`,
		},
		{
			// F2: an ANONYMOUS struct has no declaration for the name-based
			// analysis to visit, and renders as "".
			"an anonymous struct result carrying a handler",
			`package solution
import "net/http"
func (s *Server) Routes() struct{ H http.Handler } { return struct{ H http.Handler }{} }`,
		},
		{
			"an anonymous struct whose field is an aliased handler",
			`package solution
import "net/http"
type hidden = http.Handler
func (s *Server) Routes() struct{ H hidden } { return struct{ H hidden }{} }`,
		},
		{
			"an anonymous struct nesting another",
			`package solution
import "net/http"
func (s *Server) Routes() struct{ In struct{ H http.Handler } } { return struct{ In struct{ H http.Handler } }{} }`,
		},
		{
			"an anonymous struct embedding a handler",
			`package solution
import "net/http"
func (s *Server) Routes() struct{ http.Handler } { return struct{ http.Handler }{} }`,
		},
		{
			"a slice of anonymous carriers",
			`package solution
import "net/http"
func (s *Server) Routes() []struct{ H http.Handler } { return nil }`,
		},
	}
	exports := func(t *testing.T, source string) []string {
		t.Helper()
		file := parse(t, source)
		files := map[string]*ast.File{"probe.go": file}
		return servableExports("probe.go", file, localHandlerTypes(files))
	}
	for _, probe := range caught {
		t.Run(probe.shape, func(t *testing.T) {
			if findings := exports(t, probe.source); len(findings) == 0 {
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
		{
			// The anonymous-struct rule must look at REACHABLE fields only,
			// or every exported method returning a small struct is refused.
			"an anonymous struct whose handler field is unexported",
			`package solution
import "net/http"
func (s *Server) Routes() struct{ h http.Handler } { return struct{ h http.Handler }{} }`,
		},
		{
			"an anonymous struct carrying no handler at all",
			`package solution
func (s *Server) Describe() struct{ Name string } { return struct{ Name string }{} }`,
		},
	}
	for _, probe := range passes {
		t.Run("passes: "+probe.shape, func(t *testing.T) {
			if findings := exports(t, probe.source); len(findings) != 0 {
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
func build() any { return &workcontext.Claims{} }`,
		},
		{
			// Round thirteen's major 3: no literal, no new(), and the decode
			// lands in the zero value the declaration allocated.
			"a decode into a zero-value variable",
			`package solution
import (
	"google.golang.org/protobuf/proto"
	"github.com/codefly-dev/sdk-go/workcontext"
)
func sealOf(raw []byte) (*workcontext.SealedValues, error) {
	var seal workcontext.SealedValues
	if err := proto.Unmarshal(raw, &seal); err != nil {
		return nil, err
	}
	return &seal, nil
}`,
		},
		{
			"the same, declared at package level",
			`package solution
import "github.com/codefly-dev/sdk-go/workcontext"
var scratchSeal workcontext.SealedValues`,
		},
	}
	for _, probe := range caught {
		t.Run(probe.shape, func(t *testing.T) {
			file := parse(t, probe.source)
			if built := coreCapabilityConstructions(file, localCapabilityTypes(map[string]*ast.File{"probe.go": file})); len(built) == 0 {
				t.Errorf("the gate did not catch %s, so a second decoder of core's encoding can grow here:\n%s", probe.shape, probe.source)
			}
		})
	}

	t.Run("passes: reading a seal through the accessor", func(t *testing.T) {
		// What credential.go actually does. The type is named, in a parameter
		// and a result, and nothing is allocated — so a rule on the NAME would
		// refuse the supported way to read a seal, and this one does not.
		control := parse(t, `package solution
import "github.com/codefly-dev/sdk-go/workcontext"
func holdSealedIdentity(seal *workcontext.SealedValues) sealedIdentity {
	return sealedIdentity{
		installation: seal.GetInstallationId(),
		digest:       seal.GetImageDigest(),
		incarnation:  seal.GetBuildIncarnation(),
	}
}`)
		built := coreCapabilityConstructions(control, localCapabilityTypes(map[string]*ast.File{"probe.go": control}))
		if len(built) != 0 {
			t.Errorf("the gate refused reading a seal through the SDK's accessor, which is the one supported way to do it: %v", built)
		}
	})
}

// issuesTLSMaterialOnly is THE condition the signing-primitive relaxation
// turns on, as one function.
//
// It was a copy: the gate computed the condition inline and the test that
// claimed to pin it recomputed the same expression. An executed round changed
// the real gate to permit a signing import in every passthroughtest file and
// the test still passed — which makes it worthless as evidence for the gate,
// and it is the exact failure I had written into the gate's own comments as
// the thing to avoid ("a probe that re-implements the check proves only that
// two copies agree"). Struck as evidence and replaced by this.
func issuesTLSMaterialOnly(name string, file *ast.File) bool {
	return strings.HasPrefix(name, "passthroughtest/") &&
		len(workContextImports(file)) == 0 && dotImportedWorkContext(file) == ""
}

// TestTheSigningRelaxationIsConditional pins the one relaxation in the
// signing-primitive rule, in both directions.
//
// A file under passthroughtest that issues TLS material may hold a key
// primitive, because sdk-go#51 requires the fake mint endpoint to present a
// SPIFFE ID and httptest's shared certificate has none. The same file may NOT
// hold one once it touches anything capability-shaped — a file doing both is
// precisely what this gate exists to refuse, and "it is only the test seam" is
// how that would arrive.
func TestTheSigningRelaxationIsConditional(t *testing.T) {
	parse := func(t *testing.T, source string) *ast.File {
		t.Helper()
		file, err := parser.ParseFile(token.NewFileSet(), "probe.go", source, 0)
		if err != nil {
			t.Fatalf("parse the probe: %v", err)
		}
		return file
	}
	// THE rule the gate uses, not a copy of it. The copy survived the real
	// condition being removed, which is why this calls the function the
	// scanner calls.
	relaxed := issuesTLSMaterialOnly

	tlsOnly := parse(t, `package passthroughtest
import (
	"crypto/ecdsa"
	"crypto/x509"
)
func leaf() (*x509.Certificate, *ecdsa.PrivateKey) { return nil, nil }`)
	if !relaxed("passthroughtest/identity.go", tlsOnly) {
		t.Error("the relaxation does not cover a passthroughtest file that only issues TLS material, so the seam cannot present the SPIFFE ID the SDK now requires of the mint endpoint")
	}
	if relaxed("credential.go", tlsOnly) {
		t.Error("the relaxation reaches the root package: this is where the runtime lives, and a signing primitive here is the first step of the duplication this gate exists to refuse")
	}

	alsoCapabilities := parse(t, `package passthroughtest
import (
	"crypto/ecdsa"
	"github.com/codefly-dev/sdk-go/workcontext"
)
func sign(seal *workcontext.SealedValues, key *ecdsa.PrivateKey) []byte { return nil }`)
	if relaxed("passthroughtest/identity.go", alsoCapabilities) {
		t.Error("a passthroughtest file holding BOTH a signing primitive and a work-context import is relaxed: that is a capability signer in the test seam, which is the shape this gate was written for and the one most likely to be argued for as harmless")
	}
}

// TestTheCapabilityDecodeGateCatchesADestinationItDidNotAllocate is round
// fourteen's B3.
//
// I asserted that decoding requires an allocation. A reviewer showed the
// zero-value declaration, which `ValueSpec` closed, and then showed the
// premise was wrong a second way: the allocation need not be in the inspected
// code at all. The destination arrives as a parameter and the caller allocated
// it, so there is no literal, no `new`, no declaration, no generated import,
// no signing primitive, no verifier and no prohibited name.
func TestTheCapabilityDecodeGateCatchesADestinationItDidNotAllocate(t *testing.T) {
	parse := func(t *testing.T, source string) *ast.File {
		t.Helper()
		file, err := parser.ParseFile(token.NewFileSet(), "probe.go", source, 0)
		if err != nil {
			t.Fatalf("parse the probe: %v", err)
		}
		return file
	}
	decodes := func(t *testing.T, source string) []string {
		t.Helper()
		file := parse(t, source)
		return capabilityDecodes(file, localCapabilityTypes(map[string]*ast.File{"probe.go": file}))
	}

	caught := []struct{ shape, source string }{
		{
			"the destination is a parameter the caller allocated",
			`package solution
import (
	"google.golang.org/protobuf/proto"
	"github.com/codefly-dev/sdk-go/workcontext"
)
func decodeSeal(raw []byte, dst *workcontext.SealedValues) error {
	return proto.Unmarshal(raw, dst)
}`,
		},
		{
			"the same, through a local alias for the capability type",
			`package solution
import (
	"google.golang.org/protobuf/proto"
	"github.com/codefly-dev/sdk-go/workcontext"
)
type mySeal = workcontext.SealedValues
func decodeSeal(raw []byte, dst *mySeal) error { return proto.Unmarshal(raw, dst) }`,
		},
		{
			"protojson rather than proto",
			`package solution
import (
	"google.golang.org/protobuf/encoding/protojson"
	"github.com/codefly-dev/sdk-go/workcontext"
)
func decodeSeal(raw []byte, dst *workcontext.SealedValues) error {
	return protojson.Unmarshal(raw, dst)
}`,
		},
		{
			"a whole capability, not just its seal",
			`package solution
import (
	"google.golang.org/protobuf/proto"
	"github.com/codefly-dev/sdk-go/workcontext"
)
func decode(raw []byte, dst *workcontext.Claims) error { return proto.Unmarshal(raw, dst) }`,
		},
		{
			// Round fifteen: the destination is put in a name the scanner had
			// never heard of, and there is no allocation either.
			"the destination is assigned to another name first",
			`package solution
import (
	"google.golang.org/protobuf/proto"
	"github.com/codefly-dev/sdk-go/workcontext"
)
func decodeSeal(raw []byte, dst *workcontext.SealedValues) error {
	target := dst
	return proto.Unmarshal(raw, target)
}`,
		},
		{
			"the same, two assignments deep",
			`package solution
import (
	"google.golang.org/protobuf/proto"
	"github.com/codefly-dev/sdk-go/workcontext"
)
func decodeSeal(raw []byte, dst *workcontext.SealedValues) error {
	a := dst
	b := a
	return proto.Unmarshal(raw, b)
}`,
		},
		{
			"an assignment in a declaration's clothing",
			`package solution
import (
	"google.golang.org/protobuf/proto"
	"github.com/codefly-dev/sdk-go/workcontext"
)
func decodeSeal(raw []byte, dst *workcontext.SealedValues) error {
	var target = dst
	return proto.Unmarshal(raw, target)
}`,
		},
		{
			// The executed round's second shape: a local type alias, and the
			// zero value it declares.
			"a local type alias for the seal, decoded into its zero value",
			`package solution
import (
	"google.golang.org/protobuf/proto"
	"github.com/codefly-dev/sdk-go/workcontext"
)
type hiddenSeal = workcontext.SealedValues
func decodeAlias(raw []byte) error {
	var seal hiddenSeal
	return proto.Unmarshal(raw, &seal)
}`,
		},
		{
			// F1, and the reason it hid for three rounds: the gate knew
			// "WorkContextV1" and the SDK does not export that name — it
			// exports Claims. Both probes that claimed to cover the whole
			// capability named a type that does not exist, and a probe only
			// PARSES its source, so nothing ever failed.
			"the SDK's REAL whole-capability alias",
			`package solution
import (
	"google.golang.org/protobuf/proto"
	"github.com/codefly-dev/sdk-go/workcontext"
)
func reviewDecode(raw []byte) error {
	var dst workcontext.Claims
	return proto.Unmarshal(raw, &dst)
}`,
		},
		{
			"a Decode rather than an Unmarshal",
			`package solution
import (
	"encoding/json"
	"io"
	"github.com/codefly-dev/sdk-go/workcontext"
)
func decodeSeal(r io.Reader, dst *workcontext.SealedValues) error {
	return json.NewDecoder(r).Decode(dst)
}`,
		},
		{
			"a FUNCTION-LOCAL type alias, which no package-level scan sees",
			`package solution
import (
	"google.golang.org/protobuf/proto"
	"github.com/codefly-dev/sdk-go/workcontext"
)
func decodeSeal(raw []byte) error {
	type localSeal = workcontext.SealedValues
	var dst localSeal
	return proto.Unmarshal(raw, &dst)
}`,
		},
		{
			"the operation-binding alias, which the list also omitted",
			`package solution
import (
	"google.golang.org/protobuf/proto"
	"github.com/codefly-dev/sdk-go/workcontext"
)
func decodeBinding(raw []byte, dst *workcontext.SealedOperationBinding) error {
	return proto.Unmarshal(raw, dst)
}`,
		},
	}
	for _, probe := range caught {
		t.Run(probe.shape, func(t *testing.T) {
			if found := decodes(t, probe.source); len(found) == 0 {
				t.Errorf("the gate did not catch a decode where %s, so a second reader of core's encoding can grow here:\n%s", probe.shape, probe.source)
			}
		})
	}

	t.Run("passes: reading a seal through the accessor", func(t *testing.T) {
		// What credential.go does. The type is named in a parameter and
		// nothing is decoded, so a rule on the NAME would refuse the one
		// supported way to read a seal.
		found := decodes(t, `package solution
import "github.com/codefly-dev/sdk-go/workcontext"
func holdSealedIdentity(seal *workcontext.SealedValues) sealedIdentity {
	return sealedIdentity{
		installation: seal.GetInstallationId(),
		digest:       seal.GetImageDigest(),
		incarnation:  seal.GetBuildIncarnation(),
	}
}`)
		if len(found) != 0 {
			t.Errorf("the gate refused reading a seal through the SDK's accessor, which is the one supported way to do it: %v", found)
		}
	})

	t.Run("passes: an accessor read through an assignment", func(t *testing.T) {
		// The alias-following must not turn an ordinary local into a decode.
		found := decodes(t, `package solution
import "github.com/codefly-dev/sdk-go/workcontext"
func hold(seal *workcontext.SealedValues) string {
	s := seal
	return s.GetInstallationId()
}`)
		if len(found) != 0 {
			t.Errorf("the gate refused reading a seal through a local, which decodes nothing: %v", found)
		}
	})

	t.Run("passes: an ordinary json Decode", func(t *testing.T) {
		// Adding Decode to the matched names must not refuse every decoder in
		// the package, which serves and reads JSON for a living.
		found := decodes(t, `package solution
import (
	"encoding/json"
	"io"
)
func decode(r io.Reader, dst *struct{ A int }) error { return json.NewDecoder(r).Decode(dst) }`)
		if len(found) != 0 {
			t.Errorf("the gate refused an ordinary json decode: %v", found)
		}
	})

	t.Run("passes: an ordinary json Decode", func(t *testing.T) {
		// Matching "Decode" as well as "Unmarshal" must not refuse every
		// decoder in a package that reads JSON for a living.
		found := decodes(t, `package solution
import (
	"encoding/json"
	"io"
)
func decode(r io.Reader, dst *struct{ A int }) error { return json.NewDecoder(r).Decode(dst) }`)
		if len(found) != 0 {
			t.Errorf("the gate refused an ordinary json decode: %v", found)
		}
	})

	t.Run("passes: decoding something that is not a capability", func(t *testing.T) {
		// This package decodes module responses for a living.
		found := decodes(t, `package solution
import "google.golang.org/protobuf/proto"
func decode(raw []byte, msg proto.Message) error { return proto.Unmarshal(raw, msg) }`)
		if len(found) != 0 {
			t.Errorf("the gate refused an ordinary protobuf decode, which is most of what this package does: %v", found)
		}
	})
}

// TestEverySDKCapabilityAliasIsInTheGatesList derives the gate's capability
// names from the PINNED SDK rather than trusting the list.
//
// This is the test that would have caught F1 three rounds earlier. The gate
// knew "WorkContextV1" and the SDK does not export that name at all — it
// exports `Claims`, an alias for core's `basev0.WorkContextV1` — so the whole
// capability was never covered, and both probes that claimed to cover it named
// a nonexistent type. They only PARSED their source, so a name that cannot
// compile supplied the evidence that the rule worked.
//
// Reading the SDK's own source means an alias it adds later fails this test
// instead of silently widening the hole.
func TestEverySDKCapabilityAliasIsInTheGatesList(t *testing.T) {
	out, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/codefly-dev/sdk-go/workcontext").Output()
	if err != nil {
		t.Skipf("the pinned workcontext module is not resolvable here, so this cannot check the list: %v", err)
	}
	dir := strings.TrimSpace(string(out))
	sources, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil || len(sources) == 0 {
		t.Fatalf("found %d sources in the pinned SDK at %q: a check that reads nothing passes", len(sources), dir)
	}

	// Core's capability messages. An alias for one of these is an alias for a
	// thing only core may encode or decode.
	capabilityMessages := map[string]bool{
		"WorkContextV1": true, "WorkSealV1": true, "WorkOperationBindingV1": true,
	}
	fset := token.NewFileSet()
	found := 0
	for _, name := range sources {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse the pinned SDK's %s: %v", filepath.Base(name), err)
		}
		for _, decl := range file.Decls {
			declared, ok := decl.(*ast.GenDecl)
			if !ok || declared.Tok != token.TYPE {
				continue
			}
			for _, spec := range declared.Specs {
				typed, ok := spec.(*ast.TypeSpec)
				if !ok || typed.Assign == 0 || !typed.Name.IsExported() {
					continue // a definition, or unexported: neither is a name a consumer can write
				}
				target, ok := typed.Type.(*ast.SelectorExpr)
				if !ok || !capabilityMessages[target.Sel.Name] {
					continue
				}
				found++
				if !coreCapabilityType(typed.Name.Name) {
					t.Errorf("the pinned SDK exports %s = %s, an alias for one of core's capability messages, and the gate's name list does not contain it: a decode into that name escapes every rule here, which is exactly how the whole capability went uncovered while two probes claimed otherwise",
						typed.Name.Name, target.Sel.Name)
				}
			}
		}
	}
	if found == 0 {
		t.Fatal("found no capability aliases in the pinned SDK at all, so this check proves nothing: the SDK re-exports core's WorkContextV1 and WorkSealV1 and this test is the thing that notices when it stops")
	}
	t.Logf("checked %d exported capability aliases in the pinned SDK", found)
}
