package solution

import (
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
		// Constructing and decoding one of core's capability messages used to
		// be checked here, syntactically. Both are in
		// typed_boundary_test.go now
		// (TestNoCapabilityIsConstructedOrDecodedByType), keyed on core's
		// GENERATED PACKAGE PATH rather than on a set of message names — so an
		// alias, a function-local alias, an assignment, a supplied destination
		// and a message core adds tomorrow are all one case. The list of names
		// was the defect: it knew WorkContextV1 and WorkSealV1, the SDK
		// exports those as Claims and SealedValues, and three rounds went into
		// adding names to it.

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

// The handler-export, capability-decoder and seal-construction rules used to
// live here, syntactically: name lists, rendered type spellings, alias maps and
// a probe list that every review round extended by one shape. They are in
// typed_boundary_test.go now, built on go/types, where an alias, an anonymous
// struct, a supplied destination and an assignment are all resolved rather than
// matched. What stays in this file is what is genuinely syntactic: the import
// rules, the declaration-name rule, the verifier rule and the seam's call
// graph.

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
