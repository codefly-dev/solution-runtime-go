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
// This checks signing primitives, local capability declarations, verifier
// references, and decoding into Core's capability/seal wire types. It does not
// forbid encoding/json — this package serves JSON documents for a living — and
// the one capability-shaped JSON this package does touch, the mint endpoint's
// HTTP bodies, lives in the SDK client and not here.
func TestNoWorkContextImplementationGrowsHere(t *testing.T) {
	for _, pkg := range moduleBoundaryPackages(t) {
		for _, violation := range implementationViolations(pkg) {
			t.Error(violation)
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
	for _, pkg := range moduleBoundaryPackages(t) {
		for _, violation := range typedVerifierReferences(pkg) {
			t.Error(violation)
		}
		for _, file := range pkg.files {
			if dotted := dotImportedWorkContext(file); dotted != "" {
				t.Errorf("%s dot-imports %s: keep the owner of capability operations explicit", pkg.fset.Position(file.Pos()), dotted)
			}
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
	for _, pkg := range moduleBoundaryPackages(t) {
		for _, violation := range newSeamBoundary(pkg).violations() {
			t.Error(violation)
		}
		for _, file := range pkg.files {
			for _, decl := range file.Decls {
				if decl, ok := decl.(*ast.GenDecl); ok {
					for _, spec := range decl.Specs {
						if typed, ok := spec.(*ast.TypeSpec); ok && typed.Name.Name == "PassthroughEnvironment" {
							t.Errorf("%s exports the removed PassthroughEnvironment", pkg.fset.Position(typed.Pos()))
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
	for _, pkg := range moduleBoundaryPackages(t) {
		for _, violation := range newHandlerBoundary(t, pkg).violations() {
			t.Error(violation)
		}
	}
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
			if name := entry.Name(); path != "." && (name == "vendor" || name == "testdata" || strings.HasPrefix(name, ".")) {
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
	for _, tc := range []struct {
		name, probe string
		refused     bool
	}{
		{"an exported path one hop from the seam is seen", "seam_indirect", true},
		{"a refusal one hop away is seen too", "control_guard_helper", false},
		{"a function that reaches nothing is not flagged", "control_guard_unrelated", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			violations := newSeamBoundary(boundaryProbe(t, tc.probe)).violations()
			if (len(violations) != 0) != tc.refused {
				t.Fatalf("refused=%t, want %t: %v", len(violations) != 0, tc.refused, violations)
			}
		})
	}
}
