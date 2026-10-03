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
		ast.Inspect(file, func(node ast.Node) bool {
			selector, ok := node.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			if selector.Sel.Name == "Verify" || selector.Sel.Name == "NewVerifier" {
				if pkg, ok := selector.X.(*ast.Ident); ok && (pkg.Name == "workcontext" || pkg.Name == "corework") {
					t.Errorf("%s verifies a capability (%s.%s): a verifier needs the issuer's live revision, replay, grant and seal sources, which this runtime does not hold. It presents its own credential and lets the component that holds them decide.",
						name, pkg.Name, selector.Sel.Name)
				}
			}
			return true
		})
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
