package solution

import (
	"fmt"
	"go/ast"
	"go/types"
	"strconv"
	"strings"
	"testing"
)

func implementationDeclarations(file *ast.File) []string {
	var violations []string
	for _, imported := range file.Imports {
		path, err := strconv.Unquote(imported.Path.Value)
		if err != nil {
			violations = append(violations, err.Error())
			continue
		}
		switch path {
		case "crypto/ed25519", "crypto/ecdsa", "crypto/hmac", "crypto/rsa", "crypto/ed25519/internal/edwards25519":
			violations = append(violations, "imports signing primitive "+path+": only Core signs capabilities")
		}
		if strings.HasPrefix(path, "golang.org/x/crypto") || strings.Contains(path, "go-jose") || strings.Contains(path, "jwt") || strings.Contains(path, "jws") || strings.Contains(path, "jwk") {
			violations = append(violations, "imports signed-encoding implementation "+path)
		}
	}
	// These are the public refusal, mint-answer principals, and a cache of
	// opaque credentials, not a local capability implementation.
	// RequireWorkContextScope is not an exception:
	// enforcing a capability's authority belongs beside Core's verifier.
	allowed := map[string]bool{"WorkContextRefusal": true, "WorkContextPrincipals": true, "newWorkContextCache": true}
	check := func(name string) {
		if strings.Contains(name, "WorkContext") && !allowed[name] {
			violations = append(violations, "declares "+name+": this runtime carries capabilities; Core implements them")
		}
	}
	for _, decl := range file.Decls {
		switch decl := decl.(type) {
		case *ast.FuncDecl:
			check(decl.Name.Name)
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				if spec, ok := spec.(*ast.TypeSpec); ok {
					check(spec.Name.Name)
				}
			}
		}
	}
	return violations
}

func typedVerifierReferences(pkg *boundaryPackage) []string {
	var violations []string
	for id, object := range pkg.info.Uses {
		if object.Pkg() != nil && isWorkContextPath(object.Pkg().Path()) && strings.Contains(object.Name(), "Verif") {
			violations = append(violations, fmt.Sprintf("%s: references %s.%s: this runtime holds none of the verifier's live sources", pkg.fset.Position(id.Pos()), object.Pkg().Path(), object.Name()))
		}
	}
	return violations
}

const boundaryBaseProto = "github.com/codefly-dev/core/generated/go/codefly/base/v0"

func capabilityWireType(typ types.Type) bool {
	if typ == nil {
		return false
	}
	typ = types.Unalias(typ)
	if pointer, ok := typ.(*types.Pointer); ok {
		return capabilityWireType(pointer.Elem())
	}
	return boundaryNamed(typ, boundaryBaseProto, "WorkSealV1") || boundaryNamed(typ, boundaryBaseProto, "WorkContextV1")
}

func capabilityDecoder(object types.Object) bool {
	if object == nil || object.Pkg() == nil || object.Name() != "Unmarshal" {
		return false
	}
	switch object.Pkg().Path() {
	case "google.golang.org/protobuf/proto", "google.golang.org/protobuf/encoding/protojson", "encoding/json":
		return true
	}
	return false
}

// Core's SealedValues is now an alias of basev0.WorkSealV1. Reading a seal
// supplied by Credential.Seal is carriage, while decoding attacker-provided
// bytes into that same type is a second implementation. Check the decoder and
// its destination by object/type identity, not by the import spelling or the
// local alias's name. Track interface erasure and decoder function values too.
func localCapabilityDecoders(pkg *boundaryPackage) []string {
	wireValues, decoders := map[types.Object]bool{}, map[types.Object]bool{}
	var wireValue func(ast.Expr) bool
	wireValue = func(expr ast.Expr) bool {
		if capabilityWireType(pkg.info.TypeOf(expr)) || wireValues[boundaryObject(pkg.info, expr)] {
			return true
		}
		switch expr := ast.Unparen(expr).(type) {
		case *ast.UnaryExpr:
			return wireValue(expr.X)
		case *ast.CallExpr:
			if pkg.info.Types[expr.Fun].IsType() && len(expr.Args) == 1 {
				return wireValue(expr.Args[0])
			}
		}
		return false
	}
	for changed := true; changed; {
		changed = false
		bind := func(lhs, rhs ast.Expr) {
			object := boundaryObject(pkg.info, lhs)
			if object == nil {
				return
			}
			if wireValue(rhs) && !wireValues[object] {
				wireValues[object], changed = true, true
			}
			ref := boundaryObject(pkg.info, rhs)
			if (capabilityDecoder(ref) || decoders[ref]) && !decoders[object] {
				decoders[object], changed = true, true
			}
		}
		for _, file := range pkg.files {
			ast.Inspect(file, func(node ast.Node) bool {
				switch node := node.(type) {
				case *ast.AssignStmt:
					for i, lhs := range node.Lhs {
						if i < len(node.Rhs) {
							bind(lhs, node.Rhs[i])
						}
					}
				case *ast.ValueSpec:
					for i, name := range node.Names {
						if i < len(node.Values) {
							bind(name, node.Values[i])
						}
					}
				}
				return true
			})
		}
	}
	var violations []string
	for _, file := range pkg.files {
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			object := boundaryObject(pkg.info, call.Fun)
			if (capabilityDecoder(object) || decoders[object]) && len(call.Args) >= 2 && wireValue(call.Args[len(call.Args)-1]) {
				violations = append(violations, fmt.Sprintf("%s: locally decodes Core's capability/seal wire type; use the SDK/Core carrier", pkg.fset.Position(call.Pos())))
			}
			return true
		})
	}
	return violations
}

func implementationViolations(pkg *boundaryPackage) []string {
	violations := append(typedVerifierReferences(pkg), localCapabilityDecoders(pkg)...)
	for _, file := range pkg.files {
		for _, violation := range implementationDeclarations(file) {
			violations = append(violations, fmt.Sprintf("%s: %s", pkg.fset.Position(file.Pos()), violation))
		}
	}
	return violations
}

func TestImplementationBoundaryProbes(t *testing.T) {
	for _, name := range []string{"gr1_seal_reader", "seal_reader_alias", "seal_reader_sdk_alias", "seal_reader_erased", "seal_reader_options", "implementation_verifier", "implementation_ed25519", "implementation_require_scope"} {
		t.Run(name, func(t *testing.T) {
			violations := implementationViolations(boundaryProbe(t, name))
			if len(violations) == 0 {
				t.Fatal("admitted a local capability implementation")
			}
			t.Logf("refused: %s", strings.Join(violations, "; "))
		})
	}
	for _, name := range []string{"control_proto_message", "control_carried_seal", "control_core_fixtures"} {
		t.Run(name, func(t *testing.T) {
			if violations := implementationViolations(boundaryProbe(t, name)); len(violations) != 0 {
				t.Fatalf("refused control: %v", violations)
			}
			t.Log("admitted control")
		})
	}
}
