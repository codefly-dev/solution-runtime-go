package solution

import (
	"fmt"
	"go/ast"
	"go/types"
	"strings"
	"testing"
)

// Type identity survives import aliases and unexported aliases. Result values
// matter as well as result signatures: returning a handler through any still
// hands out that handler. The fixed point follows assignments and local return
// values, including a helper that already erased the handler's type.
type handlerBoundary struct {
	pkg       *boundaryPackage
	handler   *types.Interface
	roundTrip *types.Interface
	function  types.Type
	values    map[types.Object]bool
	returns   map[types.Object][]bool
}

func newHandlerBoundary(t *testing.T, pkg *boundaryPackage) *handlerBoundary {
	t.Helper()
	http, err := pkg.imp.Import("net/http")
	if err != nil {
		t.Fatal(err)
	}
	gate := &handlerBoundary{
		pkg:       pkg,
		handler:   http.Scope().Lookup("Handler").Type().Underlying().(*types.Interface),
		roundTrip: http.Scope().Lookup("RoundTripper").Type().Underlying().(*types.Interface),
		function:  http.Scope().Lookup("HandlerFunc").Type(),
		values:    map[types.Object]bool{}, returns: map[types.Object][]bool{},
	}
	for changed := true; changed; {
		changed = false
		mark := func(object types.Object, value bool, into map[types.Object]bool) {
			if object != nil && value && !into[object] {
				into[object], changed = true, true
			}
		}
		for _, file := range pkg.files {
			ast.Inspect(file, func(node ast.Node) bool {
				switch node := node.(type) {
				case *ast.AssignStmt:
					for i, lhs := range node.Lhs {
						if i < len(node.Rhs) {
							mark(boundaryObject(pkg.info, lhs), gate.expressionAt(node.Rhs[i], 0), gate.values)
						} else if len(node.Rhs) == 1 {
							mark(boundaryObject(pkg.info, lhs), gate.expressionAt(node.Rhs[0], i), gate.values)
						}
					}
				case *ast.ValueSpec:
					for i, name := range node.Names {
						if i < len(node.Values) {
							mark(pkg.info.Defs[name], gate.expressionAt(node.Values[i], 0), gate.values)
						} else if len(node.Values) == 1 {
							mark(pkg.info.Defs[name], gate.expressionAt(node.Values[0], i), gate.values)
						}
					}
				case *ast.FuncDecl:
					object := pkg.info.Defs[node.Name]
					returned := gate.bodyReturns(node.Body, node.Type)
					if gate.returns[object] == nil {
						gate.returns[object] = make([]bool, len(returned))
					}
					for i, value := range returned {
						if value && !gate.returns[object][i] {
							gate.returns[object][i], changed = true, true
						}
					}
				}
				return true
			})
		}
	}
	return gate
}

func (g *handlerBoundary) servable(typ types.Type) bool {
	seen := map[types.Type]bool{}
	var visit func(types.Type) bool
	visit = func(typ types.Type) bool {
		if typ == nil || seen[typ] {
			return false
		}
		seen[typ] = true
		typ = types.Unalias(typ)
		_, function := typ.Underlying().(*types.Signature)
		if types.Implements(typ, g.handler) || types.Implements(typ, g.roundTrip) || (function && types.ConvertibleTo(typ, g.function)) {
			return true
		}
		if named, ok := typ.(*types.Named); ok {
			if types.Implements(types.NewPointer(named), g.handler) || types.Implements(types.NewPointer(named), g.roundTrip) {
				return true
			}
			// An external client/configuration is not a handler wrapper owned
			// here. In particular Gateway.HTTPClient is an intentional API.
			if named.Obj().Pkg() != nil && !strings.HasPrefix(named.Obj().Pkg().Path(), boundaryModule) {
				return false
			}
		}
		switch typ := typ.Underlying().(type) {
		case *types.Pointer:
			return visit(typ.Elem())
		case *types.Slice:
			return visit(typ.Elem())
		case *types.Array:
			return visit(typ.Elem())
		case *types.Map:
			return visit(typ.Key()) || visit(typ.Elem())
		case *types.Chan:
			return visit(typ.Elem())
		case *types.Struct:
			for i := 0; i < typ.NumFields(); i++ {
				if field := typ.Field(i); field.Exported() && visit(field.Type()) {
					return true
				}
			}
		case *types.Signature:
			return visit(typ.Results())
		case *types.Tuple:
			for i := 0; i < typ.Len(); i++ {
				if visit(typ.At(i).Type()) {
					return true
				}
			}
		}
		return false
	}
	return visit(typ)
}

func (g *handlerBoundary) expression(expr ast.Expr) bool {
	if g.servable(g.pkg.info.TypeOf(expr)) || g.values[boundaryObject(g.pkg.info, expr)] {
		return true
	}
	switch expr := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		if anyHandler(g.returns[boundaryObject(g.pkg.info, expr.Fun)]) {
			return true
		}
		if g.pkg.info.Types[expr.Fun].IsType() {
			for _, arg := range expr.Args {
				if g.expression(arg) {
					return true
				}
			}
		}
		if literal, ok := ast.Unparen(expr.Fun).(*ast.FuncLit); ok {
			return anyHandler(g.bodyReturns(literal.Body, literal.Type))
		}
	case *ast.FuncLit:
		return anyHandler(g.bodyReturns(expr.Body, expr.Type))
	case *ast.UnaryExpr:
		return g.expression(expr.X)
	case *ast.TypeAssertExpr:
		return g.expression(expr.X)
	case *ast.IndexExpr:
		return g.expression(expr.X)
	case *ast.CompositeLit:
		// Collections of any can erase handlers just as a return can. For
		// structs only exported fields are accessible to a consumer.
		typ := g.pkg.info.TypeOf(expr)
		if named, ok := types.Unalias(typ).(*types.Named); ok && named.Obj().Pkg() != nil && !strings.HasPrefix(named.Obj().Pkg().Path(), boundaryModule) {
			return false
		}
		structure, isStruct := typ.Underlying().(*types.Struct)
		for i, element := range expr.Elts {
			if pair, ok := element.(*ast.KeyValueExpr); ok {
				if isStruct {
					field, ok := boundaryObject(g.pkg.info, pair.Key).(*types.Var)
					if !ok || !field.Exported() {
						continue
					}
				} else if g.expression(pair.Key) {
					return true
				}
				element = pair.Value
			} else if isStruct && !structure.Field(i).Exported() {
				continue
			}
			if g.expression(element) {
				return true
			}
		}
	}
	return false
}

// Tuple slots stay separate: a helper returning (http.Handler, error) must
// never taint the error as a handler and then poison every caller's error path.
func (g *handlerBoundary) expressionAt(expr ast.Expr, index int) bool {
	if tuple, ok := g.pkg.info.TypeOf(expr).(*types.Tuple); ok {
		if g.servable(tuple.At(index).Type()) {
			return true
		}
		if call, ok := ast.Unparen(expr).(*ast.CallExpr); ok {
			returned := g.returns[boundaryObject(g.pkg.info, call.Fun)]
			return index < len(returned) && returned[index]
		}
		return false
	}
	return index == 0 && g.expression(expr)
}

func anyHandler(values []bool) bool {
	for _, value := range values {
		if value {
			return true
		}
	}
	return false
}

func (g *handlerBoundary) bodyReturns(body *ast.BlockStmt, signature *ast.FuncType) []bool {
	var names []*ast.Ident
	if signature.Results != nil {
		for _, field := range signature.Results.List {
			if len(field.Names) == 0 {
				names = append(names, nil)
			} else {
				names = append(names, field.Names...)
			}
		}
	}
	found := make([]bool, len(names))
	if body == nil {
		return found
	}
	ast.Inspect(body, func(node ast.Node) bool {
		if _, closure := node.(*ast.FuncLit); closure {
			return false
		}
		if ret, ok := node.(*ast.ReturnStmt); ok {
			for i := range found {
				if len(ret.Results) == 0 {
					if names[i] != nil {
						found[i] = found[i] || g.values[g.pkg.info.Defs[names[i]]]
					}
				} else if len(ret.Results) == 1 {
					found[i] = found[i] || g.expressionAt(ret.Results[0], i)
				} else {
					found[i] = found[i] || g.expression(ret.Results[i])
				}
			}
		}
		return true
	})
	return found
}

func (g *handlerBoundary) violations() []string {
	if g.pkg.pkg.Path() == boundaryModule+"/internal/seam" || g.pkg.pkg.Path() == boundaryModule+"/passthroughtest" {
		// The seam gate separately requires production refusal in the
		// importable test harness. Only internal/seam has the compiler gate.
		return nil
	}
	var violations []string
	for _, file := range g.pkg.files {
		for _, decl := range file.Decls {
			switch decl := decl.(type) {
			case *ast.FuncDecl:
				if decl.Name.IsExported() && (g.servable(g.pkg.info.TypeOf(decl.Name)) || anyHandler(g.returns[g.pkg.info.Defs[decl.Name]])) {
					violations = append(violations, fmt.Sprintf("%s: %s returns a servable handler outside Serve", g.pkg.fset.Position(decl.Pos()), decl.Name.Name))
				}
			case *ast.GenDecl:
				for _, spec := range decl.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						if spec.Name.IsExported() && g.servable(g.pkg.info.TypeOf(spec.Name)) {
							violations = append(violations, fmt.Sprintf("%s: %s exposes a servable type", g.pkg.fset.Position(spec.Pos()), spec.Name.Name))
						}
					case *ast.ValueSpec:
						for _, name := range spec.Names {
							if name.IsExported() && (g.servable(g.pkg.info.TypeOf(name)) || g.values[g.pkg.info.Defs[name]]) {
								violations = append(violations, fmt.Sprintf("%s: %s exposes a servable value", g.pkg.fset.Position(name.Pos()), name.Name))
							}
						}
					}
				}
			}
		}
	}
	return violations
}

func TestHandlerBoundaryProbes(t *testing.T) {
	for _, name := range []string{"g3_any", "g4_import_alias", "g5u_local_alias", "handler_direct", "handler_erased_helper", "handler_named_return", "handler_collection", "handler_field", "handler_function"} {
		t.Run(name, func(t *testing.T) {
			violations := newHandlerBoundary(t, boundaryProbe(t, name)).violations()
			if len(violations) == 0 {
				t.Fatal("admitted a handler escape")
			}
			t.Logf("refused: %s", strings.Join(violations, "; "))
		})
	}
	for _, name := range []string{"control_values", "control_private_handler", "control_handler_error"} {
		t.Run(name, func(t *testing.T) {
			if violations := newHandlerBoundary(t, boundaryProbe(t, name)).violations(); len(violations) != 0 {
				t.Fatalf("refused control: %v", violations)
			}
			t.Log("admitted control")
		})
	}
}
