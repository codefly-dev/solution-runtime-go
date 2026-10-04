package solution

import (
	"fmt"
	"go/ast"
	"go/constant"
	"go/token"
	"go/types"
	"maps"
	"strings"
	"testing"
)

type seamBoundary struct {
	pkg     *boundaryPackage
	funcs   map[types.Object]*ast.FuncDecl
	reaches map[types.Object]bool
}

func isSeam(object types.Object) bool {
	return object != nil && object.Pkg() != nil && object.Pkg().Path() == boundaryModule+"/internal/seam" && object.Name() == "Passthrough"
}

func newSeamBoundary(pkg *boundaryPackage) *seamBoundary {
	g := &seamBoundary{pkg: pkg, funcs: map[types.Object]*ast.FuncDecl{}, reaches: map[types.Object]bool{}}
	edges := map[types.Object][]types.Object{}
	for _, file := range pkg.files {
		ast.Inspect(file, func(node ast.Node) bool {
			switch node := node.(type) {
			case *ast.FuncDecl:
				object := pkg.info.Defs[node.Name]
				g.funcs[object] = node
				ast.Inspect(node.Body, func(node ast.Node) bool {
					if id, ok := node.(*ast.Ident); ok {
						edges[object] = append(edges[object], pkg.info.ObjectOf(id))
					}
					return true
				})
			case *ast.AssignStmt:
				for i, lhs := range node.Lhs {
					if i < len(node.Rhs) {
						left, right := boundaryObject(pkg.info, lhs), boundaryObject(pkg.info, node.Rhs[i])
						edges[left] = append(edges[left], right)
						// The root registers the constructor rather than calling
						// the seam. That constructor is the same boundary.
						if isSeam(left) && right != nil {
							g.reaches[right] = true
						}
					}
				}
			case *ast.ValueSpec:
				for i, name := range node.Names {
					if i < len(node.Values) {
						edges[pkg.info.Defs[name]] = append(edges[pkg.info.Defs[name]], boundaryObject(pkg.info, node.Values[i]))
					}
				}
			}
			return true
		})
	}
	for changed := true; changed; {
		changed = false
		for caller, callees := range edges {
			for _, callee := range callees {
				if caller != nil && (isSeam(callee) || g.reaches[callee]) && !g.reaches[caller] {
					g.reaches[caller], changed = true, true
				}
			}
		}
	}
	return g
}

type refusalFlow uint8

const (
	continues refusalFlow = 1 << iota
	escapes
	refuses
)

// Refusal is a must property, unlike seam reachability (a may property). A
// syntactic call graph cannot propagate both the same way. Interpret the
// synchronous prefix with testing.Testing() false, retaining EVERY possible
// path. Only an unavoidable panic before seam use proves refusal. Never credit
// a closure merely declared, a goroutine, a deferred call, or a short-circuited
// operand. A defer before the guard can recover its panic, including through a
// helper, so it invalidates the proof. Unsupported control flow also fails
// closed; extending this small proof language requires controls and probes.
func (g *seamBoundary) functionRefuses(object types.Object, args []ast.Expr, caller map[types.Object]bool, active map[types.Object]bool) bool {
	fn := g.funcs[object]
	if fn == nil || fn.Body == nil || active[object] {
		return false
	}
	active[object] = true
	defer delete(active, object)
	facts := map[types.Object]bool{}
	signature := object.Type().(*types.Signature)
	for i, arg := range args {
		if i < signature.Params().Len() {
			if value, known := g.boolean(arg, caller); known {
				facts[signature.Params().At(i)] = value
			}
		}
	}
	return g.block(fn.Body.List, facts, active) == refuses
}

func (g *seamBoundary) boolean(expr ast.Expr, facts map[types.Object]bool) (bool, bool) {
	if value := g.pkg.info.Types[expr].Value; value != nil && value.Kind() == constant.Bool {
		return constant.BoolVal(value), true
	}
	switch expr := ast.Unparen(expr).(type) {
	case *ast.Ident:
		value, known := facts[g.pkg.info.ObjectOf(expr)]
		return value, known
	case *ast.UnaryExpr:
		if expr.Op == token.NOT {
			value, known := g.boolean(expr.X, facts)
			return !value, known
		}
	case *ast.CallExpr:
		object := boundaryObject(g.pkg.info, expr.Fun)
		if object != nil && object.Pkg() != nil && object.Pkg().Path() == "testing" && object.Name() == "Testing" {
			return false, true
		}
	}
	return false, false
}

func (g *seamBoundary) block(stmts []ast.Stmt, facts map[types.Object]bool, active map[types.Object]bool) refusalFlow {
	flow := continues
	for _, stmt := range stmts {
		if flow&continues == 0 {
			break
		}
		flow = flow&^continues | g.statement(stmt, facts, active)
	}
	return flow
}

func (g *seamBoundary) statement(stmt ast.Stmt, facts map[types.Object]bool, active map[types.Object]bool) refusalFlow {
	switch stmt := stmt.(type) {
	case *ast.EmptyStmt:
		return continues
	case *ast.BlockStmt:
		return g.block(stmt.List, facts, active)
	case *ast.ExprStmt:
		return g.expression(stmt.X, facts, active)
	case *ast.ReturnStmt:
		flow := g.expressions(stmt.Results, facts, active)
		if flow&continues != 0 {
			flow = flow&^continues | escapes
		}
		return flow
	case *ast.AssignStmt:
		flow := g.expressions(stmt.Rhs, facts, active)
		for i, lhs := range stmt.Lhs {
			object := boundaryObject(g.pkg.info, lhs)
			delete(facts, object)
			if i < len(stmt.Rhs) {
				if value, known := g.boolean(stmt.Rhs[i], facts); known {
					facts[object] = value
				}
			}
		}
		return flow
	case *ast.IfStmt:
		flow := continues
		if stmt.Init != nil {
			flow = g.statement(stmt.Init, facts, active)
		}
		if flow&continues == 0 {
			return flow
		}
		flow = flow&^continues | g.expression(stmt.Cond, facts, active)
		if flow&continues == 0 {
			return flow
		}
		otherwise := func(facts map[types.Object]bool) refusalFlow {
			if stmt.Else == nil {
				return continues
			}
			return g.statement(stmt.Else, facts, active)
		}
		var branch refusalFlow
		if value, known := g.boolean(stmt.Cond, facts); known {
			if value {
				branch = g.block(stmt.Body.List, facts, active)
			} else {
				branch = otherwise(facts)
			}
		} else {
			branch = g.block(stmt.Body.List, maps.Clone(facts), active) | otherwise(maps.Clone(facts))
			clear(facts) // no path's mutable boolean facts dominate the join
		}
		return flow&^continues | branch
	default:
		// Includes defer, go, loops, select/switch and goto. None is a
		// reason to approve an otherwise unproven production refusal.
		return escapes
	}
}

func (g *seamBoundary) expressions(exprs []ast.Expr, facts map[types.Object]bool, active map[types.Object]bool) refusalFlow {
	flow := continues
	for _, expr := range exprs {
		if flow&continues == 0 {
			break
		}
		flow = flow&^continues | g.expression(expr, facts, active)
	}
	return flow
}

func (g *seamBoundary) expression(expr ast.Expr, facts map[types.Object]bool, active map[types.Object]bool) refusalFlow {
	switch expr := ast.Unparen(expr).(type) {
	case *ast.CallExpr:
		flow := g.expression(expr.Fun, facts, active)
		if flow&continues != 0 {
			flow = flow&^continues | g.expressions(expr.Args, facts, active)
		}
		if flow&continues == 0 {
			return flow
		}
		result := continues
		object := boundaryObject(g.pkg.info, expr.Fun)
		if object == types.Universe.Lookup("panic") || g.functionRefuses(object, expr.Args, facts, active) {
			result = refuses
		} else if isSeam(object) || g.reaches[object] {
			result = escapes
		} else if literal, ok := ast.Unparen(expr.Fun).(*ast.FuncLit); ok {
			// No outer facts are lent to closure parameters or mutations.
			if g.block(literal.Body.List, map[types.Object]bool{}, active) == refuses {
				result = refuses
			}
		}
		if result == continues {
			// A returning call can mutate a captured/addressed boolean. Its
			// old value is no evidence for a guard after that call.
			clear(facts)
		}
		return flow&^continues | result
	case *ast.BinaryExpr:
		left := g.expression(expr.X, facts, active)
		if left&continues == 0 {
			return left
		}
		if expr.Op == token.LAND || expr.Op == token.LOR {
			value, known := g.boolean(expr.X, facts)
			if known && ((expr.Op == token.LAND && !value) || (expr.Op == token.LOR && value)) {
				return left
			}
			right := g.expression(expr.Y, facts, active)
			if !known {
				right |= continues
			}
			return left&^continues | right
		}
		return left&^continues | g.expression(expr.Y, facts, active)
	case *ast.UnaryExpr:
		return g.expression(expr.X, facts, active)
	case *ast.SelectorExpr:
		return g.expression(expr.X, facts, active)
	case *ast.IndexExpr:
		return g.expressions([]ast.Expr{expr.X, expr.Index}, facts, active)
	}
	return continues
}

func (g *seamBoundary) violations() []string {
	if g.pkg.pkg.Path() == boundaryModule+"/internal/seam" {
		return nil
	}
	var violations []string
	for _, name := range g.pkg.pkg.Scope().Names() {
		object := g.pkg.pkg.Scope().Lookup(name)
		if object.Exported() && g.reaches[object] {
			if _, function := object.(*types.Func); !function {
				violations = append(violations, fmt.Sprintf("%s: %s exposes the seam as a value", g.pkg.fset.Position(object.Pos()), name))
			}
		}
	}
	for object, fn := range g.funcs {
		if object.Exported() && g.reaches[object] && !g.functionRefuses(object, nil, nil, map[types.Object]bool{}) {
			violations = append(violations, fmt.Sprintf("%s: %s reaches the seam without an unavoidable production refusal", g.pkg.fset.Position(fn.Pos()), object.Name()))
		}
	}
	return violations
}

func TestSeamGuardProbes(t *testing.T) {
	for _, name := range []string{"g7a_false_guard", "g7b_recovered_guard", "b6_unreachable_helper", "b6_recovered_helper", "b6_mutated_guard", "guard_early_return", "guard_goroutine", "guard_deferred", "guard_uncalled_closure", "guard_short_circuit", "guard_wrong_argument", "guard_after_seam", "guard_goto", "guard_noop"} {
		t.Run(name, func(t *testing.T) {
			violations := newSeamBoundary(boundaryProbe(t, name)).violations()
			if len(violations) == 0 {
				t.Fatal("admitted a defeated guard")
			}
			t.Logf("refused: %s", strings.Join(violations, "; "))
		})
	}
	for _, name := range []string{"control_guard_direct", "control_guard_helper", "control_guard_branches", "control_guard_unrelated"} {
		t.Run(name, func(t *testing.T) {
			if violations := newSeamBoundary(boundaryProbe(t, name)).violations(); len(violations) != 0 {
				t.Fatalf("refused control: %v", violations)
			}
			t.Log("admitted control")
		})
	}
}
