package solution

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
)

const boundaryModule = "github.com/codefly-dev/solution-runtime-go"

type boundaryPackage struct {
	fset  *token.FileSet
	files []*ast.File
	info  *types.Info
	pkg   *types.Package
	imp   types.Importer
}

// Use the compiler's export data, not stand-in declarations of the types the
// gates protect. go/importer.Default alone cannot resolve module dependencies.
// A failed load/type check fails the gate; partial type information never means
// a source was admitted. No dependency or toolchain downloads are needed here.
var boundaryExports = sync.OnceValues(func() (map[string]string, error) {
	cmd := exec.Command("go", "list", "-deps", "-export", "-json", "-test", "./...")
	cmd.Env = append(os.Environ(), "GOPROXY=off", "GOSUMDB=off", "GOTOOLCHAIN=local")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("load boundary types: %w\n%s", err, stderr.String())
	}
	exports := map[string]string{}
	decoder := json.NewDecoder(bytes.NewReader(out))
	for {
		var pkg struct{ ImportPath, Export string }
		if err := decoder.Decode(&pkg); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		exports[pkg.ImportPath] = pkg.Export
	}
	return exports, nil
})

func boundaryImporter(t *testing.T, fset *token.FileSet) types.Importer {
	t.Helper()
	exports, err := boundaryExports()
	if err != nil {
		t.Fatal(err)
	}
	return importer.ForCompiler(fset, "gc", func(path string) (io.ReadCloser, error) {
		file := exports[path]
		if file == "" {
			return nil, fmt.Errorf("no compiler export data for %s", path)
		}
		return os.Open(file)
	})
}

func checkBoundaryPackage(t *testing.T, fset *token.FileSet, imp types.Importer, path string, files []*ast.File) *boundaryPackage {
	t.Helper()
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	conf := types.Config{Importer: imp}
	pkg, err := conf.Check(path, fset, files, info)
	if err != nil {
		t.Fatalf("type-check boundary input: %v", err)
	}
	return &boundaryPackage{fset: fset, files: files, info: info, pkg: pkg, imp: imp}
}

func moduleBoundaryPackages(t *testing.T) []*boundaryPackage {
	t.Helper()
	fset := token.NewFileSet()
	imp := boundaryImporter(t, fset)
	groups := map[string][]*ast.File{}
	var dirs []string
	for _, name := range moduleSources(t) {
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Dir(name)
		if _, ok := groups[dir]; !ok {
			dirs = append(dirs, dir)
		}
		groups[dir] = append(groups[dir], file)
	}
	var packages []*boundaryPackage
	for _, dir := range dirs {
		path := boundaryModule
		if dir != "." {
			path += "/" + filepath.ToSlash(dir)
		}
		packages = append(packages, checkBoundaryPackage(t, fset, imp, path, groups[dir]))
	}
	return packages
}

func boundaryProbe(t *testing.T, name string) *boundaryPackage {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("testdata", "boundary", name+".go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	path := boundaryModule
	if file.Name.Name != "solution" {
		path += "/" + file.Name.Name
	}
	return checkBoundaryPackage(t, fset, boundaryImporter(t, fset), path, []*ast.File{file})
}

func boundaryObject(info *types.Info, expr ast.Expr) types.Object {
	switch expr := ast.Unparen(expr).(type) {
	case *ast.Ident:
		return info.ObjectOf(expr)
	case *ast.SelectorExpr:
		return info.ObjectOf(expr.Sel)
	case *ast.IndexExpr:
		return boundaryObject(info, expr.X)
	case *ast.IndexListExpr:
		return boundaryObject(info, expr.X)
	}
	return nil
}

func boundaryNamed(typ types.Type, path, name string) bool {
	if typ == nil {
		return false
	}
	named, ok := types.Unalias(typ).(*types.Named)
	return ok && named.Obj().Pkg() != nil && named.Obj().Pkg().Path() == path && named.Obj().Name() == name
}
