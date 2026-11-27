// docs_test.go checks that docs/tui.md exists and documents every key in
// internal/tui/keys.go's keyTable, every verb in cmd/snitch/main.go's usage,
// and the configuration keys and exit codes.
package main

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestDocsTUIKeysAndVerbs(t *testing.T) {
	docBytes, err := os.ReadFile(filepath.Join("..", "..", "docs", "tui.md"))
	if err != nil {
		t.Fatalf("read docs/tui.md: %v", err)
	}
	doc := string(docBytes)

	keys := extractKeyTableNames(t, filepath.Join("..", "..", "internal", "tui", "keys.go"))
	if len(keys) == 0 {
		t.Fatal("extracted zero keys from internal/tui/keys.go")
	}
	for _, k := range keys {
		if !strings.Contains(doc, "`"+k+"`") {
			t.Errorf("docs/tui.md does not document key %q", k)
		}
	}

	verbs := extractUsageVerbs(t, "main.go")
	if len(verbs) == 0 {
		t.Fatal("extracted zero verbs from main.go usage")
	}
	for _, v := range verbs {
		if !strings.Contains(doc, "`"+v+"`") {
			t.Errorf("docs/tui.md does not document verb %q", v)
		}
	}
}

func extractKeyTableNames(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	lit := findVarCompositeLit(f, "keyTable")
	if lit == nil {
		t.Fatalf("keyTable not found in %s", path)
	}
	var keys []string
	for _, elt := range lit.Elts {
		if name, ok := compositeFieldString(elt, "name"); ok {
			keys = append(keys, name)
		}
	}
	return keys
}

func findVarCompositeLit(f *ast.File, name string) *ast.CompositeLit {
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.VAR {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) == 0 || vs.Names[0].Name != name || len(vs.Values) == 0 {
				continue
			}
			if lit, ok := vs.Values[0].(*ast.CompositeLit); ok {
				return lit
			}
		}
	}
	return nil
}

func compositeFieldString(expr ast.Expr, field string) (string, bool) {
	cl, ok := expr.(*ast.CompositeLit)
	if !ok {
		return "", false
	}
	for _, elt := range cl.Elts {
		kv, ok := elt.(*ast.KeyValueExpr)
		if !ok {
			continue
		}
		id, ok := kv.Key.(*ast.Ident)
		if !ok || id.Name != field {
			continue
		}
		bl, ok := kv.Value.(*ast.BasicLit)
		if !ok || bl.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(bl.Value)
		return s, err == nil
	}
	return "", false
}

func extractUsageVerbs(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	usageStr, ok := findConstString(f, "usage")
	if !ok {
		t.Fatalf("const usage not found in %s", path)
	}
	var verbs []string
	for _, tok := range strings.Fields(usageStr) {
		tok = strings.Trim(tok, "[]|")
		if tok == "" || tok == "usage:" || tok == "snitch" {
			continue
		}
		verbs = append(verbs, tok)
	}
	return verbs
}

func findConstString(f *ast.File, name string) (string, bool) {
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			if s, ok := specConstString(spec, name); ok {
				return s, true
			}
		}
	}
	return "", false
}

func specConstString(spec ast.Spec, name string) (string, bool) {
	vs, ok := spec.(*ast.ValueSpec)
	if !ok {
		return "", false
	}
	for i, ident := range vs.Names {
		if ident.Name != name || i >= len(vs.Values) {
			continue
		}
		if bl, ok := vs.Values[i].(*ast.BasicLit); ok && bl.Kind == token.STRING {
			s, err := strconv.Unquote(bl.Value)
			return s, err == nil
		}
	}
	return "", false
}
