// Package main is caps: the size gates from .kiro/steering/tech.md, as a go/ast walk.
// Functions are measured by body lines, files by total lines. Complexity is gocyclo's job.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
)

// Limits are the caps; zero disables a check.
type Limits struct {
	FuncLines int
	FileLines int
}

// Finding is one violation, formatted as path:line: message.
type Finding struct {
	Pos token.Position
	Msg string
}

func (f Finding) String() string { return fmt.Sprintf("%s:%d: %s", f.Pos.Filename, f.Pos.Line, f.Msg) }

// checkSource parses one file's source and reports every cap it breaks.
func checkSource(fset *token.FileSet, name string, src []byte, lim Limits) ([]Finding, error) {
	file, err := parser.ParseFile(fset, name, src, parser.SkipObjectResolution)
	if err != nil {
		return nil, err
	}
	var out []Finding
	if n := fset.File(file.Pos()).LineCount(); lim.FileLines > 0 && n > lim.FileLines {
		out = append(out, Finding{fset.Position(file.Pos()), fmt.Sprintf("file is %d lines (cap %d)", n, lim.FileLines)})
	}
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		lines := fset.Position(fn.Body.Rbrace).Line - fset.Position(fn.Body.Lbrace).Line - 1
		if lim.FuncLines > 0 && lines > lim.FuncLines {
			out = append(out, Finding{fset.Position(fn.Pos()), fmt.Sprintf("%s is %d lines (cap %d)", fn.Name.Name, lines, lim.FuncLines)})
		}
	}
	return out, nil
}

// checkDirs walks the given directories (not recursively) and checks every .go file, tests
// included: the caps apply to test code too (steering tech.md "Code shape").
func checkDirs(dirs []string, lim Limits) ([]Finding, error) {
	fset := token.NewFileSet()
	var out []Finding
	for _, dir := range dirs {
		names, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			return nil, err
		}
		for _, name := range names {
			src, err := os.ReadFile(name)
			if err != nil {
				return nil, err
			}
			fs, err := checkSource(fset, name, src, lim)
			if err != nil {
				return nil, err
			}
			out = append(out, fs...)
		}
	}
	return out, nil
}
