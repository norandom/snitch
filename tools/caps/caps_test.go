package main

import (
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func lines(n int) string { return strings.Repeat("\tx++\n", n) }

func TestFuncOverCapIsReported(t *testing.T) {
	src := "package p\n\nvar x int\n\nfunc short() {\n" + lines(3) + "}\n\nfunc long() {\n" + lines(5) + "}\n"
	got, err := checkSource(token.NewFileSet(), "p.go", []byte(src), Limits{FuncLines: 4})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.Contains(got[0].Msg, "long is 5 lines (cap 4)") {
		t.Fatalf("want one finding for long(), got %v", got)
	}
}

func TestFileOverCapIsReported(t *testing.T) {
	src := "package p\n" + strings.Repeat("\n", 20)
	got, err := checkSource(token.NewFileSet(), "p.go", []byte(src), Limits{FileLines: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || !strings.Contains(got[0].Msg, "file is 21 lines (cap 10)") {
		t.Fatalf("want one file finding, got %v", got)
	}
}

func TestZeroLimitDisables(t *testing.T) {
	src := "package p\n\nfunc f() {\n" + lines(50) + "}\n"
	got, err := checkSource(token.NewFileSet(), "p.go", []byte(src), Limits{})
	if err != nil || len(got) != 0 {
		t.Fatalf("want no findings, got %v, %v", got, err)
	}
}

func TestBadSourceIsAnError(t *testing.T) {
	if _, err := checkSource(token.NewFileSet(), "p.go", []byte("package"), Limits{FuncLines: 1}); err == nil {
		t.Fatal("want a parse error")
	}
}

func TestCheckDirsIncludesTestFiles(t *testing.T) {
	dir := t.TempDir()
	long := "package p\n\nfunc f() {\n" + lines(6) + "}\n"
	for _, name := range []string{"a.go", "a_test.go"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(long), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	got, err := checkDirs([]string{dir}, Limits{FuncLines: 4})
	if err != nil || len(got) != 2 {
		t.Fatalf("want a finding in a.go and in a_test.go, got %v, %v", got, err)
	}
}
