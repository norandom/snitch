// safe_test.go tests internal/clean's sanitiser, literal constructor, join, source pin and fuzz target.
package clean

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

const cleanImportPath = "github.com/norandom/snitch/internal/clean"

func TestTextReplacesForbiddenRunesAndInvalidUTF8(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"plain", "curl 1.2.3.4:443", "curl 1.2.3.4:443"},
		{"dot_preserved", "a·b", "a·b"},
		{"unicode_preserved", "café 日本語 — 🔒", "café 日本語 — 🔒"},
		{"valid_fffd_preserved", "\xef\xbf\xbd", "\ufffd"},
		{"newline_tab_cr", "a\nb\tc\rd", "a·b·c·d"},
		{"sgr_escape", "\x1b[31mred\x1b[0m", "·[31mred·[0m"},
		{"osc8_hyperlink", "\x1b]8;;https://evil\x07click\x1b]8;;\x07", "·]8;;https://evil·click·]8;;·"},
		{"del_and_c1", "a\x7fb\u0080c\u009bd\u009fe", "a·b·c·d·e"},
		{"bidi_controls", "\u061c\u200e\u200f\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069", "············"},
		{"invisible_formatters", "\u200b\u200c\u200d\u2060\ufeff", "·····"},
		{"invalid_utf8_bytes", "a\xffb\xc3c\xe2\x82d\xf0\x9f\x92e\xc0\xaff", "a·b·c··d···e··f"},
	}
	for _, tc := range cases {
		got := Text(tc.in)
		if string(got) != tc.want {
			t.Errorf("%s: Text(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
		if Text(string(got)) != got {
			t.Errorf("%s: not idempotent: %q", tc.name, got)
		}
	}
}

func TestTextRuneBoundaries(t *testing.T) {
	for r := rune(0); r <= 0x9f; r++ {
		want := Safe(string(r))
		if r < 0x20 || r >= 0x7f {
			want = Safe("·")
		}
		if got := Text(string(r)); got != want {
			t.Fatalf("U+%04X = %q, want %q", r, got, want)
		}
	}
	replaced := []rune{0x061c, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e, 0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xfeff}
	for _, r := range replaced {
		if got := Text(string(r)); got != Safe("·") {
			t.Fatalf("forbidden U+%04X = %q, want ·", r, got)
		}
	}
	for _, r := range []rune{0x20, 0x7e, 0xa0, 0x061b, 0x061d, 0x200a, 0x2010, 0x2029, 0x202f, 0x205f, 0x2061, 0x2065, 0x206a, 0xfefe, 0xff00} {
		if got := Text(string(r)); got != Safe(string(r)) {
			t.Fatalf("allowed U+%04X = %q, want unchanged", r, got)
		}
	}
}

func TestConstAndJoin(t *testing.T) {
	if got := Const(""); got != "" {
		t.Fatalf("Const empty = %q", got)
	}
	if got := Const("hello — world"); got != Safe("hello — world") {
		t.Fatalf("Const literal = %q", got)
	}
	for _, bad := range []string{"a\nb", "a\tb", "\x1b[0m", "\x7f", "\u009b", "\u202e", "\u200b", "\xff"} {
		contracttest.Panics(t, contract.Precondition, func() { _ = Const(bad) })
	}
	if got := Join(); got != "" {
		t.Fatalf("Join() = %q, want empty", got)
	}
	if got := Join(Const("only")); got != Safe("only") {
		t.Fatalf("Join(1) = %q, want %q", got, "only")
	}
	if got := Join(Const("a"), Text("b\nc"), Const("d")); got != Safe("ab·cd") {
		t.Fatalf("Join = %q, want %q", got, "ab·cd")
	}
	contracttest.Panics(t, contract.Postcondition, func() { _ = Join(Safe("\n")) })
}

func FuzzText_clean(f *testing.F) {
	for _, s := range []string{"", "curl", "a\nb\tc\rd", "\x1b[31m", "\x7f\u009b", "\u061c\u200b\u202e\u2066\ufeff", "\xff\xc0\xaf", "\xef\xbf\xbd", "·"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := Text(s)
		raw := string(got)
		if !utf8.ValidString(raw) {
			t.Fatalf("Text(%q) produced invalid UTF-8 %q", s, raw)
		}
		for _, r := range raw {
			if isForbiddenForTest(r) {
				t.Fatalf("Text(%q) kept forbidden rune U+%04X", s, r)
			}
		}
		if Text(raw) != got {
			t.Fatalf("Text(%q) not idempotent: %q vs %q", s, got, Text(raw))
		}
	})
}

func isForbiddenForTest(r rune) bool {
	if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
		return true
	}
	switch r {
	case 0x061c, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
		0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
		0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xfeff:
		return true
	}
	return false
}

func TestOnlySourceCleanProducesSafe(t *testing.T) {
	mod, pkgs := listModulePackages(t)
	if len(pkgs) < 5 || pkgs[mod+"/cmd/snitch"] == "" || pkgs[mod+"/cmd/snitchd"] == "" {
		t.Fatalf("unexpected module package list: %v", pkgs)
	}
	var scanned int
	for pkg, dir := range pkgs {
		if pkg != cleanImportPath {
			scanned += scanPackageDir(t, dir)
		}
	}
	if scanned < 10 {
		t.Fatalf("scanned only %d files across module", scanned)
	}
}

func scanPackageDir(t *testing.T, dir string) int {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatalf("glob %s: %v", dir, err)
	}
	for _, path := range paths {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for _, v := range checkCleanSource(path, src) {
			t.Error(v)
		}
	}
	return len(paths)
}

func listModulePackages(t *testing.T) (string, map[string]string) {
	t.Helper()
	modOut, err := exec.Command("go", "list", "-m").Output()
	if err != nil {
		t.Fatalf("go list -m: %v", err)
	}
	mod := strings.TrimSpace(string(modOut))
	out, err := exec.Command("go", "list", "-f", "{{.ImportPath}} {{.Dir}}", mod+"/...").Output()
	if err != nil {
		t.Fatalf("go list %s/...: %v", mod, err)
	}
	pkgs := map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if fields := strings.Fields(line); len(fields) == 2 {
			pkgs[fields[0]] = fields[1]
		}
	}
	return mod, pkgs
}

func TestOnlySourceCheckerCatchesViolations(t *testing.T) {
	good := `package x; import "github.com/norandom/snitch/internal/clean"; type row struct{ title clean.Safe }; var _ = clean.Const("ok"); var _ = clean.Const(` + "`raw`" + `); var _ = clean.Join(clean.Text("a"))`
	if got := checkCleanSource("good.go", []byte(good)); len(got) > 0 {
		t.Fatalf("unexpected violations for good source: %v", got)
	}
	badCases := []string{
		`package x; import "github.com/norandom/snitch/internal/clean"; var _ = clean.Safe("a")`,
		`package x; import "github.com/norandom/snitch/internal/clean"; func f(s string) clean.Safe { return clean.Safe(s) }`,
		`package x; import "github.com/norandom/snitch/internal/clean"; func f(p *string) *clean.Safe { return (*clean.Safe)(p) }`,
		`package x; import c "github.com/norandom/snitch/internal/clean"; var _ = c.Safe("a")`,
		`package x; import . "github.com/norandom/snitch/internal/clean"; var _ = Const("a")`,
		`package x; import "github.com/norandom/snitch/internal/clean"; type s = clean.Safe`,
		`package x; import "github.com/norandom/snitch/internal/clean"; func f(s string) clean.Safe { return clean.Const(s) }`,
		`package x; import "github.com/norandom/snitch/internal/clean"; const k = "a"; var _ = clean.Const(k)`,
		`package x; import "github.com/norandom/snitch/internal/clean"; var _ = clean.Const("a" + "b")`,
		`package x; import "github.com/norandom/snitch/internal/clean"; var _ = clean.Const`,
		`package x; import c "github.com/norandom/snitch/internal/clean"; func f(s string) c.Safe { return c.Const(s) }`,
	}
	for i, src := range badCases {
		if got := checkCleanSource("bad.go", []byte(src)); len(got) == 0 {
			t.Errorf("case %d (%s): expected violation, got none", i, src)
		}
	}
}

func checkCleanSource(path string, src []byte) []string {
	if !bytes.Contains(src, []byte(cleanImportPath)) {
		return nil
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return []string{path + ": parse error: " + err.Error()}
	}
	aliases, dot := cleanAliases(file)
	if len(aliases) == 0 && !dot {
		return nil
	}
	var out []string
	if dot {
		out = append(out, path+": dot-import of internal/clean is forbidden")
	}
	return append(out, walkCleanAST(fset, file, aliases)...)
}

func cleanAliases(file *ast.File) (map[string]bool, bool) {
	aliases := map[string]bool{}
	dot := false
	for _, imp := range file.Imports {
		if strings.Trim(imp.Path.Value, `"`) != cleanImportPath {
			continue
		}
		switch {
		case imp.Name == nil:
			aliases["clean"] = true
		case imp.Name.Name == ".":
			dot = true
		case imp.Name.Name != "_":
			aliases[imp.Name.Name] = true
		}
	}
	return aliases, dot
}

func walkCleanAST(fset *token.FileSet, file *ast.File, aliases map[string]bool) []string {
	constCallFuns := map[*ast.SelectorExpr]bool{}
	var out []string
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.CallExpr:
			out = append(out, checkCallExpr(fset, node, aliases, constCallFuns)...)
		case *ast.TypeSpec:
			if node.Assign.IsValid() && isCleanSel(node.Type, aliases, "Safe") != nil {
				out = append(out, fset.Position(node.Pos()).String()+": type alias to clean.Safe is forbidden")
			}
		case *ast.SelectorExpr:
			if isCleanSel(node, aliases, "Const") != nil && !constCallFuns[node] {
				out = append(out, fset.Position(node.Pos()).String()+": clean.Const may only be called directly")
			}
		}
		return true
	})
	return out
}

func checkCallExpr(fset *token.FileSet, call *ast.CallExpr, aliases map[string]bool, constFuns map[*ast.SelectorExpr]bool) []string {
	fun := ast.Unparen(call.Fun)
	if star, ok := fun.(*ast.StarExpr); ok {
		fun = ast.Unparen(star.X)
	}
	if isCleanSel(fun, aliases, "Safe") != nil {
		return []string{fset.Position(call.Pos()).String() + ": conversion to clean.Safe is forbidden"}
	}
	if sel := isCleanSel(fun, aliases, "Const"); sel != nil {
		constFuns[sel] = true
		if len(call.Args) != 1 {
			return []string{fset.Position(call.Pos()).String() + ": clean.Const requires a single string literal"}
		}
		if lit, ok := call.Args[0].(*ast.BasicLit); !ok || lit.Kind != token.STRING {
			return []string{fset.Position(call.Pos()).String() + ": clean.Const requires a single string literal"}
		}
	}
	return nil
}

func isCleanSel(expr ast.Expr, aliases map[string]bool, name string) *ast.SelectorExpr {
	sel, ok := ast.Unparen(expr).(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return nil
	}
	id, ok := sel.X.(*ast.Ident)
	if !ok || !aliases[id.Name] {
		return nil
	}
	return sel
}
