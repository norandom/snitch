// fuzz_test.go: the rules file (root's) and the overlay (the operator's, written through the
// API) are untrusted input to a root daemon (c-hardening Req 8). The seeds are the sample
// rules file, the overlay shapes the merge tests use and edge cases, run as ordinary cases by
// `go test`; scripts/fuzz.sh runs the bounded mutation runs. A contract panic reachable from
// input is a defect: input must be rejected with an error before any invariant can fail.
package rules

import (
	"bytes"
	"os"
	"slices"
	"strings"
	"testing"
)

const (
	fuzzBase    = "base.toml"
	fuzzOverlay = "overlay.toml"
)

// sampleRules is examples/rules.toml verbatim: the base every overlay is merged over.
func sampleRules(f *testing.F) []byte {
	f.Helper()
	src, err := os.ReadFile("../../examples/rules.toml")
	if err != nil {
		f.Fatal(err)
	}
	return src
}

// fuzzSeeds are inputs for both targets: overlay shapes from the merge tests and edge cases.
var fuzzSeeds = []string{
	"",
	"# only a comment\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nproto = \"tcp\"\nport = 443\nverdict = \"deny\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nproto = \"tcp\"\nport = 443\nverdict = \"deny\"\n" +
		"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nport = 443\nverdict = \"deny\"\n", // duplicate key
	"[[rule]]\nprogram = \"gh\"\nto = \"github.com\"\nproto = \"tcp\"\nport = 443\nverdict = \"allow\"\n",
	"[[rule]]\nprogram = \"any\"\nto = \"9.9.9.9\"\nproto = \"udp\"\nport = \"67-68\"\nverdict = \"allow\"\n",
	"[[program]]\nname = \"x\"\npaths = [\"/usr/bin/x\"]\n[[rule]]\nprogram = \"x\"\nto = \"::/0\"\nverdict = \"allow\"\n",
	"[[program]]\nname = \"curl\"\npaths = []\n", // a program the base declares too
	"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\nbogus = 1\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nport = 99999999999999999999\nverdict = \"allow\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nport = -1\nverdict = \"allow\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nport = \"443-80\"\nverdict = \"allow\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nport = \"1-65535\"\nverdict = \"allow\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nport = 1.5\nverdict = \"allow\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"fe80::1%eth0\"\nverdict = \"allow\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"" + strings.Repeat("a.", 16) + "com\"\nverdict = \"allow\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"example.org\"\nverdict = \"deny\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"\xff\xfe\"\nverdict = \"allow\"\n",
	"\xff\xfe[[rule]]\n",
	"x = " + strings.Repeat("[", 10000) + strings.Repeat("]", 10000) + "\n",
	"x = " + strings.Repeat("{a=", 1000) + "1" + strings.Repeat("}", 1000) + "\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\nnote = \"" + strings.Repeat("n", 1<<16) + "\"\n",
	"rule = [{program = \"curl\", to = \"1.1.1.1\", verdict = \"allow\"}]\n",
	"[[program]]\nname = \"a\"\n[[program.rule]]\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\nfirst = 1979-05-27T07:32:00Z\ncount = 3\n",
	"[[program]]\nname = \"any\"\n",
	// boundaries: port 0, the port-count limit and one past it, a name at the character limit
	// and one past it, the label limit and one past it
	"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nport = 0\nverdict = \"allow\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nport = \"1000-1255\"\nverdict = \"allow\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nport = \"1000-1256\"\nverdict = \"allow\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"" + strings.Repeat("a", 58) + ".com\"\nverdict = \"allow\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"" + strings.Repeat("a", 59) + ".com\"\nverdict = \"allow\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"" + strings.Repeat("a.", 14) + "com\"\nverdict = \"allow\"\n",
	"[[rule]]\nprogram = \"curl\"\nto = \"" + strings.Repeat("a.", 15) + "com\"\nverdict = \"allow\"\n",
	"[[program]]\n[[rule]]\n",
}

// FuzzParse: a rules file parses to a well-formed File or to an *Error, never a panic.
func FuzzParse(f *testing.F) {
	f.Add(sampleRules(f))
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		file := parseOrError(t, data, fuzzBase, true)
		if file != nil {
			checkFile(t, file, fuzzBase, true)
		}
	})
}

// FuzzParseOverlay: an overlay parses to a well-formed File or to an *Error, and a parsed
// overlay merges over the sample rules file to a well-formed File or an error, never a panic.
func FuzzParseOverlay(f *testing.F) {
	base, err := Parse(bytes.NewReader(sampleRules(f)), fuzzBase)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(sampleRules(f))
	for _, s := range fuzzSeeds {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		over := parseOrError(t, data, fuzzOverlay, false)
		if over == nil {
			return
		}
		checkFile(t, over, fuzzOverlay, false)
		merged, err := Merge(base, over)
		if err != nil {
			if _, ok := err.(*Error); !ok || merged != nil {
				t.Fatalf("merge: want nil and an *Error, got %v, %T %v", merged, err, err)
			}
			return
		}
		checkMerged(t, base, over, merged)
	})
}

// parseOrError parses data and requires exactly one of a File and an *Error naming the file.
func parseOrError(t *testing.T, data []byte, name string, declared bool) *File {
	t.Helper()
	file, err := parseWith(bytes.NewReader(data), name, declared)
	if err != nil {
		e, ok := err.(*Error)
		if !ok || file != nil || e.File != name || e.Msg == "" {
			t.Fatalf("want nil and an *Error naming %s, got %v, %T %v", name, file, err, err)
		}
		return nil
	}
	if file == nil {
		t.Fatal("neither a file nor an error")
	}
	return file
}

// checkFile holds a parsed File to what validation promises: every record sourced and
// lined, ids dense, every value one the encoder accepts, and validation still passing.
func checkFile(t *testing.T, f *File, name string, declared bool) {
	t.Helper()
	if f.Name != name {
		t.Fatalf("file name %q, want %q", f.Name, name)
	}
	for _, p := range f.Programs {
		if p.Source != name || p.Line < 1 || p.Name == "" || p.Name == anyProgram {
			t.Fatalf("program %+v: want a name, Source %s and a line", p, name)
		}
	}
	for _, r := range f.Rules {
		if why := ruleDefect(r, name, declared); why != "" {
			t.Fatalf("rule %+v: %s", r, why)
		}
	}
	assertDenseIDs(f)
	if err := validate(f, declared); err != nil {
		t.Fatalf("a parsed file fails validation again: %v", err)
	}
}

// ruleDefect names the first defect of a rule parsed from name (a missing Source or line, a
// value the encoder would not accept), or "".
func ruleDefect(r Rule, name string, declared bool) string {
	for _, c := range []struct {
		bad bool
		why string
	}{
		{r.Source != name || r.Line < 1, "want Source " + name + " and a line"},
		{r.Program == "" && declared, "no program"},
		{r.IsName() == r.To.IsValid(), "want exactly one of a prefix and a name"},
		{r.To.IsValid() && r.To != r.To.Masked(), "prefix not masked"},
		{r.Proto != AnyProto && r.Proto != TCP && r.Proto != UDP, "unknown proto"},
		{r.Verdict != Allow && r.Verdict != Deny, "unknown verdict"},
		{r.IsName() && r.Verdict == Deny, "a deny by name"},
		{len(r.Ports) > maxPortsPerRule, "too many ports"},
		{slices.Contains(r.Ports, 0), "port 0"},
	} {
		if c.bad {
			return c.why
		}
	}
	return ""
}

// checkMerged: the base's programs then the overlay's, the surviving base rules in order then
// every overlay rule, sourced, dense, and the inputs untouched.
func checkMerged(t *testing.T, base, over, m *File) {
	t.Helper()
	if m.Name != base.Name || len(m.Programs) != len(base.Programs)+len(over.Programs) {
		t.Fatalf("merged %s with %d programs from %d + %d", m.Name, len(m.Programs), len(base.Programs), len(over.Programs))
	}
	kept := len(m.Rules) - len(over.Rules)
	if kept < 0 || kept > len(base.Rules) {
		t.Fatalf("merged %d rules from %d + %d", len(m.Rules), len(base.Rules), len(over.Rules))
	}
	for i, r := range m.Rules[kept:] {
		if r.Source != fuzzOverlay || r.Line != over.Rules[i].Line {
			t.Fatalf("merged rule %d is not overlay rule %d: %+v", kept+i, i, r)
		}
	}
	for _, r := range m.Rules[:kept] {
		if r.Source != fuzzBase {
			t.Fatalf("a kept rule from %s", r.Source)
		}
	}
	checkShadowing(t, base, over, m.Rules[:kept])
	assertSourced(m)
	assertDenseIDs(m)
	assertDenseIDs(base)
	assertDenseIDs(over)
	checkFile(t, base, fuzzBase, true)
}

// checkShadowing states Merge's documented rule as a property: a base rule survives exactly
// when none of its expanded keys is one an overlay rule encodes to, and survivors keep their
// base order. Base rules are told apart by their line.
func checkShadowing(t *testing.T, base, over *File, kept []Rule) {
	t.Helper()
	overlay := map[ruleKey]bool{}
	for i := range over.Rules {
		for _, k := range expandedKeys(&over.Rules[i]) {
			overlay[k] = true
		}
	}
	var want []int
	for i := range base.Rules {
		hit := false
		for _, k := range expandedKeys(&base.Rules[i]) {
			hit = hit || overlay[k]
		}
		if !hit {
			want = append(want, base.Rules[i].Line)
		}
	}
	if len(want) != len(kept) {
		t.Fatalf("kept %d base rules, the shadowing rule keeps %d", len(kept), len(want))
	}
	for i, r := range kept {
		if r.Line != want[i] {
			t.Fatalf("kept base rule %d is from line %d, want line %d", i, r.Line, want[i])
		}
	}
}
