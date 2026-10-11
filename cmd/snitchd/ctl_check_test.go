package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// selfExe is this test binary: a real executable the resolver maps on any machine.
func selfExe(t *testing.T) string {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return self
}

// runCheckAs dispatches `check args...` through the real table as a non-root user, the way
// CI and the operator call it.
func runCheckAs(t *testing.T, euid int, args ...string) (code int, out, errw string) {
	t.Helper()
	c, o, e := testCtl(t, probes{})
	c.euid = func() int { return euid }
	code = dispatch(verbs, c, append([]string{"check"}, args...))
	return code, o.String(), e.String()
}

func TestCheckValidFilePrintsTheSummaryAndTheUnresolvedPatterns(t *testing.T) {
	p := writeRules(t, "[[program]]\nname = \"me\"\npaths = [\""+selfExe(t)+"\"]\n\n"+
		"[[program]]\nname = \"ghost\"\npaths = [\"/nonexistent/ghost\", \"/nonexistent/*\"]\n\n"+
		"[[rule]]\nprogram = \"me\"\nto = \"1.1.1.1\"\nproto = \"tcp\"\nport = 443\nverdict = \"allow\"\n")
	code, out, errw := runCheckAs(t, 1000, "-rules", p)
	if code != 0 {
		t.Fatalf("exit %d stderr %q, want 0", code, errw)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 3 {
		t.Fatalf("stdout %q: want the summary and two unresolved lines", out)
	}
	for _, want := range []string{"rules: 2 programs (1 resolved, 1 unresolved (ghost))", "2 patterns unmatched", "1 executables mapped", "1 rules effective"} {
		if !strings.Contains(lines[0], want) {
			t.Errorf("summary %q lacks %q", lines[0], want)
		}
	}
	for i, want := range []string{"unresolved: ghost /nonexistent/ghost (", "unresolved: ghost /nonexistent/* ("} {
		if !strings.HasPrefix(lines[i+1], want) || !strings.HasSuffix(lines[i+1], ")") {
			t.Errorf("line %d %q, want prefix %q and a reason in parentheses", i+1, lines[i+1], want)
		}
	}
}

func TestCheckInvalidFileExitsOneWithFileAndLine(t *testing.T) {
	p := writeRules(t, "[[program]]\nname = \"curl\"\npaths = [\"/usr/bin/curl\"]\n\n[[rule]]\nprogram = \"wget\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\n")
	code, out, errw := runCheckAs(t, 1000, "-rules", p)
	if code != 1 || out != "" {
		t.Fatalf("exit %d stdout %q, want 1 and nothing on stdout", code, out)
	}
	if !regexp.MustCompile(regexp.QuoteMeta(p)+`:\d+: `).MatchString(errw) || !strings.Contains(errw, "wget") {
		t.Fatalf("stderr %q, want %s:<line>: <reason> naming wget", errw, p)
	}
}

func TestCheckResolverConflictExitsOneWithFileAndLine(t *testing.T) {
	self := selfExe(t)
	p := writeRules(t, "[[program]]\nname = \"a\"\npaths = [\""+self+"\"]\n\n[[program]]\nname = \"b\"\npaths = [\""+self+"\"]\n")
	code, _, errw := runCheckAs(t, 1000, "-rules", p)
	if code != 1 || !strings.Contains(errw, p+":5: ") || !strings.Contains(errw, "is both program") {
		t.Fatalf("exit %d stderr %q, want 1 and %s:5: executable ... is both program", code, errw, p)
	}
}

func TestCheckMissingFileExitsOneSayingDoesNotExist(t *testing.T) {
	p := filepath.Join(t.TempDir(), "none.toml")
	code, out, errw := runCheckAs(t, 1000, "-rules", p)
	if code != 1 || out != "" || !strings.Contains(errw, p+": does not exist") {
		t.Fatalf("exit %d stdout %q stderr %q, want 1 and %q", code, out, errw, p+": does not exist")
	}
}

func TestCheckUsageErrorsExitTwo(t *testing.T) {
	valid := writeRules(t, "")
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"bad flag", []string{"-bogus"}, "-rules"},
		{"positional word", []string{"-rules", valid, "extra"}, "extra"},
		{"empty path", []string{"-rules", ""}, "empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			code, out, errw := runCheckAs(t, 1000, tc.args...)
			if code != 2 || out != "" || !strings.Contains(errw, tc.want) {
				t.Fatalf("exit %d stdout %q stderr %q, want 2 and %q on stderr", code, out, errw, tc.want)
			}
		})
	}
}

func TestCheckHelpExitsZero(t *testing.T) {
	code, _, errw := runCheckAs(t, 1000, "-h")
	if code != 0 || !strings.Contains(errw, "snitchd check") || !strings.Contains(errw, "-rules") {
		t.Fatalf("exit %d usage %q, want 0 and the usage naming -rules", code, errw)
	}
}

func TestCheckAcceptsAndIgnoresTheSharedFlags(t *testing.T) {
	p := writeRules(t, "")
	code, out, errw := runCheckAs(t, 1000, "-state-dir", "/nonexistent/sd", "-status", "/nonexistent/st", "-rules", p)
	if code != 0 || !strings.HasPrefix(out, "rules: 0 programs") || errw != "" {
		t.Fatalf("exit %d stdout %q stderr %q, want 0 and the empty summary", code, out, errw)
	}
}

func TestCheckRulesDefaultsToTheServicePath(t *testing.T) {
	c, _, _ := testCtl(t, probes{})
	c.name = "check"
	path, code, done := c.checkFlags(nil)
	if done || code != 0 || path != defaultRules {
		t.Fatalf("got %q %d %v, want %q 0 false", path, code, done, defaultRules)
	}
}

func TestContractCheckNeedsARulesPath(t *testing.T) {
	c, _, _ := testCtl(t, probes{})
	c.name = "check"
	contracttest.Panics(t, contract.Precondition, func() { c.checkRules("") })
}

func TestContractCheckNeedsItsWriters(t *testing.T) {
	for _, blank := range []func(c *ctl){func(c *ctl) { c.out = nil }, func(c *ctl) { c.errw = nil }} {
		c, _, _ := testCtl(t, probes{})
		c.name = "check"
		blank(c)
		if got := contracttest.Panics(t, contract.Precondition, func() { c.checkRules("/x") }); got.Msg != "check: incomplete writers" {
			t.Errorf("violation %q, want \"check: incomplete writers\"", got.Msg)
		}
	}
}
