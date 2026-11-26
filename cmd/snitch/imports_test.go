// imports_test.go: the forbidden-import pin (design, Allowed Dependencies; requirements 4.7,
// 8.5, 13.9 and 14.6). The snitch binary runs as the user and reads the daemon only through
// its API; if it ever linked the BPF bindings, cilium/ebpf or the daemon's rules, trial or
// dns packages, it could read or touch the daemon's state another way. It also forbids UI and
// helper modules that pull in clipboard executables, large unicode tables or unstable APIs,
// and confines charm.land/... imports to internal/term alone. The tests ask the go tool for
// the binary's full dependency list and the module's package imports, so imports added by
// later tasks are covered without changing this file.
package main

import (
	"os/exec"
	"strings"
	"testing"
)

const (
	module  = "github.com/norandom/snitch"
	termPkg = module + "/internal/term"
)

// forbidden are import paths the binary may not depend on, each with all its subpackages.
var forbidden = []string{
	module + "/internal/bpf",
	module + "/internal/rules",
	module + "/internal/trial",
	module + "/internal/dns",
	"github.com/cilium/ebpf",
	"charm.land/bubbles",
	"github.com/NimbleMarkets/ntcharts",
	"golang.org/x/text",
	"github.com/atotto/clipboard",
}

// forbiddenIn returns the entries of deps that are a forbidden package or below one.
func forbiddenIn(deps []string) []string {
	var hits []string
	for _, d := range deps {
		for _, f := range forbidden {
			if d == f || strings.HasPrefix(d, f+"/") {
				hits = append(hits, d)
			}
		}
	}
	return hits
}

func isCharmLand(imp string) bool {
	return imp == "charm.land" || strings.HasPrefix(imp, "charm.land/")
}

// charmLandViolations scans `go list` lines ("<pkg> <imports...>") and reports whether
// internal/term was seen, whether it imports charm.land/..., and any non-term imports of
// charm.land/... as "<pkg> -> <imp>".
func charmLandViolations(lines []string) (sawTerm, termUsesCharm bool, hits []string) {
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		pkg := fields[0]
		if pkg == termPkg {
			sawTerm = true
		}
		for _, imp := range fields[1:] {
			if !isCharmLand(imp) {
				continue
			}
			if pkg == termPkg {
				termUsesCharm = true
				continue
			}
			hits = append(hits, pkg+" -> "+imp)
		}
	}
	return sawTerm, termUsesCharm, hits
}

func TestImportsPinForbidsTheDaemonsPackages(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	deps := strings.Fields(string(out))
	// a list without the package itself or the contract package means go list answered for
	// something else: the pin would pass for nothing
	if !contains(deps, module+"/cmd/snitch") || !contains(deps, module+"/internal/contract") {
		t.Fatalf("go list -deps did not list this binary's dependencies: %q", deps)
	}
	if hits := forbiddenIn(deps); len(hits) > 0 {
		t.Fatalf("cmd/snitch depends on forbidden packages: %q", hits)
	}
}

func TestImportsOnlyTermImportsCharmLand(t *testing.T) {
	const tmpl = `{{.ImportPath}} {{join .Imports " "}} {{join .TestImports " "}} {{join .XTestImports " "}}`
	out, err := exec.Command("go", "list", "-f", tmpl, module+"/...").Output()
	if err != nil {
		t.Fatalf("go list module/...: %v", err)
	}
	sawTerm, termUsesCharm, hits := charmLandViolations(strings.Split(string(out), "\n"))
	if !sawTerm || !termUsesCharm {
		t.Fatalf("expected %s to exist and import charm.land/... (sawTerm=%v, termUsesCharm=%v)",
			termPkg, sawTerm, termUsesCharm)
	}
	if len(hits) > 0 {
		t.Fatalf("packages other than %s import charm.land/: %q", termPkg, hits)
	}
}

// The matcher itself: exact paths and subpackages hit, look-alike prefixes do not.
func TestImportsMatcherCatchesSubpackagesOnly(t *testing.T) {
	deps := []string{
		"github.com/cilium/ebpf/link", "github.com/cilium/ebpf", module + "/internal/bpf",
		module + "/internal/rules", module + "/internal/trial", module + "/internal/dns/cache",
		"charm.land/bubbles/v2/textinput", "github.com/NimbleMarkets/ntcharts/v2",
		"golang.org/x/text/unicode/norm", "github.com/atotto/clipboard",
		module + "/internal/dnsx", module + "/internal/api", "fmt", "github.com/cilium/ebpfx",
		"charm.land/bubbletea/v2", "charm.land/lipgloss/v2", "golang.org/x/sys/unix",
		"github.com/NimbleMarkets/ntchartsx",
	}
	got := forbiddenIn(deps)
	want := deps[:10]
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("want %q, got %q", want, got)
	}
}

func TestImportsCharmLandCheckRejectsSecondPackage(t *testing.T) {
	lines := []string{
		termPkg + " charm.land/bubbletea/v2 charm.land/lipgloss/v2",
		module + "/cmd/snitch " + termPkg + " charm.landx/foo",
		module + "/internal/tui " + module + "/internal/clean charm.land/lipgloss/v2",
	}
	sawTerm, termUsesCharm, hits := charmLandViolations(lines)
	if !sawTerm || !termUsesCharm {
		t.Fatalf("want sawTerm=true, termUsesCharm=true, got %v, %v", sawTerm, termUsesCharm)
	}
	want := module + "/internal/tui -> charm.land/lipgloss/v2"
	if len(hits) != 1 || hits[0] != want {
		t.Fatalf("want [%q], got %q", want, hits)
	}
}

func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}
