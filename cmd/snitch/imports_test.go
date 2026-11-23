// imports_test.go: the forbidden-import pin (design, Allowed Dependencies; requirements 4.7
// and 8.5). The snitch binary runs as the user and reads the daemon only through its API; if
// it ever linked the BPF bindings, cilium/ebpf or the daemon's rules, trial or dns packages,
// it could read or touch the daemon's state another way. The test asks the go tool for the
// binary's full dependency list (not its tests'), so imports added by later tasks are covered
// without changing this file.
package main

import (
	"os/exec"
	"strings"
	"testing"
)

const module = "github.com/norandom/snitch"

// forbidden are import paths the binary may not depend on, each with all its subpackages.
var forbidden = []string{
	module + "/internal/bpf",
	module + "/internal/rules",
	module + "/internal/trial",
	module + "/internal/dns",
	"github.com/cilium/ebpf",
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

// The matcher itself: exact paths and subpackages hit, look-alike prefixes do not.
func TestImportsMatcherCatchesSubpackagesOnly(t *testing.T) {
	deps := []string{
		"github.com/cilium/ebpf/link", "github.com/cilium/ebpf", module + "/internal/bpf",
		module + "/internal/rules", module + "/internal/trial", module + "/internal/dns/cache",
		module + "/internal/dnsx", module + "/internal/api", "fmt", "github.com/cilium/ebpfx",
	}
	got := forbiddenIn(deps)
	want := deps[:6]
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("want %q, got %q", want, got)
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
