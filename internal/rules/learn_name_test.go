// Name learning tests pin aggregation and persistence without DNS or kernel access.
package rules_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/rules"
)

func TestLearnNameCollapsesAddressesAndKeepsDirtySemantics(t *testing.T) {
	l := rules.NewLearned(nil)
	for _, addr := range []string{"1.1.1.1", "2001:db8::1"} {
		o := obs("/usr/bin/curl", curl, addr, rules.TCP, 443, t0)
		o.Name = "api.github.com"
		l.Observe(o)
	}
	got := l.Observations()
	if len(got) != 1 {
		t.Fatalf("want one projection, got %+v", got)
	}
	checkLearnedNameProjection(t, got[0])
	if !l.Dirty() {
		t.Fatal("read projection must keep dirty")
	}
	f := l.File()
	if len(f.Rules) != 1 || f.Rules[0].Dest() != "api.github.com" || f.Rules[0].To.IsValid() || f.Rules[0].Verdict != rules.Allow {
		t.Fatalf("want one allow name rule: %+v", f.Rules)
	}
	if l.Dirty() {
		t.Fatal("File must clear dirty")
	}
}

func TestLearnNameSeedRoundTripsAndContinues(t *testing.T) {
	seed := parse(t, curlProgram+ruleTable("curl", "api.github.com", "tcp", "443", "allow"))
	l := rules.NewLearned(seed)
	if l.Dirty() || l.File().Rules[0].Name != "api.github.com" {
		t.Fatal("seeding must preserve name and stay clean")
	}
	o := obs("/usr/bin/curl", curl, "9.9.9.9", rules.TCP, 443, t0)
	o.Name = "api.github.com"
	l.Observe(o)
	want := l.File()
	if len(want.Rules) != 1 || want.Rules[0].Count != 2 {
		t.Fatalf("seed must merge by name: %+v", want.Rules)
	}
	path := filepath.Join(t.TempDir(), "learned.toml")
	if err := rules.WriteFile(path, want); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(path)
	if err != nil || !strings.Contains(strings.Join(strings.Fields(string(src)), " "), "to = \"api.github.com\"") {
		t.Fatalf("name destination missing: %s (%v)", src, err)
	}
	got, err := rules.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(strip(rules.NewLearned(got).File()), strip(want)) {
		t.Fatal("seed round trip changed model")
	}
}

func TestLearnNamesStayDistinctFromAddressesAndEachOther(t *testing.T) {
	l := rules.NewLearned(nil)
	for _, name := range []string{"b.example", "", "a.example"} {
		o := obs("/usr/bin/curl", curl, "1.1.1.1", rules.TCP, 443, t0)
		o.Name = name
		l.Observe(o)
	}
	a, b := l.File(), l.File()
	if len(a.Rules) != 3 || !reflect.DeepEqual(a, b) {
		t.Fatalf("destinations must stay distinct and sorted: %+v", a.Rules)
	}
	var address bool
	for _, r := range a.Rules {
		if r.Name == "" {
			address = r.To == netip.MustParsePrefix("1.1.1.1/32")
		}
	}
	if !address {
		t.Fatal("unnamed observation must remain /32")
	}
}

func checkLearnedNameProjection(t *testing.T, got rules.Observed) {
	t.Helper()
	if got.Name != "api.github.com" || got.Count != 2 || got.Addr.IsValid() {
		t.Fatalf("want name destination and combined count, got %+v", got)
	}
}
