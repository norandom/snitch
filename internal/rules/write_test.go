package rules_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/rules"
)

const localHeader = "local rules written by snitchd's API"

func TestWriteWithPutsTheHeaderInTheFile(t *testing.T) {
	f := parse(t, programs+ruleTable("curl", "1.1.1.1", "tcp", "443", "allow"))
	path := filepath.Join(t.TempDir(), "local.toml")
	if err := rules.WriteWith(path, f, localHeader); err != nil {
		t.Fatal(err)
	}
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(src), "# "+localHeader+"\n") {
		t.Fatalf("the header is the first comment line, got:\n%s", src)
	}
	if strings.Contains(string(src), "learned") {
		t.Fatal("the learned header must not leak into an overlay")
	}
}

func TestWriteWithMultiLineHeaderIsAllComments(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local.toml")
	if err := rules.WriteWith(path, &rules.File{}, "one\ntwo"); err != nil {
		t.Fatal(err)
	}
	src, _ := os.ReadFile(path)
	if string(src) != "# one\n# two\n" {
		t.Fatalf("got %q", src)
	}
}

func TestWriteWithRoundTripsThroughLoad(t *testing.T) {
	want := parse(t, programs+
		ruleTable("curl", "1.1.1.1", "tcp", "443", "allow")+
		ruleTable("claude", "2001:db8::/32", "", "", "allow")+
		ruleTable("any", "9.9.9.9", "udp", "\"53-54\"", "deny"))
	path := filepath.Join(t.TempDir(), "local.toml")
	if err := rules.WriteWith(path, want, localHeader); err != nil {
		t.Fatal(err)
	}
	got, err := rules.Load(path)
	if err != nil {
		t.Fatalf("the written file must load without edits: %v", err)
	}
	if len(got.Rules) != len(want.Rules) || len(got.Programs) != len(want.Programs) {
		t.Fatalf("round trip changed the record count: %+v", got)
	}
	for i := range want.Rules {
		if !sameRule(want.Rules[i], got.Rules[i], path) {
			t.Fatalf("rule %d changed:\n got %+v\nwant %+v", i, got.Rules[i], want.Rules[i])
		}
	}
	if entries, _ := os.ReadDir(filepath.Dir(path)); len(entries) != 1 {
		t.Fatalf("temp file left behind: %v", entries)
	}
}

// sameRule: the written rule read back is the same key, verdict and port count, from the file.
func sameRule(w, g rules.Rule, source string) bool {
	return keyOf(w) == keyOf(g) && w.Verdict == g.Verdict && len(w.Ports) == len(g.Ports) && g.Source == source
}

func TestWriteWithRequiresAHeader(t *testing.T) {
	path := filepath.Join(t.TempDir(), "local.toml")
	contracttest.Panics(t, contract.Precondition, func() { rules.WriteWith(path, &rules.File{}, "") })
	if _, err := os.Stat(path); err == nil {
		t.Fatal("nothing may be written when the contract trips")
	}
}

func TestWriteFileKeepsTheLearnedHeader(t *testing.T) {
	// cmd/snitchd passes rules.WriteFile by value to the learner: its shape and header stay
	path := filepath.Join(t.TempDir(), "learned.toml")
	var write func(string, *rules.File) error = rules.WriteFile
	if err := write(path, rules.NewLearned(nil).File()); err != nil {
		t.Fatal(err)
	}
	src, _ := os.ReadFile(path)
	lines := strings.SplitN(string(src), "\n", 3)
	if !strings.HasPrefix(lines[0], "# snitch learned rules, written 20") || !strings.HasSuffix(lines[0], ": what programs connected to while nothing was") {
		t.Fatalf("first header line changed: %q", lines[0])
	}
	if lines[1] != "# blocked. Review, then merge into the live rules file; snitchd never does that itself." {
		t.Fatalf("second header line changed: %q", lines[1])
	}
}
