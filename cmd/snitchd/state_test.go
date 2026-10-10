package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/rules"
)

// recorder is a fake map: it logs operations in order and can fail a put.
type recorder struct {
	log  []string
	fail bool
}

func (r *recorder) ops(name string) putDel {
	return putDel{
		put: func(key, val any) error {
			if r.fail {
				return errors.New("E2BIG")
			}
			r.log = append(r.log, name+" put")
			return nil
		},
		del: func(key any) error { r.log = append(r.log, name+" del"); return nil },
	}
}

func TestApplyPutsEverythingBeforeDeleting(t *testing.T) {
	rec := &recorder{}
	ch := rules.Changes{
		PutPrograms: map[rules.ExeKey]uint32{{Ino: 1}: 1},
		DelPrograms: []rules.ExeKey{{Ino: 2}},
		PutRules:    map[rules.RuleKey]rules.RuleVal{{Prefixlen: 64}: {Verdict: 1}},
		DelRules:    []rules.RuleKey{{Prefixlen: 96}},
	}
	if err := apply(rec.ops("programs"), rec.ops("rules"), ch); err != nil {
		t.Fatal(err)
	}
	want := "programs put,rules put,programs del,rules del"
	if got := strings.Join(rec.log, ","); got != want {
		t.Fatalf("order: got %q want %q", got, want)
	}
}

func TestApplyStopsAtTheFirstFailure(t *testing.T) {
	rec := &recorder{fail: true}
	ch := rules.Changes{PutRules: map[rules.RuleKey]rules.RuleVal{{Prefixlen: 64}: {Verdict: 1}}, DelRules: []rules.RuleKey{{Prefixlen: 96}}}
	if err := apply(rec.ops("programs"), rec.ops("rules"), ch); err == nil || len(rec.log) != 0 {
		t.Fatalf("want an error and no deletes after a failed put, got %v, %v", err, rec.log)
	}
}

func writeRules(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "rules.toml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadRulesMissingFileIsEmptyWithNotice(t *testing.T) {
	var notes []string
	snap, err := loadRules(filepath.Join(t.TempDir(), "none.toml"), func(m string) { notes = append(notes, m) })
	if err != nil || len(snap.res.File.Programs) != 0 || len(snap.ent.Rules) != 0 {
		t.Fatalf("want an empty snapshot, got %+v, %v", snap, err)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "no rules loaded") {
		t.Fatalf("want one notice, got %q", notes)
	}
}

func TestLoadRulesInvalidFileIsAnErrorWithLine(t *testing.T) {
	p := writeRules(t, "[[program]]\nname = \"curl\"\npaths = []\n\n[[rule]]\nprogram = \"wget\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\n")
	_, err := loadRules(p, func(string) {})
	var e *rules.Error
	if !errors.As(err, &e) || e.Line != 5 {
		t.Fatalf("want a rules error at line 5, got %v", err)
	}
}

func TestLoadRulesResolvesAndEncodes(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	p := writeRules(t, "[[program]]\nname = \"me\"\npaths = [\""+self+"\"]\n\n[[program]]\nname = \"ghost\"\npaths = [\"/nonexistent/ghost\"]\n\n"+
		"[[rule]]\nprogram = \"me\"\nto = \"1.1.1.1\"\nproto = \"tcp\"\nport = 443\nverdict = \"allow\"\n\n[[rule]]\nprogram = \"ghost\"\nto = \"::/0\"\nverdict = \"deny\"\n")
	snap, err := loadRules(p, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.ent.Programs) != 1 || len(snap.ent.Rules) != 2 || len(snap.res.Unresolved) != 1 {
		t.Fatalf("want 1 executable, 2 rules, 1 unresolved: %+v", snap.ent)
	}
	s := summary(snap)
	for _, want := range []string{"2 programs", "1 resolved", "1 unresolved (ghost)", "1 executable", "2 rules effective"} {
		if !strings.Contains(s, want) {
			t.Fatalf("summary %q lacks %q", s, want)
		}
	}
}

func TestStatePublishesSnapshots(t *testing.T) {
	var st state
	if st.current() != nil {
		t.Fatal("no snapshot before publish")
	}
	snap := &snapshot{res: &rules.Resolved{File: &rules.File{}}}
	st.publish(snap)
	if st.current() != snap {
		t.Fatal("publish must make the snapshot current")
	}
}
