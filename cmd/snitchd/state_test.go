package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
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
	snap, err := loadRules(filepath.Join(t.TempDir(), "none.toml"), "", func(m string) { notes = append(notes, m) })
	if err != nil || len(snap.res.File.Programs) != 0 || len(snap.ent.Rules) != 0 {
		t.Fatalf("want an empty snapshot, got %+v, %v", snap, err)
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "no rules loaded") {
		t.Fatalf("want one notice, got %q", notes)
	}
}

func TestLoadRulesInvalidFileIsAnErrorWithLine(t *testing.T) {
	p := writeRules(t, "[[program]]\nname = \"curl\"\npaths = []\n\n[[rule]]\nprogram = \"wget\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\n")
	_, err := loadRules(p, "", func(string) {})
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
	snap, err := loadRules(p, "", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	if len(snap.ent.Programs) != 1 || len(snap.ent.Rules) != 2 || len(snap.res.Unresolved) != 1 {
		t.Fatalf("want 1 executable, 2 rules, 1 unresolved: %+v", snap.ent)
	}
	s := summary(snap)
	for _, want := range []string{"2 programs", "1 resolved", "1 unresolved (ghost)", "1 patterns unmatched (ghost:/nonexistent/ghost)", "1 executable", "2 rules effective"} {
		if !strings.Contains(s, want) {
			t.Fatalf("summary %q lacks %q", s, want)
		}
	}
}

func TestSummaryCountsAProgramResolvedWhenOnePathMaps(t *testing.T) {
	self, _ := os.Executable()
	p := writeRules(t, "[[program]]\nname = \"me\"\npaths = [\""+self+"\", \""+t.TempDir()+"/*\"]\n")
	snap, err := loadRules(p, "", func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	s := summary(snap)
	if !strings.Contains(s, "1 programs (1 resolved, 0 unresolved)") || !strings.Contains(s, "1 patterns unmatched (me:") {
		t.Fatalf("got %q", s)
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

// baseFor is a base file with one program (this test binary) and one allow rule.
func baseFor(t *testing.T) string {
	t.Helper()
	self, _ := os.Executable()
	return writeRules(t, "[[program]]\nname = \"me\"\npaths = [\""+self+"\"]\n\n[[rule]]\nprogram = \"me\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\n")
}

func writeOverlay(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "local.toml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadRulesWithoutAnOverlayFileIsBaseOnly(t *testing.T) {
	var notes []string
	for _, overlay := range []string{"", filepath.Join(t.TempDir(), "none.toml")} {
		snap, err := loadRules(baseFor(t), overlay, func(m string) { notes = append(notes, m) })
		if err != nil || snap.rulesErr != nil || len(snap.res.File.Rules) != 1 || len(notes) != 0 {
			t.Fatalf("overlay %q: want the base alone and no notice, got %+v, %v, %v, notes %q", overlay, snap.res.File, snap.rulesErr, err, notes)
		}
	}
}

func TestLoadRulesMergesTheOverlayWithPrecedence(t *testing.T) {
	ov := writeOverlay(t, "[[rule]]\nprogram = \"me\"\nto = \"1.1.1.1\"\nverdict = \"deny\"\n\n[[rule]]\nprogram = \"me\"\nto = \"8.8.8.8\"\nverdict = \"allow\"\n")
	snap, err := loadRules(baseFor(t), ov, func(string) {})
	if err != nil || snap.rulesErr != nil {
		t.Fatalf("a valid overlay merges: %v, %v", err, snap.rulesErr)
	}
	rs := snap.res.File.Rules
	if len(rs) != 2 || rs[0].To.String() != "1.1.1.1/32" || rs[0].Verdict != rules.Deny || rs[0].Source != ov || rs[1].Source != ov {
		t.Fatalf("want the overlay's deny for 1.1.1.1 and its 8.8.8.8 rule, both sourced from the overlay, got %+v", rs)
	}
	if len(snap.ent.Rules) != 2 || !strings.Contains(summary(snap), "2 rules effective") {
		t.Fatalf("want two kernel entries, got %d: %s", len(snap.ent.Rules), summary(snap))
	}
}

// Req 5.4 and the design's startup row: an invalid overlay never refuses the start (an API
// write must not break the next boot); the base is effective and the error is recorded.
func TestLoadRulesInvalidOverlayAtStartupIsBaseOnlyWithTheErrorRecorded(t *testing.T) {
	cases := map[string]string{
		"syntax":          "garbage = [\n",
		"unknown program": "[[rule]]\nprogram = \"nobody\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\n",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			ov := writeOverlay(t, body)
			snap, err := loadRules(baseFor(t), ov, func(string) {})
			if err != nil {
				t.Fatalf("the start must not be refused: %v", err)
			}
			if snap.rulesErr == nil || !strings.Contains(snap.rulesErr.Error(), ov) {
				t.Fatalf("want the overlay error naming %s, got %v", ov, snap.rulesErr)
			}
			if len(snap.res.File.Rules) != 1 || snap.res.File.Rules[0].Verdict != rules.Allow || len(snap.ent.Rules) != 1 {
				t.Fatalf("want the base alone effective, got %+v", snap.res.File.Rules)
			}
		})
	}
}

func TestLoadRulesInvalidBaseIsStillAnErrorWithAnOverlay(t *testing.T) {
	ov := writeOverlay(t, "[[rule]]\nprogram = \"me\"\nto = \"8.8.8.8\"\nverdict = \"allow\"\n")
	if _, err := loadRules(writeRules(t, "garbage = [\n"), ov, func(string) {}); err == nil {
		t.Fatal("a broken base file is the operator's error, overlay or not")
	}
}

func TestLoadRulesRequiresABasePath(t *testing.T) {
	v := contracttest.Panics(t, contract.Precondition, func() { loadRules("", "", func(string) {}) })
	if !strings.Contains(v.Msg, "rules path") {
		t.Fatalf("want the precondition to name the rules path, got %q", v.Msg)
	}
}

func TestApplyFullRetriesOnce(t *testing.T) {
	calls, evictions := 0, 0
	ops := putDel{put: func(any, any) error {
		calls++
		if calls == 1 {
			return syscall.ENOSPC
		}
		return nil
	}}
	ch := rules.Changes{PutRules: map[rules.RuleKey]rules.RuleVal{{}: {Verdict: 1}}}
	err := applyWith(putDel{}, ops, ch, func() bool { evictions++; return true })
	if err != nil || calls != 2 || evictions != 1 {
		t.Fatalf("%v calls %d evictions %d", err, calls, evictions)
	}
}

func TestApplyFullRetryLimits(t *testing.T) {
	for _, full := range []func() bool{nil, func() bool { return false }, func() bool { return true }} {
		calls := 0
		ops := putDel{put: func(any, any) error { calls++; return syscall.ENOSPC }}
		ch := rules.Changes{PutRules: map[rules.RuleKey]rules.RuleVal{{}: {Verdict: 1}}}
		err := applyWith(putDel{}, ops, ch, full)
		want := 1
		if full != nil && full() {
			want = 2
		}
		if !errors.Is(err, syscall.ENOSPC) || calls != want {
			t.Fatalf("%v calls %d want %d", err, calls, want)
		}
	}
}
