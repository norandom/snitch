package tui

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/conf"
)

type hostileNamed struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type nonASCIIVec struct {
	Raw      string `json:"raw"`
	Punycode string `json:"punycode"`
	RawLabel string `json:"raw_label"`
}

type hostileCorpus struct {
	Strings        []hostileNamed `json:"strings"`
	InvalidUTF8Hex []string       `json:"invalid_utf8_hex"`
	NonASCIINames  []nonASCIIVec  `json:"non_ascii_names"`
	Pastes         []string       `json:"pastes"`
	ActionKeys     []string       `json:"action_keys"`
	ConfirmKeys    []string       `json:"confirm_keys"`
}

func loadHostileCorpus(t *testing.T) hostileCorpus {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "hostile_corpus.json"))
	if err != nil {
		t.Fatalf("read hostile corpus: %v", err)
	}
	var c hostileCorpus
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("unmarshal hostile corpus: %v", err)
	}
	if len(c.Strings) == 0 || len(c.InvalidUTF8Hex) == 0 || len(c.Pastes) == 0 {
		t.Fatalf("hostile corpus missing required sections")
	}
	return c
}

func (c hostileCorpus) allVectors(t *testing.T) []hostileNamed {
	t.Helper()
	out := slices.Clone(c.Strings)
	for i, hx := range c.InvalidUTF8Hex {
		raw, err := hex.DecodeString(hx)
		if err != nil {
			t.Fatalf("decode invalid_utf8_hex[%d]: %v", i, err)
		}
		out = append(out, hostileNamed{Name: "invalid_utf8_" + hx, Value: string(raw)})
	}
	return out
}

func isReplacedRune(r rune) bool {
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

func assertSafeText(t *testing.T, where, s string) {
	t.Helper()
	if !utf8.ValidString(s) {
		t.Fatalf("%s contains invalid UTF-8: %q", where, s)
	}
	for _, r := range s {
		if isReplacedRune(r) {
			t.Fatalf("%s leaked replaced rune U+%04X in %q", where, r, s)
		}
	}
}

func assertScreenAndLogSafe(t *testing.T, label string, m Model, fx []Effect, now time.Time, wantRows int) {
	t.Helper()
	scr := Render(m, now)
	assertSafeText(t, label+" title", string(scr.Title))
	if wantRows > 0 && len(scr.Lines) != wantRows {
		t.Fatalf("%s row count = %d, want %d", label, len(scr.Lines), wantRows)
	}
	for _, line := range scr.Lines {
		assertSafeText(t, label+" line", flattenLine(line))
	}
	for _, entry := range m.log {
		assertSafeText(t, label+" log", string(entry))
	}
	for _, app := range appendsOf(fx) {
		assertSafeText(t, label+" append", string(app.Line))
	}
}

func baselineModel(t *testing.T, t0 time.Time, egress bool) (Model, int) {
	t.Helper()
	st := api.Status{Running: true, Mode: "monitor", Counting: true}
	rules := []api.RuleView{{Id: 1, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "allow", Note: "ok", Source: "rules"}}
	progs := []api.ProgramView{{Name: "curl", Paths: []string{"/usr/bin/curl"}, Resolved: true}}
	entries := []api.Entry{
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "api.example.com", Port: 443, Protocol: "tcp", AllowCount: 1, BytesSent: 512, LastSeen: t0.Format(time.RFC3339), Verdict: "allow-rule"},
		{Program: "unknown", Path: "/opt/bin/custom", Addr: "9.9.9.9", Name: "bad.example.org", Port: 443, Protocol: "tcp", DenyCount: 1, BytesSent: 128, LastSeen: t0.Format(time.RFC3339), Verdict: "deny-rule"},
	}
	m := overviewModel(t, t0, Options{Conf: conf.Default(), Loc: time.UTC, Egress: egress}, st, rules, progs, entries)
	return m, len(Render(m, t0).Lines)
}

func buildHostileModel(t *testing.T, t0 time.Time, v string, egress bool) (Model, []Effect) {
	t.Helper()
	st := api.Status{Running: true, Mode: "monitor", Counting: true, RulesError: v, Source: v}
	rules := []api.RuleView{{Id: 1, Program: v, To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "deny", Note: v, Source: v}}
	progs := []api.ProgramView{{Name: v, Paths: []string{v}, Resolved: true, Source: v}}
	entries := []api.Entry{
		{Program: v, Path: "/opt/" + v, Addr: "1.1.1.1", Name: v + ".example", Port: 443, Protocol: "tcp", AllowCount: 1, BytesSent: 512, LastSeen: t0.Format(time.RFC3339), Verdict: v},
		{Program: "unknown", Path: "/opt/" + v, Addr: "9.9.9.9", Name: v + ".example", Port: 443, Protocol: "tcp", DenyCount: 1, BytesSent: 128, LastSeen: t0.Format(time.RFC3339), Verdict: "deny-rule"},
	}
	m := overviewModel(t, t0, Options{Conf: conf.Default(), Loc: time.UTC, Egress: egress, Socket: clean.Text(v)}, st, rules, progs, entries)
	var allFx, fx []Effect
	m, fx = Update(m, client.EventLine{Event: api.Event{Program: v, Path: "/opt/" + v, Addr: "9.9.9.9", Name: v + ".example", Port: 443, Protocol: "tcp", Verdict: "deny-rule", Rule: &api.RuleRef{Id: 1, Note: v, Source: v}}}, t0.Add(time.Second))
	allFx = append(allFx, fx...)
	m, fx = Update(m, client.StateLine{State: api.State{Mode: "enforce", Reason: v}}, t0.Add(2*time.Second))
	allFx = append(allFx, fx...)
	m, fx = Update(m, client.Down{Reason: v}, t0.Add(3*time.Second))
	allFx = append(allFx, fx...)
	if len(appendsOf(allFx)) != 2 {
		t.Fatalf("expected 2 append effects, got %d", len(appendsOf(allFx)))
	}
	return m, allFx
}

func checkHostileNoticesAndConfirm(t *testing.T, t0 time.Time, v string, wantRows int) {
	t.Helper()
	m := trialUpModel(t, t0, Options{Conf: conf.Default(), Loc: time.UTC})
	m, fx := Update(m, Key{Name: "E", At: t0}, t0)
	tok := sendsOf(fx)[0].Token
	m1, fx1 := Update(m, client.Answered{Token: tok, Text: v, Reply: &api.Reply{Ok: true, Text: v}}, t0.Add(time.Second))
	assertScreenAndLogSafe(t, "answer text", m1, fx1, t0.Add(time.Second), wantRows)
	m2, fx2 := Update(m, client.Answered{Token: tok, Err: v}, t0.Add(time.Second))
	assertScreenAndLogSafe(t, "answer error", m2, fx2, t0.Add(time.Second), wantRows)
	m3, _ := Update(m, Key{Name: "T", At: t0}, t0)
	m3, _ = Update(m3, Key{Name: "y", At: t0.Add(time.Second)}, t0.Add(time.Second))
	m3, fx3 := Update(m3, client.Answered{Token: m3.nextToken, Err: v + " [y/N]", Question: true}, t0.Add(2*time.Second))
	assertScreenAndLogSafe(t, "answer question", m3, fx3, t0.Add(2*time.Second), wantRows)
}

func TestHostileDaemonFieldsScreenAndLog(t *testing.T) {
	corpus := loadHostileCorpus(t)
	t0 := feedTime()
	_, overRows := baselineModel(t, t0, false)
	_, graphRows := baselineModel(t, t0, true)
	for _, vec := range corpus.allVectors(t) {
		t.Run(vec.Name, func(t *testing.T) {
			m, fx := buildHostileModel(t, t0, vec.Value, false)
			assertScreenAndLogSafe(t, "overview program", m, fx, t0.Add(3*time.Second), overRows)
			mOpen, fxOpen := Update(m, Key{Name: "enter", At: t0.Add(4 * time.Second)}, t0.Add(4*time.Second))
			assertScreenAndLogSafe(t, "overview opened", mOpen, fxOpen, t0.Add(4*time.Second), overRows)
			mDown, fxDown := Update(mOpen, Key{Name: "down", At: t0.Add(5 * time.Second)}, t0.Add(5*time.Second))
			assertScreenAndLogSafe(t, "overview host", mDown, fxDown, t0.Add(5*time.Second), overRows)
			mEnd, fxEnd := Update(mDown, Key{Name: "end", At: t0.Add(6 * time.Second)}, t0.Add(6*time.Second))
			assertScreenAndLogSafe(t, "overview unknown path", mEnd, fxEnd, t0.Add(6*time.Second), overRows)
			mGraph, fxGraph := buildHostileModel(t, t0, vec.Value, true)
			assertScreenAndLogSafe(t, "graph", mGraph, fxGraph, t0.Add(3*time.Second), graphRows)
			checkHostileNoticesAndConfirm(t, t0, vec.Value, overRows)
		})
	}
}

func TestHostileNonASCIINamePunycode(t *testing.T) {
	corpus := loadHostileCorpus(t)
	t0 := feedTime()
	for _, tc := range corpus.NonASCIINames {
		t.Run(tc.Raw, func(t *testing.T) {
			st := api.Status{Running: true, Mode: "monitor", Counting: true}
			entries := []api.Entry{{Program: "curl", Path: "/usr/bin/curl", Addr: "9.9.9.9", Name: tc.Raw, Port: 443, Protocol: "tcp", DenyCount: 1, BytesSent: 512, LastSeen: t0.Format(time.RFC3339), Verdict: "deny-rule"}}
			m := overviewModel(t, t0, Options{Conf: conf.Default(), Loc: time.UTC}, st, nil, nil, entries)
			m, fx := Update(m, client.EventLine{Event: api.Event{Program: "curl", Path: "/usr/bin/curl", Addr: "9.9.9.9", Name: tc.Raw, Port: 443, Protocol: "tcp", Verdict: "deny-rule"}}, t0.Add(time.Second))
			m, _ = Update(m, Key{Name: "enter", At: t0.Add(2 * time.Second)}, t0.Add(2*time.Second))
			m, _ = Update(m, Key{Name: "down", At: t0.Add(3 * time.Second)}, t0.Add(3*time.Second))
			over := flattenScreen(Render(m, t0.Add(3*time.Second)))
			mGraph, _ := Update(m, Key{Name: "e", At: t0.Add(4 * time.Second)}, t0.Add(4*time.Second))
			graph := flattenScreen(Render(mGraph, t0.Add(4*time.Second)))
			for name, body := range map[string]string{"overview": over, "graph": graph, "log": string(m.log[len(m.log)-1]), "append": string(appendsOf(fx)[0].Line)} {
				if !strings.Contains(body, tc.Punycode) || strings.Contains(body, tc.RawLabel) {
					t.Fatalf("%s punycode check failed (want %q, forbid %q):\n%s", name, tc.Punycode, tc.RawLabel, body)
				}
			}
		})
	}
}

func TestHostilePasteNeverSends(t *testing.T) {
	corpus := loadHostileCorpus(t)
	t0 := feedTime()
	base := blockModelWith(t, t0, Options{Conf: conf.Default(), Loc: time.UTC}, []api.Entry{blockEntry("curl", "/usr/bin/curl", "1.1.1.1", "api.example.com", t0)}, nil)
	wantRows := len(Render(base, t0).Lines)
	mGraph, _ := Update(base, Key{Name: "e", At: t0.Add(time.Second)}, t0.Add(time.Second))
	mConf, _ := Update(base, Key{Name: "T", At: t0.Add(time.Second)}, t0.Add(time.Second))
	for _, p := range corpus.Pastes {
		for name, m := range map[string]Model{"overview": base, "graph": mGraph, "confirm": mConf} {
			if next, fx := Update(m, Paste{Text: p}, t0.Add(time.Second)); len(sendsOf(fx)) != 0 || len(appendsOf(fx)) != 0 || next.confirm != m.confirm {
				t.Fatalf("paste %q in %s acted: fx=%#v", p, name, fx)
			}
		}
		mSearch, _ := Update(base, Key{Name: "/", At: t0.Add(time.Second)}, t0.Add(time.Second))
		mSearch, fx := Update(mSearch, Paste{Text: p}, t0.Add(2*time.Second))
		if len(sendsOf(fx)) != 0 || mSearch.search == nil {
			t.Fatalf("paste %q in search sent or closed search: fx=%#v", p, fx)
		}
		assertScreenAndLogSafe(t, "paste search", mSearch, fx, t0.Add(2*time.Second), wantRows)
	}
}

func TestHostileTypeaheadAndBurstNeverSends(t *testing.T) {
	corpus := loadHostileCorpus(t)
	t0 := feedTime()
	base := blockModelWith(t, t0, Options{Conf: conf.Default(), Loc: time.UTC}, []api.Entry{blockEntry("curl", "/usr/bin/curl", "1.1.1.1", "api.example.com", t0)}, nil)
	for _, openKey := range []string{"T", "K"} {
		for _, k := range corpus.ConfirmKeys {
			m, _ := Update(base, Key{Name: openKey, At: t0}, t0)
			for _, dt := range []time.Duration{0, 200 * time.Millisecond, 599 * time.Millisecond} {
				if next, fx := Update(m, Key{Name: k, At: t0.Add(dt)}, t0.Add(dt)); len(sendsOf(fx)) != 0 || next.confirm == nil {
					t.Fatalf("typeahead %q after %q at %v bypassed confirm gate: fx=%#v", k, openKey, dt, fx)
				}
			}
		}
	}
	checkBurstAndRepeat(t, base, corpus.ActionKeys, t0)
}

func checkBurstAndRepeat(t *testing.T, base Model, actionKeys []string, t0 time.Time) {
	t.Helper()
	for _, k := range actionKeys {
		if _, fx := Update(base, Key{Name: k, Repeat: true, At: t0.Add(time.Second)}, t0.Add(time.Second)); len(sendsOf(fx)) != 0 {
			t.Fatalf("repeat key %q sent request: %#v", k, fx)
		}
	}
	m, _ := Update(base, Key{Name: "down", At: t0}, t0)
	at := t0
	for _, k := range actionKeys {
		at = at.Add(10 * time.Millisecond)
		var fx []Effect
		if m, fx = Update(m, Key{Name: k, At: at}, at); len(sendsOf(fx)) != 0 {
			t.Fatalf("burst key %q sent request: %#v", k, fx)
		}
	}
	mConf, _ := Update(base, Key{Name: "T", At: t0}, t0)
	mConf, _ = Update(mConf, Key{Name: "down", At: t0.Add(580 * time.Millisecond)}, t0.Add(580*time.Millisecond))
	if mConf.confirm == nil {
		t.Fatalf("confirm closed before 600ms gate")
	}
	if _, fxYes := Update(mConf, Key{Name: "y", At: t0.Add(610 * time.Millisecond)}, t0.Add(610*time.Millisecond)); len(sendsOf(fxYes)) != 0 {
		t.Fatalf("burst y in open confirm sent request: %#v", fxYes)
	}
}

func TestHostileNonRootSocketNeverSends(t *testing.T) {
	corpus := loadHostileCorpus(t)
	t0 := feedTime()
	for _, uid := range []uint32{1, 1000, 65534} {
		m, _, _, sReq := upModel(t, t0, Options{Conf: conf.Default(), Loc: time.UTC})
		m, _ = Update(m, client.Up{PeerKnown: true, PeerUID: uid}, t0)
		m, _ = Update(m, client.Answered{Token: sReq.Token, Reply: &api.Reply{Ok: true, Window: m.window, Entries: []api.Entry{blockEntry("curl", "/usr/bin/curl", "1.1.1.1", "api.example.com", t0)}}}, t0)
		m, _ = Update(m, Tick{}, t0.Add(rebuildEvery))
		assertContainsAll(t, flattenScreen(Render(m, t0.Add(rebuildEvery))), "FOREIGN (not root)")
		at := t0.Add(time.Second)
		for _, k := range corpus.ActionKeys {
			at = at.Add(time.Second)
			var fx []Effect
			if m, fx = Update(m, Key{Name: k, At: at}, at); len(sendsOf(fx)) != 0 || string(m.notice) != "not the system daemon: writes are off" {
				t.Fatalf("foreign uid %d key %q acted: fx=%#v notice=%q", uid, k, fx, m.notice)
			}
		}
	}
}
