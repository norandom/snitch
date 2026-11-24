package tray

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/client"
)

// zone is a fixed local zone, passed through Options so no test touches time.Local.
var zone = time.FixedZone("CEST", 2*3600)

// now is the fixed clock of these tests; the trial deadline is 10 min after it.
var now = time.Date(2026, 10, 11, 12, 2, 0, 0, time.UTC)

const deadline = "2026-10-11T12:12:00Z" // 14:12 in zone

// running is a daemon in monitor mode with every fact set.
func running() api.Status {
	return api.Status{
		Running: true, Version: "0.4.0", Mode: "monitor",
		Rules: api.RulesSummary{Programs: 18, Rules: 13,
			File: "/etc/snitch/rules.toml", Overlay: "/etc/snitch/rules.d/local.toml"},
		Started: "2026-10-11T06:00:00Z",
		DNS:     &api.DNSStatus{On: true, Names: 120, Compiled: 4},
	}
}

// model is a tray model holding st; gone marks the daemon as gone with st as stale facts.
func model(st api.Status, gone bool) Model {
	m := NewModel(Options{Loc: zone})
	m.facts = &st
	m.gone = gone
	m.canNotify, m.canAct = true, true
	return m
}

// combo builds the status of one of the 32 combinations of the five conditions of 2.2.
func combo(i int) (api.Status, bool) {
	st := running()
	if i&2 != 0 {
		st.Kill = true
	}
	if i&4 != 0 {
		st.RulesError = "rules: line 3: unknown key"
	}
	if i&8 != 0 {
		st.Mode, st.Kept = "enforce", true
	}
	if i&16 != 0 {
		st.Mode, st.Trial = "enforce", deadline
	}
	return st, i&1 != 0
}

// expected is the first condition of 2.2 that holds in combination i.
func expected(i int) State {
	for bit, s := range []State{Gone, Kill, RulesError, Kept, Trial} {
		if i&(1<<bit) != 0 {
			return s
		}
	}
	return Monitor
}

// 2.1, 2.2, 2.3, 3.6: every combination shows the first condition that holds, attention for
// the first three states, and the menu's header names the same state as the icon.
func TestStateAllCombinations(t *testing.T) {
	for i := 0; i < 32; i++ {
		st, gone := combo(i)
		v := Render(model(st, gone), now)
		want := expected(i)
		if v.State != want {
			t.Errorf("combination %05b: state %v, want %v", i, v.State, want)
		}
		attention := want == Gone || want == Kill || want == RulesError
		if v.Attention != attention {
			t.Errorf("combination %05b: attention %v, want %v", i, v.Attention, attention)
		}
		if v.Title != "snitch: "+want.String() {
			t.Errorf("combination %05b: title %q", i, v.Title)
		}
		if h := v.Menu[0]; h.ID != RowHeader || !strings.Contains(h.Label, want.String()) {
			t.Errorf("combination %05b: header %+v does not name %v", i, h, want)
		}
	}
}

// Enforce without a deadline and not kept (a daemon started with -mode enforce) is a trial
// without a deadline: never monitor, because the kernel denies.
func TestStateEnforceWithoutDeadline(t *testing.T) {
	st := running()
	st.Mode = "enforce"
	v := Render(model(st, false), now)
	if v.State != Trial || !strings.Contains(v.Tooltip, "no deadline") {
		t.Fatalf("state %v tooltip %q", v.State, v.Tooltip)
	}
}

// 2.4, 2.5: the deadline in local time and the minutes left, rounded up, at two times.
func TestTooltipTrialMinutesLeft(t *testing.T) {
	st := running()
	st.Mode, st.Trial = "enforce", deadline
	m := model(st, false)
	cases := []struct {
		at   time.Time
		want string
	}{
		{now, "until 14:12 (10 min left)"},
		{now.Add(9*time.Minute + 1*time.Second), "until 14:12 (1 min left)"},
		{now.Add(4*time.Minute + 30*time.Second), "until 14:12 (6 min left)"},
	}
	for _, c := range cases {
		if tip := Render(m, c.at).Tooltip; !strings.Contains(tip, c.want) {
			t.Errorf("at %v: tooltip %q lacks %q", c.at, tip, c.want)
		}
	}
}

// 2.4: the state first, then every other condition that holds.
func TestTooltipOtherConditions(t *testing.T) {
	st := running()
	st.Kill, st.RulesError, st.Mode, st.Trial = true, "bad", "enforce", deadline
	tip := Render(model(st, false), now).Tooltip
	lines := strings.Split(tip, "\n")
	if lines[0] != Kill.String() {
		t.Fatalf("first line %q, want the state", lines[0])
	}
	for _, want := range []string{RulesError.String(), Trial.String() + " until 14:12"} {
		if !strings.Contains(tip, want) {
			t.Errorf("tooltip %q lacks %q", tip, want)
		}
	}
	if strings.Contains(tip, Monitor.String()) {
		t.Errorf("tooltip %q names monitor during a trial", tip)
	}
}

// 2.6, 5.10, 4.4: learning, paused and not answering are said; nothing of that otherwise.
func TestTooltipLearningPausedNotAnswering(t *testing.T) {
	st := running()
	plain := Render(model(st, false), now).Tooltip
	for _, w := range []string{"learning", "questions paused", client.NotAnswering} {
		if strings.Contains(plain, w) {
			t.Errorf("plain tooltip %q says %q", plain, w)
		}
	}
	st.Learning = true
	m := model(st, false)
	m.paused = true
	tip := Render(m, now).Tooltip
	for _, w := range []string{"learning", "questions paused"} {
		if !strings.Contains(tip, w) {
			t.Errorf("tooltip %q lacks %q", tip, w)
		}
	}
	m.gone, m.down = true, client.NotAnswering
	tip = Render(m, now).Tooltip
	if !strings.Contains(tip, client.NotAnswering) || strings.Contains(tip, "learning") {
		t.Errorf("gone tooltip %q: wants not answering and no stale fact", tip)
	}
}

// 3.1: a running daemon's facts, in the closed order of the design.
func TestMenuFacts(t *testing.T) {
	st := running()
	m := model(st, false)
	m.writer = true
	rows := Render(m, now).Menu
	want := []RowID{RowHeader, RowMode, RowTrial, RowKept, RowKill, RowLearning, RowCounts,
		RowRulesFile, RowOverlay, RowDNS, RowDaemon, RowRole, RowSeparator, RowPause, RowQuit}
	if got := ids(rows); !slices.Equal(got, want) {
		t.Fatalf("rows %v, want %v", got, want)
	}
	labels := map[RowID]string{
		RowMode: "monitor", RowTrial: "no trial", RowKept: "no", RowKill: "clear",
		RowLearning: "off", RowCounts: "18 programs, 13 rules",
		RowRulesFile: "/etc/snitch/rules.toml", RowOverlay: "/etc/snitch/rules.d/local.toml",
		RowDNS: "on, 120 names, 4 compiled", RowDaemon: "0.4.0, started 2026-10-11 08:00",
		RowRole: "operator",
	}
	for id, w := range labels {
		if l := row(t, rows, id).Label; !strings.Contains(l, w) {
			t.Errorf("row %d %q lacks %q", id, l, w)
		}
	}
	m.writer = false
	if l := row(t, Render(m, now).Menu, RowRole).Label; !strings.Contains(l, "read only") {
		t.Errorf("reader role row %q", l)
	}
}

// 3.1: an off tap shows the daemon's reason; a trial shows its deadline.
func TestMenuDNSOffAndTrial(t *testing.T) {
	st := running()
	st.DNS = &api.DNSStatus{Reason: "no BTF for the tap"}
	st.Mode, st.Trial = "enforce", deadline
	rows := Render(model(st, false), now).Menu
	if l := row(t, rows, RowDNS).Label; !strings.Contains(l, "off (no BTF for the tap)") {
		t.Errorf("dns row %q", l)
	}
	if l := row(t, rows, RowTrial).Label; !strings.Contains(l, "until 14:12 (10 min left)") {
		t.Errorf("trial row %q", l)
	}
}

// 3.2: the rules error in full, line breaks and all.
func TestMenuRulesErrorInFull(t *testing.T) {
	st := running()
	st.RulesError = "rules: /etc/snitch/rules.toml: line 7: program \"firefox\": " +
		strings.Repeat("a very long reason ", 20) + "\nsecond line"
	l := row(t, Render(model(st, false), now).Menu, RowRulesError).Label
	if !strings.Contains(l, st.RulesError) {
		t.Fatalf("rules error row %q lacks the full text", l)
	}
}

// 3.3: a gone daemon shows the header and the last three rows, no stale fact.
func TestMenuGoneHasNoFactRow(t *testing.T) {
	st := running()
	st.RulesError, st.Kill = "stale", true
	for _, m := range []Model{model(st, true), NewModel(Options{Loc: zone})} {
		rows := Render(m, now).Menu
		want := []RowID{RowHeader, RowSeparator, RowPause, RowQuit}
		if got := ids(rows); !slices.Equal(got, want) {
			t.Fatalf("gone rows %v, want %v", got, want)
		}
		if !strings.Contains(rows[0].Label, "not running") {
			t.Errorf("gone header %q", rows[0].Label)
		}
	}
}

// 3.4, 3.5: only Pause and quit can be clicked, over every combination and capability; no
// label names a trial verb, the kill switch toggle or a mode change.
func TestMenuOnlyPauseAndQuit(t *testing.T) {
	for i := 0; i < 64; i++ {
		st, gone := combo(i & 31)
		m := model(st, gone)
		m.paused, m.canAct = i&32 != 0, i&32 == 0
		for _, r := range Render(m, now).Menu {
			checkRow(t, r)
		}
		p := row(t, Render(m, now).Menu, RowPause)
		if !p.Check || p.Checked != m.paused || p.Label != "Pause questions" {
			t.Errorf("pause row %+v, paused %v", p, m.paused)
		}
	}
}

// checkRow fails a row outside the closed set, an enabled row other than Pause and quit, and
// an enabled row whose label names a trial verb, the kill switch or a mode change.
func checkRow(t *testing.T, r Row) {
	t.Helper()
	if r.ID < RowHeader || r.ID > RowQuit {
		t.Errorf("row %d %q is outside the closed set", r.ID, r.Label)
	}
	if r.Enabled != (r.ID == RowPause || r.ID == RowQuit) {
		t.Errorf("row %d %q enabled %v", r.ID, r.Label, r.Enabled)
	}
	for _, v := range []string{"start", "end trial", "keep", "unkeep", "set kill",
		"clear kill", "enforce now", "switch"} {
		if r.Enabled && strings.Contains(strings.ToLower(r.Label), v) {
			t.Errorf("row %q offers %q", r.Label, v)
		}
	}
}

// 8.6: the hint that questions cannot be answered here, only when they cannot.
func TestMenuCannotAnswerHint(t *testing.T) {
	for _, c := range []struct{ notify, act, hint bool }{
		{true, true, false}, {true, false, true}, {false, false, true}, {false, true, true},
	} {
		m := model(running(), false)
		m.canNotify, m.canAct = c.notify, c.act
		has := false
		for _, r := range Render(m, now).Menu {
			has = has || r.ID == RowNoAnswer
		}
		if has != c.hint {
			t.Errorf("notify %v act %v: hint %v", c.notify, c.act, has)
		}
	}
}
