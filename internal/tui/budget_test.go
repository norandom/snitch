package tui

import (
	"fmt"
	"maps"
	"runtime/debug"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/conf"
	"github.com/norandom/snitch/internal/table"
)

const (
	budgetProgs   = 64
	budgetHosts   = 8
	budgetAddrs   = 8
	budgetEntries = budgetProgs * budgetHosts * budgetAddrs
)

var benchScreenSink Screen

func budgetEntriesSlice(t0 time.Time, delta uint64) []api.Entry {
	out := make([]api.Entry, 0, budgetEntries)
	for p := range budgetProgs {
		prog := fmt.Sprintf("prog-%02d", p)
		path := fmt.Sprintf("/usr/bin/%s", prog)
		for h := range budgetHosts {
			host := fmt.Sprintf("h%d.%s.example", h, prog)
			for a := range budgetAddrs {
				ts := t0.Add(-time.Duration(len(out)) * time.Millisecond).Format(time.RFC3339Nano)
				out = append(out, api.Entry{
					Program:     prog,
					Path:        path,
					Addr:        fmt.Sprintf("10.%d.%d.%d", p, h, a+1),
					Name:        host,
					Port:        443,
					Protocol:    "tcp",
					AllowCount:  1 + delta,
					BytesSent:   100 + delta,
					Rate:        64,
					LastSeen:    ts,
					LastAllowed: ts,
					Verdict:     "allow-rule",
				})
			}
		}
	}
	return out
}

func budgetProgramsAndRules() ([]api.ProgramView, []api.RuleView) {
	progs := make([]api.ProgramView, 0, budgetProgs)
	for p := range budgetProgs {
		name := fmt.Sprintf("prog-%02d", p)
		progs = append(progs, api.ProgramView{
			Name: name, Paths: []string{"/usr/bin/" + name}, Resolved: true, Executables: 1,
		})
	}
	rules := []api.RuleView{
		{Id: 1, Program: "prog-00", To: "h0.prog-00.example", Protocol: "tcp", Port: 443, Verdict: "allow"},
		{Id: 2, Program: "prog-01", To: "10.1.0.0/16", Protocol: "tcp", Port: 443, Verdict: "allow"},
	}
	return progs, rules
}

func openAllRows(tb testing.TB, m Model, t0 time.Time) Model {
	tb.Helper()
	for range 2 {
		open := maps.Clone(m.view.Open)
		if open == nil {
			open = make(map[table.RowID]bool)
		}
		for _, r := range m.rows {
			if r.HasKids {
				open[r.ID] = true
			}
		}
		m.view.Open = open
		m = rebuildRows(m, t0)
	}
	for _, r := range m.rows {
		if r.HasKids && !r.Open {
			tb.Fatalf("row %q remained closed", r.ID)
		}
	}
	return m
}

func setupBudgetModel(tb testing.TB, t0 time.Time, entries []api.Entry) Model {
	tb.Helper()
	progs, rules := budgetProgramsAndRules()
	m, fx := Update(New(Options{Conf: conf.Default(), Loc: time.UTC}), client.Up{PeerUID: 0, PeerKnown: true}, t0)
	var rReq, pReq, sReq Send
	for _, eff := range fx {
		s, ok := eff.(Send)
		if !ok {
			continue
		}
		switch s.Req.Type {
		case "rules":
			rReq = s
		case "programs":
			pReq = s
		case "snapshot":
			sReq = s
		}
	}
	m, _ = Update(m, Resize{W: 120, H: 40}, t0)
	m, _ = Update(m, client.Facts{Status: api.Status{Running: true, Mode: "monitor"}}, t0)
	m, _ = Update(m, client.Answered{Token: rReq.Token, Reply: &api.Reply{Ok: true, Rules: rules}}, t0)
	m, _ = Update(m, client.Answered{Token: pReq.Token, Reply: &api.Reply{Ok: true, Programs: progs}}, t0)
	m, _ = Update(m, client.Answered{Token: sReq.Token, Reply: &api.Reply{Ok: true, Window: m.window, Entries: entries}}, t0)
	m, _ = Update(m, Tick{}, t0)
	m = openAllRows(tb, m, t0)
	if m.store.Len() != budgetEntries {
		tb.Fatalf("store len=%d, want %d", m.store.Len(), budgetEntries)
	}
	return m
}

func raceDetectorActive() bool {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return false
	}
	for _, s := range bi.Settings {
		if s.Key == "-race" && s.Value == "true" {
			return true
		}
	}
	return false
}

func TestBudgetMoveAndSummaryRebuild(t *testing.T) {
	t0 := feedTime()
	m := setupBudgetModel(t, t0, budgetEntriesSlice(t0, 0))
	before := m.rebuilds
	t1 := t0.Add(100 * time.Millisecond)

	start := time.Now()
	m, _ = Update(m, Key{Name: "down", At: t1}, t1)
	scr := Render(m, t1)
	elapsed := time.Since(start)
	race := raceDetectorActive()
	t.Logf("move update+render (%d entries, %d open rows, race=%v): %v", m.store.Len(), len(m.rows), race, elapsed)

	if len(scr.Lines) == 0 || m.rebuilds != before {
		t.Fatalf("after move: lines=%d rebuilds=%d (want %d)", len(scr.Lines), m.rebuilds, before)
	}
	if !race && elapsed >= 100*time.Millisecond {
		t.Fatalf("move update+render took %v, want < 100ms", elapsed)
	}

	for i, k := range []string{"pgdown", "end", "up", "home"} {
		at := t1.Add(time.Duration(i+1) * 20 * time.Millisecond)
		m, _ = Update(m, Key{Name: k, At: at}, at)
	}
	if m.rebuilds != before {
		t.Fatalf("movement keys triggered %d rebuilds, want 0", m.rebuilds-before)
	}
	assertSummaryOneRebuild(t, m, t0, before)
}

func assertSummaryOneRebuild(t *testing.T, m Model, t0 time.Time, before int) {
	t.Helper()
	updated := budgetEntriesSlice(t0.Add(200*time.Millisecond), 500)
	m, _ = Update(m, client.SummaryLine{Entries: updated}, t0.Add(200*time.Millisecond))
	if !m.dirty || m.rebuilds != before {
		t.Fatalf("summary before tick: dirty=%v rebuilds=%d (want %d)", m.dirty, m.rebuilds, before)
	}
	m, _ = Update(m, Key{Name: "down", At: t0.Add(250 * time.Millisecond)}, t0.Add(250*time.Millisecond))
	if m.rebuilds != before {
		t.Fatalf("move while dirty triggered %d rebuilds, want 0", m.rebuilds-before)
	}

	m, _ = Update(m, Tick{}, t0.Add(rebuildEvery))
	wantRows := budgetProgs + budgetProgs*budgetHosts + budgetEntries
	if m.dirty || m.rebuilds != before+1 || len(m.rows) != wantRows {
		t.Fatalf("after summary tick: dirty=%v rebuilds=%d (want %d) rows=%d (want %d)", m.dirty, m.rebuilds, before+1, len(m.rows), wantRows)
	}
	if got, ok := m.store.Get(table.KeyOf(updated[0])); !ok || got.BytesSent != 600 {
		t.Fatalf("updated entry=%+v ok=%v, want BytesSent=600", got, ok)
	}
}

func BenchmarkMoveOpen4096(b *testing.B) {
	t0 := feedTime()
	m := setupBudgetModel(b, t0, budgetEntriesSlice(t0, 0))
	keys := []string{"down", "pgdown", "up", "pgup"}
	b.ResetTimer()
	for i := range b.N {
		at := t0.Add(time.Duration(i+1) * 10 * time.Millisecond)
		m, _ = Update(m, Key{Name: keys[i%len(keys)], At: at}, at)
		benchScreenSink = Render(m, at)
	}
}
