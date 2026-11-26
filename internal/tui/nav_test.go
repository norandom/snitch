package tui

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/conf"
	"github.com/norandom/snitch/internal/table"
)

func navModelWith(t *testing.T, t0 time.Time, opts Options, entries []api.Entry) Model {
	t.Helper()
	m, _, _, snap := upModel(t, t0, opts)
	m, _ = Update(m, client.Answered{Token: snap.Token, Reply: &api.Reply{Ok: true, Window: m.window, Entries: entries}}, t0)
	m, _ = Update(m, Tick{}, t0)
	return m
}

func pressKey(m Model, name string, at time.Time) (Model, []Effect) {
	return Update(m, Key{Name: name, At: at}, at)
}

func rowTitles(rows []table.Row) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = string(r.Title)
	}
	return out
}

func ent(prog, addr, name string, last time.Time) api.Entry {
	return api.Entry{Program: prog, Addr: addr, Name: name, Port: 443, Protocol: "tcp", LastSeen: last.Format(time.RFC3339)}
}

func numberedEntries(n int, t0 time.Time) []api.Entry {
	out := make([]api.Entry, 0, n)
	for i := range n {
		out = append(out, ent(fmt.Sprintf("prog-%02d", i), fmt.Sprintf("1.1.1.%d", i+1), fmt.Sprintf("h%02d.example", i), t0.Add(-time.Duration(i)*time.Second)))
	}
	return out
}

func TestNavStartsClosedMovesAndZeroRebuilds(t *testing.T) {
	t0 := feedTime()
	m := navModelWith(t, t0, Options{}, numberedEntries(15, t0))
	if len(m.rows) != 15 || m.cursor != m.rows[0].ID {
		t.Fatalf("initial rows=%d cursor=%q, want 15 closed rows", len(m.rows), m.cursor)
	}
	for _, r := range m.rows {
		if r.Open || r.Depth != 0 {
			t.Fatalf("row %q not closed at start: open=%v depth=%d", r.Title, r.Open, r.Depth)
		}
	}
	m = checkMovementKeys(t, m, t0)
	check100MovementsZeroRebuilds(t, m, t0)
}

func checkMovementKeys(t *testing.T, m Model, t0 time.Time) Model {
	t.Helper()
	page := max(1, m.size.H-18)
	steps := []struct {
		key  string
		want int
	}{{"down", 1}, {"down", 2}, {"up", 1}, {"pgdown", 1 + page}, {"pgup", 1}, {"end", len(m.rows) - 1}, {"down", len(m.rows) - 1}, {"home", 0}, {"up", 0}}
	for i, s := range steps {
		m, _ = pressKey(m, s.key, t0.Add(time.Duration(i+1)*100*time.Millisecond))
		if m.cursor != m.rows[s.want].ID {
			t.Fatalf("after %s: cursor=%q, want rows[%d]=%q", s.key, m.cursor, s.want, m.rows[s.want].ID)
		}
		if s.want < m.top || s.want >= m.top+page {
			t.Fatalf("after %s: idx=%d outside viewport [%d, %d)", s.key, s.want, m.top, m.top+page)
		}
	}
	return m
}

func check100MovementsZeroRebuilds(t *testing.T, m Model, t0 time.Time) {
	t.Helper()
	e := ent("prog-00", "1.1.1.1", "h00.example", t0)
	e.BytesSent = 99
	m, _ = Update(m, client.SummaryLine{Entries: []api.Entry{e}}, t0.Add(2*time.Second))
	before := m.rebuilds
	keys := []string{"down", "up", "pgdown", "pgup", "end", "home"}
	for i := range 100 {
		m, _ = pressKey(m, keys[i%len(keys)], t0.Add(3*time.Second+time.Duration(i)*10*time.Millisecond))
	}
	if m.rebuilds != before {
		t.Fatalf("100 movement keys triggered %d rebuilds, want 0", m.rebuilds-before)
	}
}

func assertBuildState(t *testing.T, m Model, rebuilds int, dirty bool, rows int) {
	t.Helper()
	if m.rebuilds != rebuilds || m.dirty != dirty || (rows >= 0 && len(m.rows) != rows) {
		t.Fatalf("rebuilds=%d (want %d) dirty=%v (want %v) rows=%d", m.rebuilds, rebuilds, m.dirty, dirty, len(m.rows))
	}
}

func TestNavRebuildThrottledAt500ms(t *testing.T) {
	t0 := feedTime()
	m, _, _, snap := upModel(t, t0, Options{})
	m, _ = Update(m, client.Answered{Token: snap.Token, Reply: &api.Reply{Ok: true, Window: "1h", Entries: numberedEntries(2, t0)}}, t0)
	assertBuildState(t, m, 0, true, -1)
	m, _ = Update(m, Tick{}, t0)
	assertBuildState(t, m, 1, false, 2)
	m, _ = Update(m, client.SummaryLine{Entries: numberedEntries(3, t0)}, t0.Add(100*time.Millisecond))
	m, _ = Update(m, Tick{}, t0.Add(400*time.Millisecond))
	assertBuildState(t, m, 1, true, -1)
	m, _ = Update(m, Tick{}, t0.Add(500*time.Millisecond))
	assertBuildState(t, m, 2, false, 3)
	m, _ = Update(m, Tick{}, t0.Add(1000*time.Millisecond))
	assertBuildState(t, m, 2, false, 3)
}

func TestNavOpenCloseParentAndCursorIdentity(t *testing.T) {
	t0 := feedTime()
	m := navModelWith(t, t0, Options{}, []api.Entry{
		ent("alpha", "1.1.1.1", "a.example", t0.Add(-1*time.Second)),
		ent("bravo", "2.2.2.2", "b.example", t0.Add(-2*time.Second)),
		{Program: "unknown", BytesSent: 50, LastSeen: t0.Add(-3 * time.Second).Format(time.RFC3339)},
	})
	m, _ = pressKey(m, "end", t0.Add(1*time.Second))
	m, _ = pressKey(m, "enter", t0.Add(2*time.Second))
	if len(m.rows) != 3 {
		t.Fatalf("unknown bucket opened: len=%d", len(m.rows))
	}
	m, _ = pressKey(m, "home", t0.Add(3*time.Second))
	for _, openKey := range []string{"enter", "right", "l"} {
		m1, _ := pressKey(m, openKey, t0.Add(4*time.Second))
		if len(m1.rows) != 4 || m1.rows[1].Title != clean.Const("a.example") {
			t.Fatalf("open key %q failed: titles=%v", openKey, rowTitles(m1.rows))
		}
	}
	checkHostLeafAndClose(t, m, t0)
	checkCursorSurvivesAndNearest(t, m, t0)
}

func checkHostLeafAndClose(t *testing.T, m Model, t0 time.Time) {
	t.Helper()
	m, _ = pressKey(m, "l", t0.Add(4*time.Second))
	m, _ = pressKey(m, "down", t0.Add(5*time.Second))
	m, _ = pressKey(m, "right", t0.Add(6*time.Second))
	if len(m.rows) != 5 || m.rows[2].Title != clean.Const("1.1.1.1:443 tcp") {
		t.Fatalf("host open failed: titles=%v", rowTitles(m.rows))
	}
	m, _ = pressKey(m, "down", t0.Add(7*time.Second))
	before := m.rebuilds
	m, _ = pressKey(m, "h", t0.Add(8*time.Second))
	if m.cursor != m.rows[1].ID || m.rebuilds != before {
		t.Fatalf("h on leaf: cursor=%q want %q, rebuilds=%d/%d", m.cursor, m.rows[1].ID, m.rebuilds, before)
	}
	m, _ = pressKey(m, "left", t0.Add(9*time.Second))
	if len(m.rows) != 4 || m.cursor != m.rows[1].ID || m.rows[1].Open {
		t.Fatalf("left on open host did not close: titles=%v cursor=%q", rowTitles(m.rows), m.cursor)
	}
	m, _ = pressKey(m, "h", t0.Add(10*time.Second))
	if m.cursor != m.rows[0].ID {
		t.Fatalf("h on closed host did not go to parent: cursor=%q want %q", m.cursor, m.rows[0].ID)
	}
}

func checkCursorSurvivesAndNearest(t *testing.T, m Model, t0 time.Time) {
	t.Helper()
	m, _ = pressKey(m, "down", t0.Add(11*time.Second))
	bravoID := m.rows[1].ID
	if m.cursor != bravoID || m.rows[1].Title != clean.Const("bravo") {
		t.Fatalf("cursor = %q (%q), want bravo", m.cursor, m.rows[1].Title)
	}
	m, _ = Update(m, client.SummaryLine{Entries: []api.Entry{ent("charlie", "3.3.3.3", "", t0)}}, t0.Add(12*time.Second))
	m, _ = Update(m, Tick{}, t0.Add(12*time.Second))
	if m.cursor != bravoID {
		t.Fatalf("cursor lost identity after insert: got %q, want %q", m.cursor, bravoID)
	}
	m = navModelWith(t, t0, Options{}, []api.Entry{
		ent("a", "1.1.1.1", "", t0.Add(-1*time.Second)),
		ent("b", "2.2.2.2", "", t0.Add(-2*time.Second)),
		ent("c", "3.3.3.3", "", t0.Add(-3*time.Second)),
	})
	m, _ = pressKey(m, "down", t0.Add(time.Second))
	m.store = (table.Store{}).Replace([]api.Entry{
		ent("a", "1.1.1.1", "", t0.Add(-1*time.Second)),
		ent("c", "3.3.3.3", "", t0.Add(-3*time.Second)),
	})
	m.dirty = true
	m, _ = Update(m, Tick{}, t0.Add(2*time.Second))
	if cur, ok := m.currentRow(); !ok || cur.Title != clean.Const("c") {
		t.Fatalf("nearest row after deletion = %q (ok=%v), want c", cur.Title, ok)
	}
}

func assertWindowStep(t *testing.T, m Model, key string, at time.Time, want string, wantSend bool) Model {
	t.Helper()
	next, fx := pressKey(m, key, at)
	if next.window != want {
		t.Fatalf("key %q: window=%q, want %q", key, next.window, want)
	}
	if !wantSend {
		if len(fx) != 0 {
			t.Fatalf("key %q: unexpected fx=%#v", key, fx)
		}
		return next
	}
	if s := mustSend(t, sendsOf(fx), "snapshot"); s.Req.Window != want {
		t.Fatalf("key %q: send window=%q, want %q", key, s.Req.Window, want)
	}
	return next
}

func TestWindowCycleAndDigits(t *testing.T) {
	t0 := feedTime()
	m, _, _, _ := upModel(t, t0, Options{Conf: conf.Config{Periods: []string{"15m", "1h", "24h"}, Since: "1h"}})
	m = assertWindowStep(t, m, "t", t0.Add(time.Second), "24h", true)
	m = assertWindowStep(t, m, "t", t0.Add(2*time.Second), "15m", true)
	m = assertWindowStep(t, m, "2", t0.Add(3*time.Second), "1h", true)
	m = assertWindowStep(t, m, "9", t0.Add(4*time.Second), "1h", false)
	m.graph = true
	m = assertWindowStep(t, m, "1", t0.Add(5*time.Second), "15m", true)
	m.up = false
	_ = assertWindowStep(t, m, "t", t0.Add(6*time.Second), "1h", false)
}

func TestSortActivityIntervalAndName(t *testing.T) {
	t0 := feedTime()
	m := navModelWith(t, t0, Options{}, []api.Entry{
		ent("Alpha", "1.1.1.1", "", t0.Add(-10*time.Second)),
		ent("bravo", "2.2.2.2", "", t0.Add(-1*time.Second)),
	})
	if !slices.Equal(rowTitles(m.rows), []string{"bravo", "Alpha"}) {
		t.Fatalf("initial activity order = %v", rowTitles(m.rows))
	}
	m, _ = Update(m, client.SummaryLine{Entries: []api.Entry{
		ent("Alpha", "1.1.1.1", "", t0.Add(2*time.Second)),
		ent("charlie", "3.3.3.3", "", t0.Add(-50*time.Second)),
	}}, t0.Add(2*time.Second))
	m, _ = Update(m, Tick{}, t0.Add(5*time.Second))
	if !slices.Equal(rowTitles(m.rows), []string{"charlie", "bravo", "Alpha"}) {
		t.Fatalf("before 10s interval: order = %v, want [charlie bravo Alpha]", rowTitles(m.rows))
	}
	m, _ = Update(m, Tick{}, t0.Add(10*time.Second))
	if !slices.Equal(rowTitles(m.rows), []string{"Alpha", "bravo", "charlie"}) {
		t.Fatalf("after 10s interval: order = %v, want [Alpha bravo charlie]", rowTitles(m.rows))
	}
	m, _ = pressKey(m, "s", t0.Add(11*time.Second))
	if m.notice != clean.Const("sorted by activity, re-sorted every 20s") {
		t.Fatalf("notice after s = %q", m.notice)
	}
	m, _ = pressKey(m, "S", t0.Add(12*time.Second))
	if m.notice != clean.Const("sorted by name") || !slices.Equal(rowTitles(m.rows), []string{"Alpha", "bravo", "charlie"}) {
		t.Fatalf("after S: notice=%q titles=%v", m.notice, rowTitles(m.rows))
	}
	m, _ = pressKey(m, "s", t0.Add(13*time.Second))
	if m.notice != clean.Const("sorted by activity, re-sorted every 20s") || m.view.Sort.ByName {
		t.Fatalf("s from name: notice=%q byName=%v", m.notice, m.view.Sort.ByName)
	}
}

func assertSearchClosed(t *testing.T, m Model, query string, titles ...string) {
	t.Helper()
	if m.search != nil || m.view.Search != query {
		t.Fatalf("search=%v view.Search=%q, want nil / %q", m.search, m.view.Search, query)
	}
	if len(titles) > 0 && !slices.Equal(rowTitles(m.rows), titles) {
		t.Fatalf("rows=%v, want %v", rowTitles(m.rows), titles)
	}
}

func TestSearchOpenTypeApplyClear(t *testing.T) {
	t0 := feedTime()
	m := navModelWith(t, t0, Options{}, []api.Entry{
		ent("curl", "1.1.1.1", "api.example", t0.Add(-1*time.Second)),
		{Program: "dig", Addr: "8.8.8.8", Name: "dns.google", Port: 53, Protocol: "udp", LastSeen: t0.Add(-2 * time.Second).Format(time.RFC3339)},
	})
	m, _ = pressKey(m, "/", t0.Add(1*time.Second))
	if m.search == nil {
		t.Fatalf("/ did not open search line")
	}
	for i, ch := range []string{"E", "X", "Z"} {
		at := t0.Add(time.Duration(2+i) * time.Second)
		m, _ = Update(m, Key{Name: ch, Text: ch, At: at}, at)
	}
	m, _ = pressKey(m, "backspace", t0.Add(5*time.Second))
	if *m.search != "EX" {
		t.Fatalf("search text = %q, want EX", *m.search)
	}
	m, _ = pressKey(m, "enter", t0.Add(6*time.Second))
	assertSearchClosed(t, m, "EX", "curl", "api.example", "1.1.1.1:443 tcp")
	m, _ = pressKey(m, "esc", t0.Add(7*time.Second))
	assertSearchClosed(t, m, "", "curl", "dig")
	m, _ = pressKey(m, "/", t0.Add(8*time.Second))
	m, _ = Update(m, Key{Name: "d", Text: "d", At: t0.Add(9 * time.Second)}, t0.Add(9*time.Second))
	m, _ = pressKey(m, "esc", t0.Add(10*time.Second))
	assertSearchClosed(t, m, "")
}
