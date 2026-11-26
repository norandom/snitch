package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/conf"
)

func graphEntries(t0 time.Time) []api.Entry {
	ts := t0.Format(time.RFC3339)
	return []api.Entry{
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "api.example.com", Port: 443, Protocol: "tcp", AllowCount: 10, BytesSent: 6144, Rate: 512, LastSeen: ts, Verdict: "allow-rule"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.2", Name: "cdn.example.com", Port: 443, Protocol: "tcp", AllowCount: 5, BytesSent: 3072, Rate: 128, LastSeen: ts, Verdict: "allow-rule"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "9.9.9.9", Port: 53, Protocol: "udp", AllowCount: 2, BytesSent: 2048, LastSeen: ts, Verdict: "allow-monitor"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.3", Name: "metrics.example.com", Port: 443, Protocol: "tcp", AllowCount: 2, BytesSent: 1024, LastSeen: ts, Verdict: "allow-rule"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.4", Name: "auth.example.com", Port: 443, Protocol: "tcp", AllowCount: 1, BytesSent: 800, LastSeen: ts, Verdict: "allow-rule"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.5", Name: "tail1.example.com", Port: 443, Protocol: "tcp", AllowCount: 1, BytesSent: 512, LastSeen: ts, Verdict: "allow-rule"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.6", Name: "tail2.example.com", Port: 443, Protocol: "tcp", AllowCount: 1, BytesSent: 256, LastSeen: ts, Verdict: "allow-rule"},
		{Program: "dig", Path: "/usr/bin/dig", Addr: "8.8.8.8", Port: 53, Protocol: "udp", AllowCount: 3, BytesSent: 1024, LastSeen: ts, Verdict: "allow-rule"},
	}
}

func TestGraphGoldenFilledAndToggle(t *testing.T) {
	t0 := feedTime()
	opts := Options{
		Conf:    conf.Default(),
		Loc:     time.UTC,
		Socket:  clean.Const("/run/snitch/snitch.sock"),
		LogTail: []clean.Safe{clean.Const("2026-11-26 11:59:00  BLOCKED curl > 1.1.1.1:443 tcp")},
	}
	st := api.Status{Running: true, Mode: "monitor", Counting: true}
	m := overviewModel(t, t0, opts, st, nil, nil, graphEntries(t0))
	overBefore := flattenScreen(Render(m, t0))

	m, fx := pressKey(m, "e", t0.Add(time.Second))
	if !m.graph || len(fx) != 0 {
		t.Fatalf("after e: graph=%v fx=%#v, want graph=true fx=nil", m.graph, fx)
	}
	scr := Render(m, t0.Add(time.Second))
	got := flattenScreen(scr)
	assertGolden(t, "graph_filled", got)

	assertContainsAll(t, got, "connections active in last 1h", "bytes counted since first seen")
	assertBarStylesPresent(t, scr)

	m, fx2 := pressKey(m, "e", t0.Add(2*time.Second))
	if m.graph || len(fx2) != 0 {
		t.Fatalf("after second e: graph=%v fx=%#v, want graph=false fx=nil", m.graph, fx2)
	}
	if overAfter := flattenScreen(Render(m, t0.Add(2*time.Second))); overAfter != overBefore {
		t.Fatalf("second e did not restore overview:\n--- GOT ---\n%s\n--- WANT ---\n%s", overAfter, overBefore)
	}
}

func TestGraphGoldenEmptyAndCountingOff(t *testing.T) {
	t0 := feedTime()
	opts := Options{
		Conf:   conf.Default(),
		Loc:    time.UTC,
		Socket: clean.Const("/run/snitch/snitch.sock"),
		Egress: true,
	}
	m := overviewModel(t, t0, opts, api.Status{Running: true, Mode: "monitor", Counting: true}, nil, nil, []api.Entry{
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Port: 443, Protocol: "tcp", AllowCount: 1, LastSeen: t0.Format(time.RFC3339)},
	})
	if !m.graph {
		t.Fatalf("Options{Egress: true} did not start in graph")
	}
	assertGolden(t, "graph_empty", flattenScreen(Render(m, t0)))

	m, _ = Update(m, client.Facts{Status: api.Status{Running: true, Mode: "monitor", Counting: false}}, t0.Add(time.Second))
	assertGolden(t, "graph_counting_off", flattenScreen(Render(m, t0.Add(time.Second))))
}

func TestGraphRefreshEveryTwoSecondsAndWindow(t *testing.T) {
	t0 := feedTime()
	opts := Options{Conf: conf.Default(), Loc: time.UTC, Egress: true}
	st := api.Status{Running: true, Mode: "monitor", Counting: true}
	m := overviewModel(t, t0, opts, st, nil, nil, []api.Entry{
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "api.example.com", Port: 443, Protocol: "tcp", BytesSent: 1024, LastSeen: t0.Format(time.RFC3339)},
	})
	if got := flattenScreen(Render(m, t0)); !strings.Contains(got, "1K") {
		t.Fatalf("initial graph missing 1K:\n%s", got)
	}

	m, _ = Update(m, client.SummaryLine{Entries: []api.Entry{
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "api.example.com", Port: 443, Protocol: "tcp", BytesSent: 64 * 1024, LastSeen: t0.Add(time.Second).Format(time.RFC3339)},
	}}, t0.Add(time.Second))
	m, _ = Update(m, Tick{}, t0.Add(1500*time.Millisecond))
	if got := flattenScreen(Render(m, t0.Add(1500*time.Millisecond))); strings.Contains(got, "64K") {
		t.Fatalf("graph recomputed before 2s:\n%s", got)
	}

	m, _ = Update(m, Tick{}, t0.Add(2*time.Second))
	if got := flattenScreen(Render(m, t0.Add(2*time.Second))); !strings.Contains(got, "64K") {
		t.Fatalf("graph did not recompute at 2s:\n%s", got)
	}

	m, fx := pressKey(m, "2", t0.Add(3*time.Second))
	snap := mustSend(t, sendsOf(fx), "snapshot")
	if m.window != "30m" || snap.Req.Window != "30m" {
		t.Fatalf("window switch in graph failed: window=%q req=%+v", m.window, snap.Req)
	}
	m, _ = Update(m, client.Answered{Token: snap.Token, Reply: &api.Reply{
		Ok:      true,
		Window:  "30m",
		Entries: []api.Entry{{Program: "dig", Path: "/usr/bin/dig", Addr: "8.8.8.8", Port: 53, Protocol: "udp", BytesSent: 2048, LastSeen: t0.Add(3 * time.Second).Format(time.RFC3339)}},
	}}, t0.Add(3100*time.Millisecond))
	m, _ = Update(m, Tick{}, t0.Add(3200*time.Millisecond))
	gotWin := flattenScreen(Render(m, t0.Add(3200*time.Millisecond)))
	if !strings.Contains(gotWin, "last 30m") || !strings.Contains(gotWin, "dig") || strings.Contains(gotWin, "curl") {
		t.Fatalf("graph did not show 30m snapshot:\n%s", gotWin)
	}
}

func TestGraphKeysScopeAndXNoop(t *testing.T) {
	t0 := feedTime()
	opts := Options{Conf: conf.Default(), Loc: time.UTC, Egress: true}
	st := api.Status{Running: true, Mode: "monitor", Counting: true}
	m := overviewModel(t, t0, opts, st, nil, nil, graphEntries(t0))

	// Table keys (including x and space) must do nothing in the graph.
	tableKeys := []string{"x", "space", "up", "down", "pgup", "pgdown", "home", "end", "enter", "right", "l", "left", "h", "s", "S", "/", "esc"}
	for i, k := range tableKeys {
		at := t0.Add(time.Duration(i+1) * time.Second)
		next, fx := pressKey(m, k, at)
		if len(fx) != 0 || next.notice != "" || next.armed != "" || next.search != nil || next.cursor != m.cursor {
			t.Fatalf("table key %q acted in graph: fx=%#v notice=%q armed=%q search=%v", k, fx, next.notice, next.armed, next.search)
		}
	}

	// Trial keys work in the graph.
	mTrial, fxT := pressKey(m, "T", t0.Add(20*time.Second))
	if mTrial.confirm == nil || len(fxT) != 0 {
		t.Fatalf("T in graph did not open confirmation: confirm=%+v fx=%#v", mTrial.confirm, fxT)
	}
	_, fxY := pressKey(mTrial, "y", t0.Add(21*time.Second))
	mustSend(t, sendsOf(fxY), "trial")

	// Quit keys work in the graph.
	for i, qk := range []string{"q", "ctrl+c"} {
		_, fxQ := pressKey(m, qk, t0.Add(time.Duration(25+i)*time.Second))
		assertQuitEffect(t, qk, fxQ)
	}
}

func TestGraphSanitisesUntrustedStrings(t *testing.T) {
	t0 := feedTime()
	opts := Options{Conf: conf.Default(), Loc: time.UTC, Egress: true}
	st := api.Status{Running: true, Mode: "monitor", Counting: true}
	m := overviewModel(t, t0, opts, st, nil, nil, []api.Entry{
		{Program: "curl\x1b[31m", Addr: "1.1.1.1", Name: "bad\x1b]8;;x\x07.example", Port: 443, Protocol: "tcp", BytesSent: 4096, LastSeen: t0.Format(time.RFC3339)},
	})
	got := flattenScreen(Render(m, t0))
	if strings.Contains(got, "\x1b") || strings.Contains(got, "\x07") {
		t.Fatalf("escape leaked into graph screen: %q", got)
	}
}

func TestGraphTopTenAndWideResize(t *testing.T) {
	t0 := feedTime()
	ts := t0.Format(time.RFC3339)
	entries := make([]api.Entry, 0, 12)
	for i := 1; i <= 12; i++ {
		entries = append(entries, api.Entry{
			Program:   "prog" + string(rune('a'+i-1)),
			Addr:      "198.51.100.1",
			Port:      443,
			Protocol:  "tcp",
			BytesSent: uint64(i) * 1024,
			LastSeen:  ts,
		})
	}
	opts := Options{Conf: conf.Default(), Loc: time.UTC, Egress: true}
	st := api.Status{Running: true, Mode: "monitor", Counting: true}
	m := overviewModel(t, t0, opts, st, nil, nil, entries)
	m, _ = Update(m, Resize{W: 120, H: 30}, t0)
	got := flattenScreen(Render(m, t0))
	assertContainsAll(t, got, "78K sent by 12 programs", "progl", "progc")
	if strings.Contains(got, "proga") || strings.Contains(got, "progb") {
		t.Fatalf("graph showed more than top 10 programs:\n%s", got)
	}
}

func assertBarStylesPresent(t *testing.T, scr Screen) {
	t.Helper()
	seen := map[Style]bool{}
	for _, l := range scr.Lines {
		for _, sp := range l {
			seen[sp.Style] = true
		}
	}
	for _, want := range []Style{BarLow, BarMid, BarHigh} {
		if !seen[want] {
			t.Fatalf("missing bar style %v in rendered graph", want)
		}
	}
}
