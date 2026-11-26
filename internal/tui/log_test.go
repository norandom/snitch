package tui

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
)

func TestLogTailInitialization(t *testing.T) {
	tail := []clean.Safe{
		clean.Const("2026-11-26 11:55:00  mode monitor"),
		clean.Const("2026-11-26 11:56:00  denied curl > 1.1.1.1:443"),
		clean.Const("2026-11-26 11:57:00  BLOCKED curl > 1.1.1.1:443 tcp"),
		clean.Const("2026-11-26 11:58:00  UNBLOCKED curl > 1.1.1.1:443 tcp"),
		clean.Const("2026-11-26 11:59:00  mode trial until 12:10"),
	}
	want := slices.Clone(tail)
	m := New(Options{LogTail: tail})
	tail[0] = clean.Const("mutated")

	if !slices.Equal(m.log, want) {
		t.Fatalf("log tail = %v, want %v", m.log, want)
	}
}

func TestLogDeniedVerdictsAndFormatting(t *testing.T) {
	t0 := feedTime()
	m := New(Options{Loc: time.UTC})
	for _, v := range []string{"allow-local", "allow-rule", "allow-monitor", "allow-stale", "allow-kill"} {
		var fx []Effect
		m, fx = Update(m, client.EventLine{Event: api.Event{Program: "curl", Addr: "1.1.1.1", Port: 443, Verdict: v}}, t0)
		if len(m.log) != 0 || len(appendsOf(fx)) != 0 {
			t.Fatalf("verdict %q logged unexpectedly: log=%v fx=%#v", v, m.log, fx)
		}
	}

	cases := []struct {
		ev   api.Event
		want clean.Safe
	}{
		{
			ev:   api.Event{Program: "curl", Addr: "1.1.1.1", Name: "api.example.com", Port: 443, Protocol: "tcp", Verdict: "deny-rule"},
			want: clean.Const("denied curl > api.example.com:443"),
		},
		{
			ev:   api.Event{Program: "curl\x1b[31m", Addr: "9.9.9.9", Name: "bücher.example", Port: 443, Protocol: "tcp", Verdict: "deny-default"},
			want: clean.Const("denied curl·[31m > xn--bcher-kva.example:443"),
		},
		{
			ev:   api.Event{Program: "unknown", Path: "/usr/bin/dig", Addr: "2620:fe::fe", Port: 53, Protocol: "udp", Verdict: "deny-rule"},
			want: clean.Const("denied /usr/bin/dig > [2620:fe::fe]:53"),
		},
	}
	for i, tc := range cases {
		at := t0.Add(time.Duration(i+1) * time.Second)
		var fx []Effect
		m, fx = Update(m, client.EventLine{Event: tc.ev}, at)
		assertAppendedLog(t, m, fx, i+1, tc.want)
	}
}

func TestLogDeniedThrottle3sAnd11s(t *testing.T) {
	t0 := feedTime()
	ev := client.EventLine{Event: api.Event{
		Program: "curl", Addr: "1.1.1.1", Port: 443, Protocol: "tcp", Verdict: "deny-default",
	}}
	m1, fx1 := Update(New(Options{Loc: time.UTC}), ev, t0)
	assertAppendedLog(t, m1, fx1, 1, clean.Const("denied curl > 1.1.1.1:443"))

	snap := m1
	m2, fx2 := Update(m1, ev, t0.Add(3*time.Second))
	if len(m2.log) != 1 || len(appendsOf(fx2)) != 0 {
		t.Fatalf("denial at 3s should be throttled: log=%v fx=%#v", m2.log, fx2)
	}

	other := client.EventLine{Event: api.Event{
		Program: "curl", Addr: "8.8.8.8", Port: 443, Protocol: "tcp", Verdict: "deny-default",
	}}
	m3, fx3 := Update(m2, other, t0.Add(4*time.Second))
	assertAppendedLog(t, m3, fx3, 2, clean.Const("denied curl > 8.8.8.8:443"))

	m4, fx4 := Update(m1, ev, t0.Add(11*time.Second))
	assertAppendedLog(t, m4, fx4, 2, clean.Const("denied curl > 1.1.1.1:443"))
	if len(snap.log) != 1 || len(snap.denied) != 1 {
		t.Fatalf("prior Model mutated: log=%v denied=%v", snap.log, snap.denied)
	}
}

func TestLogModeChangeReason(t *testing.T) {
	t0 := feedTime()
	m, _, _, _ := upModel(t, t0, Options{Loc: time.UTC})
	m, _ = Update(m, client.Facts{Status: api.Status{Running: true, Mode: "monitor"}}, t0)

	m, fxReload := Update(m, client.StateLine{State: api.State{
		Mode: "monitor", RulesChanged: true, Reason: "rules reloaded",
	}}, t0.Add(time.Second))
	if len(m.log) != 0 || len(appendsOf(fxReload)) != 0 {
		t.Fatalf("rules reload logged as mode change: log=%v fx=%#v", m.log, fxReload)
	}

	m, fxEnforce := Update(m, client.StateLine{State: api.State{
		Mode: "enforce", Trial: "2026-11-26T12:10:00Z", Reason: "trial until 2026-11-26T12:10:00Z\x1b[31m",
	}}, t0.Add(2*time.Second))
	assertAppendedLog(t, m, fxEnforce, 1, clean.Const("mode trial until 2026-11-26T12:10:00Z·[31m"))

	m, fxSame := Update(m, client.StateLine{State: api.State{
		Mode: "enforce", Reason: "unchanged",
	}}, t0.Add(3*time.Second))
	if len(m.log) != 1 || len(appendsOf(fxSame)) != 0 {
		t.Fatalf("unchanged mode logged: log=%v fx=%#v", m.log, fxSame)
	}

	m, fxMonitor := Update(m, client.StateLine{State: api.State{
		Mode: "monitor", Reason: "trial ended at its deadline",
	}}, t0.Add(4*time.Second))
	assertAppendedLog(t, m, fxMonitor, 2, clean.Const("mode trial ended at its deadline"))
}

func TestLogKeepAndUnkeepWithinEnforce(t *testing.T) {
	t0 := feedTime()
	m, _, _, _ := upModel(t, t0, Options{Loc: time.UTC})
	m, _ = Update(m, client.Facts{Status: api.Status{
		Running: true, Mode: "enforce", Trial: "2026-11-26T12:10:00Z", Kept: false,
	}}, t0)

	m, fxKept := Update(m, client.StateLine{State: api.State{
		Mode: "enforce", Kept: true, Reason: "enforce kept",
	}}, t0.Add(time.Second))
	assertAppendedLog(t, m, fxKept, 1, clean.Const("mode enforce kept"))

	m, fxSameKept := Update(m, client.StateLine{State: api.State{
		Mode: "enforce", Kept: true, Reason: "enforce kept",
	}}, t0.Add(2*time.Second))
	if len(m.log) != 1 || len(appendsOf(fxSameKept)) != 0 {
		t.Fatalf("unchanged kept state logged: log=%v fx=%#v", m.log, fxSameKept)
	}

	m, fxUnkept := Update(m, client.StateLine{State: api.State{
		Mode: "enforce", Trial: "2026-11-26T12:10:00Z", Kept: false, Reason: "enforce unkept: file removed",
	}}, t0.Add(3*time.Second))
	assertAppendedLog(t, m, fxUnkept, 2, clean.Const("mode enforce unkept: file removed"))

	m, fxSameUnkept := Update(m, client.StateLine{State: api.State{
		Mode: "enforce", Trial: "2026-11-26T12:10:00Z", Kept: false, Reason: "unchanged",
	}}, t0.Add(4*time.Second))
	if len(m.log) != 2 || len(appendsOf(fxSameUnkept)) != 0 {
		t.Fatalf("unchanged unkept state logged: log=%v fx=%#v", m.log, fxSameUnkept)
	}
}

func TestLogBrokenAtStartup(t *testing.T) {
	t0 := feedTime()
	m := New(Options{LogBroken: true, Loc: time.UTC})
	m, fx := Update(m, client.EventLine{Event: api.Event{
		Program: "curl", Addr: "1.1.1.1", Port: 443, Verdict: "deny-rule",
	}}, t0)
	if len(m.log) != 1 || len(appendsOf(fx)) != 0 {
		t.Fatalf("LogBroken startup: log=%v fx=%#v", m.log, fx)
	}
	m, fxFail := Update(m, LogFailed{Err: clean.Const("read-only")}, t0.Add(time.Second))
	if len(m.log) != 1 || len(appendsOf(fxFail)) != 0 {
		t.Fatalf("LogFailed after LogBroken added extra line: log=%v fx=%#v", m.log, fxFail)
	}
}

func TestLogFailedShownOnceAndContinues(t *testing.T) {
	t0 := feedTime()
	m0 := New(Options{Loc: time.UTC})
	m1, fx1 := Update(m0, LogFailed{Err: clean.Const("disk full")}, t0)
	if !m1.logBroken || len(m1.log) != 1 || !strings.Contains(string(m1.log[0]), "disk full") {
		t.Fatalf("1st LogFailed: broken=%v log=%v", m1.logBroken, m1.log)
	}
	assertNoAppends(t, fx1, "1st LogFailed")

	m2, fx2 := Update(m1, LogFailed{Err: clean.Const("disk full again")}, t0.Add(time.Second))
	if len(m2.log) != 1 {
		t.Fatalf("2nd LogFailed not suppressed: log=%v", m2.log)
	}
	assertNoAppends(t, fx2, "2nd LogFailed")

	m3, fx3 := Update(m2, client.SummaryLine{Entries: []api.Entry{{Program: "curl", Addr: "1.1.1.1", Port: 443, Protocol: "tcp"}}}, t0.Add(2*time.Second))
	m4, fx4 := Update(m3, client.EventLine{Event: api.Event{Program: "curl", Addr: "1.1.1.1", Port: 443, Verdict: "deny-default"}}, t0.Add(3*time.Second))
	if m4.store.Len() != 1 || len(m4.log) != 2 || len(m0.log) != 0 || len(m1.log) != 1 {
		t.Fatalf("session/immutability after LogFailed: store=%d m4.log=%v m1.log=%v", m4.store.Len(), m4.log, m1.log)
	}
	assertNoAppends(t, fx3, "SummaryLine after LogFailed")
	assertNoAppends(t, fx4, "EventLine after LogFailed")
}

func assertNoAppends(t *testing.T, fx []Effect, what string) {
	t.Helper()
	if apps := appendsOf(fx); len(apps) != 0 {
		t.Fatalf("%s emitted appends: %#v", what, apps)
	}
}

func assertAppendedLog(t *testing.T, m Model, fx []Effect, wantLen int, wantLine clean.Safe) {
	t.Helper()
	apps := appendsOf(fx)
	if len(apps) != 1 || apps[0].Line != wantLine {
		t.Fatalf("appends = %#v, want [%q]", apps, wantLine)
	}
	if len(m.log) != wantLen || !strings.HasSuffix(string(m.log[wantLen-1]), "  "+string(wantLine)) {
		t.Fatalf("log = %v (len %d, want %d), want suffix %q", m.log, len(m.log), wantLen, wantLine)
	}
}
