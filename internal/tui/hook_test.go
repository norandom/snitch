package tui

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/conf"
)

func hookModel(t *testing.T, t0 time.Time, egress bool, st api.Status, entries []api.Entry) Model {
	t.Helper()
	opts := Options{
		Conf:   conf.Default(),
		Egress: egress,
		Loc:    time.UTC,
		Socket: clean.Const("/run/snitch/snitch.sock"),
	}
	var progs []api.ProgramView
	if len(entries) > 0 && entries[0].Program == "curl" {
		progs = []api.ProgramView{{Name: "curl", Paths: []string{"/usr/bin/curl"}, Resolved: true, Executables: 1}}
	}
	m := overviewModel(t, t0, opts, st, nil, progs, entries)
	m, _ = Update(m, Resize{W: 80, H: 20}, t0)
	return m
}

func TestHookGoldensAt80x20(t *testing.T) {
	t0 := feedTime()
	keptEntries := []api.Entry{{
		Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "api.example.com",
		Port: 443, Protocol: "tcp", AllowCount: 12, BytesSent: 4096, Rate: 512,
		LastSeen: t0.Format(time.RFC3339), LastAllowed: t0.Format(time.RFC3339), Verdict: "allow-rule",
	}}
	cases := []struct {
		name    string
		egress  bool
		status  api.Status
		entries []api.Entry
		wantTag bool
		wantMsg string
	}{
		{"blind", false, api.Status{Running: true, Mode: "monitor", Hook: &api.HookStatus{State: api.HookInactive}}, nil, true, "kernel hook inactive: connections not seen or blocked - boot not configured"},
		{"blind_pending", false, api.Status{Running: true, Mode: "monitor", Hook: &api.HookStatus{State: api.HookInactive, Pending: true}}, nil, true, "kernel hook inactive: connections not seen or blocked - reboot to activate"},
		{"blind_unsupported", false, api.Status{Running: true, Mode: "monitor", Hook: &api.HookStatus{State: api.HookInactive, Pending: true, Unsupported: true}}, nil, true, "kernel hook unavailable: kernel built without BPF LSM - snitch cannot work"},
		{"blind_kept", false, api.Status{Running: true, Mode: "enforce", Kept: true, Hook: &api.HookStatus{State: api.HookInactive}}, keptEntries, true, "kernel hook inactive: connections not seen or blocked - boot not configured"},
		{"blind_graph", true, api.Status{Running: true, Mode: "monitor", Counting: true, Hook: &api.HookStatus{State: api.HookInactive}}, nil, true, "kernel hook inactive: connections not seen or blocked - boot not configured"},
		{"hook_unknown", false, api.Status{Running: true, Mode: "monitor", Hook: &api.HookStatus{State: api.HookUnknown}}, nil, false, "kernel hook could not be checked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := hookModel(t, t0, tc.egress, tc.status, tc.entries)
			scr := Render(m, t0)
			assertGolden(t, tc.name, flattenScreen(scr))
			assertHookLayout80x20(t, scr, tc.egress, tc.wantTag, tc.wantMsg)
		})
	}
}

func assertHookLayout80x20(t *testing.T, scr Screen, egress, wantTag bool, wantMsg string) {
	t.Helper()
	if !egress && len(scr.Lines) != 20 {
		t.Fatalf("overview at 80x20 produced %d lines, want 20", len(scr.Lines))
	}
	assertHookHeaderTag(t, scr.Lines[0], wantTag)
	bottom := flattenLine(scr.Lines[len(scr.Lines)-2])
	if !strings.Contains(bottom, wantMsg) || utf8.RuneCountInString(bottom) > 80 {
		t.Fatalf("bottom line %q (len %d) does not fit %q in 80 cols", bottom, utf8.RuneCountInString(bottom), wantMsg)
	}
}

func assertHookHeaderTag(t *testing.T, line Line, wantTag bool) {
	t.Helper()
	head := flattenLine(line)
	if !wantTag {
		if strings.Contains(head, "NO KERNEL HOOK") {
			t.Fatalf("unexpected NO KERNEL HOOK tag in %q", head)
		}
		return
	}
	const prefix = " snitch | NO KERNEL HOOK |"
	if !strings.HasPrefix(head, prefix) || utf8.RuneCountInString(prefix) > 30 {
		t.Fatalf("header %q missing prefix %q within 30 cols", head, prefix)
	}
	if line[0].Style != Head || line[1].Style != Bad {
		t.Fatalf("header span styles = (%v, %v), want (Head, Bad)", line[0].Style, line[1].Style)
	}
}

func TestHookGraphAllStatesAndFixedWording(t *testing.T) {
	t0 := feedTime()
	hostile := "attacker \x1b[31m spoofed reason"
	cases := []struct {
		name    string
		hook    *api.HookStatus
		wantTag bool
		want    string
	}{
		{"pending", &api.HookStatus{State: api.HookInactive, Pending: true, Reason: hostile}, true, "reboot to activate"},
		{"unsupported", &api.HookStatus{State: api.HookInactive, Unsupported: true, Reason: hostile}, true, "kernel built without BPF LSM"},
		{"unknown", &api.HookStatus{State: api.HookUnknown, Reason: hostile}, false, "kernel hook could not be checked"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			m := hookModel(t, t0, true, api.Status{Running: true, Mode: "monitor", Counting: true, Hook: tc.hook}, nil)
			scr := Render(m, t0)
			flat := flattenScreen(scr)
			if strings.Contains(flat, "attacker") || strings.Contains(flat, "\x1b") {
				t.Fatalf("daemon Reason leaked into TUI screen:\n%s", flat)
			}
			assertHookLayout80x20(t, scr, true, tc.wantTag, tc.want)
		})
	}
}

func TestHookClearedByActiveFactsWithoutRestart(t *testing.T) {
	t0 := feedTime()
	for _, egress := range []bool{false, true} {
		m := hookModel(t, t0, egress, api.Status{
			Running: true,
			Mode:    "monitor",
			Hook:    &api.HookStatus{State: api.HookInactive, Pending: true},
		}, nil)
		before := flattenScreen(Render(m, t0))
		if !strings.Contains(before, "NO KERNEL HOOK") || !strings.Contains(before, "reboot to activate") {
			t.Fatalf("egress=%v missing initial warning:\n%s", egress, before)
		}
		m, _ = Update(m, client.Facts{Status: api.Status{
			Running: true,
			Mode:    "monitor",
			Hook:    &api.HookStatus{State: api.HookActive, Reason: "kernel hook active"},
		}}, t0.Add(time.Second))
		after := flattenScreen(Render(m, t0.Add(time.Second)))
		if strings.Contains(after, "NO KERNEL HOOK") || strings.Contains(after, "kernel hook") {
			t.Fatalf("egress=%v warning remained after active Facts:\n%s", egress, after)
		}
	}
}

func TestHookNilAndFutureStateSilent(t *testing.T) {
	t0 := feedTime()
	for _, hook := range []*api.HookStatus{nil, {State: api.HookActive}, {State: "future-state"}} {
		m := hookModel(t, t0, false, api.Status{Running: true, Mode: "monitor", Hook: hook}, nil)
		scr := Render(m, t0)
		flat := flattenScreen(scr)
		if strings.Contains(flat, "NO KERNEL HOOK") || strings.Contains(flat, "kernel hook") {
			t.Fatalf("unexpected hook text for %+v:\n%s", hook, flat)
		}
		if scr.Lines[0][0].Style != Head || !strings.HasPrefix(string(scr.Lines[0][0].Text), " snitch |") {
			t.Fatalf("unexpected header span 0: %+v", scr.Lines[0][0])
		}
	}
}

func TestHookKeepsKeysWorking(t *testing.T) {
	t0 := feedTime()
	m := hookModel(t, t0, false, api.Status{
		Running: true,
		Mode:    "monitor",
		Hook:    &api.HookStatus{State: api.HookInactive},
	}, baseOverviewEntries(t0))

	m, _ = pressKey(m, "down", t0.Add(time.Second))
	if m.cursor == "" {
		t.Fatalf("down key stopped working while hook inactive")
	}
	m, fx := pressKey(m, "2", t0.Add(2*time.Second))
	mustSend(t, sendsOf(fx), "snapshot")
	m, _ = pressKey(m, "e", t0.Add(3*time.Second))
	if !m.graph {
		t.Fatalf("e key did not toggle to graph while hook inactive")
	}
	m, _ = pressKey(m, "e", t0.Add(4*time.Second))
	if m.graph {
		t.Fatalf("e key did not toggle back from graph while hook inactive")
	}
	_, fxQ := pressKey(m, "q", t0.Add(5*time.Second))
	assertQuitEffect(t, "q", fxQ)
}

func TestHookPromptAndNoticePriority(t *testing.T) {
	t0 := feedTime()
	m := hookModel(t, t0, false, api.Status{
		Running: true,
		Mode:    "monitor",
		Hook:    &api.HookStatus{State: api.HookInactive},
	}, baseOverviewEntries(t0))

	m, _ = pressKey(m, "/", t0.Add(time.Second))
	if s := flattenLine(Render(m, t0.Add(time.Second)).Lines[18]); !strings.Contains(s, "enter: apply") {
		t.Fatalf("search prompt overwritten by hook line: %q", s)
	}
	m, _ = pressKey(m, "esc", t0.Add(2*time.Second))
	if s := flattenLine(Render(m, t0.Add(2*time.Second)).Lines[18]); !strings.Contains(s, "boot not configured") {
		t.Fatalf("hook line did not return after closing search: %q", s)
	}
	m, _ = pressKey(m, "T", t0.Add(3*time.Second))
	if s := flattenLine(Render(m, t0.Add(3*time.Second)).Lines[18]); !strings.Contains(s, "Start enforce trial") {
		t.Fatalf("confirm prompt overwritten by hook line: %q", s)
	}
	m, _ = pressKey(m, "esc", t0.Add(4*time.Second))
	if s := flattenLine(Render(m, t0.Add(4*time.Second)).Lines[18]); !strings.Contains(s, "trial cancelled") {
		t.Fatalf("notice overwritten by hook line: %q", s)
	}
	m.notice = ""
	if s := flattenLine(Render(m, t0.Add(4*time.Second)).Lines[18]); !strings.Contains(s, "boot not configured") {
		t.Fatalf("hook line did not return after clearing notice: %q", s)
	}
}
