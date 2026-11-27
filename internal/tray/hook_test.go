package tray

import (
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/client"
)

func hookInactiveStatus(pending, unsupported bool, reason string) api.Status {
	st := running()
	st.Hook = &api.HookStatus{
		State:       api.HookInactive,
		Pending:     pending,
		Unsupported: unsupported,
		Reason:      reason,
	}
	return st
}

// 6.2: Blind ranks directly after Gone and before Kill, has label "kernel hook inactive",
// and requires Attention.
func TestBlindRankLabelAndAttention(t *testing.T) {
	if !(Gone < Blind && Blind < Kill) {
		t.Fatalf("unexpected state order: Gone=%d Blind=%d Kill=%d", Gone, Blind, Kill)
	}
	if Blind.String() != "kernel hook inactive" {
		t.Fatalf("Blind.String() = %q", Blind.String())
	}
	if !Blind.Attention() {
		t.Fatal("Blind.Attention() = false, want true")
	}
}

// 6.1, 6.2, 6.3, 3.3: Blind wins over Kill, RulesError, Kept, Trial, and Monitor (even
// with kept enforce or open trial recorded), while Gone still beats Blind.
func TestBlindBeatsModesAndKeepsGoneFirst(t *testing.T) {
	st := hookInactiveStatus(false, false, "kernel hook inactive: test")
	st.Kill = true
	st.RulesError = "rules: line 1"
	st.Mode, st.Kept, st.Trial = "enforce", true, deadline

	v := Render(model(st, false), now)
	if v.State != Blind || !v.Attention {
		t.Fatalf("inactive with kept+trial+kill: state=%v attention=%v, want Blind/true", v.State, v.Attention)
	}
	if v.Title != "snitch: kernel hook inactive" || v.Menu[0].ID != RowHeader || v.Menu[0].Label != v.Title {
		t.Fatalf("title=%q header=%+v", v.Title, v.Menu[0])
	}
	lines := strings.Split(v.Tooltip, "\n")
	if lines[0] != "kernel hook inactive" || !strings.Contains(v.Tooltip, Kept.String()) {
		t.Fatalf("tooltip = %q", v.Tooltip)
	}
	if gv := Render(model(st, true), now); gv.State != Gone {
		t.Fatalf("gone with inactive hook: state=%v, want Gone", gv.State)
	}
}

// 6.1, 6.5: non-inactive hook states (nil, active, unknown) never trigger Blind.
func TestBlindOnlyWhenHookInactive(t *testing.T) {
	for _, h := range []*api.HookStatus{
		nil,
		{State: api.HookActive, Reason: "kernel hook active"},
		{State: api.HookUnknown, Reason: "kernel hook not checked"},
	} {
		st := running()
		st.Hook = h
		v := Render(model(st, false), now)
		if v.State != Monitor {
			t.Errorf("hook %+v: state=%v, want Monitor", h, v.State)
		}
		for _, r := range v.Menu {
			if r.ID == RowHook {
				t.Errorf("hook %+v: unexpected RowHook %+v", h, r)
			}
		}
	}
}

// 6.3, 1.7, 6.5: RowHook is shown only while Blind, distinguishes unsupported/pending/unconfigured,
// and stays disabled (no mode change or rule write).
func TestBlindMenuHookRow(t *testing.T) {
	cases := []struct {
		name        string
		pending     bool
		unsupported bool
		want        string
	}{
		{"unsupported overrides pending", true, true, "Kernel hook: kernel lacks BPF LSM"},
		{"unsupported", false, true, "Kernel hook: kernel lacks BPF LSM"},
		{"pending", true, false, "Kernel hook: reboot pending"},
		{"not configured", false, false, "Kernel hook: boot not configured"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st := hookInactiveStatus(tc.pending, tc.unsupported, "reason")
			m := model(st, false)
			r := row(t, Render(m, now).Menu, RowHook)
			if r.Label != tc.want {
				t.Errorf("RowHook.Label = %q, want %q", r.Label, tc.want)
			}
			checkRow(t, r)
			m2, fx := Update(m, MenuClick{Row: RowHook}, now)
			if m2.facts.Mode != "monitor" || len(fx) != 1 {
				t.Errorf("MenuClick RowHook had side effects: fx=%v", fx)
			}
		})
	}
	if rows := Render(model(hookInactiveStatus(false, false, "r"), true), now).Menu; len(rows) != 4 {
		t.Fatalf("gone menu should not include RowHook, got %d rows", len(rows))
	}
}

// 6.4: entering Blind notifies once (urgent, 30 s, sanitised reason); baseline, staying, and
// leaving emit no hook notice.
func TestBlindTransitionNote(t *testing.T) {
	_ = started(t, hookInactiveStatus(false, false, "at start")) // baseline must be silent

	m := started(t, running())
	in := hookInactiveStatus(false, false, "kernel hook inactive\x1b[31m\nmore")
	m, posts := step(t, m, client.Facts{Status: in}, now)
	n := one(t, "enter blind", posts)
	if n.Summary != "snitch: kernel hook inactive" || !n.Urgent || n.Timeout != 30*time.Second || len(n.Actions) != 0 {
		t.Fatalf("enter blind note = %+v", n)
	}
	if strings.ContainsAny(n.Body, "\x1b\n") || !strings.Contains(n.Body, "kernel hook inactive") {
		t.Fatalf("unsanitised or missing body: %q", n.Body)
	}

	// Staying inactive (even when pending flips) does not notify again.
	m, posts = step(t, m, client.Facts{Status: hookInactiveStatus(true, false, "reboot to activate")}, now)
	none(t, "stay blind", posts)

	// Leaving Blind emits no hook notice; re-entering with blank reason uses fallback text.
	act := running()
	act.Hook = &api.HookStatus{State: api.HookActive, Reason: "kernel hook active"}
	m, posts = step(t, m, client.Facts{Status: act}, now)
	none(t, "leave blind", posts)

	_, posts = step(t, m, client.Facts{Status: hookInactiveStatus(false, false, "  \x1b[0m ")}, now)
	if n2 := one(t, "re-enter blank", posts); strings.ContainsAny(n2.Body, "\x1b") || n2.Body == "" {
		t.Fatalf("blank reason fallback = %+v", n2)
	}
}
