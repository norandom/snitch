package verbs

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
)

type barHookInactiveCase struct {
	name      string
	hook      *api.HookStatus
	wantFirst string
}

func barHookInactiveCases() []barHookInactiveCase {
	return []barHookInactiveCase{
		{
			name:      "not configured",
			hook:      &api.HookStatus{State: api.HookInactive, Reason: "kernel hook inactive: bpf is not in the kernel's LSM list and the next boot is not configured for it; connections are neither seen nor blocked"},
			wantFirst: "kernel hook inactive: bpf is not in the kernel's LSM list and the next boot is not configured for it; connections are neither seen nor blocked",
		},
		{
			name:      "pending",
			hook:      &api.HookStatus{State: api.HookInactive, Pending: true, Reason: "kernel hook inactive: reboot to activate it; until then connections are neither seen nor blocked"},
			wantFirst: "kernel hook inactive: reboot to activate it; until then connections are neither seen nor blocked",
		},
		{
			name:      "unsupported",
			hook:      &api.HookStatus{State: api.HookInactive, Unsupported: true, Reason: "kernel hook unavailable: this kernel is built without BPF LSM support, so no reboot can activate it; connections are neither seen nor blocked"},
			wantFirst: "kernel hook unavailable: this kernel is built without BPF LSM support, so no reboot can activate it; connections are neither seen nor blocked",
		},
		{
			name:      "empty reason fallback",
			hook:      &api.HookStatus{State: api.HookInactive, Reason: "   "},
			wantFirst: "kernel hook inactive: connections are neither seen nor blocked",
		},
	}
}

func TestBarHookInactiveStates(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	for _, tc := range barHookInactiveCases() {
		t.Run(tc.name, func(t *testing.T) {
			line := Bar(&api.Status{Mode: "monitor", Hook: tc.hook}, nil, now, "")
			if line.Class != "down" {
				t.Fatalf("Class = %q, want %q", line.Class, "down")
			}
			if line.Text != wantShieldAllow {
				t.Fatalf("Text = %q, want %q", line.Text, wantShieldAllow)
			}
			tipLines := strings.Split(line.Tooltip, "\n")
			if tipLines[0] != tc.wantFirst {
				t.Fatalf("first tooltip line = %q, want %q", tipLines[0], tc.wantFirst)
			}
			if len(tipLines) != 3 || tipLines[1] != "mode: monitor (allow by default)" || tipLines[2] != "denied in the last hour: 0" {
				t.Fatalf("unexpected tooltip lines: %#v", tipLines)
			}
			b, err := json.Marshal(line)
			if err != nil || strings.Contains(string(b), "\n") {
				t.Fatalf("JSON marshal err=%v body=%q", err, string(b))
			}
		})
	}
}

func TestBarHookInactiveOverridesEnforceAndKept(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	reason := "kernel hook inactive: reboot to activate it; until then connections are neither seen nor blocked"
	hook := &api.HookStatus{State: api.HookInactive, Pending: true, Reason: reason}
	cases := []struct {
		name     string
		st       *api.Status
		wantMode string
	}{
		{
			name:     "kept enforce",
			st:       &api.Status{Mode: "enforce", Kept: true, Hook: hook},
			wantMode: "mode: enforce (deny by default, kept)",
		},
		{
			name:     "trial enforce",
			st:       &api.Status{Mode: "enforce", Trial: now.Add(5 * time.Minute).Format(time.RFC3339), Hook: hook},
			wantMode: "mode: enforce (trial until 12:05 (5m0s left))",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			line := Bar(tc.st, nil, now, "")
			if line.Class != "down" {
				t.Fatalf("Class = %q, want %q", line.Class, "down")
			}
			if line.Text != wantShieldAllow {
				t.Fatalf("Text = %q, want %q", line.Text, wantShieldAllow)
			}
			tipLines := strings.Split(line.Tooltip, "\n")
			if len(tipLines) != 3 || tipLines[0] != reason || tipLines[1] != tc.wantMode || tipLines[2] != "denied in the last hour: 0" {
				t.Fatalf("unexpected tooltip lines: %#v", tipLines)
			}
		})
	}
}

func TestBarHookActiveUnknownAndNilMatchBaseline(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	entries := []api.Entry{{Program: "curl", LastBlocked: now.Add(-5 * time.Minute).Format(time.RFC3339)}}
	hooks := []*api.HookStatus{
		nil,
		{State: api.HookActive, Reason: "kernel hook active"},
		{State: api.HookUnknown, Reason: "kernel hook not checked: the kernel's LSM list could not be read"},
	}

	for _, mode := range []struct {
		name string
		kept bool
		mode string
	}{
		{name: "monitor", mode: "monitor"},
		{name: "enforce kept", mode: "enforce", kept: true},
	} {
		baseline := Bar(&api.Status{Mode: mode.mode, Kept: mode.kept}, entries, now, "")
		for _, h := range hooks {
			got := Bar(&api.Status{Mode: mode.mode, Kept: mode.kept, Hook: h}, entries, now, "")
			if got != baseline {
				t.Fatalf("%s hook=%#v: got %#v, want baseline %#v", mode.name, h, got, baseline)
			}
		}
	}
}

func TestBarHookSanitisesHostileReason(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	evil := "\x1b[31mred\x1b[0m\nfake\tline\r\x7f\u009b\u202ebidi\u200b\ufeff\xff"
	line := Bar(&api.Status{
		Mode: "monitor",
		Hook: &api.HookStatus{State: api.HookInactive, Reason: evil},
	}, nil, now, "")

	if line.Class != "down" {
		t.Fatalf("Class = %q, want %q", line.Class, "down")
	}
	assertSafeField(t, 0, "text", line.Text)
	assertSafeField(t, 0, "class", line.Class)
	tipLines := strings.Split(line.Tooltip, "\n")
	if len(tipLines) != 3 {
		t.Fatalf("expected 3 tooltip lines (newline in reason must be sanitised), got %d: %#v", len(tipLines), tipLines)
	}
	if tipLines[0] != string(clean.Text(evil)) {
		t.Fatalf("first tooltip line = %q, want %q", tipLines[0], string(clean.Text(evil)))
	}
	for j, tipLine := range tipLines {
		assertSafeField(t, j, "tooltip-line", tipLine)
	}
}
