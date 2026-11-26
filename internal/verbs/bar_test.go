package verbs

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
)

const (
	wantShieldDeny  = "\U000F0498"
	wantShieldAllow = "\U000F0499"
)

type barClassCase struct {
	name       string
	st         *api.Status
	down       string
	wantClass  string
	wantShield string
	wantTip    []string
}

func barClassCases(now time.Time) []barClassCase {
	deadline := now.Add(10 * time.Minute).Format(time.RFC3339)
	return []barClassCase{
		{name: "allow monitor", st: &api.Status{Mode: "monitor"}, wantClass: "allow", wantShield: wantShieldAllow, wantTip: []string{"monitor", "0"}},
		{name: "deny enforce trial", st: &api.Status{Mode: "enforce", Trial: deadline}, wantClass: "deny", wantShield: wantShieldDeny, wantTip: []string{"enforce", "12:10", "0"}},
		{name: "deny enforce kept", st: &api.Status{Mode: "enforce", Kept: true}, wantClass: "deny", wantShield: wantShieldDeny, wantTip: []string{"enforce", "kept", "0"}},
		{name: "down unreachable", down: "dial unix /run/snitch/api.sock: no such file or directory", wantClass: "down", wantShield: wantShieldAllow, wantTip: []string{"no such file or directory"}},
		{name: "down timeout stale heartbeat", down: "daemon does not answer: context deadline exceeded", wantClass: "down", wantShield: wantShieldAllow, wantTip: []string{"does not answer", "15 s"}},
		{name: "down foreign socket", down: "socket belongs to uid 1000, not root", wantClass: "down", wantShield: wantShieldAllow, wantTip: []string{"uid 1000", "not root"}},
		{name: "down kill switch", st: &api.Status{Mode: "enforce", Kill: true}, wantClass: "down", wantShield: wantShieldAllow, wantTip: []string{"kill switch", "enforce"}},
		{name: "down nil status without reason", wantClass: "down", wantShield: wantShieldAllow, wantTip: []string{"down"}},
	}
}

func TestBarClasses(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	for _, tc := range barClassCases(now) {
		t.Run(tc.name, func(t *testing.T) {
			got := Bar(tc.st, nil, now, tc.down)
			if got.Class != tc.wantClass {
				t.Fatalf("Class = %q, want %q", got.Class, tc.wantClass)
			}
			if got.Text != tc.wantShield {
				t.Fatalf("Text = %q, want %q", got.Text, tc.wantShield)
			}
			for _, sub := range tc.wantTip {
				if !strings.Contains(strings.ToLower(got.Tooltip), strings.ToLower(sub)) {
					t.Errorf("Tooltip %q missing %q", got.Tooltip, sub)
				}
			}
		})
	}
}

func TestBarDeniedCountLastHour(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	entries := []api.Entry{
		{Program: "curl", LastBlocked: now.Add(-10 * time.Minute).Format(time.RFC3339)},
		{Program: "wget", LastBlocked: now.Add(-59 * time.Minute).Format(time.RFC3339Nano)},
		{Program: "nc", LastBlocked: now.Add(-time.Hour).Format(time.RFC3339)},
		{Program: "old", LastBlocked: now.Add(-61 * time.Minute).Format(time.RFC3339)},
		{Program: "allowed", LastBlocked: ""},
		{Program: "bad", LastBlocked: "not-a-timestamp"},
	}

	allowLine := Bar(&api.Status{Mode: "monitor"}, entries, now, "")
	if allowLine.Text != wantShieldAllow+" 3" {
		t.Fatalf("allow Text = %q, want %q", allowLine.Text, wantShieldAllow+" 3")
	}
	if !strings.Contains(allowLine.Tooltip, "3") {
		t.Fatalf("allow Tooltip = %q, want count 3", allowLine.Tooltip)
	}

	denyLine := Bar(&api.Status{Mode: "enforce"}, entries, now, "")
	if denyLine.Text != wantShieldDeny+" 3" {
		t.Fatalf("deny Text = %q, want %q", denyLine.Text, wantShieldDeny+" 3")
	}

	killLine := Bar(&api.Status{Mode: "enforce", Kill: true}, entries, now, "")
	if killLine.Class != "down" || killLine.Text != wantShieldAllow+" 3" {
		t.Fatalf("kill Line = %#v", killLine)
	}
}

func TestBarJSON(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	line := Bar(&api.Status{Mode: "monitor"}, nil, now, "")
	b, err := json.Marshal(line)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	if strings.Contains(string(b), "\n") {
		t.Fatalf("JSON spans lines: %q", string(b))
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	for _, k := range []string{"text", "class", "tooltip"} {
		if _, ok := m[k]; !ok {
			t.Fatalf("JSON missing key %q: %s", k, string(b))
		}
	}
	if len(m) != 3 {
		t.Fatalf("unexpected extra JSON keys: %s", string(b))
	}
}

func TestBarSanitisesHostileStrings(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	evil := "\x1b[31mred\x1b[0m\nfake\tline\r\x7f\u009b\u202ebidi\u200b\ufeff\xff"

	lines := []Line{
		Bar(&api.Status{Mode: evil, Trial: evil, RulesError: evil}, nil, now, ""),
		Bar(nil, nil, now, evil),
	}
	for i, l := range lines {
		assertSafeField(t, i, "text", l.Text)
		assertSafeField(t, i, "class", l.Class)
		for j, tipLine := range strings.Split(l.Tooltip, "\n") {
			assertSafeField(t, i*100+j, "tooltip-line", tipLine)
		}
	}
}

func assertSafeField(t *testing.T, idx int, field, val string) {
	t.Helper()
	if !utf8.ValidString(val) {
		t.Fatalf("case %d %s invalid utf8: %q", idx, field, val)
	}
	if clean.Text(val) != clean.Text(string(clean.Text(val))) || string(clean.Text(val)) != val {
		t.Fatalf("case %d %s contains unsafe runes: %q", idx, field, val)
	}
}
