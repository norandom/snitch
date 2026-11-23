// rule_test.go: the rule forms of the design's table, program against path, the note,
// Answerable, and the contract violations of RuleFor.
package ask

import (
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

var at = time.Date(2026, 11, 23, 14, 5, 59, 0, time.UTC)

func question(t *testing.T, name string) Question {
	t.Helper()
	ev := event("deny-default", "140.82.112.5")
	ev.Name = name
	q, ok := From(ev, All)
	if !ok {
		t.Fatal("no question")
	}
	return q
}

func TestRuleForForms(t *testing.T) {
	note := "snitch tray " + at.Local().Format("2006-01-02 15:04")
	base := api.Request{Type: "rule.add", Program: "firefox", Proto: "tcp", Port: 443, Note: note}
	cases := []struct {
		name        string
		answer      Answer
		to, verdict string
	}{
		{"api.github.com", Allow, "api.github.com", "allow"},
		{"", Allow, "140.82.112.5", "allow"},
		{"api.github.com", Block, "140.82.112.5", "deny"},
		{"", Block, "140.82.112.5", "deny"},
	}
	for _, c := range cases {
		want := base
		want.To, want.Verdict = c.to, c.verdict
		if got := RuleFor(question(t, c.name), c.answer, at); got != want {
			t.Fatalf("name %q answer %d: %+v, want %+v", c.name, c.answer, got, want)
		}
	}
}

func TestRuleForPath(t *testing.T) {
	ev := event("allow-monitor", "2001:db8::1")
	ev.Program, ev.Path, ev.Protocol, ev.Port = "unknown", "/opt/x/bin/x", "udp", 5353
	q, ok := From(ev, All)
	if !ok {
		t.Fatal("no question")
	}
	got := RuleFor(q, Allow, at)
	if got.Program != "" || got.Path != "/opt/x/bin/x" || got.Proto != "udp" || got.Port != 5353 ||
		got.To != "2001:db8::1" {
		t.Fatalf("%+v", got)
	}
}

func TestRuleForNote(t *testing.T) {
	zone := time.FixedZone("X", 90*60)
	orig := time.Local
	time.Local = zone
	t.Cleanup(func() { time.Local = orig })
	if got := RuleFor(question(t, ""), Block, at).Note; got != "snitch tray 2026-11-23 15:35" {
		t.Fatalf("note %q", got)
	}
}

func TestAnswerable(t *testing.T) {
	q := question(t, "")
	if !Answerable(q) {
		t.Fatal("declared program not answerable")
	}
	q.Event.Program = "unknown"
	if !Answerable(q) {
		t.Fatal("unknown program with a path not answerable")
	}
	q.Event.Path = ""
	if Answerable(q) {
		t.Fatal("unknown program without a path answerable")
	}
}

// Contracts: asking for the rule of an unanswerable question, or for an answer that is
// neither Allow nor Block, is a programming error of the tray.
func TestRuleForViolation(t *testing.T) {
	q := question(t, "")
	q.Event.Program, q.Event.Path = "unknown", ""
	contracttest.Panics(t, contract.Precondition, func() { RuleFor(q, Allow, at) })
	contracttest.Panics(t, contract.Precondition, func() { RuleFor(question(t, ""), Answer(7), at) })
}
