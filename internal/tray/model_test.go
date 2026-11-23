package tray

import (
	"testing"
	"time"

	"github.com/norandom/snitch/internal/ask"
)

// The six states have six distinct names; an unknown value still prints something.
func TestStateNames(t *testing.T) {
	seen := map[string]State{}
	for _, s := range []State{Gone, Kill, RulesError, Kept, Trial, Monitor} {
		name := s.String()
		if name == "" {
			t.Fatalf("state %d has no name", int(s))
		}
		if prev, dup := seen[name]; dup {
			t.Fatalf("states %d and %d share the name %q", int(prev), int(s), name)
		}
		seen[name] = s
	}
	if State(99).String() == "" {
		t.Fatal("an unknown state prints nothing")
	}
}

// NewModel keeps the options, falls back to the local zone, and starts with no facts, so the
// first view is the gone state until the daemon has said something (3.3).
func TestNewModelDefaults(t *testing.T) {
	m := NewModel(Options{Scope: ask.Enforce, Writer: true})
	for _, c := range append(startFacts(m), startWork(m)...) {
		if !c.ok {
			t.Errorf("start model: not %s: %+v", c.what, m)
		}
	}
}

// check is one named assertion over a model.
type check struct {
	what string
	ok   bool
}

// startFacts are the start model's options, facts and display.
func startFacts(m Model) []check {
	return []check{
		{"loc is time.Local", m.loc == time.Local},
		{"writer and scope kept", m.writer && m.opts.Scope == ask.Enforce},
		{"no facts, gone", m.facts == nil && m.gone && m.down == ""},
		{"not paused, no notification service", !m.paused && !m.canNotify && !m.canAct},
		{"no gone notice", m.goneSince.IsZero() && !m.goneNoticed && m.lastReason == ""},
		{"gone state shown", Render(m, time.Unix(0, 0)).State == Gone},
		{"zone of the options used", NewModel(Options{Loc: zone}).loc == zone},
	}
}

// startWork are the start model's questions, notices and requests: none.
func startWork(m Model) []check {
	_, open := m.queue.Open()
	return []check{
		{"no open note", m.openNote == 0 && m.openSince.IsZero() && !open},
		{"empty queue", m.queue.Stats() == (ask.Stats{})},
		{"nothing pending, no notices", len(m.pending) == 0 && len(m.notices) == 0},
		{"no notice being posted", len(m.posting) == 0},
		{"first token", m.nextToken == 0},
	}
}

// ids lists the row ids of a menu.
func ids(rows []Row) []RowID {
	out := make([]RowID, len(rows))
	for i, r := range rows {
		out[i] = r.ID
	}
	return out
}

// row finds a row by id.
func row(t *testing.T, rows []Row, id RowID) Row {
	t.Helper()
	for _, r := range rows {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("no row %d in %v", id, ids(rows))
	return Row{}
}
