package trial

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// Fixed instants: a trial started at t0, due at t0+10m, on boot "b1".
var (
	t0   = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	tEnd = t0.Add(10 * time.Minute)
	own  = &Deadline{Start: t0, End: tEnd, Boot: "b1"}
	// far: End still ahead of every "now" below, so only the Start cap can end it.
	far = &Deadline{Start: t0, End: t0.Add(1000 * time.Hour), Boot: "b1"}
)

// decideCase is one row of the design's decision table, read at now on boot "b1".
type decideCase struct {
	name     string
	now      time.Time
	st       State
	learning bool
	want     Decision
}

// decideTable: every row of the design's decision table, plus the time edges of each bound.
var decideTable = []decideCase{
	{"learning ignores kept", t0, State{Kept: true}, true,
		Decision{Monitor, "learning: trial/kept files ignored", false}},
	{"learning ignores an active trial", t0.Add(time.Minute), State{Trial: own}, true,
		Decision{Monitor, "learning: trial/kept files ignored", false}},
	{"learning ignores a malformed trial", t0, State{Problems: []string{"bad"}}, true,
		Decision{Monitor, "learning: trial/kept files ignored", false}},
	{"kept without a trial", t0, State{Kept: true}, false,
		Decision{Enforce, "enforce kept", false}},
	{"kept supersedes a trial", t0.Add(time.Minute), State{Kept: true, Trial: own}, false,
		Decision{Enforce, "enforce kept", true}},
	{"kept with a malformed trial", t0, State{Kept: true, Problems: []string{"bad"}}, false,
		Decision{Enforce, "enforce kept; trial file unreadable: bad, removed", true}},
	{"no trial", t0, State{}, false,
		Decision{Monitor, "no trial", false}},
	{"foreign boot, deadline ahead", t0.Add(time.Minute), State{Trial: &Deadline{Start: t0, End: tEnd, Boot: "b0"}}, false,
		Decision{Monitor, "trial ended at boot", true}},
	{"foreign boot, deadline passed", tEnd.Add(time.Hour), State{Trial: &Deadline{Start: t0, End: tEnd, Boot: "b0"}}, false,
		Decision{Monitor, "trial ended at boot", true}},
	{"deadline passed", tEnd.Add(time.Second), State{Trial: own}, false,
		Decision{Monitor, "trial ended at its deadline", true}},
	{"deadline reached exactly", tEnd, State{Trial: own}, false,
		Decision{Monitor, "trial ended at its deadline", true}},
	{"clock jump: older than the maximum", t0.Add(MaxTrial + time.Second), State{Trial: far}, false,
		Decision{Monitor, "trial ended at its deadline", true}},
	{"clock jump: exactly the maximum is still active", t0.Add(MaxTrial), State{Trial: far}, false,
		Decision{Enforce, "trial until " + far.End.Format(time.RFC3339), false}},
	{"active", t0.Add(time.Minute), State{Trial: own}, false,
		Decision{Enforce, "trial until 2026-10-10T12:10:00Z", false}},
	{"active one second before the end", tEnd.Add(-time.Second), State{Trial: own}, false,
		Decision{Enforce, "trial until 2026-10-10T12:10:00Z", false}},
	{"malformed", t0, State{Problems: []string{"trial: line 2: no end="}}, false,
		Decision{Monitor, "trial file unreadable: trial: line 2: no end=, removed", true}},
	{"malformed, several problems", t0, State{Problems: []string{"a", "b"}}, false,
		Decision{Monitor, "trial file unreadable: a; b, removed", true}},
}

func TestDecideTable(t *testing.T) {
	for _, c := range decideTable {
		t.Run(c.name, func(t *testing.T) {
			got := Decide(c.now, "b1", c.st, c.learning)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("\n got %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestDecideDoesNotChangeTheState(t *testing.T) {
	st := State{Trial: &Deadline{Start: t0, End: tEnd, Boot: "b0"}, Problems: []string{"x"}}
	before := State{Trial: &Deadline{Start: t0, End: tEnd, Boot: "b0"}, Problems: []string{"x"}}
	Decide(t0, "b1", st, false)
	if !reflect.DeepEqual(st, before) {
		t.Fatalf("state changed: %+v", st)
	}
}

func TestDecideModeValuesAreTheControlMapValues(t *testing.T) {
	if Monitor != 0 || Enforce != 1 {
		t.Fatalf("Monitor=%d Enforce=%d", Monitor, Enforce)
	}
}

func TestBoundsEdges(t *testing.T) {
	cases := []struct {
		d  time.Duration
		ok bool
	}{
		{59 * time.Second, false},
		{time.Minute, true},
		{DefaultTrial, true},
		{60 * time.Minute, true},
		{61 * time.Minute, false},
		{0, false},
		{-time.Minute, false},
	}
	for _, c := range cases {
		err := Bounds(c.d)
		if (err == nil) != c.ok {
			t.Errorf("Bounds(%v) = %v, want ok=%v", c.d, err, c.ok)
		}
		if err != nil && !strings.Contains(err.Error(), c.d.String()) {
			t.Errorf("Bounds(%v): error %q does not name the duration", c.d, err)
		}
	}
}

func TestBoundsConstants(t *testing.T) {
	got := []time.Duration{MinTrial, DefaultTrial, MaxTrial}
	want := []time.Duration{time.Minute, 10 * time.Minute, time.Hour}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v want %v", got, want)
	}
}

func TestBootIDReadsTheKernelFileTrimmed(t *testing.T) {
	var asked string
	read := func(p string) ([]byte, error) {
		asked = p
		return []byte(" 0b2a1d9e-5b1c-4e9e-9d0b-1f3c3b4b7a21\n"), nil
	}
	id, err := BootID(read)
	if err != nil || id != "0b2a1d9e-5b1c-4e9e-9d0b-1f3c3b4b7a21" {
		t.Fatalf("got %q, %v", id, err)
	}
	if asked != "/proc/sys/kernel/random/boot_id" {
		t.Fatalf("read %q", asked)
	}
}

func TestBootIDErrors(t *testing.T) {
	boom := errors.New("boom")
	cases := []struct {
		name string
		read func(string) ([]byte, error)
		want error // nil: any non-nil error
	}{
		{"read error passes through", func(string) ([]byte, error) { return nil, boom }, boom},
		{"empty file", func(string) ([]byte, error) { return []byte("\n"), nil }, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			id, err := BootID(c.read)
			if err == nil || id != "" || (c.want != nil && !errors.Is(err, c.want)) {
				t.Fatalf("got %q, %v", id, err)
			}
		})
	}
}

// Every documented contract has a test that trips it.

func TestContractDecideNeedsATime(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { Decide(time.Time{}, "b1", State{}, false) })
}

func TestContractDecideNeedsABootID(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { Decide(t0, "", State{}, false) })
}

func TestContractDecideSpentOnlyWithATrialOrAProblem(t *testing.T) {
	contracttest.Panics(t, contract.Postcondition, func() { spent(State{}, Decision{ClearTrial: true}) })
	if d := spent(State{Trial: own}, Decision{ClearTrial: true}); !d.ClearTrial {
		t.Fatal("a spent trial was dropped")
	}
}
