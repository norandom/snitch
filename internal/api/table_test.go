package api

import (
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// clock is the fake clock every table test drives; t0 is minute- and hour-aligned.
type clock struct{ t time.Time }

var t0 = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)

func newClock() *clock                   { return &clock{t: t0} }
func (c *clock) now() time.Time          { return c.t }
func (c *clock) advance(d time.Duration) { c.t = c.t.Add(d) }
func newTable(c *clock) *Table           { return NewTable(c.now) }
func ev(prog, addr string, port uint16, verdict string) Event {
	return Event{Program: prog, Path: "/usr/bin/" + prog, Addr: addr, Port: port, Protocol: "tcp", Verdict: verdict}
}
func cookieEv(e Event, cookie uint64) Event { e.Cookie = cookie; return e }

// checkCookies is the whole-map form of the cookie invariant, for tests after removals.
func checkCookies(t *testing.T, tb *Table) {
	t.Helper()
	for c, b := range tb.cookies {
		if _, ok := tb.m[b.key]; !ok {
			t.Fatalf("cookie %d maps to an absent entry %+v", c, b.key)
		}
	}
}

// Req 2.2 and design "Dedupe": fresh on a new key, after the window, or on a changed verdict.
func TestTableDedupe(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	e := ev("curl", "1.1.1.1", 443, "allow-rule")
	if !tb.Observe(e) {
		t.Fatal("first event must be fresh")
	}
	c.advance(5 * time.Second)
	if tb.Observe(e) {
		t.Fatal("same key within the window is a duplicate")
	}
	c.advance(tb.Dedupe - 5*time.Second - time.Nanosecond) // one ns short of the window
	if tb.Observe(e) {
		t.Fatal("one ns inside the window is still a duplicate")
	}
	c.advance(time.Nanosecond) // exactly Dedupe after the last event
	if !tb.Observe(e) {
		t.Fatal("exactly the window after the last event is fresh")
	}
	c.advance(time.Second)
	e.Verdict = "deny-rule"
	if !tb.Observe(e) {
		t.Fatal("a changed verdict is fresh inside the window")
	}
	if tb.Observe(ev("wget", "1.1.1.1", 443, "deny-rule")) != true {
		t.Fatal("another program is another key")
	}
	if tb.Len() != 2 {
		t.Fatalf("Len %d, want 2", tb.Len())
	}
}

// Req 3.1: counts, first/last seen, last allowed and blocked; Req 2.4: duplicates mark dirty.
func TestTableCountsAndTimes(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	e := ev("curl", "1.1.1.1", 443, "allow-rule")
	tb.Observe(e)
	c.advance(time.Second)
	tb.Observe(e) // duplicate: still counted
	c.advance(time.Second)
	e.Verdict = "deny-default"
	tb.Observe(e)
	got := tb.Changed(time.Time{})
	want := Entry{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Port: 443, Protocol: "tcp",
		AllowCount: 2, DenyCount: 1, FirstSeen: stamp(t0), LastSeen: stamp(t0.Add(2 * time.Second)),
		LastAllowed: stamp(t0.Add(time.Second)), LastBlocked: stamp(t0.Add(2 * time.Second)), Verdict: "deny-default"}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("Changed:\n got %+v\nwant %+v", got, want)
	}
	if stamp(t0) != "2026-10-11T12:00:00Z" || stamp(time.Time{}) != "" {
		t.Fatalf("stamp format: %q %q", stamp(t0), stamp(time.Time{}))
	}
	if again := tb.Changed(time.Time{}); len(again) != 0 {
		t.Fatalf("Changed must clear dirty, got %d", len(again))
	}
	tb.Observe(e) // a duplicate still dirties the entry (count and last seen moved)
	if len(tb.Changed(time.Time{})) != 1 {
		t.Fatal("duplicate must mark the entry changed")
	}
}

// Req 3.6: least recently seen out first, the eviction counted, its cookies dropped.
func TestTableEvictsAtMax(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	tb.Max = 2
	tb.Observe(cookieEv(ev("a", "1.1.1.1", 1, "allow-rule"), 11))
	c.advance(time.Second)
	tb.Observe(ev("b", "1.1.1.1", 2, "allow-rule"))
	c.advance(time.Second)
	tb.Observe(ev("a", "1.1.1.1", 1, "allow-rule")) // a is now the most recent
	c.advance(time.Second)
	tb.Observe(ev("c", "1.1.1.1", 3, "allow-rule")) // evicts b
	if tb.Len() != 2 || tb.Evictions() != 1 {
		t.Fatalf("len %d evictions %d, want 2 and 1", tb.Len(), tb.Evictions())
	}
	if _, ok := tb.m[Key{Program: "b", Path: "/usr/bin/b", Addr: "1.1.1.1", Port: 2, Proto: 6}]; ok {
		t.Fatal("b (least recently seen) must be the one evicted")
	}
	c.advance(time.Second)
	tb.Observe(ev("d", "1.1.1.1", 4, "allow-rule")) // evicts a, cookie 11 goes with it
	if tb.Evictions() != 2 {
		t.Fatalf("evictions %d, want 2", tb.Evictions())
	}
	if _, ok := tb.cookies[11]; ok {
		t.Fatal("cookie of the evicted entry must be dropped")
	}
	checkCookies(t, tb)
	tb.AddBytes(11, 100, c.now()) // parks, nothing to attribute
	if tb.Len() != 2 {
		t.Fatal("bytes for a dropped cookie must not resurrect the entry")
	}
	// Contract: a table over Max after an insert is a bug. Corrupt m behind insert's back.
	tb.m[Key{Program: "ghost1"}] = &entry{}
	tb.m[Key{Program: "ghost2"}] = &entry{}
	contracttest.Panics(t, contract.InvariantKind, func() { tb.Observe(ev("e", "1.1.1.1", 5, "allow-rule")) })
}

// Req 3.5: entries idle beyond the longest window are forgotten on the sweep.
func TestTablePruneIdle(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	tb.Observe(cookieEv(ev("old", "1.1.1.1", 1, "allow-rule"), 5))
	c.advance(time.Hour)
	tb.Observe(ev("new", "1.1.1.1", 2, "allow-rule"))
	c.advance(Retention) // old is idle for 7 d + 1 h, new for exactly 7 d
	tb.Prune(c.now())
	if tb.Len() != 1 {
		t.Fatalf("Len %d after prune, want 1", tb.Len())
	}
	if _, ok := tb.cookies[5]; ok {
		t.Fatal("pruned entry must drop its cookies")
	}
	checkCookies(t, tb)
	c.advance(time.Nanosecond)
	tb.Prune(c.now())
	if tb.Len() != 0 {
		t.Fatal("exactly past the retention the last entry goes too")
	}
}

func TestTableChangedIgnoresSince(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	tb.Observe(ev("a", "1.1.1.1", 1, "allow-rule"))
	c.advance(time.Minute)
	tb.Observe(ev("b", "1.1.1.1", 2, "allow-rule"))
	got := tb.Changed(c.now().Add(time.Hour)) // a since in the future still yields every dirty row
	if len(got) != 2 || got[0].Program != "b" || got[1].Program != "a" {
		t.Fatalf("dirty rows, most recent first: %+v", got)
	}
	if len(tb.Changed(time.Time{})) != 0 {
		t.Fatal("nothing dirty after Changed")
	}
}

func TestTableRequiresClock(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { NewTable(nil) })
}

// Probe for the Observe path at the bound: a full table with 200 k live cookies, every Observe
// a new key with a cookie, so each one evicts (design "Contracts": Observe p99 under 1 ms).
func BenchmarkTableObserveEvicting(b *testing.B) {
	c := newClock()
	tb := newTable(c)
	var cookie uint64
	for i := 0; i < DefaultMax; i++ {
		e := ev("p", "10.0.0.1", uint16(i), "allow-rule")
		for j := 0; j < 200000/DefaultMax; j++ {
			cookie++
			tb.Observe(cookieEv(e, cookie))
		}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cookie++
		tb.Observe(cookieEv(ev("q", "10.0.0.2", uint16(i), "allow-rule"), cookie))
	}
}
