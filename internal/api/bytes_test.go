package api

import (
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

func unknownEntry(tb *Table) *entry { return tb.m[Key{Program: UnknownProgram}] }

// Req 3.2: bytes join the entry the cookie was observed with; the summary shows them.
func TestBytesJoinByCookie(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	tb.Observe(cookieEv(ev("curl", "1.1.1.1", 443, "allow-rule"), 42))
	tb.Changed(time.Time{})
	tb.AddBytes(42, 1500, c.now())
	tb.AddBytes(42, 500, c.now())
	got := tb.Changed(time.Time{})
	if len(got) != 1 || got[0].BytesSent != 2000 || got[0].Program != "curl" {
		t.Fatalf("bytes: %+v", got)
	}
	if unknownEntry(tb) != nil {
		t.Fatal("no unknown entry for a known cookie")
	}
}

// Design "Cookies": bytes before the event are parked and drained by Observe.
func TestBytesPendingDrainedByObserve(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	tb.AddBytes(7, 300, c.now())
	tb.Prune(c.now()) // one sweep: still parked
	if tb.Len() != 0 {
		t.Fatal("parked bytes make no entry")
	}
	tb.Observe(cookieEv(ev("curl", "1.1.1.1", 443, "allow-rule"), 7))
	got := tb.Changed(time.Time{})
	if len(got) != 1 || got[0].BytesSent != 300 {
		t.Fatalf("drained: %+v", got)
	}
	tb.Prune(c.now())
	if unknownEntry(tb) != nil {
		t.Fatal("drained bytes must not reach the unknown entry")
	}
}

// Req 3.4: bytes nobody claims after two sweeps go to the "unknown" entry, not the floor.
func TestBytesUnknownAfterTwoSweeps(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	tb.AddBytes(9, 100, c.now())
	tb.Prune(c.now())
	c.advance(2 * time.Second)
	tb.AddBytes(9, 23, c.now()) // more bytes on the parked cookie
	tb.Prune(c.now())           // second sweep: moves to unknown
	u := unknownEntry(tb)
	if u == nil || u.bytes != 123 {
		t.Fatalf("unknown entry: %+v", u)
	}
	got := snapshot(t, tb, 15*time.Minute)
	if len(got) != 1 || got[0].Program != UnknownProgram || got[0].BytesSent != 123 || got[0].Addr != "" {
		t.Fatalf("unknown in snapshot: %+v", got)
	}
	if _, parked := tb.pending[9]; parked {
		t.Fatal("moved bytes must leave pending")
	}
	tb.AddBytes(9, 1, c.now()) // the cookie is still unknown: parks again
	if u.bytes != 123 {
		t.Fatal("a new parking round starts for the same cookie")
	}
}

// Design "Contracts": every cookie maps to a present entry (TestCookiesFollowEntries).
func TestBytesCookiesFollowEntries(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	tb.Max = 1
	tb.Observe(cookieEv(ev("a", "1.1.1.1", 1, "allow-rule"), 1))
	tb.Observe(cookieEv(ev("b", "1.1.1.1", 2, "allow-rule"), 2)) // evicts a and cookie 1
	if _, ok := tb.cookies[1]; ok || len(tb.cookies) != 1 {
		t.Fatalf("cookies after eviction: %v", tb.cookies)
	}
	tb.AddBytes(1, 10, c.now()) // parks: the entry is gone
	if tb.m[keyOf(ev("b", "1.1.1.1", 2, "allow-rule"))].bytes != 0 {
		t.Fatal("bytes of an evicted cookie landed on another entry")
	}
	tb.cookies[77] = binding{key: Key{Program: "ghost"}}
	contracttest.Panics(t, contract.InvariantKind, func() { tb.AddBytes(77, 1, c.now()) })
}

// A socket reused for another destination (UDP) follows the latest key.
func TestBytesCookieRemap(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	a := cookieEv(ev("dns", "1.1.1.1", 53, "allow-rule"), 3)
	b := cookieEv(ev("dns", "9.9.9.9", 53, "allow-rule"), 3)
	tb.Observe(a)
	tb.Observe(b)
	tb.AddBytes(3, 64, c.now())
	if tb.m[keyOf(a)].bytes != 0 || tb.m[keyOf(b)].bytes != 64 {
		t.Fatal("bytes must follow the latest destination")
	}
	if len(tb.m[keyOf(a)].cookies) != 0 || len(tb.m[keyOf(b)].cookies) != 1 {
		t.Fatalf("cookie lists: %v %v", tb.m[keyOf(a)].cookies, tb.m[keyOf(b)].cookies)
	}
	tb.Max = 2
	tb.Observe(ev("other", "1.1.1.1", 1, "allow-rule")) // full: evicts a (older), b stays with cookie 3
	if k, ok := tb.cookies[3]; !ok || k.key != keyOf(b) {
		t.Fatalf("cookie 3 after evicting a: %v %v", k, ok)
	}
}

// Req 3.6: a live entry's cookie index is bounded: cookies idle for CookieIdle leave both maps
// on the sweep; the entry and its bytes stay.
func TestBytesCookiesExpire(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	e := ev("curl", "1.1.1.1", 443, "allow-rule")
	const n = 1000
	for i := uint64(1); i <= n; i++ {
		tb.Observe(cookieEv(e, i))
		tb.AddBytes(i, 1, c.now())
	}
	en := tb.m[keyOf(e)]
	if len(tb.cookies) != n || len(en.cookies) != n {
		t.Fatalf("cookies before: %d %d", len(tb.cookies), len(en.cookies))
	}
	c.advance(CookieIdle - time.Second)
	tb.AddBytes(n, 1, c.now()) // the last cookie is still sending
	c.advance(time.Second)
	tb.Prune(c.now())
	if len(tb.cookies) != 1 || len(en.cookies) != 1 || en.cookies[0] != n {
		t.Fatalf("cookies after prune: %d in the index, %d on the entry", len(tb.cookies), len(en.cookies))
	}
	if tb.Len() != 1 || en.bytes != n+1 {
		t.Fatalf("entry after prune: len %d bytes %d", tb.Len(), en.bytes)
	}
	tb.AddBytes(1, 5, c.now()) // an expired cookie parks like an unknown one
	if en.bytes != n+1 {
		t.Fatal("expired cookie must not reach the entry")
	}
	checkCookies(t, tb)
}
