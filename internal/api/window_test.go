package api

import (
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// snapshot refreshes the caches and returns the window's entries.
func snapshot(t *testing.T, tb *Table, w time.Duration) []Entry {
	t.Helper()
	tb.Changed(time.Time{})
	got, err := tb.Snapshot(w)
	if err != nil {
		t.Fatalf("Snapshot(%s): %v", w, err)
	}
	return got
}

// Design "Windows": a bucket written a full lap earlier is reset, not summed (ring wrap).
func TestWindowRingWrapResets(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	e := cookieEv(ev("curl", "1.1.1.1", 443, "allow-rule"), 1)
	tb.Observe(e)
	tb.AddBytes(1, 100, c.now()) // minute slot 0
	c.advance(60 * time.Minute)  // minute slot 0 again, one lap later
	tb.AddBytes(1, 7, c.now())
	got := snapshot(t, tb, 15*time.Minute)
	if len(got) != 1 || got[0].BytesSent != 7 || got[0].AllowCount != 0 {
		t.Fatalf("15m after a lap: %+v, want bytes 7 and no allow", got)
	}
	if got := snapshot(t, tb, time.Hour); got[0].BytesSent != 7 || got[0].AllowCount != 0 {
		t.Fatalf("1h window must not include the lapped bucket: %+v", got[0])
	}
	if got := snapshot(t, tb, 24*time.Hour); got[0].BytesSent != 107 || got[0].AllowCount != 1 {
		t.Fatalf("24h window keeps both: %+v", got[0])
	}
}

// Design "Windows": a window straddling the end of the ring sums across the boundary.
func TestWindowSumsAcrossRingBoundary(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	e := cookieEv(ev("curl", "1.1.1.1", 443, "allow-rule"), 1)
	tb.Observe(e)
	c.advance(58 * time.Minute) // minute slots 58, 59, 0, 1 and hour slots 0, 1 are written
	for i, b := range []uint64{1, 10, 100, 1000} {
		if i > 0 {
			c.advance(time.Minute)
		}
		tb.AddBytes(1, b, c.now())
	}
	if got := snapshot(t, tb, 15*time.Minute); got[0].BytesSent != 1111 {
		t.Fatalf("15m across the ring end: %d, want 1111", got[0].BytesSent)
	}
	if got := snapshot(t, tb, time.Hour); got[0].BytesSent != 1111 || got[0].AllowCount != 0 {
		t.Fatalf("1h: %+v (the allow at minute 0 is 61 min old)", got[0])
	}
	if got := snapshot(t, tb, 24*time.Hour); got[0].BytesSent != 1111 || got[0].AllowCount != 1 {
		t.Fatalf("24h: %+v", got[0])
	}
	// 1h window: the last 60 minute buckets. At minute 119 those are 60..119: 58 and 59 fall out.
	c.advance(58 * time.Minute)
	tb.Observe(ev("curl", "1.1.1.1", 443, "allow-rule")) // keeps the entry active
	if got := snapshot(t, tb, time.Hour); got[0].BytesSent != 1100 {
		t.Fatalf("1h at minute 119: %d, want 1100", got[0].BytesSent)
	}
}

// Design "Windows": a window is exactly win/step buckets; the bucket holding now-win is out.
// (15m, not 1h: with 60 slots the 1h edge bucket shares its slot with the current minute.)
func TestWindowExcludesBucketAtEdge(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	tb.Observe(cookieEv(ev("curl", "1.1.1.1", 443, "allow-rule"), 1))
	c.advance(60 * time.Minute)
	tb.AddBytes(1, 100, c.now()) // live data in minute bucket 60
	c.advance(15*time.Minute + 30*time.Second)
	tb.Observe(ev("curl", "1.1.1.1", 443, "allow-rule")) // minute 75:30
	got := snapshot(t, tb, 15*time.Minute)               // buckets 61..75
	if len(got) != 1 || got[0].BytesSent != 0 || got[0].AllowCount != 1 {
		t.Fatalf("15m at 75:30 must exclude minute 60: %+v", got)
	}
	if got := snapshot(t, tb, 30*time.Minute); got[0].BytesSent != 100 {
		t.Fatalf("30m keeps it: %+v", got[0])
	}
}

// Req 3.5: every window the Python client offers; inactive entries drop out; others are errors.
func TestSnapshotWindows(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	tb.Observe(ev("week", "1.1.1.1", 1, "deny-rule")) // 3 d old at the end
	c.advance(60 * time.Hour)
	tb.Observe(ev("day", "1.1.1.1", 2, "deny-rule")) // 12 h
	c.advance(12*time.Hour - 45*time.Minute)
	tb.Observe(ev("hour", "1.1.1.1", 3, "deny-rule")) // 45 min
	c.advance(25 * time.Minute)
	tb.Observe(ev("half", "1.1.1.1", 4, "deny-rule")) // 20 min
	c.advance(10 * time.Minute)
	tb.Observe(ev("quarter", "1.1.1.1", 5, "deny-rule")) // 10 min
	c.advance(10 * time.Minute)
	want := map[time.Duration]int{15 * time.Minute: 1, 30 * time.Minute: 2, time.Hour: 3, 24 * time.Hour: 4, 7 * 24 * time.Hour: 5}
	for w, n := range want {
		got := snapshot(t, tb, w)
		if len(got) != n {
			t.Errorf("window %s: %d entries, want %d", w, len(got), n)
		}
		for _, x := range got {
			if x.DenyCount != 1 || x.AllowCount != 0 || x.FirstSeen == "" {
				t.Errorf("window %s: %+v", w, x)
			}
		}
	}
	if _, err := tb.Snapshot(2 * time.Hour); err == nil {
		t.Fatal("2h is not a window")
	}
	if got, err := NewTable(c.now).Snapshot(time.Hour); err != nil || len(got) != 0 {
		t.Fatalf("empty table before any Changed: %v %v", got, err)
	}
}

// Design "Rate": bytes of the last 10 s from the current and previous minute buckets, / 10.
func TestWindowRate(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	tb.Observe(cookieEv(ev("curl", "1.1.1.1", 443, "allow-rule"), 1))
	tb.AddBytes(1, 6000, c.now()) // previous minute, 100 B/s if spread evenly
	c.advance(65 * time.Second)   // 5 s into the next minute
	tb.AddBytes(1, 500, c.now())
	got := tb.Changed(time.Time{})
	if got[0].Rate != 100 { // (500 + 6000*5/60) / 10
		t.Fatalf("rate %v, want 100", got[0].Rate)
	}
	c.advance(15 * time.Second) // 20 s into the minute: only the current bucket counts
	tb.AddBytes(1, 1500, c.now())
	if got = tb.Changed(time.Time{}); got[0].Rate != 100 { // 2000 * 10/20 / 10
		t.Fatalf("rate %v, want 100", got[0].Rate)
	}
	c.advance(10 * time.Minute)
	tb.Observe(ev("curl", "1.1.1.1", 443, "allow-rule"))
	if got = tb.Changed(time.Time{}); got[0].Rate != 0 {
		t.Fatalf("rate %v after 10 idle minutes, want 0", got[0].Rate)
	}
}

// Design "Contracts": a bucket index outside the ring is a bug (TestWindowIndex).
func TestWindowIndex(t *testing.T) {
	var w window
	w.add(t0, 1, 1, 0)
	if i := slot(len(w.minute), period(t0, time.Minute)); w.minute[i].bytes != 1 {
		t.Fatalf("bucket at slot %d not written", i)
	}
	contracttest.Panics(t, contract.Postcondition, func() { w.add(time.Unix(-61, 0), 1, 0, 0) })
}

// Design: Snapshot serves the cache without the table lock.
func TestSnapshotTakesNoTableLock(t *testing.T) {
	c := newClock()
	tb := newTable(c)
	tb.Observe(ev("curl", "1.1.1.1", 443, "allow-rule"))
	tb.Changed(time.Time{})
	tb.mu.Lock()
	defer tb.mu.Unlock()
	done := make(chan int)
	go func() {
		got, _ := tb.Snapshot(15 * time.Minute)
		done <- len(got)
	}()
	select {
	case n := <-done:
		if n != 1 {
			t.Fatalf("snapshot has %d entries, want 1", n)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Snapshot waited for the table lock")
	}
}
