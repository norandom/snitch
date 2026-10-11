package api

import (
	"fmt"
	"time"

	"github.com/norandom/snitch/internal/contract"
)

// Windows are the spans a snapshot can ask for, the Python client's choices (Req 3.5).
var Windows = [...]time.Duration{15 * time.Minute, 30 * time.Minute, time.Hour, 24 * time.Hour, 7 * 24 * time.Hour}

const rateSpan = 10 * time.Second

func windowIndex(d time.Duration) (int, error) {
	for i, w := range Windows {
		if w == d {
			return i, nil
		}
	}
	return 0, fmt.Errorf("window %s: want one of 15m, 30m, 1h, 24h, 7d", d)
}

// bucket holds one period's activity; period tells a live bucket from a lapped one.
type bucket struct {
	period      int64
	bytes       uint64
	allow, deny uint32
}

// window is an entry's activity: 60 minute buckets for the hour, 168 hour buckets for the week.
type window struct {
	minute [60]bucket
	hour   [168]bucket
}

func period(at time.Time, step time.Duration) int64 { return at.Unix() / int64(step/time.Second) }

func slot(n int, p int64) int {
	i := int(p % int64(n))
	contract.Ensure(i >= 0 && i < n, "window index within the ring")
	return i
}

func (w *window) add(at time.Time, bytes uint64, allow, deny uint32) {
	addTo(w.minute[:], time.Minute, at, bytes, allow, deny)
	addTo(w.hour[:], time.Hour, at, bytes, allow, deny)
}

func addTo(b []bucket, step time.Duration, at time.Time, bytes uint64, allow, deny uint32) {
	p := period(at, step)
	k := &b[slot(len(b), p)]
	switch {
	case k.period > p:
		return // a full lap behind the ring: nothing left to add it to
	case k.period < p:
		*k = bucket{period: p}
	}
	k.bytes += bytes
	k.allow += allow
	k.deny += deny
}

// sum totals the buckets inside the last win: the minute ring up to an hour, hours beyond.
func (w *window) sum(win time.Duration, now time.Time) (bytes, allow, deny uint64) {
	if win <= time.Hour {
		return sumRing(w.minute[:], time.Minute, win, now)
	}
	return sumRing(w.hour[:], time.Hour, win, now)
}

func sumRing(b []bucket, step, win time.Duration, now time.Time) (bytes, allow, deny uint64) {
	hi := period(now, step)
	lo := period(now.Add(-win), step) + 1 // the bucket holding now-win is out: win/step buckets
	for i := range b {
		k := &b[i]
		if k.period < lo || k.period > hi {
			continue
		}
		bytes += k.bytes
		allow += uint64(k.allow)
		deny += uint64(k.deny)
	}
	return bytes, allow, deny
}

// rate is bytes per second over the last 10 s, taken from the current minute bucket and, when
// the minute is younger than 10 s, the previous one; bytes are assumed spread over a bucket.
func (w *window) rate(now time.Time) float64 {
	p := period(now, time.Minute)
	elapsed := now.Sub(time.Unix(p*60, 0)).Seconds()
	span := rateSpan.Seconds()
	var b float64
	if cur := w.minute[slot(len(w.minute), p)]; cur.period == p {
		if elapsed <= span {
			b += float64(cur.bytes)
		} else {
			b += float64(cur.bytes) * span / elapsed
		}
	}
	if prev := w.minute[slot(len(w.minute), p-1)]; prev.period == p-1 && elapsed < span {
		b += float64(prev.bytes) * (span - elapsed) / time.Minute.Seconds()
	}
	return b / span
}

// windowed is the row with the window's counts and bytes; false when nothing happened in it.
func (en *entry) windowed(win time.Duration, now time.Time) (Entry, bool) {
	bytes, allow, deny := en.buckets.sum(win, now)
	if bytes == 0 && allow == 0 && deny == 0 {
		return Entry{}, false
	}
	v := en.view(now)
	v.BytesSent, v.AllowCount, v.DenyCount = bytes, allow, deny
	return v, true
}

// refreshCaches rebuilds every window's snapshot, most recently active first (lock held).
func (t *Table) refreshCaches(now time.Time) {
	var c [len(Windows)][]Entry
	for el := t.lru.Front(); el != nil; el = el.Next() {
		en := el.Value.(*entry)
		for i, w := range Windows {
			if v, ok := en.windowed(w, now); ok {
				c[i] = append(c[i], v)
			}
		}
	}
	t.cache.Store(&c)
}

// Snapshot returns the entries active within window with that window's counts and bytes, as
// of the last Changed; it never takes the table lock (Req 2.5, 3.5). Unknown windows error.
func (t *Table) Snapshot(window time.Duration) ([]Entry, error) {
	i, err := windowIndex(window)
	if err != nil {
		return nil, err
	}
	c := t.cache.Load()
	if c == nil {
		return nil, nil
	}
	return c[i], nil
}
