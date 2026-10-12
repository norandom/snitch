package api

import (
	"container/list"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/norandom/snitch/internal/contract"
)

// Table bounds (design "Table"): the maximum, the dedupe window, the longest window kept.
const (
	DefaultMax     = 4096
	DefaultDedupe  = 10 * time.Second
	Retention      = 7 * 24 * time.Hour
	UnknownProgram = "unknown"        // the entry that takes bytes nobody claimed (Req 3.4)
	CookieIdle     = 10 * time.Minute // a cookie without bytes this long leaves the index (Req 3.6)
)

// Key identifies a table entry: the program (name and path), the destination and the protocol.
type Key struct {
	Program, Path, Addr string
	Port                uint16
	Proto               uint8
}

// entry is a table row: totals, times, the per-window rings and the cookies that feed it.
type entry struct {
	name                     string
	key                      Key
	buckets                  window
	allow, deny, bytes       uint64
	first, lastActive        time.Time // first insert; last event or bytes (the row's lastSeen)
	lastAllowed, lastBlocked time.Time
	lastEvent                time.Time // last fresh decision: the dedupe window's anchor
	verdict                  string
	dirty                    bool
	el                       *list.Element
	cookies                  []uint64
}

// Table is the in-memory connection table behind events, summaries, snapshots and bytes.
// Observe, AddBytes, Changed and Prune take the lock; Snapshot reads a cache Changed built.
type Table struct {
	mu        sync.Mutex
	now       func() time.Time
	m         map[Key]*entry
	lru       *list.List // front = most recently active
	cookies   map[uint64]binding
	pending   map[uint64]*parked
	cache     atomic.Pointer[[len(Windows)][]Entry]
	Max       int
	Dedupe    time.Duration
	evictions int
}

// NewTable returns an empty table with the design's bounds, reading time from now.
func NewTable(now func() time.Time) *Table {
	contract.Require(now != nil, "table needs a clock")
	return &Table{now: now, m: map[Key]*entry{}, lru: list.New(), cookies: map[uint64]binding{},
		pending: map[uint64]*parked{}, Max: DefaultMax, Dedupe: DefaultDedupe}
}

func keyOf(e Event) Key {
	return Key{Program: e.Program, Path: e.Path, Addr: e.Addr, Port: e.Port, Proto: protoNum(e.Protocol)}
}

func protoNum(s string) uint8 {
	switch s {
	case "tcp":
		return 6
	case "udp":
		return 17
	}
	return 0
}

func protoName(p uint8) string {
	switch p {
	case 6:
		return "tcp"
	case 17:
		return "udp"
	}
	return ""
}

func isDeny(verdict string) bool { return strings.HasPrefix(verdict, "deny") }

// Observe records a decision. fresh is true when the key is new, the last event is at least
// Dedupe old, or the verdict changed; a duplicate only updates counts and times (Req 2.2).
func (t *Table) Observe(e Event) (fresh bool) {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	k := keyOf(e)
	en, known := t.m[k]
	if !known {
		en = t.insert(k, now)
	}
	fresh = !known || now.Sub(en.lastEvent) >= t.Dedupe || en.verdict != e.Verdict
	if fresh {
		en.lastEvent = now // the window counts from the last event that was sent (Req 2.2)
	}
	if e.Name != "" {
		en.name = e.Name
	}
	en.record(e.Verdict, now)
	t.touch(en, now)
	if e.Cookie != 0 {
		t.bind(e.Cookie, en, now)
	}
	return fresh
}

func (en *entry) record(verdict string, now time.Time) {
	en.verdict, en.dirty = verdict, true
	if isDeny(verdict) {
		en.deny++
		en.lastBlocked = now
		en.buckets.add(now, 0, 0, 1)
		return
	}
	en.allow++
	en.lastAllowed = now
	en.buckets.add(now, 0, 1, 0)
}

// insert adds a new entry, evicting the least recently active one when the table is full.
func (t *Table) insert(k Key, now time.Time) *entry {
	contract.Require(t.Max > 0, "table max is positive")
	if len(t.m) >= t.Max {
		t.evict()
	}
	en := &entry{key: k, first: now, lastActive: now}
	en.el = t.lru.PushFront(en)
	t.m[k] = en
	contract.Invariant(len(t.m) <= t.Max, "table within max after insert")
	return en
}

func (t *Table) evict() {
	back := t.lru.Back()
	if back == nil {
		return
	}
	t.remove(back.Value.(*entry))
	t.evictions++
}

// remove drops an entry and its cookies (O(k) in the entry's cookies: this runs under the lock
// on the pump path); bytes for those cookies park again. AddBytes checks the cookie it uses
// maps to a present entry; the whole-map form of that invariant is a test helper.
func (t *Table) remove(en *entry) {
	delete(t.m, en.key)
	t.lru.Remove(en.el)
	for _, c := range en.cookies {
		delete(t.cookies, c)
		_, still := t.cookies[c]
		contract.Invariant(!still, "a removed entry leaves no cookie behind")
	}
}

func (t *Table) touch(en *entry, now time.Time) {
	if now.After(en.lastActive) {
		en.lastActive = now
	}
	t.lru.MoveToFront(en.el)
}

// Changed returns every entry dirtied since the last call, most recently active first, clears
// their dirty mark and rebuilds the window caches Snapshot serves (Req 2.4). since is the
// summary's own bookkeeping and does not filter: drained bytes can carry an old timestamp.
func (t *Table) Changed(_ time.Time) []Entry {
	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []Entry
	for el := t.lru.Front(); el != nil; el = el.Next() {
		en := el.Value.(*entry)
		if en.dirty {
			out = append(out, en.view(now))
			en.dirty = false
		}
	}
	t.refreshCaches(now)
	return out
}

// Prune is the sweep's housekeeping: parked bytes age (two sweeps, then "unknown"), cookies
// idle for CookieIdle leave the index, and entries idle beyond Retention are forgotten (3.5).
func (t *Table) Prune(now time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.agePending(now)
	t.expireCookies(now)
	for el := t.lru.Back(); el != nil; el = t.lru.Back() {
		en := el.Value.(*entry)
		if now.Sub(en.lastActive) <= Retention {
			return
		}
		t.remove(en)
	}
}

// Len is the number of entries.
func (t *Table) Len() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.m)
}

// Evictions is how many entries were evicted at Max (Req 3.6).
func (t *Table) Evictions() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.evictions
}

func stamp(at time.Time) string {
	if at.IsZero() {
		return ""
	}
	return at.UTC().Format(time.RFC3339)
}

// view is the row with its all-time totals and the current rate.
func (en *entry) view(now time.Time) Entry {
	return Entry{Program: en.key.Program, Path: en.key.Path, Addr: en.key.Addr, Name: en.name, Port: en.key.Port,
		Protocol: protoName(en.key.Proto), AllowCount: en.allow, DenyCount: en.deny,
		FirstSeen: stamp(en.first), LastSeen: stamp(en.lastActive), LastAllowed: stamp(en.lastAllowed),
		LastBlocked: stamp(en.lastBlocked), BytesSent: en.bytes, Rate: en.buckets.rate(now), Verdict: en.verdict}
}
