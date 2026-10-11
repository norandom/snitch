package api

import (
	"slices"
	"time"

	"github.com/norandom/snitch/internal/contract"
)

// pendingSweeps is how many Prune calls parked bytes survive before they count as unknown.
const pendingSweeps = 2

// binding is a cookie's entry and the time bytes last arrived on it.
type binding struct {
	key  Key
	last time.Time
}

// parked are bytes for a cookie no event has claimed yet (design "Cookies").
type parked struct {
	bytes  uint64
	at     time.Time
	sweeps int
}

// AddBytes attributes a non-negative byte delta observed at the given time to the entry the
// cookie belongs to; an unclaimed cookie parks them (Req 3.2, 3.4).
func (t *Table) AddBytes(cookie, delta uint64, at time.Time) {
	t.mu.Lock()
	defer t.mu.Unlock()
	b, ok := t.cookies[cookie]
	if !ok {
		t.park(cookie, delta, at)
		return
	}
	en, present := t.m[b.key]
	contract.Invariant(present, "cookie maps to a present entry")
	if at.After(b.last) {
		t.cookies[cookie] = binding{key: b.key, last: at}
	}
	t.addBytes(en, delta, at)
}

func (t *Table) addBytes(en *entry, delta uint64, at time.Time) {
	if delta == 0 {
		return
	}
	en.bytes += delta
	en.buckets.add(at, delta, 0, 0)
	en.dirty = true
	t.touch(en, at)
}

func (t *Table) park(cookie, delta uint64, at time.Time) {
	if delta == 0 {
		return
	}
	p := t.pending[cookie]
	if p == nil {
		p = &parked{}
		t.pending[cookie] = p
	}
	p.bytes += delta
	p.at = at
}

// bind maps a cookie to its entry (a reused socket follows its latest destination) and drains
// bytes parked for it.
func (t *Table) bind(cookie uint64, en *entry, now time.Time) {
	if old, ok := t.cookies[cookie]; ok {
		if old.key == en.key {
			t.cookies[cookie] = binding{key: en.key, last: now}
			return
		}
		t.unbind(cookie, old.key)
	}
	t.cookies[cookie] = binding{key: en.key, last: now}
	en.cookies = append(en.cookies, cookie)
	if p, ok := t.pending[cookie]; ok {
		delete(t.pending, cookie)
		t.addBytes(en, p.bytes, p.at)
	}
}

func (t *Table) unbind(cookie uint64, k Key) {
	if old := t.m[k]; old != nil {
		old.cookies = slices.DeleteFunc(old.cookies, func(c uint64) bool { return c == cookie })
	}
}

// agePending counts a sweep for every parked cookie; after pendingSweeps the bytes go to the
// "unknown" entry (lock held).
func (t *Table) agePending(now time.Time) {
	for c, p := range t.pending {
		p.sweeps++
		if p.sweeps < pendingSweeps {
			continue
		}
		delete(t.pending, c)
		t.addBytes(t.entryFor(Key{Program: UnknownProgram}, now), p.bytes, p.at)
	}
}

func (t *Table) entryFor(k Key, now time.Time) *entry {
	if en := t.m[k]; en != nil {
		return en
	}
	return t.insert(k, now)
}

// expireCookies drops cookies without bytes for CookieIdle from the index and from their
// entries' lists, in one pass over each; the entries and their totals stay (lock held).
func (t *Table) expireCookies(now time.Time) {
	touched := map[Key]struct{}{}
	for c, b := range t.cookies {
		if now.Sub(b.last) >= CookieIdle {
			delete(t.cookies, c)
			touched[b.key] = struct{}{}
		}
	}
	for k := range touched {
		if en := t.m[k]; en != nil {
			en.cookies = slices.DeleteFunc(en.cookies, func(c uint64) bool { _, live := t.cookies[c]; return !live })
		}
	}
}
