// Package table builds the pure connection tree, sorting, search, rule coverage, block plans,
// and egress flows from the daemon's entries and rules. It has no clock, terminal library,
// or I/O, and keeps raw daemon strings in keys while sanitising display titles via clean.
//
// store.go: defines Key, KeyOf, and immutable Store with Replace (snapshot) and Upsert (summary).
//
// Fail-safe implications: none on kernel egress. Pure data transformation over snapshots and
// summaries from the daemon API; nothing here touches BPF maps or sockets.
package table

import (
	"maps"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/ask"
)

// Key identifies one connection entry in the store: Who (program name, or executable path
// when the program is "unknown"), destination address, protocol, and port.
type Key struct {
	Who, Addr, Proto string
	Port             uint16
}

// KeyOf returns the store key for an API entry.
func KeyOf(e api.Entry) Key {
	who := e.Program
	if who == ask.Unknown && e.Path != "" {
		who = e.Path
	}
	return Key{
		Who:   who,
		Addr:  e.Addr,
		Proto: e.Protocol,
		Port:  e.Port,
	}
}

// Store holds the daemon's connection entries indexed by Key. It is immutable: Replace and
// Upsert return new Store values without mutating the receiver.
type Store struct {
	entries map[Key]api.Entry
}

// Replace returns a new Store containing only es (for a snapshot reply).
func (s Store) Replace(es []api.Entry) Store {
	if len(es) == 0 {
		return Store{}
	}
	next := make(map[Key]api.Entry, len(es))
	for _, e := range es {
		next[KeyOf(e)] = e
	}
	return Store{entries: next}
}

// Upsert returns a new Store with es inserted or updated by Key (for a summary line).
func (s Store) Upsert(es []api.Entry) Store {
	if len(es) == 0 {
		return s
	}
	next := make(map[Key]api.Entry, len(s.entries)+len(es))
	maps.Copy(next, s.entries)
	for _, e := range es {
		next[KeyOf(e)] = e
	}
	return Store{entries: next}
}

// Get returns the entry for k if present.
func (s Store) Get(k Key) (api.Entry, bool) {
	e, ok := s.entries[k]
	return e, ok
}

// Len returns the number of entries in the store.
func (s Store) Len() int {
	return len(s.entries)
}
