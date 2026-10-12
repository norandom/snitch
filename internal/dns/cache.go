// This file keeps bounded address-to-name lifetimes for later allow rules. A bound breach
// is a programming error: its contract ends enforcement and therefore fails open.
package dns

import (
	"net/netip"
	"slices"
	"time"

	"github.com/norandom/snitch/internal/contract"
)

const (
	MaxAddrs = 8192
	MaxNames = 4
)

// Change is a detached snapshot; Gone tells the compiler to forget the address.
type Change struct {
	Addr  netip.Addr
	Names []string
	Gone  bool
}

type cacheName struct {
	name   string
	expiry time.Time
}

// Cache has a ready, empty zero value; its owner serializes access and calls Expire with its clock.
type Cache struct {
	entries   map[netip.Addr][]cacheName
	evictions uint64
}

// Clamp bounds how long a learned answer may contribute allows.
func Clamp(ttl time.Duration) time.Duration {
	if ttl < time.Minute {
		return time.Minute
	}
	if ttl > 24*time.Hour {
		return 24 * time.Hour
	}
	return ttl
}

// Learn does not expire entries; it returns one Change per address whose name set changed, in no particular order.
func (c *Cache) Learn(name string, addrs []netip.Addr, ttl time.Duration, now time.Time) []Change {
	contract.Require(name != "", "Learn needs a non-empty parsed name")
	contract.Require(len(addrs) > 0, "Learn needs addresses")
	for _, addr := range addrs {
		contract.Require(addr.IsValid(), "Learn needs valid addresses")
	}
	if c.entries == nil {
		c.entries = make(map[netip.Addr][]cacheName)
	}
	changes := make(map[netip.Addr]Change)
	expiry := now.Add(Clamp(ttl))
	for _, addr := range addrs {
		before := c.Names(addr)
		if _, ok := c.entries[addr]; !ok && len(c.entries) == MaxAddrs {
			victim := c.evictAddress()
			changes[victim] = Change{Addr: victim, Gone: true}
		}
		c.entries[addr] = cacheLearnName(c.entries[addr], name, expiry)
		contract.Ensure(len(c.entries[addr]) <= MaxNames, "cache name bound holds")
		after := c.Names(addr)
		if !slices.Equal(before, after) {
			changes[addr] = Change{Addr: addr, Names: after}
		}
	}
	contract.Ensure(len(c.entries) <= MaxAddrs, "cache address bound holds")
	return cacheChanges(changes)
}

func cacheLearnName(names []cacheName, name string, expiry time.Time) []cacheName {
	for i, n := range names {
		if n.name == name {
			if n.expiry.After(expiry) {
				expiry = n.expiry
			}
			names = slices.Delete(names, i, i+1)
			break
		}
	}
	if len(names) == MaxNames {
		victim := 0
		for i, n := range names {
			if n.expiry.Before(names[victim].expiry) {
				victim = i
			}
		}
		names = slices.Delete(names, victim, victim+1)
	}
	return append([]cacheName{{name: name, expiry: expiry}}, names...)
}

func (c *Cache) evictAddress() netip.Addr {
	var victim netip.Addr
	var soonest time.Time
	for addr, names := range c.entries {
		latest := names[0].expiry
		for _, n := range names {
			if n.expiry.After(latest) {
				latest = n.expiry
			}
		}
		if !victim.IsValid() || latest.Before(soonest) {
			victim, soonest = addr, latest
		}
	}
	delete(c.entries, victim)
	c.evictions++
	return victim
}

// Expire removes names whose expiry is at or before now and reports changed addresses.
func (c *Cache) Expire(now time.Time) []Change {
	var changes []Change
	for addr, names := range c.entries {
		live := slices.DeleteFunc(names, func(n cacheName) bool { return !n.expiry.After(now) })
		if len(live) == len(names) {
			continue
		}
		if len(live) == 0 {
			delete(c.entries, addr)
		} else {
			c.entries[addr] = live
		}
		changes = append(changes, Change{Addr: addr, Names: c.Names(addr), Gone: len(live) == 0})
	}
	return changes
}

// Names returns a detached snapshot, most recently learned first; a relearn moves the name to the front.
func (c *Cache) Names(addr netip.Addr) []string {
	var names []string
	for _, n := range c.entries[addr] {
		names = append(names, n.name)
	}
	return names
}

// Each calls fn for every cached address with a detached snapshot of its names (most recently
// learned first), in no particular order; the recompile on a reload needs every address, not
// only those that already produced compiled entries. fn must not mutate the cache.
func (c *Cache) Each(fn func(addr netip.Addr, names []string)) {
	for addr := range c.entries {
		fn(addr, c.Names(addr))
	}
}

// Len returns the number of cached addresses and names.
func (c *Cache) Len() (addrs, names int) {
	for _, entry := range c.entries {
		names += len(entry)
	}
	return len(c.entries), names
}

// Evictions counts address evictions only; a 5th name evicting a name on one address is not counted.
func (c *Cache) Evictions() uint64 { return c.evictions }

func cacheChanges(changes map[netip.Addr]Change) []Change {
	var out []Change
	for _, ch := range changes {
		out = append(out, ch)
	}
	return out
}
