// These tests guard resource bounds; contract failures detach enforcement and fail open.
package dns

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

func TestContractLearnNeedsAName(t *testing.T) {
	var c Cache
	contracttest.Panics(t, contract.Precondition, func() { c.Learn("", []netip.Addr{cacheAddr(1)}, time.Minute, time.Time{}) })
}

func TestContractLearnNeedsValidAddresses(t *testing.T) {
	for _, addrs := range [][]netip.Addr{nil, {}, {{}}, {cacheAddr(1), {}}} {
		var c Cache
		contracttest.Panics(t, contract.Precondition, func() { c.Learn("one.example", addrs, time.Minute, time.Time{}) })
		if x, _ := c.Len(); x != 0 {
			t.Fatal("invalid input partly learned")
		}
	}
}

func TestCacheNeverExceedsBounds(t *testing.T) {
	var c Cache
	now := time.Unix(0, 0)
	for i := 0; i < 9000; i++ {
		c.Learn("one.example", []netip.Addr{cacheAddr(i)}, time.Hour, now)
		if x, _ := c.Len(); x > maxAddrs {
			t.Fatalf("addresses = %d", x)
		}
	}
	a := cacheAddr(9000)
	for i := 0; i < 5; i++ {
		c.Learn(fmt.Sprintf("n%d.example", i), []netip.Addr{a}, time.Hour, now)
	}
	if len(c.Names(a)) != maxNames {
		t.Fatal(c.Names(a))
	}
	if c.Evictions() != 809 {
		t.Fatalf("evictions = %d", c.Evictions())
	}
}

func TestCacheEvictsSoonestName(t *testing.T) {
	var c Cache
	a := cacheAddr(1)
	now := time.Unix(0, 0)
	for i, ttl := range []time.Duration{4, 1, 3, 2, 5} {
		c.Learn(fmt.Sprintf("n%d.example", i), []netip.Addr{a}, ttl*time.Minute, now)
	}
	cacheNames(t, &c, a, "n4.example", "n3.example", "n2.example", "n0.example")
}

func TestCacheEvictsAddressWithSoonestLatestExpiry(t *testing.T) {
	var c Cache
	now := time.Unix(0, 0)
	addrs := make([]netip.Addr, maxAddrs)
	for i := range addrs {
		addrs[i] = cacheAddr(i)
	}
	c.Learn("long.example", addrs[2:], time.Hour, now)
	c.Learn("short.example", []netip.Addr{addrs[0]}, time.Minute, now)
	c.Learn("later.example", []netip.Addr{addrs[0]}, 2*time.Hour, now)
	c.Learn("victim.example", []netip.Addr{addrs[1]}, 2*time.Minute, now)
	changes := c.Learn("new.example", []netip.Addr{cacheAddr(maxAddrs)}, time.Hour, now)
	gone := 0
	for _, ch := range changes {
		if ch.Gone {
			gone++
			if ch.Addr != addrs[1] {
				t.Fatal("evicted longest-lived address")
			}
		}
	}
	if gone != 1 || c.Evictions() != 1 {
		t.Fatalf("changes=%v, evictions=%d", changes, c.Evictions())
	}
	cacheNames(t, &c, addrs[0], "later.example", "short.example")
}

func BenchmarkLearnExpire8192(b *testing.B) {
	addrs := make([]netip.Addr, maxAddrs)
	for i := range addrs {
		addrs[i] = cacheAddr(i)
	}
	now := time.Unix(0, 0)
	b.Run("Learn", func(b *testing.B) {
		for b.Loop() {
			var c Cache
			c.Learn("one.example", addrs, time.Minute, now)
		}
	})
	b.Run("Expire", func(b *testing.B) {
		var c Cache
		for i := 0; i < b.N; i++ {
			b.StopTimer()
			c.Learn("one.example", addrs, time.Minute, now)
			b.StartTimer()
			c.Expire(now.Add(time.Minute))
		}
	})
}
