// These tests pin cache lifetimes and change reports; cached names can only add allows.
package dns

import (
	"net/netip"
	"reflect"
	"testing"
	"time"
)

func cacheAddr(n int) netip.Addr {
	return netip.AddrFrom4([4]byte{10, byte(n >> 16), byte(n >> 8), byte(n)})
}

func cacheNames(t *testing.T, c *Cache, a netip.Addr, want ...string) {
	t.Helper()
	if got := c.Names(a); !reflect.DeepEqual(got, want) {
		t.Fatalf("Names = %v, want %v", got, want)
	}
}

func TestClamp(t *testing.T) {
	for _, tc := range []struct{ in, want time.Duration }{{59 * time.Second, time.Minute}, {25 * time.Hour, 24 * time.Hour}, {300 * time.Second, 300 * time.Second}} {
		if got := Clamp(tc.in); got != tc.want {
			t.Fatalf("Clamp(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestCacheZeroAndChanges(t *testing.T) {
	var c Cache
	a := cacheAddr(1)
	now := time.Unix(0, 0)
	if x, y := c.Len(); x != 0 || y != 0 || c.Evictions() != 0 {
		t.Fatal("zero cache not empty")
	}
	cacheNames(t, &c, a)
	changes := c.Learn("one.example", []netip.Addr{a, a}, time.Minute, now)
	want := []Change{{Addr: a, Names: []string{"one.example"}}}
	if !reflect.DeepEqual(changes, want) {
		t.Fatalf("changes = %v", changes)
	}
	changes[0].Names[0] = "corrupt"
	names := c.Names(a)
	names[0] = "corrupt"
	cacheNames(t, &c, a, "one.example")
	if got := c.Learn("one.example", []netip.Addr{a}, time.Minute, now); len(got) != 0 {
		t.Fatalf("unchanged set: %v", got)
	}
}

func TestCacheRelearnLaterExpiry(t *testing.T) {
	var c Cache
	a := cacheAddr(1)
	now := time.Unix(0, 0)
	c.Learn("one.example", []netip.Addr{a}, 2*time.Minute, now)
	c.Learn("two.example", []netip.Addr{a}, 5*time.Minute, now)
	c.Learn("one.example", []netip.Addr{a}, 3*time.Minute, now.Add(time.Minute))
	cacheNames(t, &c, a, "one.example", "two.example")
	c.Expire(now.Add(3 * time.Minute))
	cacheNames(t, &c, a, "one.example", "two.example")
}

func TestCacheRelearnShorterDoesNotShorten(t *testing.T) {
	var c Cache
	a := cacheAddr(1)
	now := time.Unix(0, 0)
	c.Learn("one.example", []netip.Addr{a}, 5*time.Minute, now)
	c.Learn("one.example", []netip.Addr{a}, time.Minute, now.Add(time.Minute))
	if got := c.Expire(now.Add(2 * time.Minute)); len(got) != 0 {
		t.Fatalf("shortened expiry: %v", got)
	}
	cacheNames(t, &c, a, "one.example")
}

func TestCacheExpiryBoundaryAndPartial(t *testing.T) {
	var c Cache
	a := cacheAddr(1)
	now := time.Unix(0, 0)
	c.Learn("one.example", []netip.Addr{a}, time.Minute, now)
	c.Learn("two.example", []netip.Addr{a}, 2*time.Minute, now)
	if got := c.Expire(now.Add(time.Minute - time.Nanosecond)); len(got) != 0 {
		t.Fatal(got)
	}
	want := []Change{{Addr: a, Names: []string{"two.example"}}}
	if got := c.Expire(now.Add(time.Minute)); !reflect.DeepEqual(got, want) {
		t.Fatalf("partial = %v", got)
	}
	want = []Change{{Addr: a, Gone: true}}
	if got := c.Expire(now.Add(2 * time.Minute)); !reflect.DeepEqual(got, want) {
		t.Fatalf("last = %v", got)
	}
	if x, y := c.Len(); x != 0 || y != 0 {
		t.Fatalf("Len = %d,%d", x, y)
	}
}

func TestCacheEachVisitsEveryAddressOnce(t *testing.T) {
	var c Cache
	now := time.Unix(1000, 0)
	a, b := netip.MustParseAddr("10.1.1.1"), netip.MustParseAddr("10.1.1.2")
	c.Learn("one.example", []netip.Addr{a, b}, time.Minute, now)
	c.Learn("two.example", []netip.Addr{a}, time.Minute, now)
	seen := map[netip.Addr][]string{}
	c.Each(func(addr netip.Addr, names []string) { seen[addr] = names })
	if len(seen) != 2 || len(seen[a]) != 2 || seen[a][0] != "two.example" || len(seen[b]) != 1 {
		t.Fatalf("Each visited %v", seen)
	}
	seen[a][0] = "mutated"
	if c.Names(a)[0] != "two.example" {
		t.Fatal("Each handed out the cache's own slice")
	}
}
