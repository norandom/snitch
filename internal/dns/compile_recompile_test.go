// Reload tests use detached cache iteration so new rules also cover previously unmatched addresses.
package dns

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/rules"
)

func TestRecompileRenumbersAndRemoves(t *testing.T) {
	var c Compiled
	var cache Cache
	addr := netip.MustParseAddr("192.0.2.1")
	cache.Learn("api.example.com", []netip.Addr{addr}, time.Hour, time.Time{})
	old := compilerRules(nameRule(1, 0), nameRule(2, rules.TCP, 443))
	c.Recompile(old, &cache, nil)
	next := compilerRules(nameRule(9, 0))
	puts, dels := c.Recompile(next, &cache, nil)
	compiledLengths(t, puts, dels, &c, 1, 1, 1)
	for k, v := range puts {
		if v.Id != 9 || k.Proto != 0 {
			t.Fatal(k, v)
		}
	}
	if dels[0].Proto != uint8(rules.TCP) || dels[0].Port != 443 {
		t.Fatal(dels)
	}
	if name, ok := c.NameOf(addr, 9); !ok || name != "api.example.com" {
		t.Fatal(name, ok)
	}
	if _, ok := c.NameOf(addr, 1); ok {
		t.Fatal("old id survived")
	}
}

func TestRecompileDeletesGoneAddresses(t *testing.T) {
	var c Compiled
	var cache Cache
	addr := netip.MustParseAddr("192.0.2.1")
	res := compilerRules(nameRule(1, 0))
	cache.Learn("example.com", []netip.Addr{addr}, time.Minute, time.Time{})
	c.Recompile(res, &cache, nil)
	cache.Expire(time.Time{}.Add(time.Minute))
	puts, dels := c.Recompile(res, &cache, nil)
	if len(puts) != 0 || len(dels) != 1 || c.Len() != 0 {
		t.Fatal(puts, dels, c.Len())
	}
}

func TestRecompileVisitsUnmatchedAndReputs(t *testing.T) {
	var c Compiled
	var cache Cache
	addr := netip.MustParseAddr("192.0.2.1")
	cache.Learn("example.com", []netip.Addr{addr}, time.Hour, time.Time{})
	c.Recompile(compilerRules(), &cache, nil)
	res := compilerRules(nameRule(1, 0))
	puts, _ := c.Recompile(res, &cache, nil)
	if len(puts) != 1 {
		t.Fatal(puts)
	}
	puts, _ = c.Recompile(res, &cache, nil)
	if len(puts) != 1 {
		t.Fatal("reload must re-put even unchanged ids", puts)
	}
	puts, dels := c.Recompile(res, &cache, puts)
	if len(puts)+len(dels)+c.Len() != 0 {
		t.Fatal(puts, dels, c.Len())
	}
}

func TestRecompileGoneFileKeyIsForgotten(t *testing.T) {
	var c Compiled
	var cache Cache
	addr := netip.MustParseAddr("192.0.2.1")
	cache.Learn("example.com", []netip.Addr{addr}, time.Minute, time.Time{})
	res := compilerRules(nameRule(1, 0))
	file, _ := c.Recompile(res, &cache, nil)
	cache.Expire(time.Time{}.Add(time.Minute))
	puts, dels := c.Recompile(res, &cache, file)
	if len(puts)+len(dels)+c.Len() != 0 {
		t.Fatal(puts, dels, c.Len())
	}
}

func BenchmarkRecompile(b *testing.B) {
	var c Compiled
	var cache Cache
	res := compilerRules()
	for i := 0; i < 50; i++ {
		rule := nameRule(uint32(i+1), rules.TCP, 443)
		rule.Name = fmt.Sprintf("n%d.example.com", i)
		res.File.Rules = append(res.File.Rules, rule)
	}
	for i := 0; i < 8192; i++ {
		addr := netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)})
		cache.Learn(fmt.Sprintf("n%d.example.com", i%50), []netip.Addr{addr}, time.Hour, time.Time{})
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		c.Recompile(res, &cache, nil)
	}
}
