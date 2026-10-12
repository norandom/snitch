//go:build root

// Isolated maps keep parser tests away from the daemon's policy.
package dns

import (
	"errors"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/ringbuf"
	snitchbpf "github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/rules"
)

func mustProg(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func loadDNSForTest(t *testing.T, skipQuestion bool) (*ebpf.Collection, *ebpf.Map) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	main, err := snitchbpf.LoadSnitch()
	mustProg(t, err)
	trie, err := ebpf.NewMap(main.Maps["rules"])
	mustProg(t, err)
	t.Cleanup(func() { mustProg(t, trie.Close()) })
	spec, err := snitchbpf.LoadDns()
	mustProg(t, err)
	if skipQuestion {
		mustProg(t, spec.Variables["test_skip_question"].Set(uint32(1)))
	}
	c, err := ebpf.NewCollectionWithOptions(spec, ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{"rules": trie}})
	mustProg(t, err)
	t.Cleanup(c.Close)
	return c, trie
}

func putResolver(t *testing.T, c *ebpf.Collection, addr string) {
	t.Helper()
	// the daemon's own key encoding, so the kernel's lookup is proved against it
	k := snitchbpf.DnsResolverKey{Addr: ResolverKey(netip.MustParseAddr(addr))}
	mustProg(t, c.Maps["resolvers"].Put(k, uint32(1)))
}

func putDomain(t *testing.T, c *ebpf.Collection, name string, slots []Slot) {
	t.Helper()
	v := snitchbpf.DnsDomainVal{}
	for i, s := range slots {
		v.Slot[i] = snitchbpf.DnsDomainSlot{Program: s.Program, Proto: uint8(s.Proto), Port: s.Port, Id: s.ID}
	}
	mustProg(t, c.Maps["domains"].Put(key(name), v))
}

func progStats(t *testing.T, c *ebpf.Collection) Stats {
	t.Helper()
	values := make([]uint64, 11)
	for i := range values {
		mustProg(t, c.Maps["dns_stats"].Lookup(uint32(i), &values[i]))
	}
	s, err := DecodeStats(values)
	mustProg(t, err)
	return s
}

func progTrie(t *testing.T, trie *ebpf.Map) map[rules.RuleKey]rules.RuleVal {
	t.Helper()
	out := map[rules.RuleKey]rules.RuleVal{}
	var k rules.RuleKey
	var v rules.RuleVal
	it := trie.Iterate()
	for it.Next(&k, &v) {
		out[k] = v
	}
	mustProg(t, it.Err())
	return out
}

func progKey(addr netip.Addr, s Slot) rules.RuleKey {
	k := rules.RuleKey{Prefixlen: 64 + uint32(addr.BitLen()), Program: s.Program, Proto: uint8(s.Proto), Port: s.Port, Family: 10}
	if addr.Is4() {
		k.Family = 2
		a := addr.As4()
		copy(k.Addr[:], a[:])
	} else {
		k.Addr = addr.As16()
	}
	return k
}

func progReader(t *testing.T, c *ebpf.Collection) *ringbuf.Reader {
	t.Helper()
	r, err := ringbuf.NewReader(c.Maps["dns_answers"])
	mustProg(t, err)
	t.Cleanup(func() { mustProg(t, r.Close()) })
	return r
}

func checkProgRecord(t *testing.T, r *ringbuf.Reader, want *Record) {
	t.Helper()
	r.SetDeadline(time.Now().Add(200 * time.Millisecond))
	raw, err := r.Read()
	if want == nil {
		if !errors.Is(err, os.ErrDeadlineExceeded) {
			t.Fatalf("unexpected record: %+v, %v", raw, err)
		}
		return
	}
	mustProg(t, err)
	got, err := Decode(raw.RawSample)
	mustProg(t, err)
	equalProg(t, got, *want)
	checkProgRecord(t, r, nil)
}

func equalProg(t *testing.T, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %#v; want %#v", got, want)
	}
}

func runDNSProg(t *testing.T, c *ebpf.Collection, name string, frame []byte) {
	t.Helper()
	ret, err := c.Programs[name].Run(&ebpf.RunOptions{Data: frame})
	mustProg(t, err)
	equalProg(t, ret, uint32(1))
}

func progQuestions(t *testing.T, c *ebpf.Collection) map[snitchbpf.DnsQ_key]snitchbpf.DnsQ_val {
	t.Helper()
	out := map[snitchbpf.DnsQ_key]snitchbpf.DnsQ_val{}
	var k snitchbpf.DnsQ_key
	var v snitchbpf.DnsQ_val
	it := c.Maps["questions"].Iterate()
	for it.Next(&k, &v) {
		out[k] = v
	}
	mustProg(t, it.Err())
	return out
}
