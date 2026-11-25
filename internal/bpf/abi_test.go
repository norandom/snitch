// The ABI test reads the kernel programs' own type information from the embedded objects, so
// a struct that drifted between the C and the daemon's Go view fails here without root (3.5).
// It is an external test package because internal/rules and internal/dns import this one.
package bpf_test

import (
	"fmt"
	"strings"
	"testing"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"

	"github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/dns"
	"github.com/norandom/snitch/internal/rules"
)

type structCase struct {
	name   string  // the C struct as the kernel programs' BTF names it
	daemon uintptr // the daemon's size of its Go view of that struct
}

type mapCase struct {
	name       string // map name in the object
	key, value uintptr
}

// sizeMismatch names the structure and the unit (bytes, elements, entries) so a failure says
// what drifted, not only two numbers.
func sizeMismatch(what, unit string, kernel, daemon uintptr) error {
	if kernel == daemon {
		return nil
	}
	return fmt.Errorf("%s: kernel BTF says %d %s, the daemon's Go view %d", what, kernel, unit, daemon)
}

func loadSpecs(t *testing.T) (snitch, dnsSpec *ebpf.CollectionSpec) {
	t.Helper()
	snitch, err := bpf.LoadSnitch()
	if err != nil {
		t.Fatal(err)
	}
	dnsSpec, err = bpf.LoadDns()
	if err != nil {
		t.Fatal(err)
	}
	return snitch, dnsSpec
}

func btfStructSize(t *testing.T, spec *ebpf.CollectionSpec, name string) uintptr {
	t.Helper()
	var s *btf.Struct
	if err := spec.Types.TypeByName(name, &s); err != nil {
		t.Fatalf("struct %s: %v", name, err)
	}
	return uintptr(s.Size)
}

func TestABIStructSizes(t *testing.T) {
	snitch, dnsSpec := loadSpecs(t)
	sets := []struct {
		spec  *ebpf.CollectionSpec
		cases []structCase
	}{
		{snitch, []structCase{
			{"event", unsafe.Sizeof(bpf.SnitchEvent{})},
			{"rule_key", unsafe.Sizeof(bpf.SnitchRuleKey{})},
			{"rule_key", unsafe.Sizeof(rules.RuleKey{})},
			{"exe_key", unsafe.Sizeof(bpf.SnitchExeKey{})},
			{"control_state", unsafe.Sizeof(bpf.SnitchControlState{})},
			{"rule_val", unsafe.Sizeof(bpf.SnitchRuleVal{})},
			{"rule_val", unsafe.Sizeof(rules.RuleVal{})},
			{"byte_count", unsafe.Sizeof(bpf.SnitchByteCount{})},
		}},
		{dnsSpec, []structCase{
			{"dns_answer_record", unsafe.Sizeof(bpf.DnsDnsAnswerRecord{})},
			{"domain_key", unsafe.Sizeof(bpf.DnsDomainKey{})},
			{"domain_val", unsafe.Sizeof(bpf.DnsDomainVal{})},
			{"domain_slot", unsafe.Sizeof(bpf.DnsDomainSlot{})},
			{"resolver_key", unsafe.Sizeof(bpf.DnsResolverKey{})},
			{"q_key", unsafe.Sizeof(bpf.DnsQ_key{})},
			{"q_val", unsafe.Sizeof(bpf.DnsQ_val{})},
			// the tap's own copy of the trie types must equal the daemon's, which is Snitch's
			{"rule_key", unsafe.Sizeof(rules.RuleKey{})},
			{"rule_val", unsafe.Sizeof(rules.RuleVal{})},
		}},
	}
	for _, set := range sets {
		for _, c := range set.cases {
			if err := sizeMismatch("struct "+c.name, "bytes", btfStructSize(t, set.spec, c.name), c.daemon); err != nil {
				t.Error(err)
			}
		}
	}
}

func TestABIMapSizes(t *testing.T) {
	snitch, dnsSpec := loadSpecs(t)
	u32, u64 := unsafe.Sizeof(uint32(0)), unsafe.Sizeof(uint64(0))
	sets := []struct {
		spec  *ebpf.CollectionSpec
		cases []mapCase
	}{
		{snitch, []mapCase{
			{"rules", unsafe.Sizeof(rules.RuleKey{}), unsafe.Sizeof(rules.RuleVal{})},
			{"programs", unsafe.Sizeof(bpf.SnitchExeKey{}), u32},
			{"control", u32, unsafe.Sizeof(bpf.SnitchControlState{})},
			{"kill", u32, u32},
			{"bytes", u64, unsafe.Sizeof(bpf.SnitchByteCount{})},
			{"snitch_stats", u32, u64},
		}},
		{dnsSpec, []mapCase{
			// MapReplacements hands the tap Snitch's trie, so its declared sizes must match
			{"rules", unsafe.Sizeof(rules.RuleKey{}), unsafe.Sizeof(rules.RuleVal{})},
			{"domains", unsafe.Sizeof(bpf.DnsDomainKey{}), unsafe.Sizeof(bpf.DnsDomainVal{})},
			{"resolvers", unsafe.Sizeof(bpf.DnsResolverKey{}), u32},
			{"questions", unsafe.Sizeof(bpf.DnsQ_key{}), unsafe.Sizeof(bpf.DnsQ_val{})},
			{"dns_stats", u32, u64},
		}},
	}
	for _, set := range sets {
		for _, c := range set.cases {
			m, ok := set.spec.Maps[c.name]
			if !ok {
				t.Fatalf("map %s missing", c.name)
			}
			for _, err := range []error{
				sizeMismatch("map "+c.name+" key", "bytes", uintptr(m.KeySize), c.key),
				sizeMismatch("map "+c.name+" value", "bytes", uintptr(m.ValueSize), c.value),
			} {
				if err != nil {
					t.Error(err)
				}
			}
		}
	}
}

// The DNS package keeps hand-written limits that size its keys and loops; they must equal the
// array lengths the kernel's structs give the generated types.
func TestABIHandMirrors(t *testing.T) {
	_, dnsSpec := loadSpecs(t)
	var rec bpf.DnsDnsAnswerRecord
	cases := []struct {
		name, unit   string
		kernel, hand int
	}{
		{"domain_key.name (dns.NameMax)", "elements", len(bpf.DnsDomainKey{}.Name), dns.NameMax},
		{"dns_answer_record.qname (dns.NameMax)", "elements", len(rec.Qname), dns.NameMax},
		{"q_val.qname (dns.NameMax)", "elements", len(bpf.DnsQ_val{}.Qname), dns.NameMax},
		{"domain_val.slot (dns.SlotsMax)", "elements", len(bpf.DnsDomainVal{}.Slot), dns.SlotsMax},
		{"domain_val.slot (rules.NameSlots)", "elements", len(bpf.DnsDomainVal{}.Slot), rules.NameSlots},
		// dns_stats holds the eleven fixed counters, then the contract counters task 4.3 appended
		{"dns_stats (dns.StatsCount + dns.ContractsCount)", "entries",
			int(dnsSpec.Maps["dns_stats"].MaxEntries), dns.StatsCount + dns.ContractsCount},
	}
	for _, c := range cases {
		if err := sizeMismatch(c.name, c.unit, uintptr(c.kernel), uintptr(c.hand)); err != nil {
			t.Error(err)
		}
	}
}

// A wrong expected size must fail and say which structure, or the test above proves nothing.
func TestABIMismatchNamesStructure(t *testing.T) {
	_, dnsSpec := loadSpecs(t)
	kernel := btfStructSize(t, dnsSpec, "domain_slot")
	err := sizeMismatch("struct domain_slot", "bytes", kernel, kernel+1)
	if err == nil {
		t.Fatal("a wrong size for domain_slot passed")
	}
	if !strings.Contains(err.Error(), "domain_slot") {
		t.Fatalf("mismatch does not name the structure: %v", err)
	}
	if sizeMismatch("struct domain_slot", "bytes", kernel, kernel) != nil {
		t.Fatal("equal sizes reported as a mismatch")
	}
}
