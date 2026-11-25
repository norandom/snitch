package main

import (
	"errors"
	"reflect"
	"testing"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/dns"
)

// perCPU gives key k the values k*10+1 and k*10+2 on two CPUs, so each sum is 20k+3.
func perCPU(k uint32, out *[]uint64) error {
	*out = []uint64{uint64(k)*10 + 1, uint64(k)*10 + 2}
	return nil
}

func TestEgressCountersSumPerCPUInEnumOrder(t *testing.T) {
	got := egressCounters(perCPU)
	want := api.ProgramCounters{Available: true,
		Counters:  map[string]uint64{"decisions": 3, "addr_unreadable": 23, "no_exe": 43, "event_lost": 63},
		Contracts: map[string]uint64{"kill_slot": 83, "control_slot": 103, "rule_verdict": 123, "mode": 143}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

func TestEgressCountersZeroKeepsEveryKey(t *testing.T) {
	got := egressCounters(func(_ uint32, out *[]uint64) error { *out = []uint64{0, 0}; return nil })
	if !got.Available || len(got.Counters) != 4 || len(got.Contracts) != 4 {
		t.Fatalf("%+v", got)
	}
	for _, name := range egressContractNames {
		if v, ok := got.Contracts[name]; !ok || v != 0 {
			t.Errorf("contract %s: %d present %v, want 0 present", name, v, ok)
		}
	}
}

func TestEgressCountersUnreadable(t *testing.T) {
	got := egressCounters(func(k uint32, out *[]uint64) error {
		if k == 5 {
			return errors.New("lookup failed")
		}
		return perCPU(k, out)
	})
	if got.Available || got.Reason == "" || got.Counters != nil || got.Contracts != nil {
		t.Fatalf("an unreadable map must be unavailable with no zeros: %+v", got)
	}
}

func TestDNSContractCounters(t *testing.T) {
	read := func() (dns.Contracts, error) { return dns.Contracts{NameShape: 2, DotRange: 7}, nil }
	got := dnsContractCounters(read, true, "")
	want := api.ProgramCounters{Available: true, Contracts: map[string]uint64{"name_shape": 2, "dot_range": 7}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v want %+v", got, want)
	}
	zero := dnsContractCounters(func() (dns.Contracts, error) { return dns.Contracts{}, nil }, true, "")
	if !zero.Available || !reflect.DeepEqual(zero.Contracts, map[string]uint64{"name_shape": 0, "dot_range": 0}) {
		t.Fatalf("zero contracts must all be present: %+v", zero)
	}
}

func TestDNSContractCountersUnavailable(t *testing.T) {
	boom := func() (dns.Contracts, error) { return dns.Contracts{}, errors.New("lookup failed") }
	for name, got := range map[string]api.ProgramCounters{
		"off":       dnsContractCounters(nil, false, "flag"),
		"unread":    dnsContractCounters(boom, true, ""),
		"no reader": dnsContractCounters(nil, true, ""),
	} {
		if got.Available || got.Reason == "" || got.Contracts != nil || got.Counters != nil {
			t.Errorf("%s: %+v", name, got)
		}
	}
	if got := dnsContractCounters(nil, false, "flag"); got.Reason != "flag" {
		t.Errorf("an off tap keeps the dns object's reason: %q", got.Reason)
	}
}

func TestCountersStatusAssembles(t *testing.T) {
	egress := egressCounters(perCPU)
	tap := dnsContractCounters(nil, false, "flag")
	got := countersStatus(egress, tap)
	if got == nil || !reflect.DeepEqual(got.Egress, egress) || !reflect.DeepEqual(got.DNS, tap) {
		t.Fatalf("%+v", got)
	}
}

func TestReadDNSContractsTail(t *testing.T) {
	var keys []uint32
	got, err := readDNSContracts(func(k, v any) error {
		keys = append(keys, k.(uint32))
		*v.(*uint64) = uint64(k.(uint32))
		return nil
	})
	want := dns.Contracts{NameShape: dns.StatsCount, DotRange: dns.StatsCount + 1}
	if err != nil || got != want || !reflect.DeepEqual(keys, []uint32{dns.StatsCount, dns.StatsCount + 1}) {
		t.Fatalf("%+v %v keys %v", got, err, keys)
	}
	boom := errors.New("stats unavailable")
	if got, err := readDNSContracts(func(any, any) error { return boom }); !errors.Is(err, boom) || got != (dns.Contracts{}) {
		t.Fatalf("%+v %v", got, err)
	}
}

// The name tables cover snitch_stats exactly, so a slot added in the C fails here.
func TestEgressNamesMatchMapSize(t *testing.T) {
	spec, err := bpf.LoadSnitch()
	if err != nil {
		t.Fatal(err)
	}
	if n, want := int(spec.Maps["snitch_stats"].MaxEntries), len(egressCounterNames)+len(egressContractNames); n != want {
		t.Fatalf("snitch_stats has %d entries, the name tables %d", n, want)
	}
}

// The contract names cover the dns_stats tail after the dns_stat counters exactly.
func TestDNSContractNamesMatchMapSize(t *testing.T) {
	spec, err := bpf.LoadDns()
	if err != nil {
		t.Fatal(err)
	}
	if n, want := int(spec.Maps["dns_stats"].MaxEntries)-dns.StatsCount, len(dnsContractNames); n != want {
		t.Fatalf("dns_stats has %d entries after dns.StatsCount, the name table %d", n, want)
	}
	if len(dnsContractNames) != dns.ContractsCount {
		t.Fatalf("dns.ContractsCount %d, the name table %d", dns.ContractsCount, len(dnsContractNames))
	}
}
