// Counters reader: the kernel programs' own counters as the status's counters object (5.1).
// Lookups are function values, so the sums and the unavailable cases test without root.
package main

import (
	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/dns"
)

// Names in enum snitch_stat order (bpf/snitch.bpf.c): indices 0..3 are the program's own
// counters, 4..7 its runtime contracts. Together they cover every snitch_stats slot.
var (
	egressCounterNames  = []string{"decisions", "addr_unreadable", "no_exe", "event_lost"}
	egressContractNames = []string{"kill_slot", "control_slot", "rule_verdict", "mode"}
)

// perCPULookup fills out with one value per CPU for a snitch_stats key.
type perCPULookup func(key uint32, out *[]uint64) error

// egressCounters sums each snitch_stats slot over the CPUs: totals since load (5.2). A failed
// lookup makes the whole section unavailable, never zeros (5.5).
func egressCounters(lookup perCPULookup) api.ProgramCounters {
	n := len(egressCounterNames)
	sums := make([]uint64, n+len(egressContractNames))
	for i := range sums {
		var perCPU []uint64
		if err := lookup(uint32(i), &perCPU); err != nil {
			return unavailable("snitch_stats: " + err.Error())
		}
		for _, v := range perCPU {
			sums[i] += v
		}
	}
	return api.ProgramCounters{Available: true,
		Counters: named(egressCounterNames, sums[:n]), Contracts: named(egressContractNames, sums[n:])}
}

// dnsContractCounters reports the tap's contracts; an off tap is unavailable with the same
// reason the dns object gives, a failed read with the read's error.
func dnsContractCounters(read func() (dns.Contracts, error), on bool, reason string) api.ProgramCounters {
	if !on {
		return unavailable(reason)
	}
	if read == nil {
		return unavailable("dns_stats: no reader")
	}
	c, err := read()
	if err != nil {
		return unavailable("dns_stats: " + err.Error())
	}
	return api.ProgramCounters{Available: true,
		Contracts: map[string]uint64{"name_shape": c.NameShape, "dot_range": c.DotRange}}
}

func countersStatus(egress, dnsTap api.ProgramCounters) *api.CountersStatus {
	return &api.CountersStatus{Egress: egress, DNS: dnsTap}
}

func unavailable(reason string) api.ProgramCounters {
	return api.ProgramCounters{Reason: reason}
}

func named(names []string, values []uint64) map[string]uint64 {
	m := make(map[string]uint64, len(names))
	for i, name := range names {
		m[name] = values[i]
	}
	return m
}
