// The status reply carries the counters object (5.1, 5.3): both sections from the daemon's
// lookups, every local reader of status gets it, and an unreadable map never drops the reply.
package main

import (
	"errors"
	"reflect"
	"testing"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/dns"
)

func zeroPerCPU(_ uint32, out *[]uint64) error { *out = []uint64{0, 0}; return nil }

func TestFactsServeBothCounterSections(t *testing.T) {
	var logs []string
	d := newAPIDaemon(t, sourceFlag, &logs)
	d.api.egressStats = zeroPerCPU
	d.dns = &dnsState{on: true, contracts: func() (dns.Contracts, error) { return dns.Contracts{}, nil }}
	got := d.facts().Counters
	if got == nil {
		t.Fatal("the status reply has no counters object")
	}
	if !got.Egress.Available || !got.DNS.Available {
		t.Fatalf("both sections must be available: %+v", got)
	}
	for section, contracts := range map[string]map[string]uint64{"egress": got.Egress.Contracts, "dns": got.DNS.Contracts} {
		for name, v := range contracts {
			if v != 0 {
				t.Errorf("%s contract %s = %d, want 0", section, name, v)
			}
		}
	}
	if len(got.Egress.Contracts) != len(egressContractNames) || len(got.DNS.Contracts) != len(dnsContractNames) {
		t.Fatalf("every contract name must be present: %+v", got)
	}
	if len(got.Egress.Counters) != len(egressCounterNames) {
		t.Fatalf("egress counters: %+v", got.Egress.Counters)
	}
}

// 5.5 through the reply: an unreadable snitch_stats makes egress unavailable, the reply and the
// dns section stay; an off tap gives the dns object's reason, an absent one "unavailable".
func TestFactsCountersUnavailableSections(t *testing.T) {
	var logs []string
	d := newAPIDaemon(t, sourceFlag, &logs)
	d.api.egressStats = func(uint32, *[]uint64) error { return errors.New("lookup failed") }
	d.dns = &dnsState{on: false, reason: "flag"}
	got := d.facts()
	if !got.Running || got.Counters == nil {
		t.Fatalf("the reply must still be produced with counters: %+v", got)
	}
	want := &api.CountersStatus{Egress: api.ProgramCounters{Reason: "snitch_stats: lookup failed"},
		DNS: api.ProgramCounters{Reason: "flag"}}
	if !reflect.DeepEqual(got.Counters, want) {
		t.Fatalf("got %+v\nwant %+v", got.Counters, want)
	}
	if got.DNS.Reason != got.Counters.DNS.Reason {
		t.Fatalf("dns reasons differ: %q vs %q", got.DNS.Reason, got.Counters.DNS.Reason)
	}
	d.dns, d.api.egressStats = nil, nil
	got = d.facts()
	if got.Counters == nil || got.Counters.Egress.Available || got.Counters.Egress.Reason == "" ||
		!reflect.DeepEqual(got.Counters.DNS, api.ProgramCounters{Reason: "unavailable"}) {
		t.Fatalf("absent lookups: %+v", got.Counters)
	}
}

// The tap's contract reader lives exactly as long as its stats reader.
func TestDNSContractsReaderFollowsTheTap(t *testing.T) {
	f := newDNSFixture()
	s := loadDNSWith(config{dns: true}, nil, f.deps)
	if !s.on || s.contracts == nil {
		t.Fatalf("on tap without a contracts reader: on %v", s.on)
	}
	s.off(errors.New("gone"))
	if s.contracts != nil || s.counters().Reason != "gone" {
		t.Fatalf("off tap keeps its reader: %+v", s.counters())
	}
}
