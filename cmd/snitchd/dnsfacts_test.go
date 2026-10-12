// DNS projections preserve attribution and report counters without changing decisions.
package main

import (
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/dns"
	"github.com/norandom/snitch/internal/rules"
)

func namedDNSState() *dnsState {
	s := &dnsState{on: true}
	addr := netip.MustParseAddr("1.1.1.1")
	s.cache.Learn("www.example.org", []netip.Addr{addr}, time.Minute, evNow)
	s.cache.Learn("recent.example.net", []netip.Addr{addr}, time.Minute, evNow.Add(time.Second))
	s.comp.Apply(addr, map[rules.RuleKey]dns.Entry{{}: {ID: 7, Name: "www.example.org"}}, nil)
	s.stats = func() (dns.Stats, error) {
		return dns.Stats{Seen: 42, NotResolver: 1, NotAnswer: 2, NoQuestion: 3, NameTooLong: 4, Parsed: 99}, nil
	}
	return s
}

func TestEventNameOfCompiledPrecedence(t *testing.T) {
	s := namedDNSState()
	addr := netip.MustParseAddr("1.1.1.1")
	if got := s.nameOf(addr, 7); got != "www.example.org" {
		t.Fatalf("compiled attribution: %q", got)
	}
	if got := s.nameOf(addr, 8); got != "recent.example.net" {
		t.Fatalf("recent attribution: %q", got)
	}
	if got := s.nameOf(netip.MustParseAddr("9.9.9.9"), 7); got != "" {
		t.Fatalf("unknown: %q", got)
	}
	s.on = false
	if got := s.nameOf(addr, 7); got != "" {
		t.Fatalf("off: %q", got)
	}
	var absent *dnsState
	if got := absent.nameOf(addr, 7); got != "" {
		t.Fatalf("nil: %q", got)
	}
}

func TestDNSFactsOnAndRecordLine(t *testing.T) {
	s := namedDNSState()
	s.cache.Learn("evicted.example.org", []netip.Addr{netip.MustParseAddr("9.9.9.9")}, time.Minute, evNow.Add(-time.Second))
	s.cache.Evict()
	want := &api.DNSStatus{On: true, Seen: 42, Ignored: 10, Entries: 1, Names: 2, Compiled: 1, Evictions: 1}
	if got := s.facts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("facts: %+v want %+v", got, want)
	}
	if got := s.recordLine(); got != "on seen 42 ignored 10 cache 1 names 2 compiled 1" {
		t.Fatal(got)
	}
}

func TestDNSFactsOffAndNil(t *testing.T) {
	for _, s := range []*dnsState{nil, {reason: "flag"}} {
		reason := "unavailable"
		if s != nil {
			reason = "flag"
		}
		if got := s.facts(); !reflect.DeepEqual(got, &api.DNSStatus{Reason: reason}) {
			t.Fatalf("off facts: %+v", got)
		}
		if got := s.recordLine(); got != "off: "+reason {
			t.Fatal(got)
		}
	}
}

func TestDNSFactsStatsError(t *testing.T) {
	s := namedDNSState()
	s.stats = func() (dns.Stats, error) { return dns.Stats{Seen: 99}, errors.New("lookup failed") }
	want := &api.DNSStatus{On: true, Reason: "stats: lookup failed", Entries: 1, Names: 2, Compiled: 1}
	if got := s.facts(); !reflect.DeepEqual(got, want) {
		t.Fatalf("stats error: %+v", got)
	}
}

func TestDNSFactsInAPIStatus(t *testing.T) {
	var logs []string
	d := newAPIDaemon(t, sourceFlag, &logs)
	d.dns = namedDNSState()
	if got := d.facts().DNS; !reflect.DeepEqual(got, d.dns.facts()) {
		t.Fatalf("API DNS: %+v", got)
	}
	d.dns = nil
	if got := d.facts().DNS; got == nil || got.On || got.Reason != "unavailable" {
		t.Fatalf("API nil DNS: %+v", got)
	}
}
