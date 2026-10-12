// DNS facts and names are projections only; an unavailable tap preserves address-only events.
package main

import (
	"fmt"
	"net/netip"

	"github.com/norandom/snitch/internal/api"
)

func (s *dnsState) nameOf(addr netip.Addr, ruleID uint32) string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.on {
		return ""
	}
	if name, ok := s.comp.NameOf(addr, ruleID); ok {
		return name
	}
	if names := s.cache.Names(addr); len(names) != 0 {
		return names[0]
	}
	return ""
}

func (s *dnsState) facts() *api.DNSStatus {
	if s == nil {
		return &api.DNSStatus{Reason: "unavailable"}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	f := &api.DNSStatus{On: s.on, Reason: s.reason}
	if !s.on {
		return f
	}
	entries, names := s.cache.Len()
	f.Entries, f.Names = uint64(entries), uint64(names)
	f.Compiled, f.Evictions = uint64(s.comp.Len()), s.cache.Evictions()
	if s.stats != nil {
		stats, err := s.stats()
		if err != nil {
			// Keep the tap on and its sizes visible; a failed read supplies no counters.
			f.Reason = "stats: " + err.Error()
		} else {
			f.Seen = stats.Seen
			f.Ignored = stats.NotResolver + stats.NotAnswer + stats.NoQuestion + stats.NameTooLong
		}
	}
	return f
}

func (s *dnsState) recordLine() string {
	f := s.facts()
	if !f.On {
		return "off: " + f.Reason
	}
	return fmt.Sprintf("on seen %d ignored %d cache %d names %d compiled %d", f.Seen, f.Ignored, f.Entries, f.Names, f.Compiled)
}
