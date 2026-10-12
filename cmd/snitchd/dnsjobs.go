// Resolver jobs bound which answers can add allows. Unreadable configuration
// removes trust; off or failed leaves existing decisions alone, and links die on exit.
package main

import (
	"bytes"
	"context"
	"errors"
	"time"

	"github.com/cilium/ebpf"
	"github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/dns"
	"github.com/norandom/snitch/internal/jobs"
)

func (s *dnsState) refreshResolvers() error {
	raw, err := s.readResolv()
	if err != nil {
		raw = nil
	}
	want := make(map[bpf.DnsResolverKey]bool)
	for _, a := range dns.Resolvers(bytes.NewReader(raw)) {
		want[bpf.DnsResolverKey{Addr: dns.ResolverKey(a)}] = true
	}
	if err := s.removeResolvers(want); err != nil {
		return err
	}
	for k := range want {
		if s.trusted[k] {
			continue
		}
		if err := s.resolvers.put(k, uint32(1)); err != nil {
			return err
		}
		s.trusted[k] = true
	}
	s.reason = ""
	if len(want) == 0 {
		s.reason = "no resolvers"
	}
	return nil
}

func (s *dnsState) removeResolvers(want map[bpf.DnsResolverKey]bool) error {
	// Remove old trust first: a full resolver map must still permit replacement.
	for k := range s.trusted {
		if want[k] {
			continue
		}
		if err := s.resolvers.del(k); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return err
		}
		delete(s.trusted, k)
	}
	return nil
}

func (s *dnsState) watchResolv(context.Context) error {
	now, err := s.stamp()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err == nil && now == s.lastStamp {
		return nil
	}
	if err := s.refreshResolvers(); err != nil {
		s.log("dns resolvers: " + err.Error())
		return nil // Keep retrying without stopping the existing daemon.
	}
	s.lastStamp = now
	return nil
}

func (d *daemon) dnsJobs(_ *reloader) []jobs.Job {
	if d.dns == nil || !d.dns.on {
		return nil
	}
	s := d.dns
	// One owner closes the ring reader and objects after all jobs finish.
	js := []jobs.Job{s.reader, jobs.Every(2*time.Second, s.expire), jobs.Every(filePollPeriod, s.watchResolv)}
	return []jobs.Job{func(ctx context.Context) error { defer s.close(); return jobs.Run(ctx, js...) }}
}

// expire is one tick; remaining names are recomputed so partial expiry preserves allows.
func (s *dnsState) expire(context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := s.current()
	for _, ch := range s.cache.Expire(s.now()) {
		s.change(snap, ch)
	}
	s.flush(snap)
	return nil
}

// recompile holds the tap lock across both maps so readers cannot restore stale ids.
func (s *dnsState) recompile(snap *snapshot) {
	if s == nil || !s.on {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	slots, err := dns.Slots(snap.res)
	if err != nil {
		s.log("dns slots: " + err.Error())
		return
	}
	s.rewriteDomains(slots)
	puts, dels := s.comp.Recompile(snap.res, &s.cache, snap.ent.Rules)
	// A failed old put carries an obsolete id; only the new diff may be retried.
	s.pending = nil
	s.queue(puts, dels)
	s.flush(snap)
}

func (s *dnsState) rewriteDomains(slots map[[dns.NameMax]byte][dns.SlotsMax]dns.Slot) {
	if s.domainKeys == nil {
		s.domainKeys = make(map[[64]byte]struct{})
	}
	for key, slots := range slots {
		var val bpf.DnsDomainVal
		for i, slot := range slots {
			val.Slot[i] = bpf.DnsDomainSlot{Program: slot.Program, Proto: uint8(slot.Proto), Port: slot.Port, Id: slot.ID}
		}
		if err := s.domains.put(bpf.DnsDomainKey{Name: key}, val); err != nil {
			s.noteMap(err)
			continue
		}
		s.domainKeys[key] = struct{}{}
	}
	for key := range s.domainKeys {
		if _, kept := slots[key]; kept {
			continue
		}
		if err := s.domains.del(bpf.DnsDomainKey{Name: key}); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			s.noteMap(err)
			continue
		}
		delete(s.domainKeys, key)
	}
}

func (s *dnsState) evictorFor(snap *snapshot) func() bool {
	if s == nil || !s.on {
		return nil
	}
	return func() bool { return s.evictSomeFor(snap.ent.Rules) }
}

func (s *dnsState) compiledCount() int {
	if s == nil || !s.on {
		return 0
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.comp.Len()
}
