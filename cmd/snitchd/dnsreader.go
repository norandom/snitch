// The reader mirrors allow-only keys and never touches file keys. A wedged reader
// cannot block the LSM path: the kernel makes its decisions without this job.
package main

import (
	"context"
	"errors"
	"github.com/cilium/ebpf"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/dns"
	"github.com/norandom/snitch/internal/rules"
	"net/netip"
	"os"
)

func (s *dnsState) reader(ctx context.Context) error {
	for ctx.Err() == nil {
		raw, err := s.read()
		if errors.Is(err, os.ErrDeadlineExceeded) || os.IsTimeout(err) {
			continue
		}
		if !s.noteRead(err) {
			continue
		}
		rec, err := dns.Decode(raw)
		if err != nil {
			s.malformed++
			continue
		}
		s.handle(rec)
	}
	return ctx.Err()
}

func (s *dnsState) noteRead(err error) bool {
	if err == nil {
		s.readFailing = false
		return true
	}
	s.readErrors++
	if !s.readFailing {
		s.log("dns reader: " + err.Error())
		s.readFailing = true
	}
	return false
}

func (s *dnsState) handle(rec dns.Record) {
	s.mu.Lock()
	defer s.mu.Unlock()
	contract.Require(s.current != nil, "handle needs a snapshot accessor")
	snap := s.current()
	contract.Require(snap != nil, "handle needs a snapshot")
	for _, ch := range s.cache.Learn(rec.Name, rec.Addrs, rec.TTL, s.now()) {
		s.change(snap, ch)
	}
	for _, addr := range rec.Addrs {
		s.correctSlots(snap, rec.Slots, addr)
	}
	s.flush(snap)
	s.noteCapacity()
	for s.comp.Len() > s.cap {
		if !s.evictOne(snap) {
			break
		}
	}
}

func (s *dnsState) change(snap *snapshot, ch dns.Change) {
	var want map[rules.RuleKey]dns.Entry
	if !ch.Gone {
		want = s.comp.Compute(snap.res, ch.Addr, ch.Names)
	}
	puts, dels := s.comp.Apply(ch.Addr, want, snap.ent.Rules)
	s.queue(puts, dels)
}

func (s *dnsState) correctSlots(snap *snapshot, slots []dns.Slot, addr netip.Addr) {
	want := s.comp.Compute(snap.res, addr, s.cache.Names(addr))
	for _, slot := range slots {
		r := rules.Rule{Proto: slot.Proto, Ports: []uint16{slot.Port}, Verdict: rules.Allow}
		k, _ := rules.EncodeAddr(&r, slot.Program, addr)
		_, wanted := want[k]
		_, owned := snap.ent.Rules[k]
		if !wanted && !owned {
			s.queue(nil, []rules.RuleKey{k})
		}
	}
}

// Pending operations survive map failures; newer diffs replace them, and every
// retry checks current file ownership before touching the trie.
func (s *dnsState) queue(puts map[rules.RuleKey]rules.RuleVal, dels []rules.RuleKey) {
	if s.pending == nil {
		s.pending = make(map[rules.RuleKey]*rules.RuleVal)
	}
	for k, v := range puts {
		s.pending[k] = &v
	}
	for _, k := range dels {
		s.pending[k] = nil
	}
}

func (s *dnsState) flush(snap *snapshot) {
	failed := false
	for _, deleting := range []bool{false, true} {
		for k, v := range s.pending {
			if _, owned := snap.ent.Rules[k]; owned {
				delete(s.pending, k)
				continue
			}
			if (v == nil) != deleting {
				continue
			}
			err := s.writeKey(k, v)
			if err != nil {
				failed = true
				s.noteMap(err)
				continue
			}
			delete(s.pending, k)
		}
	}
	if !failed {
		s.mapFailing = false
	}
}

func (s *dnsState) writeKey(k rules.RuleKey, v *rules.RuleVal) error {
	if v != nil {
		return s.rules.put(k, *v)
	}
	err := s.rules.del(k)
	if errors.Is(err, ebpf.ErrKeyNotExist) {
		return nil
	}
	return err
}

func (s *dnsState) noteMap(err error) {
	s.mapErrors++
	if !s.mapFailing {
		s.log("dns rules: " + err.Error())
		s.mapFailing = true
	}
}

func (s *dnsState) evictOne(snap *snapshot) bool {
	addr, ok := s.cache.Evict()
	if !ok {
		return false
	}
	_, dels := s.comp.Apply(addr, nil, snap.ent.Rules)
	s.queue(nil, dels)
	s.flush(snap)
	return true
}

// evictSome is bounded so a full file put never waits for an unbounded purge.
func (s *dnsState) evictSome() bool { return s.evictSomeFor(s.current().ent.Rules) }

func (s *dnsState) evictSomeFor(file map[rules.RuleKey]rules.RuleVal) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	snap := &snapshot{ent: rules.Entries{Rules: file}}
	evicted := false
	for range 64 {
		if !s.evictOne(snap) {
			break
		}
		evicted = true
	}
	return evicted
}

func (s *dnsState) noteCapacity() {
	full := s.comp.Len() > s.cap
	if full && !s.capacityFailing {
		s.log("dns compiled capacity: evicting allows")
	}
	s.capacityFailing = full
}
