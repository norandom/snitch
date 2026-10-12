// Resolver jobs bound which answers can add allows. Unreadable configuration
// removes trust; off or failed leaves existing decisions alone, and links die on exit.
package main

import (
	"bytes"
	"context"
	"errors"

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
	// Reader and expiry jobs join this list in task 2.2; one owner closes after all finish.
	js := []jobs.Job{jobs.Every(filePollPeriod, s.watchResolv)}
	return []jobs.Job{func(ctx context.Context) error { defer s.close(); return jobs.Run(ctx, js...) }}
}
