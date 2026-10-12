// The DNS tap can only add allows. Off or failed preserves today's decisions;
// its unpinned links die with the daemon, and the job releases its objects on exit.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/dns"
	"github.com/norandom/snitch/internal/rules"
)

const resolvPath = "/etc/resolv.conf"

type dnsState struct {
	domainKeys                       map[[64]byte]struct{}
	capacityFailing                  bool
	read                             func() ([]byte, error)
	current                          func() *snapshot
	cap                              int
	readErrors, mapErrors, malformed uint64
	readFailing, mapFailing          bool
	pending                          map[rules.RuleKey]*rules.RuleVal
	readerClose                      io.Closer
	on                               bool
	reason                           string
	objs                             *bpf.DnsObjects
	cache                            dns.Cache
	comp                             dns.Compiled
	// Held briefly, never while reading the ring buffer. Lock order: reloader then
	// dnsState; the reader never takes the reloader's lock.
	mu                        sync.Mutex
	rules, domains, resolvers putDel
	stats                     func() (dns.Stats, error)
	now                       func() time.Time
	log                       func(string)
	links                     []io.Closer
	closeObjects              func(*bpf.DnsObjects) error
	readResolv                func() ([]byte, error)
	stamp                     func() (fileStamp, error)
	lastStamp                 fileStamp
	trusted                   map[bpf.DnsResolverKey]bool
}

type dnsDeps struct {
	mounts       func() (io.ReadCloser, error)
	load         func(*bpf.DnsObjects, *ebpf.CollectionOptions) error
	closeObjects func(*bpf.DnsObjects) error
	ops          func(*ebpf.Map) putDel
	attach       func(link.CgroupOptions) (io.Closer, error)
	readResolv   func() ([]byte, error)
	stamp        func() (fileStamp, error)
	now          func() time.Time
	log          func(string)
}

func loadDNS(d *daemon) *dnsState {
	deps := dnsDeps{
		mounts:       func() (io.ReadCloser, error) { return os.Open(mountsPath) },
		load:         func(o *bpf.DnsObjects, opts *ebpf.CollectionOptions) error { return bpf.LoadDnsObjects(o, opts) },
		closeObjects: func(o *bpf.DnsObjects) error { return o.Close() }, ops: mapOps,
		attach:     func(o link.CgroupOptions) (io.Closer, error) { return link.AttachCgroup(o) },
		readResolv: func() ([]byte, error) { return os.ReadFile(resolvPath) },
		stamp: func() (fileStamp, error) {
			s, ok := stampOf(resolvPath)
			if !ok {
				return s, os.ErrNotExist
			}
			return s, nil
		},
		now: time.Now, log: d.log,
	}
	s := loadDNSWith(d.cfg, d.objs.Rules, deps)
	s.current = d.st.current
	if s.on {
		rd, err := ringbuf.NewReader(s.objs.DnsAnswers)
		if err != nil {
			return s.off(err)
		}
		s.readerClose = rd
		s.read = func() ([]byte, error) {
			rd.SetDeadline(time.Now().Add(500 * time.Millisecond))
			rec, err := rd.Read()
			return rec.RawSample, err
		}
	}
	return s
}

func loadDNSWith(cfg config, trie *ebpf.Map, deps dnsDeps) *dnsState {
	s := &dnsState{cap: dns.Max, now: deps.now, log: deps.log, readResolv: deps.readResolv, stamp: deps.stamp,
		closeObjects: deps.closeObjects, trusted: make(map[bpf.DnsResolverKey]bool)}
	if !cfg.dns {
		return s.off(errors.New("flag"))
	}
	s.objs = &bpf.DnsObjects{}
	opts := &ebpf.CollectionOptions{MapReplacements: map[string]*ebpf.Map{"rules": trie}}
	if err := deps.load(s.objs, opts); err != nil {
		return s.off(err)
	}
	s.rules, s.domains, s.resolvers = deps.ops(trie), deps.ops(s.objs.Domains), deps.ops(s.objs.Resolvers)
	s.stats = func() (dns.Stats, error) { return readDNSStats(s.objs.DnsStats.Lookup) }
	// Stamp before reading so a concurrent replacement is noticed on the next tick.
	s.lastStamp, _ = s.stamp()
	if err := s.refreshResolvers(); err != nil {
		return s.off(err)
	}
	if err := s.attach(deps); err != nil {
		return s.off(err)
	}
	s.on = true
	s.log(fmt.Sprintf("dns tap on: %d resolvers", len(s.trusted)))
	return s
}

func (s *dnsState) attach(deps dnsDeps) error {
	f, err := deps.mounts()
	if err != nil {
		return err
	}
	defer f.Close()
	root, ok := cgroupRoot(f)
	if !ok {
		return errors.New("no cgroup2 mount in " + mountsPath)
	}
	for _, o := range []link.CgroupOptions{
		{Path: root, Attach: ebpf.AttachCGroupInetEgress, Program: s.objs.DnsQuery},
		{Path: root, Attach: ebpf.AttachCGroupInetIngress, Program: s.objs.DnsAnswer},
	} {
		l, err := deps.attach(o)
		if err != nil {
			return err
		}
		s.links = append(s.links, l)
	}
	return nil
}

func (s *dnsState) off(err error) *dnsState {
	s.close()
	s.on, s.reason = false, err.Error()
	s.stats = nil
	s.rules, s.domains, s.resolvers = putDel{}, putDel{}, putDel{}
	s.log("dns tap off: " + s.reason)
	return s
}

func (s *dnsState) close() {
	if s.readerClose != nil {
		_ = s.readerClose.Close()
		s.readerClose = nil
	}
	for _, l := range s.links {
		_ = l.Close()
	}
	s.links = nil
	if s.objs != nil {
		_ = s.closeObjects(s.objs)
		s.objs = nil
	}
}

func readDNSStats(lookup func(any, any) error) (dns.Stats, error) {
	counters := make([]uint64, 11)
	for i := range counters {
		if err := lookup(uint32(i), &counters[i]); err != nil {
			return dns.Stats{}, err
		}
	}
	return dns.DecodeStats(counters)
}
