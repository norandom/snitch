// The tap only adds allows; failures release every resource and preserve existing decisions.
package main

import (
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/dns"
)

type dnsCloser struct{ closes *int }

func (c dnsCloser) Close() error { *c.closes++; return nil }

type dnsFixture struct {
	deps   dnsDeps
	events []string
	logs   []string
	closes int
	opts   *ebpf.CollectionOptions
}

func newDNSFixture() *dnsFixture {
	f := &dnsFixture{}
	f.deps = dnsDeps{
		mounts: func() (io.ReadCloser, error) {
			return io.NopCloser(strings.NewReader("none /cg cgroup2 rw 0 0\n")), nil
		},
		load:         func(o *bpf.DnsObjects, opts *ebpf.CollectionOptions) error { f.opts = opts; return nil },
		closeObjects: func(*bpf.DnsObjects) error { f.closes++; return nil },
		ops: func(*ebpf.Map) putDel {
			return putDel{put: func(k, v any) error { f.events = append(f.events, "put"); return nil }, del: func(any) error { return nil }}
		},
		attach: func(o link.CgroupOptions) (io.Closer, error) {
			f.events = append(f.events, "attach")
			if o.Path != "/cg" {
				panic(o.Path)
			}
			return dnsCloser{&f.closes}, nil
		},
		readResolv: func() ([]byte, error) { return []byte("nameserver 10.0.0.1\n"), nil },
		stamp:      func() (fileStamp, error) { return fileStamp{}, nil },
		now:        time.Now, log: func(s string) { f.logs = append(f.logs, s) },
	}
	return f
}

func TestDNSFlagOff(t *testing.T) {
	f := newDNSFixture()
	s := loadDNSWith(config{}, nil, f.deps)
	if s.on || s.reason != "flag" || s.objs != nil || len(f.events) != 0 || f.opts != nil {
		t.Fatalf("off state: %+v events %v", s, f.events)
	}
	if !reflect.DeepEqual(f.logs, []string{"dns tap off: flag"}) {
		t.Fatal(f.logs)
	}
}

func TestDNSResolversBeforeAttach(t *testing.T) {
	f := newDNSFixture()
	var directions []ebpf.AttachType
	attach := f.deps.attach
	f.deps.attach = func(o link.CgroupOptions) (io.Closer, error) {
		if len(f.events) == 0 || f.events[0] != "put" {
			t.Fatal("attach before resolvers")
		}
		directions = append(directions, o.Attach)
		return attach(o)
	}
	trie := new(ebpf.Map)
	s := loadDNSWith(config{dns: true}, trie, f.deps)
	defer s.close()
	if !dnsStartedCleanly(s, f) {
		t.Fatalf("state: %+v", s)
	}
	if f.opts.MapReplacements["rules"] != trie {
		t.Fatal("shared trie or unpinned maps lost")
	}
	if !reflect.DeepEqual(directions, []ebpf.AttachType{ebpf.AttachCGroupInetEgress, ebpf.AttachCGroupInetIngress}) {
		t.Fatal(directions)
	}
	if !reflect.DeepEqual(f.logs, []string{"dns tap on: 1 resolvers"}) {
		t.Fatal(f.logs)
	}
	if a, _ := s.cache.Len(); a != 0 {
		t.Fatal("cache not empty")
	}
}

func TestDNSAttachFailureReleasesAll(t *testing.T) {
	for _, fail := range []int{1, 2} {
		f := newDNSFixture()
		calls := 0
		f.deps.attach = func(link.CgroupOptions) (io.Closer, error) {
			calls++
			if calls == fail {
				return nil, errors.New("attach denied")
			}
			return dnsCloser{&f.closes}, nil
		}
		s := loadDNSWith(config{dns: true}, nil, f.deps)
		if s.on || s.reason != "attach denied" || s.objs != nil || len(s.links) != 0 {
			t.Fatalf("failed attach left state: %+v", s)
		}
		if f.closes != fail || !reflect.DeepEqual(f.logs, []string{"dns tap off: attach denied"}) {
			t.Fatalf("closes %d logs %v", f.closes, f.logs)
		}
	}
}

func TestDNSLoadAndMountFailures(t *testing.T) {
	for _, kind := range []string{"load", "mounts", "missing cgroup", "resolver put"} {
		f := newDNSFixture()
		switch kind {
		case "load":
			f.deps.load = func(*bpf.DnsObjects, *ebpf.CollectionOptions) error { return errors.New("load denied") }
		case "mounts":
			f.deps.mounts = func() (io.ReadCloser, error) { return nil, errors.New("mounts denied") }
		case "missing cgroup":
			f.deps.mounts = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader("none /cg cgroup rw 0 0")), nil }
		case "resolver put":
			f.deps.ops = func(*ebpf.Map) putDel { return putDel{put: func(any, any) error { return errors.New("put denied") }} }
		}
		s := loadDNSWith(config{dns: true}, nil, f.deps)
		if !dnsFailedCleanly(s, f) {
			t.Fatalf("%s: state %+v closes %d logs %v", kind, s, f.closes, f.logs)
		}
	}
}

func TestDNSStatsArray(t *testing.T) {
	got, err := readDNSStats(func(k, v any) error { *v.(*uint64) = uint64(k.(uint32) + 1); return nil })
	want, _ := dns.DecodeStats([]uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11})
	if err != nil || got != want {
		t.Fatalf("%+v %v", got, err)
	}
	boom := errors.New("stats unavailable")
	got, err = readDNSStats(func(any, any) error { return boom })
	if !errors.Is(err, boom) || got != (dns.Stats{}) {
		t.Fatalf("%+v %v", got, err)
	}
}

func dnsFailedCleanly(s *dnsState, f *dnsFixture) bool {
	return !s.on && s.objs == nil && s.reason != "" && f.closes == 1 && len(f.logs) == 1
}

func dnsStartedCleanly(s *dnsState, f *dnsFixture) bool {
	a, n := s.cache.Len()
	return s.on && s.reason == "" && s.objs != nil && f.opts.Maps.PinPath == "" && a == 0 && n == 0
}
