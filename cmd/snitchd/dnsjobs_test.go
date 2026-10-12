// Resolver changes constrain learning; an unreadable configuration removes every trusted source.
package main

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/dns"
)

func TestResolvWatchPutsDeletesAndRecovers(t *testing.T) {
	f := newDNSFixture()
	live := map[bpf.DnsResolverKey]uint32{}
	var puts, deletes int
	f.deps.ops = resolverRecorder(live, &puts, &deletes)
	var stamp fileStamp
	f.deps.stamp = func() (fileStamp, error) { return stamp, nil }
	s := loadDNSWith(config{dns: true}, nil, f.deps)
	defer s.close()
	steps := []struct {
		text   string
		err    error
		want   []string
		reason string
	}{
		{"nameserver 10.0.0.1\nnameserver 2001:db8::1", nil, []string{"10.0.0.1", "2001:db8::1"}, ""},
		{"nameserver 2001:db8::1", nil, []string{"2001:db8::1"}, ""},
		{"", errors.New("unreadable"), nil, "no resolvers"},
		{"nameserver 1.1.1.1", nil, []string{"1.1.1.1"}, ""},
		{"# empty", nil, nil, "no resolvers"},
	}
	for i, step := range steps {
		stamp.size = int64(i + 1)
		s.readResolv = func() ([]byte, error) { return []byte(step.text), step.err }
		if err := s.watchResolv(context.Background()); err != nil {
			t.Fatal(err)
		}
		want := map[bpf.DnsResolverKey]uint32{}
		for _, a := range step.want {
			want[bpf.DnsResolverKey{Addr: dns.ResolverKey(netip.MustParseAddr(a))}] = 1
		}
		if !reflect.DeepEqual(live, want) || !s.on || s.reason != step.reason {
			t.Fatalf("step %d: %v reason %q", i, live, s.reason)
		}
	}
	if puts != 3 || deletes != 3 {
		t.Fatalf("puts %d deletes %d", puts, deletes)
	}
	s.readResolv = func() ([]byte, error) { t.Fatal("unchanged file reread"); return nil, nil }
	_ = s.watchResolv(context.Background())
}

func TestDNSJobsOffAndCancellation(t *testing.T) {
	if got := (&daemon{}).dnsJobs(nil); len(got) != 0 {
		t.Fatal(got)
	}
	f := newDNSFixture()
	s := loadDNSWith(config{dns: true}, nil, f.deps)
	d := daemon{dns: s}
	js := d.dnsJobs(nil)
	if len(js) != 1 {
		t.Fatal(len(js))
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := js[0](ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if f.closes != 3 {
		t.Fatal(f.closes)
	}
}

func resolverRecorder(live map[bpf.DnsResolverKey]uint32, puts, deletes *int) func(*ebpf.Map) putDel {
	return func(*ebpf.Map) putDel {
		return putDel{
			put: func(k, v any) error { live[k.(bpf.DnsResolverKey)] = v.(uint32); *puts++; return nil },
			del: func(k any) error { delete(live, k.(bpf.DnsResolverKey)); *deletes++; return nil },
		}
	}
}

func TestResolvMapFailureRetriesSameStamp(t *testing.T) {
	f := newDNSFixture()
	s := loadDNSWith(config{dns: true}, nil, f.deps)
	defer s.close()
	s.stamp = func() (fileStamp, error) { return fileStamp{size: 1}, nil }
	s.readResolv = func() ([]byte, error) { return []byte("nameserver 1.1.1.1"), nil }
	attempts := 0
	s.resolvers = putDel{
		del: func(any) error { return nil },
		put: func(any, any) error {
			attempts++
			if attempts == 1 {
				return errors.New("map full")
			}
			return nil
		},
	}
	for range 2 {
		if err := s.watchResolv(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if attempts != 2 || s.lastStamp.size != 1 || s.reason != "" || len(s.trusted) != 1 {
		t.Fatalf("attempts %d state %+v", attempts, s)
	}
	if !reflect.DeepEqual(f.logs, []string{"dns tap on: 1 resolvers", "dns resolvers: map full"}) {
		t.Fatal(f.logs)
	}
}
