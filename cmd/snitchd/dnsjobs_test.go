// Resolver changes constrain learning; an unreadable configuration removes every trusted source.
package main

import (
	"context"
	"errors"
	"github.com/norandom/snitch/internal/rules"
	"net/netip"
	"os"
	"reflect"
	"testing"
	"time"

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

func TestDNSExpirePartialNames(t *testing.T) {
	f := newReaderFixture()
	rec := readerRecord()
	f.s.handle(rec)
	rec.Name = "other.example.org"
	rec.TTL = 2 * time.Minute
	f.s.handle(rec)
	f.at = f.at.Add(time.Minute)
	_ = f.s.expire(context.Background())
	if f.dels != 0 || f.s.comp.Len() != 1 {
		t.Fatal("partial expiry removed shared key")
	}
	f.at = f.at.Add(time.Minute)
	_ = f.s.expire(context.Background())
	if f.dels != 1 {
		t.Fatal("last name expiry did not remove key")
	}
}

func TestDNSEvictSomePreservesFileKeys(t *testing.T) {
	f := newReaderFixture()
	f.s.handle(readerRecord())
	for k := range f.live {
		f.snap.ent.Rules[k] = rules.RuleVal{Id: 99, Verdict: 2}
	}
	if !f.s.evictSome() || f.s.evictSome() || f.dels != 0 || f.s.comp.Len() != 0 {
		t.Fatal("evictor touched file or did not clear compiled")
	}
}

func TestDNSJobsExpiryTickAndReaderClose(t *testing.T) {
	f := newReaderFixture()
	f.s.handle(readerRecord())
	f.at = f.at.Add(time.Minute)
	f.s.on = true
	f.s.stamp = func() (fileStamp, error) { return fileStamp{}, nil }
	closes := 0
	f.s.readerClose = dnsCloser{&closes}
	f.s.read = func() ([]byte, error) { time.Sleep(10 * time.Millisecond); return nil, os.ErrDeadlineExceeded }
	ctx, cancel := context.WithTimeout(context.Background(), 2200*time.Millisecond)
	defer cancel()
	js := (&daemon{dns: f.s}).dnsJobs(nil)
	if err := js[0](ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	if closes != 1 || f.dels != 1 || f.s.comp.Len() != 0 {
		t.Fatalf("closes %d dels %d compiled %d", closes, f.dels, f.s.comp.Len())
	}
}

func recompileFixture() *readerFixture {
	f := newReaderFixture()
	f.s.on = true
	f.s.domains = putDel{put: func(any, any) error { return nil }, del: func(any) error { return nil }}
	return f
}

func TestRecompileRenumbersAndDropsPending(t *testing.T) {
	f := recompileFixture()
	rec := readerRecord()
	rec.Addrs = append(rec.Addrs, netip.MustParseAddr("192.0.2.2"))
	f.s.handle(rec)
	stale := rules.RuleKey{Port: 999}
	f.s.queue(map[rules.RuleKey]rules.RuleVal{stale: {Id: 1}}, nil)
	nameRule := f.snap.res.File.Rules[0]
	nameRule.ID = 8
	f.snap.res.File.Rules = []rules.Rule{{Program: "any", To: netip.MustParsePrefix("198.51.100.1/32"), Verdict: rules.Allow, ID: 7}, nameRule}
	f.s.recompile(f.snap)
	f.s.flush(f.snap)
	if _, ok := f.live[stale]; ok {
		t.Fatal("stale pending put survived recompile")
	}
	if len(f.live) != 2 || f.puts != 4 {
		t.Fatal(f.live, f.puts)
	}
	for _, v := range f.live {
		if v.Id != 8 {
			t.Fatal("old id", v)
		}
	}
}

func TestRecompileRewritesDomains(t *testing.T) {
	f := recompileFixture()
	live := map[bpf.DnsDomainKey]bpf.DnsDomainVal{}
	f.s.domains = putDel{put: func(k, v any) error {
		if f.s.mu.TryLock() {
			f.s.mu.Unlock()
			t.Fatal("domains rewrite needs tap lock")
		}
		live[k.(bpf.DnsDomainKey)] = v.(bpf.DnsDomainVal)
		return nil
	}, del: func(k any) error { delete(live, k.(bpf.DnsDomainKey)); return nil }}
	f.s.recompile(f.snap)
	old := bpf.DnsDomainKey{Name: dns.Key("example.org")}
	want := bpf.DnsDomainSlot{Proto: uint8(rules.TCP), Port: 443, Id: 7}
	if live[old].Slot[0] != want {
		t.Fatal(live)
	}
	f.snap.res.File.Rules[0].Name = "new.org"
	f.s.recompile(f.snap)
	if _, ok := live[old]; ok {
		t.Fatal("removed name still present")
	}
	if live[bpf.DnsDomainKey{Name: dns.Key("new.org")}].Slot[0] != want {
		t.Fatal(live)
	}
}

func TestEvictorForSubtractsPendingFileKeys(t *testing.T) {
	f := recompileFixture()
	f.s.handle(readerRecord())
	next := newReaderFixture().snap
	for k := range f.live {
		next.ent.Rules[k] = rules.RuleVal{Id: 99}
	}
	if !f.s.evictorFor(next)() || f.dels != 0 {
		t.Fatal("pending file key deleted", f.dels)
	}
	var off *dnsState
	off.recompile(nil)
	if off.evictorFor(nil) != nil {
		t.Fatal("off evictor")
	}
}
