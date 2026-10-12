// Reader tests fence allow-only writes and preserve file-owned keys.
package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/dns"
	"github.com/norandom/snitch/internal/rules"
	"net/netip"
	"os"
	"syscall"
	"testing"
	"time"
)

type readerFixture struct {
	s          *dnsState
	snap       *snapshot
	live       map[rules.RuleKey]rules.RuleVal
	puts, dels int
	logs       []string
	at         time.Time
}

func newReaderFixture() *readerFixture {
	f := &readerFixture{live: map[rules.RuleKey]rules.RuleVal{}, at: time.Unix(100, 0)}
	r := rules.Rule{Program: "any", Name: "example.org", Proto: rules.TCP, Ports: []uint16{443}, Verdict: rules.Allow, ID: 7}
	f.snap = &snapshot{res: &rules.Resolved{File: &rules.File{Rules: []rules.Rule{r}}}, ent: rules.Entries{Rules: map[rules.RuleKey]rules.RuleVal{}}}
	f.s = &dnsState{cap: dns.Max, current: func() *snapshot { return f.snap }, now: func() time.Time { return f.at }, log: func(s string) { f.logs = append(f.logs, s) }}
	f.s.rules = putDel{put: func(k, v any) error { f.puts++; f.live[k.(rules.RuleKey)] = v.(rules.RuleVal); return nil }, del: func(k any) error { f.dels++; delete(f.live, k.(rules.RuleKey)); return nil }}
	return f
}
func readerRecord() dns.Record {
	return dns.Record{Name: "www.example.org", TTL: time.Minute, Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1")}, Slots: []dns.Slot{{Proto: rules.TCP, Port: 443, ID: 1}}}
}
func TestDNSReaderCurrentIDAndNoRepeat(t *testing.T) {
	f := newReaderFixture()
	rec := readerRecord()
	f.s.handle(rec)
	f.s.handle(rec)
	if f.puts != 1 || len(f.live) != 1 {
		t.Fatalf("puts %d live %v", f.puts, f.live)
	}
	for _, v := range f.live {
		if v.Id != 7 || v.Verdict != 1 {
			t.Fatal(v)
		}
	}
}
func TestDNSReaderFileKeysUntouched(t *testing.T) {
	f := newReaderFixture()
	rec := readerRecord()
	k, _ := rules.EncodeAddr(&f.snap.res.File.Rules[0], 0, rec.Addrs[0])
	f.snap.ent.Rules[k] = rules.RuleVal{Id: 99, Verdict: 2}
	f.s.handle(rec)
	if f.s.comp.Len() != 0 {
		t.Fatal("file key remembered as compiled")
	}
	f.snap.res.File.Rules = nil
	f.s.handle(rec)
	if f.puts != 0 || f.dels != 0 || f.s.comp.Len() != 0 {
		t.Fatalf("puts %d dels %d", f.puts, f.dels)
	}
}
func TestDNSReaderDeletesStaleSlot(t *testing.T) {
	f := newReaderFixture()
	rec := readerRecord()
	f.snap.res.File.Rules = nil
	f.s.handle(rec)
	if f.dels != 1 {
		t.Fatalf("stale slot deletes %d", f.dels)
	}
}
func TestContractHandleNeedsASnapshot(t *testing.T) {
	f := newReaderFixture()
	f.snap = nil
	contracttest.Panics(t, contract.Precondition, func() { f.s.handle(readerRecord()) })
}
func TestDNSExpireAndEvict(t *testing.T) {
	f := newReaderFixture()
	rec := readerRecord()
	f.s.cap = 1
	f.s.handle(rec)
	rec.Addrs = []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	rec.TTL = 2 * time.Minute
	f.s.handle(rec)
	if f.s.cache.Evictions() != 1 || f.dels != 1 || f.s.comp.Len() != 1 {
		t.Fatalf("evictions %d dels %d", f.s.cache.Evictions(), f.dels)
	}
	f.at = f.at.Add(2 * time.Minute)
	_ = f.s.expire(context.Background())
	if len(f.live) != 0 || f.s.comp.Len() != 0 {
		t.Fatal(f.live)
	}
}
func TestDNSReaderSurvivesErrors(t *testing.T) {
	f := newReaderFixture()
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	f.s.read = func() ([]byte, error) {
		calls++
		if calls <= 3 {
			return nil, errors.New("read failed")
		}
		if calls == 4 {
			return []byte{1}, nil
		}
		cancel()
		return nil, syscall.ETIMEDOUT
	}
	if err := f.s.reader(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(f.logs) != 1 || f.s.readErrors != 3 || f.s.malformed != 1 {
		t.Fatalf("logs %v errors %d malformed %d", f.logs, f.s.readErrors, f.s.malformed)
	}
}

func TestDNSReaderSliceSource(t *testing.T) {
	f := newReaderFixture()
	var wire bpf.DnsDnsAnswerRecord
	copy(wire.Qname[:], ".www.example.org")
	wire.N, wire.Ttl, wire.Family[0] = 1, 60, 2
	copy(wire.Addrs[0][:], []byte{192, 0, 2, 1})
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, wire); err != nil {
		t.Fatal(err)
	}
	source := [][]byte{buf.Bytes()}
	ctx, cancel := context.WithCancel(context.Background())
	f.s.read = func() ([]byte, error) {
		if len(source) == 0 {
			cancel()
			return nil, os.ErrDeadlineExceeded
		}
		raw := source[0]
		source = source[1:]
		return raw, nil
	}
	_ = f.s.reader(ctx)
	if f.puts != 1 {
		t.Fatalf("decoded record puts %d", f.puts)
	}
}

func TestDNSReaderMapFailureRetryAndStreak(t *testing.T) {
	f := newReaderFixture()
	put := f.s.rules.put
	fail := true
	f.s.rules.put = func(k, v any) error {
		if fail {
			return errors.New("map failed")
		}
		return put(k, v)
	}
	for range 3 {
		f.s.handle(readerRecord())
	}
	if len(f.logs) != 1 || f.s.mapErrors != 3 {
		t.Fatalf("logs %v errors %d", f.logs, f.s.mapErrors)
	}
	fail = false
	f.s.handle(readerRecord())
	if f.puts != 1 || len(f.s.pending) != 0 {
		t.Fatal("failed put not retried")
	}
	fail = true
	rec := readerRecord()
	rec.Addrs = []netip.Addr{netip.MustParseAddr("192.0.2.2")}
	f.s.handle(rec)
	if len(f.logs) != 2 {
		t.Fatal(f.logs)
	}
}
