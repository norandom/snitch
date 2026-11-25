package dns

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/rules"
)

// offsets in struct dns_answer_record (bpf.DnsDnsAnswerRecord): qname[64], ttl u32, n u8.
const (
	ttlOffset = NameMax
	nOffset   = NameMax + 4
)

func fuzzSeed(f *testing.F) []byte {
	var r bpf.DnsDnsAnswerRecord
	copy(r.Qname[:], ".api.github.com")
	r.Ttl, r.N, r.Family[0] = 300, 1, 2
	copy(r.Addrs[0][:], []byte{192, 0, 2, 1})
	r.Slots[0] = bpf.DnsDomainSlot{Program: 7, Proto: 6, Port: 443, Id: 11}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, r); err != nil {
		f.Fatal(err)
	}
	return buf.Bytes()
}

func withN(raw []byte, n byte) []byte {
	b := bytes.Clone(raw)
	b[nOffset] = n
	return b
}

// FuzzDecode: any bytes decode to a value or an error, never a panic (8.2); only the struct's
// exact size decodes (8.3); a decoded record has 1-8 valid addresses, a valid name and the
// record's TTL. Run: go test -run '^$' -fuzz '^FuzzDecode$' -fuzztime 60s -fuzzminimizetime 5s
// ./internal/dns/ (minimizing a new 976-byte input otherwise stalls the run for up to 60 s).
func FuzzDecode(f *testing.F) {
	valid := fuzzSeed(f)
	long := append(bytes.Clone(valid), 0)
	f.Add(valid)
	f.Add(valid[:recordSize-1])
	f.Add(long)
	f.Add([]byte{})
	f.Add(withN(valid, addrsMax+1))
	f.Add(withN(valid, 0))
	f.Fuzz(func(t *testing.T, raw []byte) {
		rec, err := Decode(raw)
		if err != nil {
			return
		}
		if len(raw) != recordSize {
			t.Fatalf("decoded a record of %d bytes", len(raw))
		}
		checkRecord(t, raw, rec)
	})
}

func checkRecord(t *testing.T, raw []byte, rec Record) {
	t.Helper()
	checkAddrs(t, rec.Addrs, int(raw[nOffset]))
	if p, err := rules.ParseName(rec.Name); rec.Name == "" || len(rec.Name) > NameMax-2 || err != nil || p != rec.Name {
		t.Fatalf("invalid name %q: %v", rec.Name, err)
	}
	if ttl := binary.LittleEndian.Uint32(raw[ttlOffset:]); rec.TTL != time.Duration(ttl)*time.Second {
		t.Fatalf("TTL %v, record says %d s", rec.TTL, ttl)
	}
	checkSlots(t, rec.Slots)
}

// checkAddrs: the record's count n of addresses, 1 to 8, each a plain valid address.
func checkAddrs(t *testing.T, addrs []netip.Addr, n int) {
	t.Helper()
	if len(addrs) < 1 || len(addrs) > addrsMax || len(addrs) != n {
		t.Fatalf("%d addresses for n %d", len(addrs), n)
	}
	for _, a := range addrs {
		if !a.IsValid() || a.Zone() != "" {
			t.Fatalf("invalid address %v", a)
		}
	}
}

func checkSlots(t *testing.T, slots []Slot) {
	t.Helper()
	if len(slots) > len(bpf.DnsDnsAnswerRecord{}.Slots) {
		t.Fatalf("%d slots", len(slots))
	}
	for _, s := range slots {
		if s.ID == 0 {
			t.Fatal("an empty slot was decoded")
		}
	}
}
