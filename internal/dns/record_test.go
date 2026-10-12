// Record tests serialize generated bindings to exercise the actual ring-buffer ABI.
package dns

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/rules"
)

func answerFixture() bpf.DnsDnsAnswerRecord {
	var r bpf.DnsDnsAnswerRecord
	copy(r.Qname[:], ".api.github.com")
	r.Ttl, r.N = 123, 2
	r.Family[0], r.Family[1] = 2, 10
	copy(r.Addrs[0][:], []byte{192, 0, 2, 1})
	r.Addrs[1] = netip.MustParseAddr("2001:db8::1").As16()
	r.Slots[0] = bpf.DnsDomainSlot{Program: 7, Proto: 6, Port: 443, Id: 11}
	r.Slots[31] = bpf.DnsDomainSlot{Id: 12}
	r.Slots[1] = bpf.DnsDomainSlot{Program: 99}
	return r
}

func answerBytes(t *testing.T, r bpf.DnsDnsAnswerRecord) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, r); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestDecode(t *testing.T) {
	got, err := Decode(answerBytes(t, answerFixture()))
	if err != nil {
		t.Fatal(err)
	}
	want := Record{Name: "api.github.com", TTL: 123 * time.Second,
		Addrs: []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")},
		Slots: []Slot{{Program: 7, Proto: rules.Proto(6), Port: 443, ID: 11}, {ID: 12}}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestDecodeRefusesTruncated(t *testing.T) {
	raw := answerBytes(t, answerFixture())
	for _, n := range []int{0, 63, len(raw) - 1} {
		if _, err := Decode(raw[:n]); err == nil {
			t.Errorf("accepted %d bytes", n)
		}
	}
}

func TestDecodeRefusesInconsistent(t *testing.T) {
	for _, mutate := range []func(*bpf.DnsDnsAnswerRecord){
		func(r *bpf.DnsDnsAnswerRecord) { r.N = 9 }, func(r *bpf.DnsDnsAnswerRecord) { r.N = 0 },
		func(r *bpf.DnsDnsAnswerRecord) { r.Family[1] = 3 },
		func(r *bpf.DnsDnsAnswerRecord) { r.Qname = [64]byte{} },
		func(r *bpf.DnsDnsAnswerRecord) { r.Qname[0] = 'a' },
		func(r *bpf.DnsDnsAnswerRecord) { r.Qname[1] = '.' },
		func(r *bpf.DnsDnsAnswerRecord) {
			for i := range r.Qname {
				r.Qname[i] = 'a'
			}
			r.Qname[0] = '.'
		},
	} {
		r := answerFixture()
		mutate(&r)
		if _, err := Decode(answerBytes(t, r)); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
}

func TestDecodeStats(t *testing.T) {
	got, err := DecodeStats([]uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 99})
	want := Stats{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}
	if err != nil || got != want {
		t.Fatalf("%+v, %v", got, err)
	}
	for n := 0; n < 11; n++ {
		if _, err := DecodeStats(make([]uint64, n)); err == nil {
			t.Fatalf("accepted %d counters", n)
		}
	}
}
