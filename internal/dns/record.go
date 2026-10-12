// Record decoding validates the generated kernel ABI before the daemon learns an answer.
package dns

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"

	"github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/rules"
)

// Slot is shared with the task 1.6 compiler; define it once here to keep protocol types aligned.
// These are attempted kernel slots, including attempts that found existing keys or failed.
type Slot struct {
	Program uint32
	Proto   rules.Proto
	Port    uint16
	ID      uint32
}

type Record struct {
	Name  string
	TTL   time.Duration
	Addrs []netip.Addr
	Slots []Slot
}

// Decode reads the little-endian ABI emitted by dns_x86_bpfel, without unsafe host casts.
func Decode(raw []byte) (Record, error) {
	var wire bpf.DnsDnsAnswerRecord
	if err := binary.Read(bytes.NewReader(raw), binary.LittleEndian, &wire); err != nil {
		return Record{}, fmt.Errorf("DNS record: %w", err)
	}
	if wire.N == 0 || wire.N > addrsMax {
		return Record{}, fmt.Errorf("DNS record has invalid address count %d", wire.N)
	}
	name, err := keyName(wire.Qname)
	if err != nil {
		return Record{}, err
	}
	rec := Record{Name: name, TTL: time.Duration(wire.Ttl) * time.Second}
	for i := 0; i < int(wire.N); i++ {
		a, err := recordAddr(wire.Family[i], wire.Addrs[i])
		if err != nil {
			return Record{}, err
		}
		rec.Addrs = append(rec.Addrs, a)
	}
	for _, s := range wire.Slots {
		if s.Id != 0 {
			rec.Slots = append(rec.Slots, Slot{s.Program, rules.Proto(s.Proto), s.Port, s.Id})
		}
	}
	return rec, nil
}

func recordAddr(family uint8, raw [16]byte) (netip.Addr, error) {
	switch family {
	case 2:
		return netip.AddrFrom4([4]byte(raw[:4])), nil
	case 10:
		return netip.AddrFrom16(raw), nil
	default:
		return netip.Addr{}, fmt.Errorf("DNS record has invalid address family %d", family)
	}
}

// Stats fields follow dns_stat enum order; keeping the mapping explicit makes ABI review easy.
type Stats struct {
	Seen, NotResolver, NotAnswer, NoQuestion, NameTooLong, Parsed uint64
	Updates, Exists, UpdateFail, Queries, RingbufFull             uint64
}

// StatsCount is the number of counters in the kernel dns_stat enum.
const StatsCount = 11

func DecodeStats(values []uint64) (Stats, error) {
	if len(values) < StatsCount {
		return Stats{}, fmt.Errorf("DNS stats: need eleven counters, got %d", len(values))
	}
	return Stats{values[0], values[1], values[2], values[3], values[4], values[5], values[6], values[7], values[8], values[9], values[10]}, nil
}
