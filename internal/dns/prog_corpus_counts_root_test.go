//go:build root

// The length and count groups of the corpus: header length fields that disagree with the
// frame, and answer and question counts that disagree with the records present or the tap's
// limits. Line numbers cite bpf/dns.bpf.c.
package dns

import (
	"net/netip"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/norandom/snitch/internal/rules"
)

// The addresses of v4Answer and v6Answer, and the offsets of the length and count fields.
var (
	corpusAddr4 = netip.MustParseAddr("93.184.216.34")
	corpusAddr6 = netip.MustParseAddr("2001:db8::42")
)

const (
	ip4TotalOff   = ethLen + 2          // IPv4 total length
	ip6PayloadOff = ethLen + 4          // IPv6 payload length
	udp4LenOff    = ethLen + ip4Len + 4 // UDP length after an IPv4 header
	udp6LenOff    = ethLen + ip6Len + 4 // UDP length after an IPv6 header
	qdcountOff    = dns4Off + 4
	ancountOff    = dns4Off + 6
)

// learned is the outcome of a frame whose DNS message the tap reads whole: one address of
// api.github.com compiled for the github.com slot, mirrored in one record.
func learned(addr netip.Addr) (Stats, *Record, map[rules.RuleKey]rules.RuleVal) {
	s := corpusSlots[0]
	return Stats{Seen: 1, Parsed: 1, Updates: 1},
		&Record{Name: "api.github.com", TTL: 300 * time.Second, Addrs: []netip.Addr{addr}, Slots: corpusSlots},
		map[rules.RuleKey]rules.RuleVal{progKey(addr, s): {Verdict: 1, Id: s.ID}}
}

// set16 returns a frame builder that writes v at off of the base frame.
// v4UDPLenPlus sets the IPv4 answer's UDP length to the bytes present after the IPv4 header
// plus n, so n == 1 is the first value the tap's upper bound rejects.
func v4UDPLenPlus(n int) func(*testing.T) []byte {
	return func(t *testing.T) []byte {
		f := v4Answer(t)
		return setU16At(t, f, udp4LenOff, uint16(len(f)-ethLen-ip4Len+n))
	}
}

func set16(base func(*testing.T) []byte, off int, v uint16) func(*testing.T) []byte {
	return func(t *testing.T) []byte { return setU16At(t, base(t), off, v) }
}

// setByte returns a frame builder that overwrites one byte at off of the base frame.
func setByte(base func(*testing.T) []byte, off int, b byte) func(*testing.T) []byte {
	return func(t *testing.T) []byte { return overwriteAt(t, base(t), off, []byte{b}) }
}

// lengthCases: parse_l34 checks the IPv4 IHL (off < 20) and the UDP length on both sides: at
// least 8 + 12 and at most the bytes the packet holds after the network header. The IPv4 total
// length, the IPv6 payload length and a UDP length shorter than the message are not compared
// with the frame, and every later read is a bpf_skb_load_bytes of bytes actually present. Where
// those fields disagree the tap parses the real bytes and learns the well-formed answer they
// carry. Fail-safe: in production the IP
// layer (ip_rcv_core, ip6_rcv_core) and UDP (__udp4_lib_rcv / __udp6_lib_rcv) drop a datagram
// whose length fields run past the packet and trim the skb to the stated lengths before
// cgroup_skb ingress runs, so these frames reach the tap only through the kernel's test run,
// and the bytes it learns from are a complete answer from a registered resolver.
func lengthCases() []corpusCase {
	const real = "; the tap never compares this field with the frame and learns the well-formed answer in the bytes present (production drops or trims such a datagram before cgroup_skb ingress)"
	l4s, l4r, l4e := learned(corpusAddr4)
	l6s, l6r, l6e := learned(corpusAddr6)
	return []corpusCase{
		{name: "lengths-udp-below-min-ipv4", frame: set16(v4Answer, udp4LenOff, udpLen+dnsHdrLen-1), slots: corpusSlots, skipQ: true,
			probes: "IPv4, UDP length 19, below the UDP header + the 12-byte DNS header (parse_l34): passes, nothing counted (not yet seen), nothing learned"},
		{name: "lengths-udp-below-min-ipv6", frame: set16(v6Answer, udp6LenOff, udpLen+dnsHdrLen-1), slots: corpusSlots, skipQ: true,
			probes: "IPv6, UDP length 19, below the UDP header + the 12-byte DNS header (parse_l34): passes, nothing counted (not yet seen), nothing learned"},
		{name: "lengths-udp-min-shorter-than-message", frame: set16(v4Answer, udp4LenOff, udpLen+dnsHdrLen), slots: corpusSlots, skipQ: true,
			stats: l4s, record: l4r, entries: l4e,
			probes: "UDP length 20, the minimum parse_l34 accepts, shorter than the DNS message: passes" + real},
		{name: "lengths-udp-beyond-frame", frame: set16(v4Answer, udp4LenOff, 0xFFFF), slots: corpusSlots, skipQ: true,
			probes: "IPv4, UDP length 65535, more than the packet holds: parse_l34 rejects it before ST_SEEN (the UDP length must not exceed skb->len - off): passes, nothing counted, nothing learned"},
		{name: "lengths-udp-beyond-frame-ipv6", frame: set16(v6Answer, udp6LenOff, 0xFFFF), slots: corpusSlots, skipQ: true,
			probes: "IPv6, UDP length 65535, more than the packet holds: rejected in parse_l34 before ST_SEEN: passes, nothing counted, nothing learned"},
		{name: "lengths-udp-one-beyond-frame", frame: v4UDPLenPlus(1), slots: corpusSlots, skipQ: true,
			probes: "IPv4, UDP length one byte more than the packet holds (the boundary of the check): rejected in parse_l34 before ST_SEEN, nothing counted, nothing learned"},
		{name: "lengths-ipv4-total-below-payload", frame: set16(v4Answer, ip4TotalOff, ip4Len), slots: corpusSlots, skipQ: true,
			stats: l4s, record: l4r, entries: l4e,
			probes: "IPv4 total length 20, the header alone: passes" + real},
		{name: "lengths-ipv4-total-beyond-frame", frame: set16(v4Answer, ip4TotalOff, 0xFFFF), slots: corpusSlots, skipQ: true,
			stats: l4s, record: l4r, entries: l4e,
			probes: "IPv4 total length 65535, beyond the frame: passes" + real},
		{name: "lengths-ipv6-payload-beyond-frame", frame: set16(v6Answer, ip6PayloadOff, 0xFFFF), slots: corpusSlots, skipQ: true,
			stats: l6s, record: l6r, entries: l6e,
			probes: "IPv6 payload length 65535, beyond the frame: passes" + real},
		// a whole 20-byte header is present, so the test run's L3 length check does not refuse it
		{name: "lengths-ipv4-ihl-4", frame: setByte(v4Answer, ethLen, 0x44), slots: corpusSlots, skipQ: true,
			probes: "IPv4 IHL 4 (16 bytes), below 20 (line 273): passes, nothing counted (not yet seen), nothing learned"},
		{name: "lengths-ipv4-ihl-0", frame: setByte(v4Answer, ethLen, 0x40), slots: corpusSlots, skipQ: true,
			probes: "IPv4 IHL 0, below 20 (line 273): passes, nothing counted (not yet seen), nothing learned"},
	}
}

// countCases: qdcount != 1 is rejected with the header flags (line 523). ancount is clamped to
// RR_MAX (lines 570-572) and walk_step stops at the first record it cannot read (err 1 on the
// owner name's length byte, line 456) after the records it has walked, so an ancount above the
// records present keeps what those records compiled.
func countCases() []corpusCase {
	one, oneRec, oneTrie := learned(corpusAddr4)
	notAnswer := Stats{Seen: 1, NotAnswer: 1}
	return []corpusCase{
		{name: "counts-ancount-2-one-record", frame: set16(v4Answer, ancountOff, 2), slots: corpusSlots, skipQ: true,
			stats: one, record: oneRec, entries: oneTrie,
			probes: "ancount 2 with one A record: passes; the record is walked and compiled, the walk stops at the missing second owner name; one entry, one record"},
		{name: "counts-ancount-65535-one-record", frame: set16(v4Answer, ancountOff, 0xFFFF), slots: corpusSlots, skipQ: true,
			stats: one, record: oneRec, entries: oneTrie,
			probes: "ancount 65535, clamped to RR_MAX = 32, with one A record: passes; the record is compiled, the walk stops at the end of the frame; one entry, one record"},
		{name: "counts-ancount-33-address-33rd", frame: clampFrame(32), slots: corpusSlots, skipQ: true,
			stats:  Stats{Seen: 1, Parsed: 1},
			probes: "33 records present (32 CNAME, then the A record), ancount 33 clamped to RR_MAX = 32: passes, parsed, the 33rd record is never walked; nothing learned, no record (fewer entries: fail-safe)"},
		{name: "counts-ancount-33-address-32nd", frame: clampFrame(31), slots: corpusSlots, skipQ: true,
			stats: one, record: oneRec, entries: oneTrie,
			probes: "33 records present with the A record 32nd, ancount 33 clamped to 32: passes; the contrast to the entry above, the 32nd record is walked and compiled; one entry, one record"},
		{name: "counts-qdcount-0", frame: set16(v4Answer, qdcountOff, 0), slots: corpusSlots, skipQ: true, stats: notAnswer,
			probes: "qdcount 0 (line 523): passes, counted as not an answer, nothing learned"},
		{name: "counts-qdcount-2", frame: set16(v4Answer, qdcountOff, 2), slots: corpusSlots, skipQ: true, stats: notAnswer,
			probes: "qdcount 2 with one question present (line 523): passes, counted as not an answer, nothing learned"},
	}
}

// clampFrame builds an IPv4 answer for api.github.com with 33 uncompressed records: CNAME
// records to x.example except the A record for corpusAddr4 at index at (0-based). The walk
// spends five steps per record (three owner labels, the zero that ends the name, and the fixed part), 165 of STEPS_MAX = 544,
// so only the ancount clamp can stop it before the 33rd record.
func clampFrame(at int) func(*testing.T) []byte {
	return func(t *testing.T) []byte {
		t.Helper()
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
		mustProg(t, b.StartQuestions())
		name := dnsmessage.MustNewName("api.github.com.")
		mustProg(t, b.Question(dnsmessage.Question{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}))
		mustProg(t, b.StartAnswers())
		h := dnsmessage.ResourceHeader{Name: name, Class: dnsmessage.ClassINET, TTL: 300}
		for i := 0; i < 33; i++ {
			if i == at {
				mustProg(t, b.AResource(h, dnsmessage.AResource{A: corpusAddr4.As4()}))
				continue
			}
			mustProg(t, b.CNAMEResource(h, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("x.example.")}))
		}
		payload, err := b.Finish()
		mustProg(t, err)
		return wrapFrame(frameOptions{}, payload)
	}
}
