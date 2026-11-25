//go:build root

// The corpus runs the tap against malformed frames with a stated outcome per entry: the
// packet passes, the named counter moves, no contract counter moves, and no allow entry or
// record appears where the frame is malformed (requirement 6).
package dns

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	"github.com/norandom/snitch/internal/rules"
)

type corpusCase struct {
	name    string
	probes  string                          // what it probes, expected outcome (6.6)
	frame   func(t *testing.T) []byte       // well-formed builder, then mutators
	slots   []Slot                          // domain slots for github.com: a wrongful learn shows in the trie
	skipQ   bool                            // false: the question must have been recorded
	stats   Stats                           // expected counters (6.4)
	record  *Record                         // nil: no record (6.3)
	entries map[rules.RuleKey]rules.RuleVal // exact trie content (6.3, 6.5); nil: empty
	// mayRefuse: the kernel's test-run entry may refuse the frame with EINVAL before the tap
	// runs (an L3 header shorter than a full IPv4/IPv6 header); either outcome is accepted
	mayRefuse bool
}

// Offsets into the frames answerFrame builds: the Ethernet header, then IPv4 (no options) or
// IPv6 (no extension headers), UDP, and the DNS header.
const (
	ethLen    = 14
	ip4Len    = 20
	ip6Len    = 40
	udpLen    = 8
	dnsHdrLen = 12
	dns4Off   = ethLen + ip4Len + udpLen
	dns6Off   = ethLen + ip6Len + udpLen
	// "api.github.com" on the wire: 3api 6github 3com 0
	qnameWire = 16
)

var corpusSlots = []Slot{{Program: 7, ID: 3}}

func TestDNSProgCorpus(t *testing.T) {
	for _, tc := range corpusCases() {
		t.Run(tc.name, func(t *testing.T) { checkCorpusCase(t, tc) })
	}
}

// TestCorpusFramesBuild needs no kernel: every entry's mutators stay inside its base frame
// and every entry states what it probes, so a wrong offset fails here and not only as root.
func TestCorpusFramesBuild(t *testing.T) {
	for _, tc := range corpusCases() {
		if tc.probes == "" || len(tc.frame(t)) == 0 {
			t.Errorf("%s: no probes statement or an empty frame", tc.name)
		}
	}
}

func corpusCases() []corpusCase {
	return append(truncationHeaderCases(), truncationDNSCases()...)
}

// checkCorpusCase asserts pass (runDNSProg: return 1, 6.2), the counters (6.4), zero
// contract counters (6.4), the exact trie (6.3, 6.5) and the record or its absence (6.3).
func checkCorpusCase(t *testing.T, tc corpusCase) {
	t.Helper()
	c, trie := loadDNSForTest(t, tc.skipQ)
	r := progReader(t, c)
	putResolver(t, c, "10.0.0.1")
	putResolver(t, c, "2001:db8::1")
	if len(tc.slots) > 0 {
		putDomain(t, c, "github.com", tc.slots)
	}
	runCorpusFrame(t, c, tc)
	equalProg(t, progStats(t, c), tc.stats)
	equalProg(t, progContracts(t, c), Contracts{})
	want := tc.entries
	if want == nil {
		want = map[rules.RuleKey]rules.RuleVal{}
	}
	equalProg(t, progTrie(t, trie), want)
	checkProgRecord(t, r, tc.record)
}

// runCorpusFrame runs the entry's frame through dns_answer and asserts return 1 (6.2). A
// mayRefuse entry also accepts EINVAL from the kernel's test-run entry, which means the tap
// was never reached; the log line says which of the two happened. Any other error fails.
func runCorpusFrame(t *testing.T, c *ebpf.Collection, tc corpusCase) {
	t.Helper()
	if !tc.mayRefuse {
		runDNSProg(t, c, "dns_answer", tc.frame(t))
		return
	}
	ret, err := c.Programs["dns_answer"].Run(&ebpf.RunOptions{Data: tc.frame(t)})
	switch {
	case errors.Is(err, unix.EINVAL):
		t.Logf("%s: the kernel's test run refused the frame (EINVAL); the tap was not reached", tc.name)
	case err != nil:
		t.Fatalf("%s: test run: %v", tc.name, err)
	default:
		equalProg(t, ret, uint32(1))
		t.Logf("%s: the tap ran and returned 1", tc.name)
	}
}

// v4Answer and v6Answer are the well-formed answers the mutators start from: one question
// for api.github.com and one A (AAAA) record, uncompressed, from a registered resolver.
func v4Answer(t *testing.T) []byte {
	t.Helper()
	return answerFrame(t, frameOptions{name: "api.github.com", addr: netip.MustParseAddr("93.184.216.34")})
}

func v6Answer(t *testing.T) []byte {
	t.Helper()
	return answerFrame(t, frameOptions{name: "api.github.com", ipv6: true, addr: netip.MustParseAddr("2001:db8::42")})
}

// cutAt keeps the first n bytes of the base frame.
func cutAt(base func(*testing.T) []byte, n int) func(*testing.T) []byte {
	return func(t *testing.T) []byte { return truncateAt(t, base(t), n) }
}

// cutBeforeEnd drops the last k bytes of the base frame.
func cutBeforeEnd(base func(*testing.T) []byte, k int) func(*testing.T) []byte {
	return func(t *testing.T) []byte {
		f := base(t)
		return truncateAt(t, f, len(f)-k)
	}
}

// ihlBeyondFrame keeps a whole 20-byte IPv4 header whose IHL claims 15 words (60 bytes) and
// cuts the frame 40 bytes into the network header, so the claimed options run past the frame.
func ihlBeyondFrame(t *testing.T) []byte {
	f := overwriteAt(t, v4Answer(t), ethLen, []byte{0x4F})
	return truncateAt(t, f, dns4Off+dnsHdrLen)
}

// Cuts that end the frame before parse_l34 (bpf/dns.bpf.c) has the UDP header: its
// bpf_skb_load_bytes fails and dns_answer returns before ST_SEEN, so nothing is counted.
// The test-run entry (bpf_prog_test_run_skb) needs the 14-byte link header and, after
// eth_type_trans, newer kernels also refuse with EINVAL a network header shorter than a full
// struct iphdr / ipv6hdr (which kernels carry that check is not verified here). cgroup_skb
// never shows the link header to the program (skb->data is the network header), and the IP
// layer never delivers such a short L3 header to cgroup_skb ingress, so these three entries
// are mayRefuse: refused or run, the tap learns nothing. The IHL entry is always reachable.
func truncationHeaderCases() []corpusCase {
	const short = "L3 header shorter than a full IPv4/IPv6 header: refused by the kernel's test-run entry on newer kernels, never delivered to cgroup_skb ingress in production; either way passes, nothing counted, nothing learned"
	return []corpusCase{
		{name: "truncation-link", frame: cutAt(v4Answer, ethLen), slots: corpusSlots, skipQ: true, mayRefuse: true,
			probes: "frame ends at the link header, no network header (" + short + ")"},
		{name: "truncation-ipv4-header", frame: cutAt(v4Answer, ethLen+ip4Len/2), slots: corpusSlots, skipQ: true, mayRefuse: true,
			probes: "frame ends inside the IPv4 header (" + short + ")"},
		{name: "truncation-ipv6-header", frame: cutAt(v6Answer, ethLen+ip6Len/2), slots: corpusSlots, skipQ: true, mayRefuse: true,
			probes: "frame ends inside the IPv6 header (" + short + ")"},
		// parse_l34: off = ihl*4 = 60, the UDP load at 60 fails past the 40-byte network header
		{name: "truncation-ipv4-ihl-beyond-frame", frame: ihlBeyondFrame, slots: corpusSlots, skipQ: true,
			probes: "whole IPv4 header whose IHL (60 bytes) runs past the frame: passes, nothing counted (not yet seen), nothing learned"},
		{name: "truncation-udp-header-ipv4", frame: cutAt(v4Answer, ethLen+ip4Len+udpLen/2), slots: corpusSlots, skipQ: true,
			probes: "IPv4 frame ends inside the UDP header: passes, nothing counted (not yet seen), nothing learned"},
		{name: "truncation-udp-header-ipv6", frame: cutAt(v6Answer, ethLen+ip6Len+udpLen/2), slots: corpusSlots, skipQ: true,
			probes: "IPv6 frame ends inside the UDP header: passes, nothing counted (not yet seen), nothing learned"},
	}
}

// Cuts after the UDP header: the datagram is seen (ST_SEEN) from a registered resolver.
//   - inside the DNS header: the header load fails, dns_answer returns with no further counter;
//   - inside the question name: read_qname's label or name load fails, it returns 0 and
//     dns_answer counts ST_NAME_TOO_LONG;
//   - inside qtype/qclass, a record header or record data: the question name reads whole, the
//     walk starts and walk_step stops on the failed load (err 1, 4 or 5) before any address
//     is stored, so ST_PARSED counts, rec->n stays 0 and the record is discarded.
func truncationDNSCases() []corpusCase {
	seen, parsed := Stats{Seen: 1}, Stats{Seen: 1, Parsed: 1}
	return []corpusCase{
		{name: "truncation-dns-header-ipv4", frame: cutAt(v4Answer, dns4Off+dnsHdrLen/2), slots: corpusSlots, skipQ: true, stats: seen,
			probes: "IPv4 frame ends inside the DNS header: passes, seen only, nothing learned"},
		{name: "truncation-dns-header-ipv6", frame: cutAt(v6Answer, dns6Off+dnsHdrLen/2), slots: corpusSlots, skipQ: true, stats: seen,
			probes: "IPv6 frame ends inside the DNS header: passes, seen only, nothing learned"},
		{name: "truncation-question-name", frame: cutAt(v4Answer, dns4Off+dnsHdrLen+5), slots: corpusSlots, skipQ: true,
			stats:  Stats{Seen: 1, NameTooLong: 1},
			probes: "frame ends inside the question name: passes, counted as name too long, nothing learned"},
		{name: "truncation-question-type", frame: cutAt(v4Answer, dns4Off+dnsHdrLen+qnameWire+1), slots: corpusSlots, skipQ: true, stats: parsed,
			probes: "frame ends inside qtype/qclass: passes, parsed with no record walked, nothing learned, no record"},
		{name: "truncation-record-header", frame: cutBeforeEnd(v4Answer, 4+5), slots: corpusSlots, skipQ: true, stats: parsed,
			probes: "frame ends inside the answer's fixed header: passes, parsed, no address, nothing learned, no record"},
		{name: "truncation-record-data", frame: cutBeforeEnd(v4Answer, 2), slots: corpusSlots, skipQ: true, stats: parsed,
			probes: "frame ends inside the A record's address: passes, parsed, no address, nothing learned, no record"},
	}
}
