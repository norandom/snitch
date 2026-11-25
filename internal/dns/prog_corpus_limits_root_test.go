//go:build root

// The at-the-limits group of the corpus: well-formed answers at each of the tap's limits with
// the allow entries and the record they must produce (6.5), and the step budget of the answer
// walk (the 3.4 finding). Line numbers cite bpf/dns.bpf.c.
package dns

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/norandom/snitch/internal/rules"
)

// stepsMax mirrors STEPS_MAX = RR_MAX * (LABELS_MAX + 1), the answer walk's bpf_loop bound.
const stepsMax = 32 * (labelsMax + 1)

// limitRR is one record of limitFrame: an A record of a, or a CNAME to x.example when a is
// the zero Addr; owner empty means the question name.
type limitRR struct {
	owner string
	a     netip.Addr
	ttl   uint32
}

// limitFrame builds an IPv4 answer for qname with the records given, uncompressed.
func limitFrame(qname string, rrs []limitRR) func(*testing.T) []byte {
	return func(t *testing.T) []byte {
		t.Helper()
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{Response: true})
		mustProg(t, b.StartQuestions())
		q := dnsmessage.MustNewName(qname + ".")
		mustProg(t, b.Question(dnsmessage.Question{Name: q, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}))
		mustProg(t, b.StartAnswers())
		for _, r := range rrs {
			h := dnsmessage.ResourceHeader{Name: q, Class: dnsmessage.ClassINET, TTL: r.ttl}
			if r.owner != "" {
				h.Name = dnsmessage.MustNewName(r.owner + ".")
			}
			if r.a.IsValid() {
				mustProg(t, b.AResource(h, dnsmessage.AResource{A: r.a.As4()}))
				continue
			}
			mustProg(t, b.CNAMEResource(h, dnsmessage.CNAMEResource{CNAME: dnsmessage.MustNewName("x.example.")}))
		}
		payload, err := b.Finish()
		mustProg(t, err)
		return wrapFrame(frameOptions{}, payload)
	}
}

// addrsFrom returns n IPv4 A records 192.0.2.1 .. 192.0.2.n with TTL 300, 290, ... (the
// record's TTL is the smallest of the addresses collected, line 494).
func addrsFrom(n int) []limitRR {
	out := make([]limitRR, n)
	for i := range out {
		out[i] = limitRR{a: netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), ttl: uint32(300 - 10*i)}
	}
	return out
}

// learnedAll is the outcome of the first n records of rrs compiled for slot s under name: one
// entry and one mirrored address each, with the smallest of their TTLs.
func learnedAll(name string, rrs []limitRR, n int) (Stats, *Record, map[rules.RuleKey]rules.RuleVal) {
	s := corpusSlots[0]
	rec := &Record{Name: name, TTL: time.Duration(rrs[0].ttl) * time.Second, Slots: corpusSlots}
	trie := map[rules.RuleKey]rules.RuleVal{}
	for _, r := range rrs[:n] {
		rec.Addrs = append(rec.Addrs, r.a)
		rec.TTL = min(rec.TTL, time.Duration(r.ttl)*time.Second)
		trie[progKey(r.a, s)] = rules.RuleVal{Verdict: 1, Id: s.ID}
	}
	return Stats{Seen: 1, Parsed: 1, Updates: uint64(n)}, rec, trie
}

// cnamesThenA is total-1 CNAME records and then the A record of corpusAddr4, every owner the
// question name: the A record is the total-th record.
func cnamesThenA(total int) []limitRR {
	out := make([]limitRR, total)
	for i := range out[:total-1] {
		out[i].ttl = 300
	}
	out[total-1] = limitRR{a: corpusAddr4, ttl: 300}
	return out
}

// stepsFrame spends the walk's step budget on owner names: four CNAMEs owned by a legal
// 255-byte name of 127 one-letter labels (129 steps each: the labels, the closing zero, the
// fixed part), one CNAME owned by k one-letter labels (k + 2 steps), then the A record of
// corpusAddr4 under api.github.com (4 owner steps, then its fixed part). The fixed part of the
// A record is step 516 + k + 2 + 5; k = 21 makes it exactly STEPS_MAX = 544.
func stepsFrame(k int) func(*testing.T) []byte {
	long := strings.TrimSuffix(strings.Repeat("a.", 127), ".")
	rrs := []limitRR{{owner: long, ttl: 300}, {owner: long, ttl: 300}, {owner: long, ttl: 300}, {owner: long, ttl: 300},
		{owner: strings.TrimSuffix(strings.Repeat("b.", k), "."), ttl: 300}, {a: corpusAddr4, ttl: 300}}
	return limitFrame("api.github.com", rrs)
}

// limitCases: the longest name read_qname accepts is 63 wire bytes (line 330), the most labels
// 15 (lines 318-335, see nameLimitCases), and compile_addr looks the suffix up at the first
// LEVELS_MAX = 8 labels only (lines 418-420); RR_MAX = 32 records are walked (lines 570-572);
// ADDRS_MAX = 8 addresses are collected and compiled, a later A record neither (the compile is
// inside the n < ADDRS_MAX branch, lines 484-497); the walk has STEPS_MAX = 544 steps (line
// 574) and owner-name labels are not capped per name.
func limitCases() []corpusCase {
	n63 := strings.Repeat("x", 47) + ".api.github.com"
	l63s, l63r, l63e := learnedAll(n63, []limitRR{{a: corpusAddr4, ttl: 300}}, 1)
	n15 := "a.b.c.d.e.f.g.h.i.j.k.l.m.github.com"
	l15s, l15r, l15e := learnedAll(n15, []limitRR{{a: corpusAddr4, ttl: 300}}, 1)
	one, oneRec, oneTrie := learned(corpusAddr4)
	a8, a9 := addrsFrom(8), addrsFrom(9)
	l8s, l8r, l8e := learnedAll("api.github.com", a8, 8)
	parsed := Stats{Seen: 1, Parsed: 1}
	return []corpusCase{
		{name: "limits-63-byte-name", frame: v4Named(n63), slots: corpusSlots, skipQ: true,
			stats: l63s, record: l63r, entries: l63e,
			probes: "a question name of 63 wire bytes (47x.api.github.com, 62 characters), the longest accepted (n < NAME_MAX, line 330): passes; github.com matches at level 2; one entry, one record with the full name"},
		{name: "limits-15-labels-suffix-at-level-7", frame: v4Named(n15), slots: corpusSlots, domain: "h.i.j.k.l.m.github.com", skipQ: true,
			stats: l15s, record: l15r, entries: l15e,
			probes: "a question name of 15 labels, the most accepted (16 is refused, see names-16-labels), with the domain at level 7, the deepest suffix looked up (LEVELS_MAX = 8, line 418): passes; one entry, one record"},
		{name: "limits-15-labels-suffix-at-level-8", frame: v4Named(n15), slots: corpusSlots, domain: "i.j.k.l.m.github.com", skipQ: true,
			stats:  parsed,
			record: &Record{Name: n15, TTL: 300 * time.Second, Addrs: []netip.Addr{corpusAddr4}},
			probes: "the same 15-label name with the domain at level 8, one past the suffixes looked up (line 418): passes; the address is collected and mirrored with no slot, no entry (fewer entries: fail-safe)"},
		{name: "limits-32-records", frame: limitFrame("api.github.com", cnamesThenA(32)), slots: corpusSlots, skipQ: true,
			stats: one, record: oneRec, entries: oneTrie,
			probes: "32 records, ancount 32 = RR_MAX: 31 CNAMEs, then the A record as the 32nd (160 of 544 steps): passes; the last record is walked and compiled; one entry, one record"},
		{name: "limits-8-addresses", frame: limitFrame("api.github.com", a8), slots: corpusSlots, skipQ: true,
			stats: l8s, record: l8r, entries: l8e,
			probes: "8 A records (192.0.2.1-8, TTL 300 down to 230) = ADDRS_MAX: passes; eight entries, one record with the eight addresses and TTL 230 s"},
		{name: "limits-9-addresses", frame: limitFrame("api.github.com", a9), slots: corpusSlots, skipQ: true,
			stats: l8s, record: l8r, entries: l8e,
			probes: "9 A records: the ninth (192.0.2.9, TTL 220) is neither collected nor compiled (n < ADDRS_MAX, line 484) and its TTL is not taken; passes; the same eight entries and record as limits-8-addresses"},
		{name: "limits-steps-a-on-last-step", frame: stepsFrame(21), slots: corpusSlots, skipQ: true,
			stats: one, record: oneRec, entries: oneTrie,
			probes: "owner names spend 539 steps on five CNAMEs, the A record's fixed part is step 544 = STEPS_MAX (line 574): passes; the A record is compiled; one entry, one record"},
		{name: "limits-steps-a-past-budget", frame: stepsFrame(22), slots: corpusSlots, skipQ: true,
			stats:  parsed,
			probes: "one owner label more: the A record's fixed part would be step 545, past STEPS_MAX; owner-name labels have no per-name cap, so legal long owners use up the budget (the 3.4 finding); passes, parsed, nothing learned, no record (fewer entries, never a wrong one: fail-safe)"},
	}
}
