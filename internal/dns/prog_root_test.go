//go:build root

// Parser cases pin pass-through, counters, records, and exact trie contents.
package dns

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/rules"
)

type parserCase struct {
	name             string
	opts             frameOptions
	slots            []Slot
	stats            Stats
	record, existing bool
}

func parserCases() []parserCase {
	slot := []Slot{{Program: 7, ID: 3}}
	ok := Stats{Seen: 1, Parsed: 1, Updates: 1}
	return []parserCase{
		{name: "A", slots: slot, stats: ok, record: true},
		{name: "AAAA", opts: frameOptions{addr: netip.MustParseAddr("2001:db8::42")}, slots: slot, stats: ok, record: true},
		{name: "CNAME", opts: frameOptions{cname: true}, slots: slot, stats: ok, record: true},
		{name: "compression", opts: frameOptions{compressed: true}, slots: slot, stats: ok, record: true},
		{name: "truncated", opts: frameOptions{truncated: true}, slots: slot, stats: Stats{Seen: 1, NotAnswer: 1}},
		{name: "wrong-resolver", opts: frameOptions{source: "9.9.9.9"}, slots: slot, stats: Stats{Seen: 1, NotResolver: 1}},
		{name: "wrong-port", opts: frameOptions{sport: 5353}, slots: slot},
		{name: "two-questions", opts: frameOptions{twoQuestions: true}, slots: slot, stats: Stats{Seen: 1, NotAnswer: 1}},
		{name: "long-name", opts: frameOptions{name: strings.Repeat("a", 35) + "." + strings.Repeat("b", 35)}, slots: slot, stats: Stats{Seen: 1, NameTooLong: 1}},
		{name: "no-domain", stats: Stats{Seen: 1, Parsed: 1}, record: true},
		{name: "existing-file-key", slots: slot, stats: Stats{Seen: 1, Parsed: 1, Exists: 1}, record: true, existing: true},
		{name: "three-slots", slots: []Slot{{Program: 7, ID: 3}, {Program: 7, Proto: rules.TCP, Port: 443, ID: 4}, {Program: 7, Proto: rules.UDP, Port: 53, ID: 5}}, stats: Stats{Seen: 1, Parsed: 1, Updates: 3}, record: true},
		{name: "IPv6-frame", opts: frameOptions{ipv6: true, addr: netip.MustParseAddr("2001:db8::42")}, slots: slot, stats: ok, record: true},
	}
}

func TestDNSProgParser(t *testing.T) {
	for _, tc := range parserCases() {
		t.Run(tc.name, func(t *testing.T) { checkParserCase(t, tc) })
	}
}

func checkParserCase(t *testing.T, tc parserCase) {
	c, trie := loadDNSForTest(t, true)
	r := progReader(t, c)
	o := tc.opts
	if o.name == "" {
		o.name = "api.github.com"
	}
	if !o.addr.IsValid() {
		o.addr = netip.MustParseAddr("93.184.216.34")
	}
	putResolver(t, c, "10.0.0.1")
	putResolver(t, c, "2001:db8::1")
	if len(tc.slots) > 0 {
		putDomain(t, c, "github.com", tc.slots)
	}
	want := map[rules.RuleKey]rules.RuleVal{}
	if tc.existing {
		k, v := progKey(o.addr, tc.slots[0]), rules.RuleVal{Verdict: 2, Id: 9}
		mustProg(t, trie.Put(k, v))
		want[k] = v
	}
	runDNSProg(t, c, "dns_answer", answerFrame(t, o))
	equalProg(t, progStats(t, c), tc.stats)
	var rec *Record
	if tc.record {
		rec = &Record{Name: o.name, TTL: 300 * time.Second, Addrs: []netip.Addr{o.addr}, Slots: tc.slots}
		if !tc.existing {
			for _, s := range tc.slots {
				want[progKey(o.addr, s)] = rules.RuleVal{Verdict: 1, Id: s.ID}
			}
		}
	}
	equalProg(t, progTrie(t, trie), want)
	checkProgRecord(t, r, rec)
	equalProg(t, len(progQuestions(t, c)), 0)
}

func TestDNSProgQuery(t *testing.T) {
	c, trie := loadDNSForTest(t, true)
	putResolver(t, c, "10.0.0.1")
	o := frameOptions{name: "api.github.com", id: 0x1234, query: true, addr: netip.MustParseAddr("93.184.216.34")}
	runDNSProg(t, c, "dns_query", answerFrame(t, o))
	equalProg(t, progStats(t, c), Stats{Queries: 1})
	q := progQuestions(t, c)
	equalProg(t, len(q), 1)
	for k, v := range q {
		equalProg(t, v.Qname, key(o.name))
		// The ABI stores the header ID in network byte order, without ntohs.
		equalProg(t, k.Id, uint16(0x3412))
		if v.Ns == 0 {
			t.Fatal("question timestamp is zero")
		}
	}
	equalProg(t, len(progTrie(t, trie)), 0)
	checkProgRecord(t, progReader(t, c), nil)
}
