//go:build root

// The question group of the corpus: answers without a recorded question, and answers whose
// question differs from the recorded one. Line numbers cite bpf/dns.bpf.c.
package dns

import (
	"net"
	"testing"

	"github.com/cilium/ebpf"
)

// questionCases: dns_answer looks the question up by {socket cookie, DNS id} (lines 540-541)
// and compares the lowercased names lane by lane (lines 550-556); a match is deleted (line
// 557), a miss or a differing name counts ST_NO_QUESTION and keeps the recorded question. The
// kernel's test run gives each run a fresh socket, so a question can only be recorded and
// matched through real sockets: the asked entries run the answer through a fake resolver on
// 127.0.0.1:53 (runCorpusExchange), as TestDNSProgSocketJoin does.
func questionCases() []corpusCase {
	one, oneRec, oneTrie := learned(corpusAddr4)
	noQ := Stats{Seen: 1, NoQuestion: 1}
	askedNoQ := Stats{Queries: 1, Seen: 1, NoQuestion: 1}
	one.Queries = 1
	// the question name's first label starts after its length byte
	label := dns4Off + dnsHdrLen + 1
	return []corpusCase{
		{name: "question-none-recorded", frame: v4Answer, slots: corpusSlots, stats: noQ,
			probes: "a well-formed answer with no question recorded for its socket and id (line 544): passes, counted as no question, nothing learned"},
		{name: "question-id-differs", asked: "api.github.com", frame: set16(v4Answer, dns4Off, 1), slots: corpusSlots,
			stats: askedNoQ, questions: 1,
			probes: "the socket asked with id 0, the answer carries id 1 (lookup miss, line 544): passes, counted as no question, nothing learned, the question stays"},
		{name: "question-name-content-differs", asked: "api.github.com", frame: overwriteFrame(v4Answer, label, "apx"), slots: corpusSlots,
			stats: askedNoQ, questions: 1,
			probes: "the socket asked api.github.com, the answer's question is apx.github.com (name compare, line 553): passes, counted as no question, nothing learned, the question stays for the real answer"},
		{name: "question-name-case-differs", asked: "api.github.com", frame: overwriteFrame(v4Answer, label, "API"), slots: corpusSlots,
			stats: one, record: oneRec, entries: oneTrie,
			probes: "the socket asked api.github.com, the answer's question is API.github.com: DNS names compare case-insensitively and read_qname lowercases both sides, so it matches; passes, the question is used up, one entry, one record named in lowercase"},
	}
}

// overwriteFrame returns a frame builder that overwrites the base frame with s at off.
func overwriteFrame(base func(*testing.T) []byte, off int, s string) func(*testing.T) []byte {
	return func(t *testing.T) []byte { return overwriteAt(t, base(t), off, []byte(s)) }
}

// runCorpusExchange attaches the tap to a test cgroup holding this process, sends the asked
// question (id 0) from a client socket to a fake resolver on 127.0.0.1:53 (dns_query records
// it), and answers with the DNS payload of the entry's IPv4 frame. The client receiving the
// answer unchanged is the pass (6.2) for this path.
func runCorpusExchange(t *testing.T, c *ebpf.Collection, tc corpusCase) {
	t.Helper()
	attachTestDNS(t, c, testCgroup(t))
	server, client := joinSockets(t)
	q := frameOptions{name: tc.asked, query: true, addr: corpusAddr4}
	_, err := client.WriteToUDP(dnsPayload(t, q), server.LocalAddr().(*net.UDPAddr))
	mustProg(t, err)
	buf := make([]byte, 4096)
	_, peer, err := server.ReadFromUDP(buf)
	mustProg(t, err)
	sendSocketAnswer(t, server, client, peer, tc.frame(t)[dns4Off:])
}
