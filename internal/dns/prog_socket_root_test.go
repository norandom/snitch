//go:build root

// Real UDP sockets prove that egress questions authorize only their matching answer.
package dns

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/rules"
	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSProgSocketJoin(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root")
	}
	path := testCgroup(t)
	c, trie := loadDNSForTest(t, false)
	putResolver(t, c, "127.0.0.1")
	slot := Slot{Program: 7, ID: 3}
	putDomain(t, c, "github.com", []Slot{slot})
	attachTestDNS(t, c, path)
	r := progReader(t, c)
	server, client := joinSockets(t)
	o := frameOptions{name: "api.github.com", id: 0x1234, query: true, addr: netip.MustParseAddr("93.184.216.34")}
	peer := exchangeQuery(t, server, client, o)
	want := map[rules.RuleKey]rules.RuleVal{progKey(o.addr, slot): {Verdict: 1, Id: 3}}
	equalProg(t, progTrie(t, trie), want)
	equalProg(t, progStats(t, c), Stats{Queries: 1, Seen: 1, Parsed: 1, Updates: 1})
	equalProg(t, len(progQuestions(t, c)), 0)
	checkProgRecord(t, r, &Record{Name: o.name, TTL: 300 * time.Second, Addrs: []netip.Addr{o.addr}, Slots: []Slot{slot}})
	o.query = false
	o.id++
	sendSocketAnswer(t, server, client, peer, dnsPayload(t, o))
	equalProg(t, progStats(t, c), Stats{Queries: 1, Seen: 2, Parsed: 1, Updates: 1, NoQuestion: 1})
	equalProg(t, progTrie(t, trie), want)
	equalProg(t, len(progQuestions(t, c)), 0)
	checkProgRecord(t, r, nil)
}

func joinSockets(t *testing.T) (*net.UDPConn, *net.UDPConn) {
	t.Helper()
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 53})
	if err != nil {
		t.Fatalf("fake resolver must bind 127.0.0.1:53 (check for an existing listener): %v", err)
	}
	t.Cleanup(func() { mustProg(t, server.Close()) })
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	mustProg(t, err)
	t.Cleanup(func() { mustProg(t, client.Close()) })
	mustProg(t, server.SetDeadline(time.Now().Add(5*time.Second)))
	mustProg(t, client.SetDeadline(time.Now().Add(5*time.Second)))
	return server, client
}

func exchangeQuery(t *testing.T, server, client *net.UDPConn, o frameOptions) *net.UDPAddr {
	t.Helper()
	_, err := client.WriteToUDP(dnsPayload(t, o), server.LocalAddr().(*net.UDPAddr))
	mustProg(t, err)
	buf := make([]byte, 4096)
	n, peer, err := server.ReadFromUDP(buf)
	mustProg(t, err)
	var p dnsmessage.Parser
	h, err := p.Start(buf[:n])
	mustProg(t, err)
	q, err := p.Question()
	mustProg(t, err)
	equalProg(t, h.ID, o.id)
	equalProg(t, q.Name.String(), o.name+".")
	o.query = false
	sendSocketAnswer(t, server, client, peer, dnsPayload(t, o))
	return peer
}

func sendSocketAnswer(t *testing.T, server, client *net.UDPConn, peer *net.UDPAddr, data []byte) {
	t.Helper()
	_, err := server.WriteToUDP(data, peer)
	mustProg(t, err)
	buf := make([]byte, 4096)
	n, from, err := client.ReadFromUDP(buf)
	mustProg(t, err)
	equalProg(t, from.String(), server.LocalAddr().String())
	equalProg(t, buf[:n], data)
}
