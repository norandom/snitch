//go:build root

// Crafted Ethernet frames exercise parsing without sending traffic.
package dns

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

type frameOptions struct {
	name, source                                            string
	id, sport                                               uint16
	ipv6, query, truncated, twoQuestions, compressed, cname bool
	addr                                                    netip.Addr
}

func dnsPayload(t *testing.T, o frameOptions) []byte {
	t.Helper()
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: o.id, Response: !o.query, Truncated: o.truncated})
	if o.compressed {
		b.EnableCompression()
	}
	mustProg(t, b.StartQuestions())
	q := dnsmessage.Question{Name: dnsmessage.MustNewName(o.name + "."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}
	if o.addr.Is6() {
		q.Type = dnsmessage.TypeAAAA
	}
	mustProg(t, b.Question(q))
	if o.twoQuestions {
		mustProg(t, b.Question(dnsmessage.Question{Name: dnsmessage.MustNewName("other.example."), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}))
	}
	if !o.query {
		appendAnswers(t, &b, o, q.Name)
	}
	data, err := b.Finish()
	mustProg(t, err)
	// pin that the compressed case really carries a pointer to the question name (offset 12),
	// otherwise a library change would turn it into a copy of the plain A case
	if o.compressed && !bytes.Contains(data, []byte{0xC0, 0x0C}) {
		t.Fatal("compressed frame has no compression pointer")
	}
	return data
}

func appendAnswers(t *testing.T, b *dnsmessage.Builder, o frameOptions, owner dnsmessage.Name) {
	t.Helper()
	mustProg(t, b.StartAnswers())
	h := dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: 300}
	if o.cname {
		target := dnsmessage.MustNewName("x.example.")
		mustProg(t, b.CNAMEResource(h, dnsmessage.CNAMEResource{CNAME: target}))
		h.Name = target
	}
	if o.addr.Is4() {
		mustProg(t, b.AResource(h, dnsmessage.AResource{A: o.addr.As4()}))
	} else {
		mustProg(t, b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: o.addr.As16()}))
	}
}

func answerFrame(t *testing.T, o frameOptions) []byte {
	t.Helper()
	payload := dnsPayload(t, o)
	source := o.source
	if source == "" {
		source = "10.0.0.1"
		if o.ipv6 {
			source = "2001:db8::1"
		}
	}
	src, dst := netip.MustParseAddr(source), netip.MustParseAddr("10.0.0.9")
	if o.ipv6 {
		dst = netip.MustParseAddr("2001:db8::9")
	}
	sport, dport := o.sport, uint16(40000)
	if sport == 0 {
		sport = 53
	}
	if o.query {
		src, dst = dst, src
		sport, dport = 40000, 53
	}
	header := networkHeader(o.ipv6, src, dst, len(payload)+8)
	udp := make([]byte, 8)
	binary.BigEndian.PutUint16(udp, sport)
	binary.BigEndian.PutUint16(udp[2:], dport)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(payload)+8))
	eth := make([]byte, 14)
	binary.BigEndian.PutUint16(eth[12:], 0x0800)
	if o.ipv6 {
		binary.BigEndian.PutUint16(eth[12:], 0x86dd)
	}
	return append(append(append(eth, header...), udp...), payload...)
}

func networkHeader(v6 bool, src, dst netip.Addr, length int) []byte {
	if v6 {
		h := make([]byte, 40)
		h[0], h[6], h[7] = 0x60, 17, 64
		binary.BigEndian.PutUint16(h[4:], uint16(length))
		a, b := src.As16(), dst.As16()
		copy(h[8:24], a[:])
		copy(h[24:], b[:])
		return h
	}
	h := make([]byte, 20)
	h[0], h[8], h[9] = 0x45, 64, 17
	binary.BigEndian.PutUint16(h[2:], uint16(length+20))
	a, b := src.As4(), dst.As4()
	copy(h[12:16], a[:])
	copy(h[16:], b[:])
	return h
}
