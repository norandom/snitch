//go:build root

// The compression, name-limit and record-data groups of the corpus: pointers and reserved
// label types in the question and in owner names, names and labels beyond the tap's limits,
// and record data lengths that disagree with the record type or the frame. Line numbers cite
// bpf/dns.bpf.c.
package dns

import (
	"encoding/binary"
	"strings"
	"testing"
)

// Offsets into v4Answer (api.github.com, one uncompressed A record): the question name and
// the answer's owner name.
const (
	qname4Off    = dns4Off + dnsHdrLen
	ansOwner4Off = qname4Off + qnameWire + 4
	// the payload offset of the first record of a rawAnswer for api.github.com (0x20)
	rawRecordsOff = dnsHdrLen + qnameWire + 4
)

// wireName encodes a dotted name as uncompressed labels and the zero byte that ends it.
func wireName(name string) []byte {
	var b []byte
	for _, l := range strings.Split(name, ".") {
		b = append(append(b, byte(len(l))), l...)
	}
	return append(b, 0)
}

// rawAnswer builds an IPv4 frame from the resolver 10.0.0.1:53 around a hand-built answer:
// QR=1, qdcount 1, ancount len(records), the question's name bytes as given, qtype A, qclass
// IN, then the records' bytes. dnsmessage cannot express a bad pointer or a lying rdlength.
func rawAnswer(qname []byte, records ...[]byte) func(*testing.T) []byte {
	return func(*testing.T) []byte {
		p := []byte{0, 0, 0x80, 0, 0, 1, 0, byte(len(records)), 0, 0, 0, 0}
		p = append(append(p, qname...), 0, 1, 0, 1)
		for _, r := range records {
			p = append(p, r...)
		}
		return wrapFrame(frameOptions{}, p)
	}
}

// rawRecord is a record with the owner bytes as given, class IN, TTL 300, the stated
// rdlength and the record data actually present.
func rawRecord(owner []byte, typ, rdlen uint16, rdata []byte) []byte {
	f := make([]byte, 10)
	binary.BigEndian.PutUint16(f, typ)
	binary.BigEndian.PutUint16(f[2:], 1)
	binary.BigEndian.PutUint32(f[4:], 300)
	binary.BigEndian.PutUint16(f[8:], rdlen)
	return append(append(append([]byte{}, owner...), f...), rdata...)
}

// ownerA is the A record of corpusAddr4 under the given owner bytes.
func ownerA(owner []byte) []byte {
	a := corpusAddr4.As4()
	return rawRecord(owner, 1, 4, a[:])
}

// compressionCases: read_qname rejects any of the top two bits in a question length byte
// (lines 324-325: a pointer, or the reserved types 0x40 / 0x80) and dns_answer counts
// ST_NAME_TOO_LONG. In an owner name walk_step ends the name at a pointer after its two bytes
// without following it (lines 463-465), so no pointer can loop, run forward or leave the
// packet; a reserved type stops the walk (err 2, lines 466-468).
func compressionCases() []corpusCase {
	one, oneRec, oneTrie := learned(corpusAddr4)
	q := wireName("api.github.com")
	tooLong := Stats{Seen: 1, NameTooLong: 1}
	parsed := Stats{Seen: 1, Parsed: 1}
	// the owner name is never read, never followed and never compared: every A/AAAA of the
	// answer section is attributed to the matched question name, so the address is learned as
	// from the same answer with a well-formed owner (deviation from 6.3, fail-safe: the bytes
	// learned from are a complete A record from a registered resolver)
	const unfollowed = ": passes; walk_step ends the owner at the pointer without following it (lines 463-465) and compiles the A record that follows; one entry, one record (the owner is never used, fail-safe)"
	return []corpusCase{
		{name: "compression-owner-pointer-to-itself", frame: rawAnswer(q, ownerA([]byte{0xC0, rawRecordsOff})), slots: corpusSlots, skipQ: true,
			stats: one, record: oneRec, entries: oneTrie,
			probes: "the answer's owner name is a pointer to its own offset (a loop)" + unfollowed},
		{name: "compression-owner-pointer-forward", frame: rawAnswer(q, ownerA([]byte{0xC0, rawRecordsOff + 2 + 10})), slots: corpusSlots, skipQ: true,
			stats: one, record: oneRec, entries: oneTrie,
			probes: "the answer's owner name points forward, at the record's own address bytes" + unfollowed},
		{name: "compression-owner-pointer-beyond-frame", frame: rawAnswer(q, ownerA([]byte{0xFF, 0xFF})), slots: corpusSlots, skipQ: true,
			stats: one, record: oneRec, entries: oneTrie,
			probes: "the answer's owner name points at offset 0x3FFF, beyond the frame" + unfollowed},
		{name: "compression-question-pointer", frame: rawAnswer([]byte{0xC0, dnsHdrLen}, ownerA(q)), slots: corpusSlots, skipQ: true,
			stats:  tooLong,
			probes: "the question name is a pointer to itself (line 324): passes, counted as name too long, nothing learned"},
		{name: "compression-question-pointer-after-label", frame: rawAnswer([]byte{3, 'a', 'p', 'i', 0xC0, dnsHdrLen}, ownerA(q)), slots: corpusSlots, skipQ: true,
			stats:  tooLong,
			probes: "the question name is a label and then a pointer back to its start (line 324): passes, counted as name too long, nothing learned"},
		{name: "compression-reserved-0x40-question", frame: setByte(v4Answer, qname4Off, 0x43), slots: corpusSlots, skipQ: true,
			stats:  tooLong,
			probes: "the question's first length byte has the reserved type 0x40 (line 324): passes, counted as name too long, nothing learned"},
		{name: "compression-reserved-0x80-question", frame: setByte(v4Answer, qname4Off, 0x83), slots: corpusSlots, skipQ: true,
			stats:  tooLong,
			probes: "the question's first length byte has the reserved type 0x80 (line 324): passes, counted as name too long, nothing learned"},
		{name: "compression-reserved-0x40-owner", frame: setByte(v4Answer, ansOwner4Off, 0x43), slots: corpusSlots, skipQ: true,
			stats:  parsed,
			probes: "the answer's owner name starts with the reserved type 0x40 (lines 466-468, err 2): passes, parsed, the walk stops before the A record; nothing learned, no record"},
		{name: "compression-reserved-0x80-owner", frame: setByte(v4Answer, ansOwner4Off, 0x83), slots: corpusSlots, skipQ: true,
			stats:  parsed,
			probes: "the answer's owner name starts with the reserved type 0x80 (lines 466-468, err 2): passes, parsed, the walk stops before the A record; nothing learned, no record"},
	}
}

// nameLimitCases: read_qname counts n, the wire length without the closing zero, and refuses
// n >= NAME_MAX = 64 (line 330), so the longest accepted name is 63 bytes (a 62-character
// name, rules.ParseName's limit). Its loop runs LABELS_MAX = 16 times and needs one turn for
// the closing zero (lines 318-335), so the most labels accepted is 15 and 16 is the first
// refused. An owner label is skipped by its length (line 470); one past the frame stops the
// walk at the next load (err 1, line 456).
func nameLimitCases() []corpusCase {
	tooLong := Stats{Seen: 1, NameTooLong: 1}
	return []corpusCase{
		{name: "names-64-byte-name", frame: v4Named(strings.Repeat("x", 48) + ".api.github.com"), slots: corpusSlots, skipQ: true,
			stats:  tooLong,
			probes: "a question name of 64 wire bytes (48x.api.github.com), one past the longest accepted (line 330): passes, counted as name too long, nothing learned"},
		{name: "names-16-labels", frame: v4Named("a.b.c.d.e.f.g.h.i.j.k.l.m.n.github.com"), slots: corpusSlots, skipQ: true,
			stats:  tooLong,
			probes: "a question name of 16 labels: the 16-turn loop reads 16 labels and never the closing zero (line 334), so 15 is the most accepted; passes, counted as name too long, nothing learned"},
		{name: "names-17-labels", frame: v4Named("a.b.c.d.e.f.g.h.i.j.k.l.m.n.o.github.com"), slots: corpusSlots, skipQ: true,
			stats:  tooLong,
			probes: "a question name of 17 labels (line 334): passes, counted as name too long, nothing learned"},
		{name: "names-63-byte-label-overruns-frame-question", frame: rawAnswer([]byte{63, 'a', 'p', 'i'}), slots: corpusSlots, skipQ: true,
			stats:  tooLong,
			probes: "the question's first label claims 63 bytes and the frame ends 7 bytes after it (three letters, qtype, qclass, no record): n = 64 is refused before any read (line 330); passes, counted as name too long, nothing learned"},
		{name: "names-63-byte-label-overruns-frame-owner", frame: setByte(v4Answer, ansOwner4Off, 63), slots: corpusSlots, skipQ: true,
			stats:  Stats{Seen: 1, Parsed: 1},
			probes: "the answer's owner label claims 63 bytes, past the frame's end: skipped by its length (line 470), the next load fails (err 1, line 456); passes, parsed, nothing learned, no record"},
	}
}

// v4Named is the well-formed IPv4 answer of corpusAddr4 for name, uncompressed.
func v4Named(name string) func(*testing.T) []byte {
	return func(t *testing.T) []byte {
		t.Helper()
		return answerFrame(t, frameOptions{name: name, addr: corpusAddr4})
	}
}

// recordDataCases: walk_step compiles a record only for type 1 with rdlength 4 or type 28 with
// rdlength 16 (line 484); every other record is skipped by its rdlength (line 499), and a
// skip past the frame makes the next owner load fail (err 1, line 456), so a later address is
// never reached. The record data present always matches the stated rdlength unless it says
// otherwise.
func recordDataCases() []corpusCase {
	q := wireName("api.github.com")
	parsed := Stats{Seen: 1, Parsed: 1}
	const skipped = ": passes, parsed, skipped by its rdlength (lines 484, 499), nothing learned, no record"
	cname := wireName("x.example")
	return []corpusCase{
		{name: "record-a-rdlen-3", frame: rawAnswer(q, rawRecord(q, 1, 3, []byte{93, 184, 216})), slots: corpusSlots, skipQ: true,
			stats: parsed, probes: "an A record with rdlength 3 and three bytes of data" + skipped},
		{name: "record-a-rdlen-5", frame: rawAnswer(q, rawRecord(q, 1, 5, []byte{93, 184, 216, 34, 1})), slots: corpusSlots, skipQ: true,
			stats: parsed, probes: "an A record with rdlength 5 and five bytes of data" + skipped},
		{name: "record-a-rdlen-16", frame: rawAnswer(q, rawRecord(q, 1, 16, corpusAddr6.AsSlice())), slots: corpusSlots, skipQ: true,
			stats: parsed, probes: "an A record with rdlength 16 and sixteen bytes of data (an IPv6 address)" + skipped},
		{name: "record-aaaa-rdlen-4", frame: rawAnswer(q, rawRecord(q, 28, 4, corpusAddr4.AsSlice())), slots: corpusSlots, skipQ: true,
			stats: parsed, probes: "an AAAA record with rdlength 4 and four bytes of data (an IPv4 address)" + skipped},
		{name: "record-rdlen-beyond-frame", frame: rawAnswer(q, rawRecord(q, 5, 1024, cname), ownerA(q)), slots: corpusSlots, skipQ: true,
			stats:  parsed,
			probes: "a CNAME whose rdlength 1024 runs past the frame, then a well-formed A record: the skip (line 499) lands beyond the frame, the next owner load fails (err 1, line 456), the A record is never walked; passes, parsed, nothing learned, no record"},
	}
}
