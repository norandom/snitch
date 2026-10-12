package main

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
	"unsafe"

	snitchbpf "github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/rules"
)

func rawOf(e snitchbpf.SnitchEvent, extra int) []byte {
	b := make([]byte, eventSize+extra)
	copy(b, (*[eventSize]byte)(unsafe.Pointer(&e))[:])
	return b
}

func setC(dst []int8, s string) {
	for i, c := range []byte(s) {
		dst[i] = int8(c)
	}
}

func sample() snitchbpf.SnitchEvent {
	e := snitchbpf.SnitchEvent{Pid: 4242, ExeIno: 100, ExeDev: 8<<20 | 1, Program: 1, Dport: 443, Family: 2, Proto: 6, Verdict: 1, Rule: 1, Cookie: 77}
	copy(e.Addr[:], []byte{1, 1, 1, 1})
	setC(e.Comm[:], "curl")
	setC(e.Path[:], "/usr/bin/curl")
	// stale bytes after the NUL must be ignored
	for i := len("/usr/bin/curl") + 1; i < 40; i++ {
		e.Path[i] = 'X'
	}
	return e
}

func fakeSnap(t *testing.T) *snapshot {
	t.Helper()
	f, err := rules.Parse(strings.NewReader("[[program]]\nname = \"curl\"\npaths = []\n\n[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1/32\"\nproto = \"tcp\"\nport = 443\nverdict = \"allow\"\n"), "t")
	if err != nil {
		t.Fatal(err)
	}
	res, _ := rules.Resolve(f, rules.OSFS(func(string) {}))
	return &snapshot{res: res, ent: rules.Encode(res)}
}

func TestDecodeEventIsAFixedLayoutCopy(t *testing.T) {
	e := decodeEvent(rawOf(sample(), 8)) // records are padded to 8 bytes
	if e.Pid != 4242 || e.Dport != 443 || e.Rule != 1 || e.Cookie != 77 || addrOf(&e) != netip.MustParseAddr("1.1.1.1") {
		t.Fatalf("decoded wrong: %+v", e)
	}
	if pathOf(&e) != "/usr/bin/curl" || commOf(&e) != "curl" {
		t.Fatalf("strings must stop at the NUL: %q %q", pathOf(&e), commOf(&e))
	}
	contracttest.Panics(t, contract.Precondition, func() { decodeEvent(rawOf(sample(), 0)[:eventSize-1]) })
}

// The kernel's struct event is the contract: rule is the u32 at byte 64, the socket cookie the
// u64 at byte 72 (after rule and its alignment pad), the path starts at 80, and the whole
// record is 336 bytes. A binding that puts the cookie anywhere else decodes garbage here.
func TestDecodeEventReadsTheCookieAtTheKernelOffset(t *testing.T) {
	const cookieOffset, pathOffset, size = 72, 80, 336
	if eventSize != size {
		t.Fatalf("struct event is %d bytes, the kernel layout says %d", eventSize, size)
	}
	raw := make([]byte, eventSize)
	binary.LittleEndian.PutUint32(raw[64:], 9)
	binary.LittleEndian.PutUint64(raw[cookieOffset:], 0x1122334455667788)
	copy(raw[pathOffset:], "/usr/bin/curl\x00")
	e := decodeEvent(raw)
	if e.Rule != 9 || e.Cookie != 0x1122334455667788 || pathOf(&e) != "/usr/bin/curl" {
		t.Fatalf("rule %d cookie %#x path %q", e.Rule, e.Cookie, pathOf(&e))
	}
}

func TestDescribeMappedProgramWithRule(t *testing.T) {
	e := sample()
	got := describe(&e, fakeSnap(t), func(uint32) string { return "/proc/says/this" }, "")
	for _, want := range []string{"allow (rule)", "connect", "pid 4242", "curl", "tcp", "1.1.1.1:443", "program curl", "rule #1 curl 1.1.1.1/32 tcp 443 allow"} {
		if !strings.Contains(got, want) {
			t.Fatalf("%q lacks %q", got, want)
		}
	}
	if strings.Contains(got, "/proc/says") || strings.Contains(got, "unknown") {
		t.Fatalf("a mapped program is named, not pathed: %q", got)
	}
}

func TestDescribeUnknownProgramUsesTheKernelPath(t *testing.T) {
	e := sample()
	e.Program, e.Rule, e.Verdict = 0, 0, 0
	setC(e.Path[:], "/tmp/curl-copy\x00")
	got := describe(&e, fakeSnap(t), func(uint32) string { return "/proc/says/this" }, "")
	if !strings.Contains(got, "allow (monitor)") || !strings.Contains(got, "program /tmp/curl-copy (unknown)") || strings.Contains(got, "rule #") {
		t.Fatalf("got %q", got)
	}
}

func TestDescribeFallsBackToProcWhenThePathIsEmpty(t *testing.T) {
	e := sample()
	e.Program, e.Rule = 0, 3
	e.Path = [256]int8{}
	got := describe(&e, fakeSnap(t), func(pid uint32) string { return "/proc/exe/of/" + fmt.Sprint(pid) }, "")
	if !strings.Contains(got, "program /proc/exe/of/4242 (unknown)") || strings.Contains(got, "rule #") {
		t.Fatalf("got %q", got)
	}
	gone := describe(&e, nil, func(uint32) string { return "" }, "")
	if !strings.Contains(gone, "program unknown") {
		t.Fatalf("a vanished process without a path is plain unknown: %q", gone)
	}
}

func TestDescribeV6AndSendmsg(t *testing.T) {
	e := sample()
	e.Family, e.Proto, e.Hook, e.Dport, e.Program, e.Rule = 10, 17, 1, 53, 0, 0
	e.Addr = netip.MustParseAddr("2001:db8::1").As16()
	got := describe(&e, nil, func(uint32) string { return "" }, "")
	if !strings.Contains(got, "sendmsg") || !strings.Contains(got, "udp") || !strings.Contains(got, "[2001:db8::1]:53") {
		t.Fatalf("got %q", got)
	}
}

func TestObservationCarriesIdentityPathAndProgram(t *testing.T) {
	e := sample()
	e.Rule, e.Verdict = 0, 0
	at := time.Unix(1_000_000, 0)
	o := observation(&e, fakeSnap(t), func(uint32) string { return "" }, at, "")
	want := rules.Observation{Path: "/usr/bin/curl", Exe: rules.ExeKey{Ino: 100, Dev: 8<<20 | 1}, Program: "curl",
		Addr: netip.MustParseAddr("1.1.1.1"), Proto: rules.TCP, Port: 443, At: at}
	if o != want {
		t.Fatalf("\n got %+v\nwant %+v", o, want)
	}
	e.Program = 0
	e.Path = [256]int8{}
	o = observation(&e, fakeSnap(t), func(uint32) string { return "/from/proc" }, at, "")
	if o.Program != "" || o.Path != "/from/proc" {
		t.Fatalf("unknown program: no name, path from /proc: %+v", o)
	}
	_ = os.Getpid
}

func TestRuleTextSaysAnyForProtoAndPort(t *testing.T) {
	r := &rules.Rule{ID: 7, Program: "any", To: netip.MustParsePrefix("0.0.0.0/0"), Verdict: rules.Deny}
	if got := ruleText(r); got != "#7 any 0.0.0.0/0 any any deny" {
		t.Fatalf("got %q", got)
	}
}
