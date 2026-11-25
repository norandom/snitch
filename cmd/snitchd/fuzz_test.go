package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	snitchbpf "github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/rules"
)

// fullEvent fills Path and Comm to their last byte without a NUL, so the accessors' bounds,
// not a terminator, end the strings.
func fullEvent() snitchbpf.SnitchEvent {
	e := sample()
	setC(e.Path[:], "/"+strings.Repeat("p", len(e.Path)-1))
	setC(e.Comm[:], strings.Repeat("c", len(e.Comm)))
	e.Family, e.Verdict, e.Hook = unix.AF_INET6, 0xff, 0xff
	copy(e.Addr[:], netip.MustParseAddr("2001:db8::1").AsSlice())
	return e
}

// fuzzSnap is fakeSnap for a *testing.F: a rule set with rule #1, so formatters take the
// rule branch for a fuzzed rule id 1.
func fuzzSnap(f *testing.F) *snapshot {
	src := "[[program]]\nname = \"curl\"\npaths = []\n\n[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1/32\"\nverdict = \"allow\"\n"
	file, err := rules.Parse(strings.NewReader(src), "fuzz")
	if err != nil {
		f.Fatal(err)
	}
	res, _ := rules.Resolve(file, rules.OSFS(func(string) {}))
	return &snapshot{res: res, ent: rules.Encode(res)}
}

// FuzzDecodeEvent: any bytes decode to a value or an error, never a panic (8.2); only the
// struct's exact size decodes (8.3); every accessor and formatter of a decoded value stays in
// its bounds. Run: go test -run '^$' -fuzz '^FuzzDecodeEvent$' -fuzztime 60s ./cmd/snitchd/
func FuzzDecodeEvent(f *testing.F) {
	valid := rawOf(sample(), 1)
	f.Add(valid[:eventSize])
	f.Add(valid[:eventSize-1])
	f.Add(valid)
	f.Add(rawOf(fullEvent(), 0))
	f.Add([]byte{})
	snap := fuzzSnap(f)
	exe := func(uint32) string { return "/proc/exe" }
	now := time.Unix(1, 0)
	f.Fuzz(func(t *testing.T, raw []byte) {
		e, err := decodeEvent(raw)
		if (err == nil) != (len(raw) == eventSize) {
			t.Fatalf("len %d: err %v", len(raw), err)
		}
		if err != nil {
			return
		}
		if !bytes.Equal(rawOf(e, 0), raw) {
			t.Fatal("decoded event does not re-encode to the record")
		}
		checkEventAccessors(t, &e)
		_ = describe(&e, snap, exe, "example.org")
		_ = describe(&e, nil, exe, "")
		_ = toEvent(&e, snap, exe, now, func(netip.Addr, uint32) string { return "" })
		_ = observation(&e, snap, exe, now, "")
	})
}

func checkEventAccessors(t *testing.T, e *snitchbpf.SnitchEvent) {
	t.Helper()
	checkCString(t, "pathOf", pathOf(e), len(e.Path))
	checkCString(t, "commOf", commOf(e), len(e.Comm))
	if a := addrOf(e); !a.IsValid() || a.Is4() != (e.Family == unix.AF_INET) {
		t.Fatalf("addrOf %v for family %d", a, e.Family)
	}
	if h := hookName(e); h != "connect" && h != "sendmsg" {
		t.Fatalf("hookName %q", h)
	}
	if verdictName(e) == "" || protoName(e.Proto) == "" || verdictWireOf(e.Verdict) == "" {
		t.Fatal("empty verdict or protocol name")
	}
	_ = destination(e)
}

// checkCString: a C string accessor stays within its array and stops before any NUL.
func checkCString(t *testing.T, accessor, s string, limit int) {
	t.Helper()
	if len(s) > limit || strings.IndexByte(s, 0) >= 0 {
		t.Fatalf("%s out of bounds: %d bytes of %d", accessor, len(s), limit)
	}
}
