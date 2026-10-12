package main

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/rules"
)

var (
	evNow  = time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	noProc = func(uint32) string { return "" }
)

// notedSnap is fakeSnap with a note on the rule, so the reference can be checked whole.
func notedSnap(t *testing.T) *snapshot {
	t.Helper()
	f, err := rules.Parse(strings.NewReader("[[program]]\nname = \"curl\"\npaths = []\n\n[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1/32\"\nproto = \"tcp\"\nport = 443\nverdict = \"allow\"\nnote = \"dns\"\n"), "/etc/snitch/rules.toml")
	if err != nil {
		t.Fatal(err)
	}
	res, _ := rules.Resolve(f, rules.OSFS(func(string) {}))
	return &snapshot{res: res, ent: rules.Encode(res)}
}

// Req 2.1: every kernel verdict and both hooks under their wire names; the table is the
// contract, so a swapped pair (allow-rule for deny-rule) fails here.
func TestToEventVerdictAndHookNames(t *testing.T) {
	verdictNames := map[uint8]string{0: "allow-monitor", 1: "allow-rule", 2: "deny-rule", 3: "deny-default", 4: "allow-local", 5: "allow-stale", 6: "allow-kill"}
	hookNames := map[uint8]string{0: "connect", 1: "sendmsg"}
	for v, wantV := range verdictNames {
		for h, wantH := range hookNames {
			e := sample()
			e.Verdict, e.Hook = v, h
			got := toEvent(&e, fakeSnap(t), noProc, evNow, nil)
			if got.Verdict != wantV || got.Hook != wantH {
				t.Fatalf("verdict %d hook %d: got %q %q, want %q %q", v, h, got.Verdict, got.Hook, wantV, wantH)
			}
		}
	}
	e := sample()
	e.Verdict = 42
	if got := toEvent(&e, fakeSnap(t), noProc, evNow, nil); got.Verdict != "verdict-42" {
		t.Fatalf("an unknown verdict is named by its number, got %q", got.Verdict)
	}
}

func TestToEventMappedProgramWithRuleReference(t *testing.T) {
	e := sample()
	e.Ppid = 1
	got := toEvent(&e, notedSnap(t), func(uint32) string { return "/proc/says/this" }, evNow, nil)
	want := api.Event{Type: "event", Time: evNow, Program: "curl", Path: "/usr/bin/curl", Pid: 4242, Ppid: 1, Comm: "curl",
		Addr: "1.1.1.1", Port: 443, Protocol: "tcp", Verdict: "allow-rule",
		Rule: &api.RuleRef{Id: 1, Note: "dns", Source: "/etc/snitch/rules.toml"}, Hook: "connect", Cookie: 77}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("event wrong:\n got %+v (rule %+v)\nwant %+v (rule %+v)", got, got.Rule, want, want.Rule)
	}
}

func TestToEventWithoutARuleHasANilReference(t *testing.T) {
	e := sample()
	e.Rule, e.Verdict = 0, 0
	if got := toEvent(&e, fakeSnap(t), noProc, evNow, nil); got.Rule != nil || got.Program != "curl" {
		t.Fatalf("no rule decided: want a nil reference and the program name, got %+v", got)
	}
	e.Rule = 9 // a rule id the snapshot does not know (a reload raced the event)
	if got := toEvent(&e, fakeSnap(t), noProc, evNow, nil); got.Rule != nil {
		t.Fatalf("an unknown rule id is no reference, got %+v", got.Rule)
	}
}

func TestToEventIPv6AndUDP(t *testing.T) {
	e := sample()
	e.Family, e.Proto, e.Hook, e.Dport = 10, 17, 1, 53
	e.Addr = netip.MustParseAddr("2001:db8::1").As16()
	got := toEvent(&e, fakeSnap(t), noProc, evNow, nil)
	if got.Addr != "2001:db8::1" || got.Port != 53 || got.Protocol != "udp" || got.Hook != "sendmsg" {
		t.Fatalf("got %+v", got)
	}
	e.Proto = 1
	if got := toEvent(&e, fakeSnap(t), noProc, evNow, nil); got.Protocol != "1" {
		t.Fatalf("another protocol is its number, got %q", got.Protocol)
	}
}

// Req 2.1: the program name "or unknown"; the path is what the kernel wrote, else /proc.
func TestToEventUnknownProgramPath(t *testing.T) {
	e := sample()
	e.Program, e.Rule, e.Verdict = 0, 0, 0
	setC(e.Path[:], "/tmp/curl-copy\x00")
	got := toEvent(&e, fakeSnap(t), func(uint32) string { return "/proc/says/this" }, evNow, nil)
	if got.Program != "unknown" || got.Path != "/tmp/curl-copy" {
		t.Fatalf("want unknown with the kernel's path, got %q %q", got.Program, got.Path)
	}
	e.Path = [256]int8{}
	got = toEvent(&e, fakeSnap(t), func(pid uint32) string { return "/proc/exe/of/" + fmt.Sprint(pid) }, evNow, nil)
	if got.Program != "unknown" || got.Path != "/proc/exe/of/4242" {
		t.Fatalf("want the /proc fallback, got %q %q", got.Program, got.Path)
	}
	got = toEvent(&e, nil, noProc, evNow, nil)
	if got.Program != "unknown" || got.Path != "" {
		t.Fatalf("a vanished process without a path: unknown and no path, got %q %q", got.Program, got.Path)
	}
}

func TestToEventContracts(t *testing.T) {
	e := sample()
	contracttest.Panics(t, contract.Precondition, func() { toEvent(&e, fakeSnap(t), nil, evNow, nil) })
	contracttest.Panics(t, contract.Precondition, func() { toEvent(&e, fakeSnap(t), noProc, time.Time{}, nil) })
	contracttest.Panics(t, contract.Precondition, func() { rulesView(nil) })
}

// Req 4.2, 4.3: rules and programs with the file each came from, in file order; a program is
// resolved when one executable maps (a declared path that is absent resolves nothing: Resolved
// false, Executables 0); the port is the single port or 0 (any).
func TestRulesViewSourcesAndCounts(t *testing.T) {
	self, _ := os.Executable()
	base := writeRules(t, "[[program]]\nname = \"me\"\npaths = [\""+self+"\", \"/nonexistent/me\"]\n\n[[program]]\nname = \"ghost\"\npaths = []\nnote = \"nothing\"\n\n[[program]]\nname = \"absent\"\npaths = [\"/nonexistent/absent\"]\n\n[[rule]]\nprogram = \"me\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\nnote = \"base\"\n\n[[rule]]\nprogram = \"any\"\nto = \"10.0.0.0/8\"\nproto = \"udp\"\nverdict = \"deny\"\n")
	ov := writeOverlay(t, "[[rule]]\nprogram = \"me\"\nto = \"1.1.1.1\"\nverdict = \"deny\"\nnote = \"local\"\n\n[[rule]]\nprogram = \"ghost\"\nto = \"8.8.8.8\"\nproto = \"tcp\"\nport = 443\nverdict = \"allow\"\n")
	snap, err := loadRules(base, ov, func(string) {})
	if err != nil || snap.rulesErr != nil {
		t.Fatalf("load: %v %v", err, snap.rulesErr)
	}
	rs, ps := rulesView(snap)
	wantRules := []api.RuleView{
		{Id: 1, Program: "any", To: "10.0.0.0/8", Protocol: "udp", Port: 0, Verdict: "deny", Source: base},
		{Id: 2, Program: "me", To: "1.1.1.1/32", Protocol: "", Port: 0, Verdict: "deny", Note: "local", Source: ov},
		{Id: 3, Program: "ghost", To: "8.8.8.8/32", Protocol: "tcp", Port: 443, Verdict: "allow", Source: ov},
	}
	wantPrograms := []api.ProgramView{
		{Name: "me", Paths: []string{self, "/nonexistent/me"}, Resolved: true, Executables: 1, Source: base},
		{Name: "ghost", Paths: []string{}, Resolved: false, Executables: 0, Source: base},
		{Name: "absent", Paths: []string{"/nonexistent/absent"}, Resolved: false, Executables: 0, Source: base},
	}
	if !reflect.DeepEqual(rs, wantRules) {
		t.Fatalf("rules wrong:\n got %+v\nwant %+v", rs, wantRules)
	}
	if !reflect.DeepEqual(ps, wantPrograms) {
		t.Fatalf("programs wrong:\n got %+v\nwant %+v", ps, wantPrograms)
	}
}

func TestRulesViewPortRangeIsReportedAsAny(t *testing.T) {
	f, err := rules.Parse(strings.NewReader("[[program]]\nname = \"curl\"\npaths = []\n\n[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nproto = \"tcp\"\nport = \"80-81\"\nverdict = \"allow\"\n"), "t")
	if err != nil {
		t.Fatal(err)
	}
	res, _ := rules.Resolve(f, rules.OSFS(func(string) {}))
	rs, _ := rulesView(&snapshot{res: res, ent: rules.Encode(res)})
	if len(rs) != 1 || rs[0].Port != 0 || rs[0].Protocol != "tcp" {
		t.Fatalf("a range has no single port on the wire, got %+v", rs)
	}
}

// Req 4.4: the learned view on the wire, times RFC 3339 in UTC.
func TestLearnedViewConverts(t *testing.T) {
	in := []rules.Observed{
		{Program: "curl", Path: "/usr/bin/curl", Addr: netip.MustParseAddr("1.1.1.1"), Proto: rules.TCP, Port: 443, Count: 3, First: evNow.In(time.FixedZone("x", 3600)), Last: evNow.Add(time.Minute)},
		{Program: "unknown-7-9", Addr: netip.MustParseAddr("2001:db8::1"), Proto: rules.AnyProto, Port: 0, Count: 1, First: evNow, Last: evNow},
	}
	want := []api.Observation{
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Protocol: "tcp", Port: 443, Count: 3, First: "2026-10-11T12:00:00Z", Last: "2026-10-11T12:01:00Z"},
		{Program: "unknown-7-9", Path: "", Addr: "2001:db8::1", Protocol: "", Port: 0, Count: 1, First: "2026-10-11T12:00:00Z", Last: "2026-10-11T12:00:00Z"},
	}
	if got := learnedView(in); !reflect.DeepEqual(got, want) {
		t.Fatalf("learned wrong:\n got %+v\nwant %+v", got, want)
	}
	if got := learnedView(nil); got == nil || len(got) != 0 {
		t.Fatalf("no observations is an empty list, not null: %#v", got)
	}
}

func TestToEventDNSNameAndReference(t *testing.T) {
	e := sample()
	snap := notedSnap(t)
	snap.res.ByID[e.Rule].To = netip.Prefix{}
	snap.res.ByID[e.Rule].Name = "example.org"
	lookup := func(addr netip.Addr, id uint32) string {
		if addr != netip.MustParseAddr("1.1.1.1") || id != e.Rule {
			t.Fatalf("lookup %v %d", addr, id)
		}
		return "www.example.org"
	}
	got := toEvent(&e, snap, noProc, evNow, lookup)
	if got.Name != "www.example.org" || got.Rule == nil || got.Rule.Id != 1 || got.Rule.Note != "dns" {
		t.Fatalf("event: %+v", got)
	}
	b, _ := json.Marshal(got)
	if !strings.Contains(string(b), `"name":"www.example.org"`) {
		t.Fatal(string(b))
	}
	got = toEvent(&e, snap, noProc, evNow, nil)
	b, _ = json.Marshal(got)
	if strings.Contains(string(b), `"name"`) {
		t.Fatal(string(b))
	}
}

func TestToEventDNSNameReachesTable(t *testing.T) {
	e := sample()
	got := toEvent(&e, notedSnap(t), noProc, evNow, namedDNSState().nameOf)
	table := api.NewTable(func() time.Time { return evNow })
	table.Observe(got)
	entries := table.Changed(evNow)
	if len(entries) != 1 || entries[0].Name != "recent.example.net" || entries[0].Addr != got.Addr {
		t.Fatalf("table: %+v", entries)
	}
}

func TestFactsRulesViewNameDestination(t *testing.T) {
	snap := notedSnap(t)
	snap.res.File.Rules[0].To = netip.Prefix{}
	snap.res.File.Rules[0].Name = "example.org"
	rs, _ := rulesView(snap)
	if rs[0].To != "example.org" {
		t.Fatalf("destination: %q", rs[0].To)
	}
}

func TestLearnedObservationNamedZeroAddress(t *testing.T) {
	got := learnedView([]rules.Observed{{Name: "www.example.org", First: evNow, Last: evNow}})
	b, _ := json.Marshal(got)
	if got[0].Addr != "" || got[0].Name != "www.example.org" || !strings.Contains(string(b), `"addr":""`) {
		t.Fatalf("named observation: %s", b)
	}
}

func TestDescribeAndObservationDNSName(t *testing.T) {
	e := sample()
	snap := notedSnap(t)
	r := snap.res.ByID[e.Rule]
	r.To, r.Name = netip.Prefix{}, "example.org"
	got := describe(&e, snap, noProc, "www.example.org")
	want := "allow (rule)            connect  pid 4242    curl            tcp  -> 1.1.1.1:443 (www.example.org)  program curl  rule #1 curl example.org tcp 443 allow"
	if got != want || strings.Contains(got+ruleText(r), "invalid Prefix") {
		t.Fatalf("log: %q\nwant %q", got, want)
	}
	o := observation(&e, snap, noProc, evNow, "www.example.org")
	if o.Name != "www.example.org" {
		t.Fatalf("observation: %+v", o)
	}
	learned := rules.NewLearned(nil)
	learned.Observe(o)
	if got := learned.File().Rules[0].Dest(); got != "www.example.org" {
		t.Fatalf("learned destination: %q", got)
	}

}
