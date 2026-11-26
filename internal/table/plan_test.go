package table

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

var planTime = time.Date(2026, 11, 26, 14, 5, 0, 0, time.UTC)

func planNote(t time.Time) string {
	return "snitch tui " + t.Local().Format("2006-01-02 15:04")
}

func planRow(t *testing.T, s Store, r Rules, open map[RowID]bool, level Level, title string) Row {
	t.Helper()
	rows := Rows(s, r, View{Open: open})
	return mustRow(t, rows, level, title)
}

func assertRefusal(t *testing.T, p Plan, substr string) {
	t.Helper()
	if len(p.Requests) != 0 || p.Unblock || p.Note != "" {
		t.Fatalf("refusal plan has requests/unblock/note: %+v", p)
	}
	if !strings.Contains(string(p.Refusal), substr) {
		t.Fatalf("refusal = %q, want substring %q", p.Refusal, substr)
	}
}

func TestPlanAddressTableCells(t *testing.T) {
	note := planNote(planTime)
	e4 := api.Entry{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "api.example.com", Port: 443, Protocol: "tcp"}
	e6 := api.Entry{Program: "curl", Path: "/usr/bin/curl", Addr: "2001:db8::1%eth0", Name: "api.example.com", Port: 443, Protocol: "tcp"}
	eMap := api.Entry{Program: "curl", Path: "/usr/bin/curl", Addr: "::ffff:9.9.9.9", Port: 53, Protocol: "udp"}
	s := (Store{}).Replace([]api.Entry{e4, e6, eMap})
	top := Rows(s, Rules{}, View{})
	curlRow := mustRow(t, top, Program, "curl")
	openAll := map[RowID]bool{curlRow.ID: true}
	for _, r := range Rows(s, Rules{}, View{Open: openAll}) {
		if r.Level == Host || r.Level == Group {
			openAll[r.ID] = true
		}
	}
	rAllow := Rules{Overlay: testOverlay, Views: []api.RuleView{
		{Id: 1, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "allow", Source: testBase},
	}}
	p4 := MakePlan(planRow(t, s, rAllow, openAll, Address, "1.1.1.1:443 tcp"), s, rAllow, planTime)
	want4 := []api.Request{{Type: "rule.add", Program: "curl", To: "1.1.1.1/32", Proto: "tcp", Port: 443, Verdict: "deny", Note: note}}
	if p4.Unblock || p4.Refusal != "" || !slices.Equal(p4.Requests, want4) {
		t.Fatalf("Address v4 add = %+v, want %+v", p4, want4)
	}
	p6 := MakePlan(planRow(t, s, Rules{}, openAll, Address, "[2001:db8::1%eth0]:443 tcp"), s, Rules{}, planTime)
	want6 := []api.Request{{Type: "rule.add", Program: "curl", To: "2001:db8::1/128", Proto: "tcp", Port: 443, Verdict: "deny", Note: note}}
	if !slices.Equal(p6.Requests, want6) {
		t.Fatalf("Address v6 add = %+v, want %+v", p6, want6)
	}
	pMap := MakePlan(planRow(t, s, Rules{}, openAll, Address, "[::ffff:9.9.9.9]:53 udp"), s, Rules{}, planTime)
	wantMap := []api.Request{{Type: "rule.add", Program: "curl", To: "9.9.9.9/32", Proto: "udp", Port: 53, Verdict: "deny", Note: note}}
	if !slices.Equal(pMap.Requests, wantMap) {
		t.Fatalf("Address mapped-v4 add = %+v, want %+v", pMap, wantMap)
	}
}

func TestPlanAddressOwnAndEnclosing(t *testing.T) {
	e := api.Entry{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "api.example.com", Port: 443, Protocol: "tcp"}
	s := (Store{}).Replace([]api.Entry{e})
	curlRow := planRow(t, s, Rules{}, nil, Program, "curl")
	hostRow := planRow(t, s, Rules{}, map[RowID]bool{curlRow.ID: true}, Host, "api.example.com")
	addrRow := planRow(t, s, Rules{}, map[RowID]bool{curlRow.ID: true, hostRow.ID: true}, Address, "1.1.1.1:443 tcp")

	for _, src := range []string{testOverlay, testBase} {
		r := Rules{Overlay: testOverlay, Views: []api.RuleView{
			{Id: 1, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "deny", Source: src},
		}}
		p := MakePlan(addrRow, s, r, planTime)
		want := []api.Request{{Type: "rule.remove", Program: "curl", To: "1.1.1.1/32", Proto: "tcp", Port: 443}}
		if !p.Unblock || p.Refusal != "" || !slices.Equal(p.Requests, want) {
			t.Fatalf("Address own (%s) = %+v, want %+v", src, p, want)
		}
	}
	rHost := Rules{Overlay: testOverlay, Views: []api.RuleView{
		{Id: 2, Program: "curl", To: "1.1.0.0/16", Protocol: "", Port: 0, Verdict: "deny", Source: testBase},
	}}
	assertRefusal(t, MakePlan(addrRow, s, rHost, planTime), "1.1.0.0/16")

	rProg := Rules{Overlay: testOverlay, Views: []api.RuleView{
		{Id: 3, Program: "curl", To: "0.0.0.0/0", Protocol: "", Port: 0, Verdict: "deny", Source: testOverlay},
	}}
	assertRefusal(t, MakePlan(addrRow, s, rProg, planTime), "curl")
}

func hostGroupFixture(t *testing.T) (Store, Row, Row) {
	t.Helper()
	es := []api.Entry{
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "api.example.com", Port: 443, Protocol: "tcp"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "2001:db8::1", Name: "api.example.com", Port: 443, Protocol: "tcp"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "192.168.1.10", Name: "api.example.com", Port: 443, Protocol: "tcp"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "8.8.8.8", Port: 53, Protocol: "udp"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "10.0.0.5", Port: 53, Protocol: "udp"},
	}
	s := (Store{}).Replace(es)
	curlRow := planRow(t, s, Rules{}, nil, Program, "curl")
	openP := map[RowID]bool{curlRow.ID: true}
	return s, planRow(t, s, Rules{}, openP, Host, "api.example.com"), planRow(t, s, Rules{}, openP, Group, "IP Addresses")
}

func TestPlanHostCells(t *testing.T) {
	note := planNote(planTime)
	s, hostRow, _ := hostGroupFixture(t)
	rPartial := Rules{Overlay: testOverlay, Views: []api.RuleView{
		{Id: 1, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "deny", Source: testOverlay},
	}}
	pAdd := MakePlan(hostRow, s, rPartial, planTime)
	wantAdd := []api.Request{{Type: "rule.add", Program: "curl", To: "2001:db8::1/128", Proto: "tcp", Port: 443, Verdict: "deny", Note: note}}
	if pAdd.Unblock || !slices.Equal(pAdd.Requests, wantAdd) {
		t.Fatalf("Host partial add = %+v, want %+v", pAdd, wantAdd)
	}
	rOwn := Rules{Overlay: testOverlay, Views: []api.RuleView{
		{Id: 1, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "deny", Source: testOverlay},
		{Id: 2, Program: "curl", To: "2001:db8::1/128", Protocol: "tcp", Port: 443, Verdict: "deny", Source: testOverlay},
	}}
	pRem := MakePlan(hostRow, s, rOwn, planTime)
	if !pRem.Unblock || len(pRem.Requests) != 2 || pRem.Requests[0].Type != "rule.remove" {
		t.Fatalf("Host remove = %+v", pRem)
	}
	rProg := Rules{Overlay: testOverlay, Views: []api.RuleView{
		{Id: 4, Program: "curl", To: "0.0.0.0/0", Protocol: "", Port: 0, Verdict: "deny", Source: testBase},
		{Id: 5, Program: "curl", To: "::/0", Protocol: "", Port: 0, Verdict: "deny", Source: testBase},
	}}
	assertRefusal(t, MakePlan(hostRow, s, rProg, planTime), "curl")
}

func TestPlanGroupCells(t *testing.T) {
	note := planNote(planTime)
	s, _, groupRow := hostGroupFixture(t)
	pAdd := MakePlan(groupRow, s, Rules{}, planTime)
	wantAdd := []api.Request{{Type: "rule.add", Program: "curl", To: "8.8.8.8/32", Proto: "udp", Port: 53, Verdict: "deny", Note: note}}
	if pAdd.Unblock || !slices.Equal(pAdd.Requests, wantAdd) {
		t.Fatalf("Group add = %+v, want %+v", pAdd, wantAdd)
	}
	rOwn := Rules{Overlay: testOverlay, Views: []api.RuleView{
		{Id: 3, Program: "curl", To: "8.8.8.0/24", Protocol: "", Port: 0, Verdict: "deny", Source: testOverlay},
	}}
	pRem := MakePlan(groupRow, s, rOwn, planTime)
	wantRem := []api.Request{{Type: "rule.remove", Program: "curl", To: "8.8.8.0/24", Proto: "", Port: 0}}
	if !pRem.Unblock || !slices.Equal(pRem.Requests, wantRem) {
		t.Fatalf("Group remove = %+v, want %+v", pRem, wantRem)
	}
	rProg := Rules{Overlay: testOverlay, Views: []api.RuleView{
		{Id: 4, Program: "curl", To: "0.0.0.0/0", Protocol: "", Port: 0, Verdict: "deny", Source: testBase},
	}}
	assertRefusal(t, MakePlan(groupRow, s, rProg, planTime), "curl")
}

func TestPlanProgramCells(t *testing.T) {
	note := planNote(planTime)
	s := (Store{}).Replace([]api.Entry{
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Port: 443, Protocol: "tcp"},
	})
	curlRow := planRow(t, s, Rules{}, nil, Program, "curl")

	// Not blocked -> two denies (0.0.0.0/0 and ::/0) + Note about local network.
	pAdd := MakePlan(curlRow, s, Rules{}, planTime)
	wantAdd := []api.Request{
		{Type: "rule.add", Program: "curl", To: "0.0.0.0/0", Proto: "", Port: 0, Verdict: "deny", Note: note},
		{Type: "rule.add", Program: "curl", To: "::/0", Proto: "", Port: 0, Verdict: "deny", Note: note},
	}
	if pAdd.Unblock || pAdd.Refusal != "" || !slices.Equal(pAdd.Requests, wantAdd) {
		t.Fatalf("Program add = %+v, want %+v", pAdd, wantAdd)
	}
	if !strings.Contains(string(pAdd.Note), "local network") {
		t.Fatalf("Program Note = %q, want mention of local network", pAdd.Note)
	}
	// Blocked by own rules (overlay or base file) -> two removes.
	for _, src := range []string{testOverlay, testBase} {
		rOwn := Rules{Overlay: testOverlay, Views: []api.RuleView{
			{Id: 1, Program: "curl", To: "0.0.0.0/0", Protocol: "", Port: 0, Verdict: "deny", Source: src},
			{Id: 2, Program: "curl", To: "::/0", Protocol: "", Port: 0, Verdict: "deny", Source: src},
		}}
		pRem := MakePlan(curlRow, s, rOwn, planTime)
		wantRem := []api.Request{
			{Type: "rule.remove", Program: "curl", To: "0.0.0.0/0", Proto: "", Port: 0},
			{Type: "rule.remove", Program: "curl", To: "::/0", Proto: "", Port: 0},
		}
		if !pRem.Unblock || pRem.Refusal != "" || !slices.Equal(pRem.Requests, wantRem) {
			t.Fatalf("Program remove (%s) = %+v, want %+v", src, pRem, wantRem)
		}
	}
	// Blocked otherwise (any-program rule) -> refusal.
	rAny := Rules{Overlay: testOverlay, Views: []api.RuleView{
		{Id: 3, Program: "any", To: "0.0.0.0/0", Protocol: "", Port: 0, Verdict: "deny", Source: testBase},
	}}
	assertRefusal(t, MakePlan(curlRow, s, rAny, planTime), "any")
}

func TestPlanUnnameableAndLocalRefusals(t *testing.T) {
	s := (Store{}).Replace([]api.Entry{
		{Program: "unknown", BytesSent: 500},
		{Program: "unknown", Addr: "1.1.1.1", Port: 443, Protocol: "tcp"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "127.0.0.1", Port: 80, Protocol: "tcp"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "fe80::1%eth0", Port: 80, Protocol: "tcp"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "::ffff:10.0.0.1", Port: 80, Protocol: "tcp"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "192.168.1.1", Name: "router.lan", Port: 80, Protocol: "tcp"},
	})
	top := Rows(s, Rules{}, View{})
	assertRefusal(t, MakePlan(mustRow(t, top, Bucket, "unknown"), s, Rules{}, planTime), "no rule can name it")
	unkRow := mustRow(t, top, Program, "unknown")
	assertRefusal(t, MakePlan(unkRow, s, Rules{}, planTime), "no rule can name it")

	curlRow := mustRow(t, top, Program, "curl")
	openC := map[RowID]bool{curlRow.ID: true}
	for _, r := range Rows(s, Rules{}, View{Open: openC}) {
		if r.Level == Host || r.Level == Group {
			openC[r.ID] = true
		}
	}
	// Host with only local address -> local refusal.
	assertRefusal(t, MakePlan(planRow(t, s, Rules{}, openC, Host, "router.lan"), s, Rules{}, planTime), "local network")
	// Even if a rule existed in Rules, local addresses are never blockable or removable.
	rLocal := Rules{Overlay: testOverlay, Views: []api.RuleView{
		{Id: 1, Program: "curl", To: "127.0.0.1/32", Protocol: "tcp", Port: 80, Verdict: "deny", Source: testOverlay},
	}}
	for _, title := range []string{"127.0.0.1:80 tcp", "[fe80::1%eth0]:80 tcp", "[::ffff:10.0.0.1]:80 tcp"} {
		assertRefusal(t, MakePlan(planRow(t, s, rLocal, openC, Address, title), s, rLocal, planTime), "local network")
	}
}

func TestPlanPathProgramAndLocalTimeNote(t *testing.T) {
	zone := time.FixedZone("X", 90*60)
	orig := time.Local
	time.Local = zone
	t.Cleanup(func() { time.Local = orig })

	s := (Store{}).Replace([]api.Entry{
		{Program: "unknown", Path: "/opt/bin/tool", Addr: "9.9.9.9", Port: 53, Protocol: "udp"},
	})
	progRow := planRow(t, s, Rules{}, nil, Program, "/opt/bin/tool")
	pProg := MakePlan(progRow, s, Rules{}, planTime)
	if len(pProg.Requests) != 2 || pProg.Requests[0].Path != "/opt/bin/tool" || pProg.Requests[0].Program != "" {
		t.Fatalf("unknown with path = %+v", pProg)
	}
	if pProg.Requests[0].Note != "snitch tui 2026-11-26 15:35" {
		t.Fatalf("local note = %q", pProg.Requests[0].Note)
	}
	// Once r.Programs declares the path under a name, rule.add uses Program instead of Path.
	rDeclared := Rules{Programs: []api.ProgramView{{Name: "tool", Paths: []string{"/opt/bin/tool"}, Source: testOverlay}}}
	pNamed := MakePlan(progRow, s, rDeclared, planTime)
	if pNamed.Requests[0].Program != "tool" || pNamed.Requests[0].Path != "" {
		t.Fatalf("declared by path = %+v", pNamed)
	}
}

func TestPlanRefusalSanitisesHostileStrings(t *testing.T) {
	s := (Store{}).Replace([]api.Entry{
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Port: 443, Protocol: "tcp"},
	})
	curlRow := planRow(t, s, Rules{}, nil, Program, "curl")
	r := Rules{Overlay: testOverlay, Views: []api.RuleView{
		{Id: 1, Program: "any", To: "0.0.0.0/0\x1b[31m", Verdict: "deny", Source: "/etc/snitch/\nrules.toml"},
	}}
	p := MakePlan(curlRow, s, r, planTime)
	if strings.ContainsAny(string(p.Refusal), "\x1b\n") || string(p.Refusal) != string(clean.Text(string(p.Refusal))) {
		t.Fatalf("unsanitised refusal: %q", p.Refusal)
	}
}

func TestPlanContracts(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() {
		MakePlan(Row{Level: Level(99)}, Store{}, Rules{}, planTime)
	})
	contracttest.Panics(t, contract.Postcondition, func() {
		finishPlan(Plan{})
	})
	contracttest.Panics(t, contract.Postcondition, func() {
		finishPlan(Plan{
			Requests: []api.Request{{Type: "rule.add", Program: "curl", To: "1.1.1.1/32"}},
			Refusal:  clean.Const("conflict"),
		})
	})
	for _, localTo := range []string{"192.168.1.1/32", "10.0.0.1", "fe80::1/128", "::ffff:127.0.0.1/32"} {
		contracttest.Panics(t, contract.Postcondition, func() {
			finishPlan(Plan{Requests: []api.Request{{Type: "rule.add", Program: "curl", To: localTo}}})
		})
	}
}
