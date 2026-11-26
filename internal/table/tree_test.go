package table

import (
	"slices"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
)

func fixtureEntries() []api.Entry {
	return []api.Entry{
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "api.example.com", Port: 443, Protocol: "tcp", AllowCount: 2, LastSeen: "2026-10-11T12:00:10Z", BytesSent: 1000, Rate: 10.5, Verdict: "allow-monitor"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "2001:db8::1", Name: "api.example.com", Port: 443, Protocol: "tcp", AllowCount: 1, DenyCount: 1, LastSeen: "2026-10-11T12:00:20Z", BytesSent: 2000, Rate: 20.5, Verdict: "deny-rule"},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "9.9.9.9", Port: 8443, Protocol: "tcp", AllowCount: 4, LastSeen: "2026-10-11T12:00:05Z", BytesSent: 500, Rate: 5.0, Verdict: "allow-rule"},
		{Program: "unknown", Path: "/usr/bin/dig", Addr: "2620:fe::fe", Port: 53, Protocol: "udp", AllowCount: 3, LastSeen: "2026-10-11T12:00:15Z", BytesSent: 300, Rate: 3.0, Verdict: "allow-monitor"},
		{Program: "unknown", LastSeen: "2026-10-11T12:00:01Z", BytesSent: 9216},
	}
}

func mustRow(t *testing.T, rows []Row, level Level, title string) Row {
	t.Helper()
	for _, r := range rows {
		if r.Level == level && string(r.Title) == title {
			return r
		}
	}
	t.Fatalf("missing row level=%d title=%q", level, title)
	return Row{}
}

func mustChild(t *testing.T, rows []Row, level Level, parent RowID) Row {
	t.Helper()
	for _, r := range rows {
		if r.Level == level && r.Parent == parent {
			return r
		}
	}
	t.Fatalf("missing child level=%d parent=%q", level, parent)
	return Row{}
}

func assertShape(t *testing.T, r Row, depth int, parent RowID, hasKids, open bool) {
	t.Helper()
	if r.Depth != depth || r.Parent != parent || r.HasKids != hasKids || r.Open != open {
		t.Fatalf("%q shape = depth:%d parent:%q hasKids:%v open:%v, want %d/%q/%v/%v",
			r.Title, r.Depth, r.Parent, r.HasKids, r.Open, depth, parent, hasKids, open)
	}
}

func TestRowsClosedAndBucketLocked(t *testing.T) {
	s := (Store{}).Replace(fixtureEntries())
	closed := Rows(s, Rules{}, View{})
	if len(closed) != 3 {
		t.Fatalf("closed rows = %d, want 3", len(closed))
	}
	assertShape(t, mustRow(t, closed, Program, "curl"), 0, "", true, false)
	assertShape(t, mustRow(t, closed, Program, "/usr/bin/dig"), 0, "", true, false)
	bucketRow := mustRow(t, closed, Bucket, "unknown")
	assertShape(t, bucketRow, 0, "", false, false)
	openBucket := Rows(s, Rules{}, View{Open: map[RowID]bool{bucketRow.ID: true}})
	if len(openBucket) != 3 {
		t.Fatalf("opening bucket changed row count to %d, want 3", len(openBucket))
	}
	assertShape(t, mustRow(t, openBucket, Bucket, "unknown"), 0, "", false, false)
}

func TestRowsThreeLevelsAndIPAddresses(t *testing.T) {
	s := (Store{}).Replace(fixtureEntries())
	top := Rows(s, Rules{}, View{})
	curlRow, digRow := mustRow(t, top, Program, "curl"), mustRow(t, top, Program, "/usr/bin/dig")
	openMid := Rows(s, Rules{}, View{Open: map[RowID]bool{curlRow.ID: true, digRow.ID: true}})
	if len(openMid) != 6 {
		t.Fatalf("openMid rows = %d, want 6", len(openMid))
	}
	hostRow := mustRow(t, openMid, Host, "api.example.com")
	assertShape(t, hostRow, 1, curlRow.ID, true, false)
	curlGroup, digGroup := mustChild(t, openMid, Group, curlRow.ID), mustChild(t, openMid, Group, digRow.ID)
	assertShape(t, curlGroup, 1, curlRow.ID, true, false)
	if string(curlGroup.Title) != "IP Addresses" || string(digGroup.Title) != "IP Addresses" {
		t.Fatalf("group titles = %q / %q, want IP Addresses", curlGroup.Title, digGroup.Title)
	}
	openAll := Rows(s, Rules{}, View{Open: map[RowID]bool{curlRow.ID: true, hostRow.ID: true, curlGroup.ID: true, digRow.ID: true, digGroup.ID: true}})
	if len(openAll) != 10 {
		t.Fatalf("fully expanded rows = %d, want 10", len(openAll))
	}
	assertShape(t, mustRow(t, openAll, Address, "1.1.1.1:443 tcp"), 2, hostRow.ID, false, false)
	assertShape(t, mustRow(t, openAll, Address, "[2620:fe::fe]:53 udp"), 2, digGroup.ID, false, false)
}

func assertSums(t *testing.T, r Row, sent, allow, deny uint64, rate float64, keys int) {
	t.Helper()
	if r.Sent != sent || r.Rate != rate || r.Allow != allow || r.Deny != deny || len(r.Keys) != keys {
		t.Fatalf("%q sums = sent:%d rate:%v allow:%d deny:%d keys:%d", r.Title, r.Sent, r.Rate, r.Allow, r.Deny, len(r.Keys))
	}
}
func TestRowsSumsAndVerdict(t *testing.T) {
	s := (Store{}).Replace(fixtureEntries())
	curlRow := mustRow(t, Rows(s, Rules{}, View{}), Program, "curl")
	hostRow := mustRow(t, Rows(s, Rules{}, View{Open: map[RowID]bool{curlRow.ID: true}}), Host, "api.example.com")
	wantLast, _ := time.Parse(time.RFC3339, "2026-10-11T12:00:20Z")
	assertSums(t, curlRow, 3500, 7, 1, 36.0, 3)
	if !curlRow.Last.Equal(wantLast) || string(curlRow.Verdict) != "deny-rule" {
		t.Fatalf("curl last/verdict = %v / %q", curlRow.Last, curlRow.Verdict)
	}
	assertSums(t, hostRow, 3000, 3, 1, 31.0, 2)
}

func TestRowsIdentitySurvivesSummary(t *testing.T) {
	entries := fixtureEntries()
	s1 := (Store{}).Replace(entries)
	curl1 := mustRow(t, Rows(s1, Rules{}, View{}), Program, "curl")
	host1 := mustRow(t, Rows(s1, Rules{}, View{Open: map[RowID]bool{curl1.ID: true}}), Host, "api.example.com")
	open := map[RowID]bool{curl1.ID: true, host1.ID: true}
	addr1 := mustRow(t, Rows(s1, Rules{}, View{Open: open}), Address, "1.1.1.1:443 tcp")
	updated := entries[0]
	updated.BytesSent, updated.Rate, updated.AllowCount, updated.LastSeen, updated.Verdict = 5000, 100.0, 10, "2026-10-11T12:00:30Z", "allow-rule"
	after := Rows(s1.Upsert([]api.Entry{updated}), Rules{}, View{Open: open})
	curl2, host2, addr2 := mustRow(t, after, Program, "curl"), mustRow(t, after, Host, "api.example.com"), mustRow(t, after, Address, "1.1.1.1:443 tcp")
	if curl2.ID != curl1.ID || host2.ID != host1.ID || addr2.ID != addr1.ID {
		t.Fatalf("IDs changed across summary")
	}
	if addr2.Sent != 5000 || host2.Sent != 7000 || curl2.Sent != 7500 || string(curl2.Verdict) != "allow-rule" {
		t.Fatalf("updated sums wrong: addr=%d host=%d curl=%d verdict=%q", addr2.Sent, host2.Sent, curl2.Sent, curl2.Verdict)
	}
}

func TestRowsIdentitySurvivesSnapshot(t *testing.T) {
	entries := fixtureEntries()
	s1 := (Store{}).Replace(entries)
	curl1 := mustRow(t, Rows(s1, Rules{}, View{}), Program, "curl")
	mid1 := Rows(s1, Rules{}, View{Open: map[RowID]bool{curl1.ID: true}})
	host1, group1 := mustRow(t, mid1, Host, "api.example.com"), mustChild(t, mid1, Group, curl1.ID)
	open := map[RowID]bool{curl1.ID: true, host1.ID: true}
	addr1 := mustRow(t, Rows(s1, Rules{}, View{Open: open}), Address, "1.1.1.1:443 tcp")
	rev := slices.Clone(entries)
	slices.Reverse(rev)
	after := Rows(s1.Replace(rev), Rules{}, View{Open: open})
	curl2, host2 := mustRow(t, after, Program, "curl"), mustRow(t, after, Host, "api.example.com")
	group2, addr2 := mustChild(t, after, Group, curl2.ID), mustRow(t, after, Address, "1.1.1.1:443 tcp")
	if curl2.ID != curl1.ID || host2.ID != host1.ID || group2.ID != group1.ID || addr2.ID != addr1.ID {
		t.Fatalf("IDs changed after Replace")
	}
}

func TestRowsSanitisesTitlesAndKeepsRawKeys(t *testing.T) {
	hostile := api.Entry{
		Program: "bad\x1b[31m\nprog", Path: "/opt/bad\x07/bin", Addr: "1.2.3.4\x1b[0m",
		Name: "münchen\u202e.de", Port: 443, Protocol: "tcp\r", Verdict: "allow\x1b[32m", LastSeen: "2026-10-11T12:00:00Z",
	}
	s := (Store{}).Replace([]api.Entry{hostile})
	prog := Rows(s, Rules{}, View{})[0]
	if clean.Text(string(prog.Title)) != prog.Title || string(prog.Title) != "bad·[31m·prog" ||
		clean.Text(string(prog.Verdict)) != prog.Verdict || string(prog.Verdict) != "allow·[32m" {
		t.Fatalf("unsafe title/verdict: %q / %q", prog.Title, prog.Verdict)
	}
	if len(prog.Keys) != 1 || prog.Keys[0] != KeyOf(hostile) {
		t.Fatalf("raw key lost: %+v", prog.Keys)
	}
	host := Rows(s, Rules{}, View{Open: map[RowID]bool{prog.ID: true}})[1]
	addr := Rows(s, Rules{}, View{Open: map[RowID]bool{prog.ID: true, host.ID: true}})[2]
	if host.Title != clean.Name(hostile.Name) || clean.Text(string(addr.Title)) != addr.Title {
		t.Fatalf("host/addr unsafe: %q / %q", host.Title, addr.Title)
	}
}

func TestRowsEmptyAndUnknownWithoutPath(t *testing.T) {
	if got := Rows(Store{}, Rules{}, View{}); len(got) != 0 {
		t.Fatalf("empty Store rows = %d, want 0", len(got))
	}
	s := (Store{}).Replace([]api.Entry{
		{Program: "unknown", Addr: "8.8.8.8", Port: 53, Protocol: "udp", LastSeen: "2026-10-11T12:00:10Z"},
		{Program: "unknown", BytesSent: 512, LastSeen: "2026-10-11T12:00:05Z"},
	})
	top := Rows(s, Rules{}, View{})
	if len(top) != 2 || top[0].Level != Program || top[1].Level != Bucket || top[0].ID == top[1].ID {
		t.Fatalf("unexpected top rows: %+v", top)
	}
}

func allOpen(s Store) map[RowID]bool {
	open := make(map[RowID]bool)
	for range 2 {
		for _, r := range Rows(s, Rules{}, View{Open: open}) {
			open[r.ID] = true
		}
	}
	return open
}

func assertOrderAndMarks(t *testing.T, rows []Row, wantTitles []string, wantBlocked []bool) {
	t.Helper()
	titles := make([]string, len(rows))
	blocked := make([]bool, len(rows))
	for i, r := range rows {
		titles[i], blocked[i] = string(r.Title), r.Blocked
	}
	if !slices.Equal(titles, wantTitles) || !slices.Equal(blocked, wantBlocked) {
		t.Fatalf("got titles=%v blocked=%v, want titles=%v blocked=%v", titles, blocked, wantTitles, wantBlocked)
	}
}

func TestRowsMarkedOrderSearchAndBlocks(t *testing.T) {
	s := (Store{}).Replace(fixtureEntries())
	open, rank := allOpen(s), Rank(s)
	rules := Rules{
		Programs: []api.ProgramView{{Name: "dig", Paths: []string{"/usr/bin/dig"}}},
		Views: []api.RuleView{
			{Id: 1, Program: "dig", To: "::/0", Verdict: "deny"}, {Id: 2, Program: "curl", To: "api.example.com", Protocol: "tcp", Port: 443, Verdict: "deny"},
			{Id: 3, Program: "curl", To: "9.9.9.9/32", Protocol: "tcp", Port: 8443, Verdict: "deny"}, {Id: 4, Program: "curl", To: "0.0.0.0/0", Verdict: "allow"},
		},
	}
	wantAct := []string{"curl", "api.example.com", "[2001:db8::1]:443 tcp", "1.1.1.1:443 tcp", "IP Addresses", "9.9.9.9:8443 tcp", "/usr/bin/dig", "IP Addresses", "[2620:fe::fe]:53 udp", "unknown"}
	wantActB := []bool{false, true, true, true, true, true, true, true, true, false}
	assertOrderAndMarks(t, Rows(s, rules, View{Open: open, Sort: Sort{Rank: rank}}), wantAct, wantActB)
	sBumped := s.Upsert([]api.Entry{{Program: "unknown", Path: "/usr/bin/dig", Addr: "2620:fe::fe", Port: 53, Protocol: "udp", LastSeen: "2026-10-11T12:00:59Z"}})
	assertOrderAndMarks(t, Rows(sBumped, rules, View{Open: open, Sort: Sort{Rank: rank}}), wantAct, wantActB)

	wantName := []string{"/usr/bin/dig", "IP Addresses", "[2620:fe::fe]:53 udp", "curl", "api.example.com", "1.1.1.1:443 tcp", "[2001:db8::1]:443 tcp", "IP Addresses", "9.9.9.9:8443 tcp", "unknown"}
	wantNameB := []bool{true, true, true, false, true, true, true, true, true, false}
	assertOrderAndMarks(t, Rows(s, rules, View{Open: open, Sort: Sort{ByName: true}}), wantName, wantNameB)

	assertOrderAndMarks(t, Rows(s, rules, View{Open: open, Sort: Sort{Rank: rank}, Search: "API.EXAMPLE"}), wantAct[:4], wantActB[:4])
	assertOrderAndMarks(t, Rows(s, rules, View{Open: open, Sort: Sort{ByName: true}, Search: "api.example"}), wantName[3:7], wantNameB[3:7])

	partial := Rules{Views: []api.RuleView{{Id: 5, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "deny"}}}
	pRows := Rows(s, partial, View{Open: open, Sort: Sort{ByName: true}, Search: "api.example"})
	assertOrderAndMarks(t, pRows, []string{"curl", "api.example.com", "1.1.1.1:443 tcp", "[2001:db8::1]:443 tcp"}, []bool{false, false, true, false})
}

func TestRowsSearchClosedAndPartialTree(t *testing.T) {
	s := (Store{}).Replace(fixtureEntries())
	curl := mustRow(t, Rows(s, Rules{}, View{}), Program, "curl")
	byHost := Rows(s, Rules{}, View{Sort: Sort{ByName: true}, Search: "api.example"})
	assertOrderAndMarks(t, byHost, []string{"curl", "api.example.com", "1.1.1.1:443 tcp", "[2001:db8::1]:443 tcp"}, make([]bool, 4))
	if !byHost[0].Open || !byHost[1].Open || byHost[2].Open {
		t.Fatalf("search parents not opened: %+v", byHost)
	}
	partial := map[RowID]bool{curl.ID: true}
	byAddr := Rows(s, Rules{}, View{Open: partial, Sort: Sort{ByName: true}, Search: "2620:fe::fe"})
	assertOrderAndMarks(t, byAddr, []string{"/usr/bin/dig", "IP Addresses", "[2620:fe::fe]:53 udp"}, make([]bool, 3))
	if !byAddr[0].Open || !byAddr[1].Open || len(partial) != 1 || !partial[curl.ID] {
		t.Fatalf("search mutated Open or missed parent open: partial=%v rows=%+v", partial, byAddr)
	}
	if noSearch := Rows(s, Rules{}, View{Open: partial}); len(noSearch) != 5 {
		t.Fatalf("empty search with partial Open = %d rows, want 5", len(noSearch))
	}
}

func TestRowsBlockedPrecedenceAndFamilies(t *testing.T) {
	s := (Store{}).Replace([]api.Entry{
		{Program: "curl", Addr: "1.1.1.1", Name: "api.example.com", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:10Z"},
		{Program: "curl", Addr: "2001:db8::1", Name: "api.example.com", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:20Z"},
		{Program: "p4", Addr: "1.1.1.1", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:05Z"},
		{Program: "p6", Addr: "2001:db8::1", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:04Z"},
		{Program: "dual", Addr: "1.1.1.1", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:03Z"},
		{Program: "dual", Addr: "2001:db8::1", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:02Z"},
	})
	rules := Rules{Views: []api.RuleView{
		{Id: 1, Program: "curl", To: "0.0.0.0/0", Verdict: "deny"}, {Id: 2, Program: "curl", To: "::/0", Verdict: "deny"},
		{Id: 3, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "allow"},
		{Id: 4, Program: "p4", To: "0.0.0.0/0", Verdict: "allow"}, {Id: 5, Program: "p4", To: "::/0", Verdict: "deny"},
		{Id: 6, Program: "p6", To: "0.0.0.0/0", Verdict: "allow"}, {Id: 7, Program: "p6", To: "::/0", Verdict: "deny"},
		{Id: 8, Program: "dual", To: "0.0.0.0/0", Verdict: "allow"}, {Id: 9, Program: "dual", To: "::/0", Verdict: "deny"},
	}}
	got := Rows(s, rules, View{Open: allOpen(s), Sort: Sort{ByName: true}})
	wantT := []string{"curl", "api.example.com", "1.1.1.1:443 tcp", "[2001:db8::1]:443 tcp", "dual", "IP Addresses", "1.1.1.1:443 tcp", "[2001:db8::1]:443 tcp", "p4", "IP Addresses", "1.1.1.1:443 tcp", "p6", "IP Addresses", "[2001:db8::1]:443 tcp"}
	wantB := []bool{true, false, false, true, false, false, false, true, false, false, false, true, true, true}
	assertOrderAndMarks(t, got, wantT, wantB)

	rev := Rules{Views: []api.RuleView{
		{Id: 10, Program: "p4", To: "0.0.0.0/0", Verdict: "deny"}, {Id: 11, Program: "p4", To: "::/0", Verdict: "allow"},
		{Id: 12, Program: "dual", To: "0.0.0.0/0", Verdict: "deny"}, {Id: 13, Program: "dual", To: "::/0", Verdict: "allow"},
	}}
	gotRev := Rows(s, rev, View{Sort: Sort{ByName: true}})
	if !mustRow(t, gotRev, Program, "p4").Blocked || mustRow(t, gotRev, Program, "dual").Blocked {
		t.Fatalf("v4 deny + v6 allow wrong: %+v", gotRev)
	}
}

func TestRowsLocalAddressNeverBlocked(t *testing.T) {
	s := (Store{}).Replace([]api.Entry{
		{Program: "app", Addr: "127.0.0.1", Name: "local.test", Port: 8080, Protocol: "tcp", LastSeen: "2026-10-11T12:00:03Z"},
		{Program: "app", Addr: "192.168.1.1", Port: 53, Protocol: "udp", LastSeen: "2026-10-11T12:00:02Z"},
		{Program: "app", Addr: "fe80::1%eth0", Port: 5353, Protocol: "udp", LastSeen: "2026-10-11T12:00:01Z"},
	})
	wantT := []string{"app", "IP Addresses", "192.168.1.1:53 udp", "[fe80::1%eth0]:5353 udp", "local.test", "127.0.0.1:8080 tcp"}
	progDeny := Rules{Views: []api.RuleView{
		{Id: 1, Program: "app", To: "0.0.0.0/0", Verdict: "deny"}, {Id: 2, Program: "app", To: "::/0", Verdict: "deny"},
	}}
	assertOrderAndMarks(t, Rows(s, progDeny, View{Open: allOpen(s), Sort: Sort{ByName: true}}), wantT, []bool{true, false, false, false, false, false})
	cidrDeny := Rules{Views: []api.RuleView{
		{Id: 3, Program: "app", To: "127.0.0.1/32", Protocol: "tcp", Port: 8080, Verdict: "deny"},
		{Id: 4, Program: "app", To: "192.168.1.1/32", Protocol: "udp", Port: 53, Verdict: "deny"},
		{Id: 5, Program: "app", To: "fe80::1/128", Protocol: "udp", Port: 5353, Verdict: "deny"},
	}}
	assertOrderAndMarks(t, Rows(s, cidrDeny, View{Open: allOpen(s), Sort: Sort{ByName: true}}), wantT, make([]bool, 6))
}
