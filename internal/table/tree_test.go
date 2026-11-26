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
		{
			Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "api.example.com",
			Port: 443, Protocol: "tcp", AllowCount: 2, DenyCount: 0,
			LastSeen: "2026-10-11T12:00:10Z", BytesSent: 1000, Rate: 10.5, Verdict: "allow-monitor",
		},
		{
			Program: "curl", Path: "/usr/bin/curl", Addr: "2001:db8::1", Name: "api.example.com",
			Port: 443, Protocol: "tcp", AllowCount: 1, DenyCount: 1,
			LastSeen: "2026-10-11T12:00:20Z", BytesSent: 2000, Rate: 20.5, Verdict: "deny-rule",
		},
		{
			Program: "curl", Path: "/usr/bin/curl", Addr: "9.9.9.9",
			Port: 8443, Protocol: "tcp", AllowCount: 4, DenyCount: 0,
			LastSeen: "2026-10-11T12:00:05Z", BytesSent: 500, Rate: 5.0, Verdict: "allow-rule",
		},
		{
			Program: "unknown", Path: "/usr/bin/dig", Addr: "2620:fe::fe",
			Port: 53, Protocol: "udp", AllowCount: 3, DenyCount: 0,
			LastSeen: "2026-10-11T12:00:15Z", BytesSent: 300, Rate: 3.0, Verdict: "allow-monitor",
		},
		{
			Program: "unknown", LastSeen: "2026-10-11T12:00:01Z", BytesSent: 9216, Rate: 0,
		},
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
	if r.Depth != depth || r.Parent != parent {
		t.Fatalf("%q depth/parent = %d/%q, want %d/%q", r.Title, r.Depth, r.Parent, depth, parent)
	}
	if r.HasKids != hasKids || r.Open != open {
		t.Fatalf("%q hasKids/open = %v/%v, want %v/%v", r.Title, r.HasKids, r.Open, hasKids, open)
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
	curlRow := mustRow(t, top, Program, "curl")
	digRow := mustRow(t, top, Program, "/usr/bin/dig")

	openMid := Rows(s, Rules{}, View{Open: map[RowID]bool{curlRow.ID: true, digRow.ID: true}})
	if len(openMid) != 6 {
		t.Fatalf("openMid rows = %d, want 6", len(openMid))
	}
	hostRow := mustRow(t, openMid, Host, "api.example.com")
	assertShape(t, hostRow, 1, curlRow.ID, true, false)
	curlGroup := mustChild(t, openMid, Group, curlRow.ID)
	assertShape(t, curlGroup, 1, curlRow.ID, true, false)
	if string(curlGroup.Title) != "IP Addresses" {
		t.Fatalf("curlGroup.Title = %q, want IP Addresses", curlGroup.Title)
	}
	digGroup := mustChild(t, openMid, Group, digRow.ID)
	if string(digGroup.Title) != "IP Addresses" {
		t.Fatalf("digGroup.Title = %q, want IP Addresses", digGroup.Title)
	}

	openAll := Rows(s, Rules{}, View{Open: map[RowID]bool{
		curlRow.ID: true, hostRow.ID: true, curlGroup.ID: true, digRow.ID: true, digGroup.ID: true,
	}})
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
	openCurl := Rows(s, Rules{}, View{Open: map[RowID]bool{curlRow.ID: true}})
	hostRow := mustRow(t, openCurl, Host, "api.example.com")

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
	updated.BytesSent, updated.Rate, updated.AllowCount = 5000, 100.0, 10
	updated.LastSeen, updated.Verdict = "2026-10-11T12:00:30Z", "allow-rule"

	after := Rows(s1.Upsert([]api.Entry{updated}), Rules{}, View{Open: open})
	curl2 := mustRow(t, after, Program, "curl")
	host2 := mustRow(t, after, Host, "api.example.com")
	addr2 := mustRow(t, after, Address, "1.1.1.1:443 tcp")

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
	host1 := mustRow(t, mid1, Host, "api.example.com")
	group1 := mustChild(t, mid1, Group, curl1.ID)
	open := map[RowID]bool{curl1.ID: true, host1.ID: true}
	addr1 := mustRow(t, Rows(s1, Rules{}, View{Open: open}), Address, "1.1.1.1:443 tcp")

	rev := slices.Clone(entries)
	slices.Reverse(rev)
	after := Rows(s1.Replace(rev), Rules{}, View{Open: open})
	curl2 := mustRow(t, after, Program, "curl")
	host2 := mustRow(t, after, Host, "api.example.com")
	group2 := mustChild(t, after, Group, curl2.ID)
	addr2 := mustRow(t, after, Address, "1.1.1.1:443 tcp")

	if curl2.ID != curl1.ID || host2.ID != host1.ID || group2.ID != group1.ID || addr2.ID != addr1.ID {
		t.Fatalf("IDs changed after Replace")
	}
}

func TestRowsSanitisesTitlesAndKeepsRawKeys(t *testing.T) {
	hostile := api.Entry{
		Program: "bad\x1b[31m\nprog", Path: "/opt/bad\x07/bin",
		Addr: "1.2.3.4\x1b[0m", Name: "münchen\u202e.de",
		Port: 443, Protocol: "tcp\r", Verdict: "allow\x1b[32m",
		LastSeen: "2026-10-11T12:00:00Z",
	}
	s := (Store{}).Replace([]api.Entry{hostile})
	prog := Rows(s, Rules{}, View{})[0]
	if clean.Text(string(prog.Title)) != prog.Title || string(prog.Title) != "bad·[31m·prog" {
		t.Fatalf("prog.Title = %q", prog.Title)
	}
	if clean.Text(string(prog.Verdict)) != prog.Verdict || string(prog.Verdict) != "allow·[32m" {
		t.Fatalf("prog.Verdict = %q", prog.Verdict)
	}
	if len(prog.Keys) != 1 || prog.Keys[0] != KeyOf(hostile) {
		t.Fatalf("raw key lost: %+v", prog.Keys)
	}
	host := Rows(s, Rules{}, View{Open: map[RowID]bool{prog.ID: true}})[1]
	if host.Title != clean.Name(hostile.Name) {
		t.Fatalf("host.Title = %q, want %q", host.Title, clean.Name(hostile.Name))
	}
	addr := Rows(s, Rules{}, View{Open: map[RowID]bool{prog.ID: true, host.ID: true}})[2]
	if clean.Text(string(addr.Title)) != addr.Title {
		t.Fatalf("addr.Title unsafe: %q", addr.Title)
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
