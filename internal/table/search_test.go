package table

import (
	"slices"
	"testing"

	"github.com/norandom/snitch/internal/api"
)

func searchFixtureRows(t *testing.T) []Row {
	t.Helper()
	entries := []api.Entry{
		{
			Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "Api.Example.com",
			Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:10Z",
		},
		{
			Program: "curl", Path: "/usr/bin/curl", Addr: "2001:db8::1", Name: "Api.Example.com",
			Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:20Z",
		},
		{
			Program: "curl", Path: "/usr/bin/curl", Addr: "9.9.9.9",
			Port: 8443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:05Z",
		},
		{
			Program: "unknown", Path: "/usr/bin/dig", Addr: "2620:fe::fe",
			Port: 53, Protocol: "udp", LastSeen: "2026-10-11T12:00:15Z",
		},
		{
			Program: "unknown", LastSeen: "2026-10-11T12:00:01Z", BytesSent: 9216,
		},
	}
	s := (Store{}).Replace(entries)
	all := Rows(s, Rules{}, View{})
	open := make(map[RowID]bool, len(all)*3)
	for _, r := range all {
		open[r.ID] = true
	}
	for _, r := range Rows(s, Rules{}, View{Open: open}) {
		open[r.ID] = true
	}
	return Rows(s, Rules{}, View{Open: open})
}

func TestFilterEmptyQueryReturnsAll(t *testing.T) {
	if got := Filter(nil, "curl"); len(got) != 0 {
		t.Fatalf("Filter(nil, query) = %d, want 0", len(got))
	}
	rows := searchFixtureRows(t)
	got := Filter(rows, "")
	if len(got) != len(rows) {
		t.Fatalf("Filter(rows, \"\") = %d, want %d", len(got), len(rows))
	}
}

type filterCase struct {
	name  string
	query string
	want  []string
}

func runFilterCases(t *testing.T, rows []Row, cases []filterCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Filter(rows, tc.query)
			titles := make([]string, len(got))
			for i, r := range got {
				titles[i] = string(r.Title)
			}
			if !slices.Equal(titles, tc.want) {
				t.Fatalf("Filter(%q) = %v, want %v", tc.query, titles, tc.want)
			}
		})
	}
}

func TestFilterMatchesPathCaseInsensitiveAndKeepsParents(t *testing.T) {
	rows := searchFixtureRows(t)
	runFilterCases(t, rows, []filterCase{
		{"address keeps parents", "1.1.1.1", []string{"curl", "Api.Example.com", "1.1.1.1:443 tcp"}},
		{"host case-insensitive", "api.example", []string{"curl", "Api.Example.com", "[2001:db8::1]:443 tcp", "1.1.1.1:443 tcp"}},
		{"program case-insensitive", "CURL", []string{"curl", "Api.Example.com", "[2001:db8::1]:443 tcp", "1.1.1.1:443 tcp", "IP Addresses", "9.9.9.9:8443 tcp"}},
		{"group case-insensitive", "ip addresses", []string{"curl", "IP Addresses", "9.9.9.9:8443 tcp", "/usr/bin/dig", "IP Addresses", "[2620:fe::fe]:53 udp"}},
		{"protocol case-insensitive", "UDP", []string{"/usr/bin/dig", "IP Addresses", "[2620:fe::fe]:53 udp"}},
		{"bucket case-insensitive", "UNKNOWN", []string{"unknown"}},
		{"full path with separator", "curl › api.example.com", []string{"curl", "Api.Example.com", "[2001:db8::1]:443 tcp", "1.1.1.1:443 tcp"}},
		{"no match", "not-in-tree", []string{}},
	})
}

func TestFilterDoesNotMutateAndHandlesMissingParent(t *testing.T) {
	rows := []Row{
		{ID: "A:orphan", Parent: "H:missing", Level: Address, Title: "1.2.3.4:80 tcp"},
	}
	orig := slices.Clone(rows)
	got := Filter(rows, "1.2.3.4")
	if len(got) != 1 || got[0].ID != "A:orphan" {
		t.Fatalf("Filter orphan = %+v", got)
	}
	if !slices.EqualFunc(rows, orig, func(a, b Row) bool { return a.ID == b.ID }) {
		t.Fatalf("Filter mutated input")
	}
}
