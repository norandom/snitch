package table

import (
	"slices"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
)

func TestRankOrdersAllLevelsByActivity(t *testing.T) {
	if got := Rank(Store{}); len(got) != 0 {
		t.Fatalf("Rank(empty) len = %d, want 0", len(got))
	}

	entries := []api.Entry{
		{Program: "alpha", Addr: "1.1.1.1", Name: "one.example", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:10Z"},
		{Program: "alpha", Addr: "1.1.1.2", Name: "one.example", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:30Z"},
		{Program: "alpha", Addr: "8.8.8.8", Port: 53, Protocol: "udp", LastSeen: "2026-10-11T12:00:25Z"},
		{Program: "bravo", Addr: "2.2.2.2", Name: "two.example", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:40Z"},
		{Program: "unknown", LastSeen: "2026-10-11T12:00:05Z", BytesSent: 100},
	}
	s := (Store{}).Replace(entries)
	rank := Rank(s)

	progs, bucket := groupEntries(s)
	tops := sortRows(topRows(progs, bucket, nil), Sort{Rank: rank})
	assertTitles(t, tops, []string{"bravo", "alpha", "unknown"})

	alphaRow := mustRow(t, tops, Program, "alpha")
	mids, midLeaves := midRows(progs["alpha"], alphaRow.ID, nil)
	sortedMids := sortRows(mids, Sort{Rank: rank})
	assertTitles(t, sortedMids, []string{"one.example", "IP Addresses"})

	hostRow := mustRow(t, sortedMids, Host, "one.example")
	leaves := sortRows(leafRows(midLeaves[hostRow.ID], hostRow.ID), Sort{Rank: rank})
	assertTitles(t, leaves, []string{"1.1.1.2:443 tcp", "1.1.1.1:443 tcp"})
}

func rankFreezeStores() (Store, Store) {
	s1 := (Store{}).Replace([]api.Entry{
		{Program: "alpha", Addr: "1.1.1.1", Name: "a.example", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:10Z"},
		{Program: "alpha", Addr: "1.1.1.2", Name: "a.example", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:15Z"},
		{Program: "alpha", Addr: "8.8.8.8", Port: 53, Protocol: "udp", LastSeen: "2026-10-11T12:00:12Z"},
		{Program: "bravo", Addr: "2.2.2.2", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:20Z"},
		{Program: "charlie", Addr: "3.3.3.3", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:30Z"},
	})
	s2 := s1.Upsert([]api.Entry{
		{Program: "alpha", Addr: "1.1.1.1", Name: "a.example", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:40Z"},
		{Program: "alpha", Addr: "8.8.8.8", Port: 53, Protocol: "udp", LastSeen: "2026-10-11T12:00:35Z"},
		{Program: "alpha", Addr: "1.1.1.3", Name: "a.example", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:02Z"},
		{Program: "delta", Addr: "4.4.4.4", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:05Z"},
		{Program: "echo", Addr: "5.5.5.5", Port: 443, Protocol: "tcp", LastSeen: "2026-10-11T12:00:08Z"},
	})
	return s1, s2
}

func TestRankFreezesOrderBetweenResortsAndPlacesNewOnTop(t *testing.T) {
	s1, s2 := rankFreezeStores()
	frozen := Rank(s1)

	progs, bucket := groupEntries(s2)
	tops := sortRows(topRows(progs, bucket, nil), Sort{Rank: frozen})
	assertTitles(t, tops, []string{"echo", "delta", "charlie", "bravo", "alpha"})

	alphaRow := mustRow(t, tops, Program, "alpha")
	mids, midLeaves := midRows(progs["alpha"], alphaRow.ID, nil)
	sortedMids := sortRows(mids, Sort{Rank: frozen})
	assertTitles(t, sortedMids, []string{"a.example", "IP Addresses"})

	hostRow := mustRow(t, sortedMids, Host, "a.example")
	leaves := sortRows(leafRows(midLeaves[hostRow.ID], hostRow.ID), Sort{Rank: frozen})
	assertTitles(t, leaves, []string{"1.1.1.3:443 tcp", "1.1.1.2:443 tcp", "1.1.1.1:443 tcp"})

	topsAfter := sortRows(topRows(progs, bucket, nil), Sort{Rank: Rank(s2)})
	assertTitles(t, topsAfter, []string{"alpha", "charlie", "bravo", "echo", "delta"})
}

func TestRankNilSortsByActivity(t *testing.T) {
	rows := []Row{
		{ID: "P:old", Title: clean.Const("old"), Last: mustTime(t, "2026-10-11T12:00:05Z")},
		{ID: "P:new", Title: clean.Const("new"), Last: mustTime(t, "2026-10-11T12:00:15Z")},
		{ID: "P:mid", Title: clean.Const("mid"), Last: mustTime(t, "2026-10-11T12:00:10Z")},
	}
	got := sortRows(rows, Sort{})
	assertTitles(t, got, []string{"new", "mid", "old"})
}

func TestSortByNameCaseInsensitive(t *testing.T) {
	rows := []Row{
		{ID: "P:z", Title: clean.Const("Zebra"), Last: mustTime(t, "2026-10-11T12:00:40Z")},
		{ID: "P:b", Title: clean.Const("bravo"), Last: mustTime(t, "2026-10-11T12:00:10Z")},
		{ID: "P:a", Title: clean.Const("Alpha"), Last: mustTime(t, "2026-10-11T12:00:20Z")},
		{ID: "P:c", Title: clean.Const("charlie"), Last: mustTime(t, "2026-10-11T12:00:30Z")},
	}
	rank := map[RowID]int{"P:z": 0, "P:c": 1, "P:a": 2, "P:b": 3}
	assertTitles(t, sortRows(rows, Sort{ByName: true, Rank: rank}), []string{"Alpha", "bravo", "charlie", "Zebra"})

	tieRows := []Row{
		{ID: "P:lower", Title: clean.Const("beta")},
		{ID: "P:upper", Title: clean.Const("Beta")},
	}
	assertTitles(t, sortRows(tieRows, Sort{ByName: true}), []string{"Beta", "beta"})

	midLevel := []Row{
		{ID: "H:z", Level: Host, Title: clean.Const("zeta.example")},
		{ID: "G:1", Level: Group, Title: clean.Const("IP Addresses")},
		{ID: "H:a", Level: Host, Title: clean.Const("alpha.example")},
	}
	assertTitles(t, sortRows(midLevel, Sort{ByName: true}), []string{"alpha.example", "IP Addresses", "zeta.example"})
}

func assertTitles(t *testing.T, rows []Row, want []string) {
	t.Helper()
	got := make([]string, len(rows))
	for i, r := range rows {
		got[i] = string(r.Title)
	}
	if !slices.Equal(got, want) {
		t.Fatalf("titles = %v, want %v", got, want)
	}
}

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, s)
	if err != nil {
		t.Fatalf("time.Parse(%q): %v", s, err)
	}
	return parsed
}
