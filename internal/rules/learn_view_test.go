package rules_test

import (
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/rules"
)

// Req 4.4: the API reads the learned observations without touching the write cycle. File()
// clears the dirty flag (the learner holds its projection until written); Observations()
// must not, or a client asking for the learned list would silence the next flush.
func TestLearnObservationsLeavesDirtyAloneAndSorts(t *testing.T) {
	l := rules.NewLearned(nil)
	l.Observe(obs("/usr/bin/curl", curl, "9.9.9.9", rules.TCP, 443, t0.Add(time.Minute)))
	l.Observe(obs("/usr/bin/curl", curl, "1.1.1.1", rules.UDP, 53, t0.Add(2*time.Minute)))
	l.Observe(obs("/usr/bin/curl", curl, "1.1.1.1", rules.TCP, 443, t0.Add(3*time.Minute)))
	l.Observe(obs("/usr/bin/curl", curl, "1.1.1.1", rules.TCP, 443, t0))
	gone := rules.ExeKey{Ino: 7, Dev: 9}
	o := obs("", gone, "8.8.8.8", rules.UDP, 53, t0)
	o.Program = "resolver"
	l.Observe(o)
	if !l.Dirty() {
		t.Fatal("observations make the state dirty")
	}
	got := l.Observations()
	if !l.Dirty() {
		t.Fatal("Observations() must leave the dirty flag as it was (File() is the only projection that clears it)")
	}
	want := []rules.Observed{
		// a pathed subject is keyed by its path alone (an upgraded binary keeps its entry): no Exe
		{Program: "curl", Path: "/usr/bin/curl", Addr: netip.MustParseAddr("1.1.1.1"), Proto: rules.TCP, Port: 443, Count: 2, First: t0, Last: t0.Add(3 * time.Minute)},
		{Program: "curl", Path: "/usr/bin/curl", Addr: netip.MustParseAddr("1.1.1.1"), Proto: rules.UDP, Port: 53, Count: 1, First: t0.Add(2 * time.Minute), Last: t0.Add(2 * time.Minute)},
		{Program: "curl", Path: "/usr/bin/curl", Addr: netip.MustParseAddr("9.9.9.9"), Proto: rules.TCP, Port: 443, Count: 1, First: t0.Add(time.Minute), Last: t0.Add(time.Minute)},
		{Program: "resolver", Path: "", Exe: gone, Addr: netip.MustParseAddr("8.8.8.8"), Proto: rules.UDP, Port: 53, Count: 1, First: t0, Last: t0},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("observations wrong:\n got %+v\nwant %+v", got, want)
	}
	l.File()
	if l.Dirty() {
		t.Fatal("File() clears the flag")
	}
	if again := l.Observations(); l.Dirty() || !reflect.DeepEqual(again, want) {
		t.Fatalf("a clean state stays clean and reads the same: dirty %v, %+v", l.Dirty(), again)
	}
}

func TestLearnObservationsOfAnEmptySetIsEmpty(t *testing.T) {
	if got := rules.NewLearned(nil).Observations(); len(got) != 0 {
		t.Fatalf("want nothing, got %+v", got)
	}
}
