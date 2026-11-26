package clienttest

import (
	"os"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

func TestSnapshotVerb(t *testing.T) {
	s := writer(t)
	if err := s.Do("event curl /usr/bin/curl 1.1.1.1=one.one 443 tcp allow-rule"); err != nil {
		t.Fatal(err)
	}
	if err := s.Do("summary"); err != nil {
		t.Fatal(err)
	}
	c := dial(t, s)
	rep := decodeLine[api.Reply](t, rawAsk(t, c, `{"type":"snapshot","id":1,"window":"15m"}`))
	if !rep.Ok || rep.Window != "15m" || len(rep.Entries) != 1 {
		t.Fatalf("snapshot = %+v", rep)
	}
	wantEntry(t, rep.Entries[0], "curl", "1.1.1.1", "one.one", "allow-rule", 1, 0)
	wantErrPrefix(t, c, `{"type":"snapshot","id":2,"window":"5m"}`,
		"unknown window 5m: want one of 15m, 30m, 1h, 24h, 7d")
}

func wantEntry(t *testing.T, e api.Entry, prog, addr, name, verdict string, allow, deny uint64) {
	t.Helper()
	got := [6]any{e.Program, e.Addr, e.Name, e.Verdict, e.AllowCount, e.DenyCount}
	if got != [6]any{prog, addr, name, verdict, allow, deny} {
		t.Fatalf("entry = %+v", e)
	}
}

func TestSummaryStream(t *testing.T) {
	s := Start(t, Options{Operator: uint32(os.Getuid()), SummaryEvery: 30 * time.Millisecond})
	c := dial(t, s)
	if l := c.ask(`{"type":"subscribe","id":1,"events":false,"summary":true}`); !l.Ok {
		t.Fatalf("subscribe: %+v", l)
	}
	if err := s.Do("event curl /usr/bin/curl 9.9.9.9=quad9.net 443 tcp deny-rule"); err != nil {
		t.Fatal(err)
	}
	sum := decodeLine[api.Summary](t, nextBytes(t, c))
	if sum.Type != "summary" || sum.Id != 0 || len(sum.Entries) != 1 {
		t.Fatalf("summary = %+v", sum)
	}
	wantEntry(t, sum.Entries[0], "curl", "9.9.9.9", "quad9.net", "deny-rule", 0, 1)
	_ = c.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	if b, err := c.r.ReadBytes('\n'); err == nil {
		t.Fatalf("unexpected summary when nothing changed: %s", b)
	}
}

func TestDroppedLine(t *testing.T) {
	s := writer(t)
	c := subscribed(t, s)
	idle := dial(t, s)
	if err := s.Do("drop 17"); err != nil {
		t.Fatal(err)
	}
	d := decodeLine[api.Dropped](t, nextBytes(t, c))
	if d.Type != "dropped" || d.Id != 0 || d.Count != 17 {
		t.Fatalf("dropped = %+v", d)
	}
	_ = idle.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if b, err := idle.r.ReadBytes('\n'); err == nil {
		t.Fatalf("unsubscribed connection got dropped line: %s", b)
	}
	st := c.ask(`{"type":"status","id":2}`).Status
	if st == nil || st.Dropped < 17 {
		t.Fatalf("status dropped = %+v", st)
	}
}

func TestDropContractViolation(t *testing.T) {
	s := writer(t)
	contracttest.Panics(t, contract.Precondition, func() { s.Drop(0) })
	contracttest.Panics(t, contract.Precondition, func() { s.Drop(-1) })
}
