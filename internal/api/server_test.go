package api

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"golang.org/x/sys/unix"
)

const operatorUid = 42

// fixture is a server with fake delegates over a unix socket in a temp dir. Peer credentials
// are injected (uid 1000, a reader, unless a test sets f.uid before dialling).
type fixture struct {
	t     *testing.T
	s     *Server
	c     *clock
	path  string
	uid   uint32
	learn bool
	mu    sync.Mutex
	log   []string
	calls []string
}

func newFixture(t *testing.T) *fixture { return newFixtureWith(t, nil) }

// newFixtureWith lets a test alter the delegates before New.
func newFixtureWith(t *testing.T, alter func(*Deps)) *fixture {
	f := &fixture{t: t, c: newClock(), uid: 1000, learn: true}
	d := f.deps()
	if alter != nil {
		alter(&d)
	}
	f.s = New(d)
	f.s.creds = func(net.Conn) *unix.Ucred { return &unix.Ucred{Uid: f.uid} }
	return f
}

func (f *fixture) deps() Deps {
	return Deps{Operator: operatorUid, Table: NewTable(f.c.now), Now: f.c.now, Log: f.record(&f.log),
		Facts: func() Status { return Status{Running: true, Pid: 7} },
		Rules: func() ([]RuleView, []ProgramView) {
			return []RuleView{{Id: 1, Program: "curl"}}, []ProgramView{{Name: "curl"}}
		},
		Learned: func() ([]Observation, bool) { return []Observation{{Program: "curl"}}, f.learn },
		Trial:   f.delegate("trial"), RuleEdit: f.delegate("edit")}
}

func (f *fixture) record(to *[]string) func(string) {
	return func(line string) { f.mu.Lock(); *to = append(*to, line); f.mu.Unlock() }
}

// delegate records "name type uid=N"; a note or duration "fail" makes it refuse.
func (f *fixture) delegate(name string) func(Request, uint32) (string, error) {
	return func(req Request, who uint32) (string, error) {
		f.record(&f.calls)(fmt.Sprintf("%s %s uid=%d", name, req.Type, who))
		if req.Note == "fail" || req.Duration == "fail" {
			return "", errors.New("refused: " + req.Type)
		}
		return name + " ok " + req.Type, nil
	}
}

func (f *fixture) lines(of *[]string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), *of...)
}

// listen runs the job on a fresh socket (wrap decorates the listener) until the test ends.
func (f *fixture) listen(wrap func(net.Listener) net.Listener) {
	f.path = filepath.Join(f.t.TempDir(), "api.sock")
	l, err := net.Listen("unix", f.path)
	if err != nil {
		f.t.Fatal(err)
	}
	if wrap != nil {
		l = wrap(l)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- f.s.Job(l)(ctx) }()
	f.t.Cleanup(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			f.t.Errorf("job ended with %v, want Canceled", err)
		}
	})
}

func (f *fixture) event(addr, verdict string) Event {
	e := ev("curl", addr, 443, verdict)
	e.Time = f.c.now()
	return e
}

// peer is one client connection with line helpers.
type peer struct {
	t *testing.T
	net.Conn
	r *bufio.Reader
}

func (f *fixture) dial() *peer {
	conn, err := net.Dial("unix", f.path)
	if err != nil {
		f.t.Fatal(err)
	}
	f.t.Cleanup(func() { _ = conn.Close() })
	return &peer{t: f.t, Conn: conn, r: bufio.NewReader(conn)}
}

func (p *peer) send(line string) {
	p.t.Helper()
	_ = p.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := p.Write([]byte(line + "\n")); err != nil {
		p.t.Fatal(err)
	}
}

func (p *peer) line() string {
	p.t.Helper()
	_ = p.SetReadDeadline(time.Now().Add(5 * time.Second))
	s, err := p.r.ReadString('\n')
	if err != nil {
		p.t.Fatalf("read: %v (got %q)", err, s)
	}
	return strings.TrimSpace(s)
}

func (p *peer) ask(line string) string { p.t.Helper(); p.send(line); return p.line() }

// noLine asserts nothing arrives within 50 ms.
func (p *peer) noLine() {
	p.t.Helper()
	_ = p.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	if s, err := p.r.ReadString('\n'); !errors.Is(err, os.ErrDeadlineExceeded) {
		p.t.Fatalf("want silence, got %q (%v)", s, err)
	}
}

func (p *peer) eof() {
	p.t.Helper()
	_ = p.SetReadDeadline(time.Now().Add(5 * time.Second))
	if s, err := p.r.ReadString('\n'); err == nil {
		p.t.Fatalf("want the connection closed, got %q", s)
	}
}

func decode[T any](t *testing.T, line, typ string) T {
	t.Helper()
	var v T
	if err := json.Unmarshal([]byte(line), &v); err != nil {
		t.Fatalf("%q: %v", line, err)
	}
	var env struct{ Type string }
	_ = json.Unmarshal([]byte(line), &env)
	if env.Type != typ {
		t.Fatalf("%q: want type %q", line, typ)
	}
	return v
}

func (p *peer) reply(line string) Reply { p.t.Helper(); return decode[Reply](p.t, line, "reply") }
func (p *peer) errorOf(line string) Error {
	p.t.Helper()
	return decode[Error](p.t, line, "error")
}
func (p *peer) subscribe(opts string) {
	p.t.Helper()
	if r := p.reply(p.ask(`{"type":"subscribe","id":1` + opts + `}`)); !r.Ok || r.Id != 1 {
		p.t.Fatalf("subscribe: %+v", r)
	}
}

// Design "Contracts": New requires its delegates; Emit requires a time.
func TestNewRequiresDeps(t *testing.T) {
	f := newFixture(t)
	for _, strip := range []func(*Deps){
		func(d *Deps) { d.Table = nil }, func(d *Deps) { d.Facts = nil },
		func(d *Deps) { d.Log = nil }, func(d *Deps) { d.Now = nil },
	} {
		d := f.deps()
		strip(&d)
		contracttest.Panics(t, contract.Precondition, func() { New(d) })
	}
	contracttest.Panics(t, contract.Precondition, func() { f.s.Emit(Event{Addr: "1.1.1.1"}) })
	contracttest.Panics(t, contract.Precondition, func() { f.s.Job(nil) })
}

// Req 2.3: a subscriber gets fresh events; allow-local only when it asked for local; a repeat
// inside the dedupe window is no event; unsubscribe stops the stream (Req 1.5: others go on).
func TestSubscribeFiltersLocal(t *testing.T) {
	f := newFixture(t)
	f.listen(nil)
	quiet, noisy, idle := f.dial(), f.dial(), f.dial()
	quiet.subscribe("")
	noisy.subscribe(`,"local":true`)
	f.s.Emit(f.event("10.0.0.5", "allow-local"))
	f.s.Emit(f.event("1.1.1.1", "allow-rule"))
	f.s.Emit(f.event("1.1.1.1", "allow-rule")) // same key within the window: no event
	if e := decode[Event](t, noisy.line(), "event"); e.Addr != "10.0.0.5" || e.Verdict != "allow-local" {
		t.Fatalf("noisy wants the local event first, got %+v", e)
	}
	for _, p := range []*peer{quiet, noisy} {
		if e := decode[Event](t, p.line(), "event"); e.Addr != "1.1.1.1" || e.Id != 0 || e.Time.IsZero() {
			t.Fatalf("want the public event, got %+v", e)
		}
		p.noLine()
	}
	idle.noLine()
	if r := quiet.reply(quiet.ask(`{"type":"unsubscribe","id":2}`)); !r.Ok {
		t.Fatal(r)
	}
	f.s.Emit(f.event("2.2.2.2", "deny-rule"))
	quiet.noLine()
	if e := decode[Event](t, noisy.line(), "event"); e.Addr != "2.2.2.2" {
		t.Fatalf("noisy still subscribed, got %+v", e)
	}
	if f.s.d.Table.Len() != 3 {
		t.Fatalf("every emitted event feeds the table: %d entries", f.s.d.Table.Len())
	}
}

// Req 2.4: a summary carries the entries changed since the last one (a deduped repeat too),
// only to subscribers that want summaries; the tick refreshes the snapshot cache; no change,
// no summary.
func TestSummaryEveryTick(t *testing.T) {
	f := newFixture(t)
	f.listen(nil)
	sum, evOnly := f.dial(), f.dial()
	sum.subscribe(`,"events":false`)
	evOnly.subscribe(`,"summary":false`)
	f.s.Emit(f.event("1.1.1.1", "allow-rule"))
	f.s.Emit(f.event("1.1.1.1", "allow-rule"))
	evOnly.line()
	f.c.advance(SummaryEvery)
	if err := f.s.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
	s := decode[Summary](t, sum.line(), "summary")
	if s.Since != stamp(t0) || len(s.Entries) != 1 || s.Entries[0].AllowCount != 2 || s.Id != 0 {
		t.Fatalf("summary: %+v", s)
	}
	evOnly.noLine()
	if r := sum.reply(sum.ask(`{"type":"snapshot","id":3,"window":"15m"}`)); len(r.Entries) != 1 || r.Window != "15m" {
		t.Fatalf("snapshot after the tick: %+v", r)
	}
	f.c.advance(SummaryEvery)
	_ = f.s.tick(context.Background())
	sum.noLine()
	f.s.Emit(f.event("3.3.3.3", "deny-default"))
	_ = f.s.tick(context.Background())
	if s := decode[Summary](t, sum.line(), "summary"); s.Since != stamp(t0.Add(2*SummaryEvery)) || s.Entries[0].Addr != "3.3.3.3" {
		t.Fatalf("second summary: %+v", s)
	}
}

// The job itself ticks the summary (the cadence is shortened to keep the test fast).
func TestSummaryJobTicks(t *testing.T) {
	f := newFixture(t)
	f.s.every = 5 * time.Millisecond
	f.listen(nil)
	p := f.dial()
	p.subscribe(`,"events":false`)
	f.s.Emit(f.event("1.1.1.1", "allow-rule"))
	if s := decode[Summary](t, p.line(), "summary"); len(s.Entries) != 1 {
		t.Fatalf("summary: %+v", s)
	}
}

// Req 4.5: state events reach subscribers of either kind, nobody else.
func TestServerStateChanged(t *testing.T) {
	f := newFixture(t)
	f.listen(nil)
	a, b, idle := f.dial(), f.dial(), f.dial()
	a.subscribe(`,"summary":false`)
	b.subscribe(`,"events":false`)
	f.s.StateChanged(State{Mode: "enforce", Trial: "2026-10-11T13:00:00Z", Reason: "trial"})
	for _, p := range []*peer{a, b} {
		if st := decode[State](t, p.line(), "state"); st.Mode != "enforce" || st.Reason != "trial" || st.Id != 0 {
			t.Fatalf("state: %+v", st)
		}
	}
	idle.noLine()
}
