// Package clienttest is the stand-in daemon: the daemon's own API server (internal/api) with
// its facts held in memory and changed by commands, so the tray's client is tested against the
// real protocol without root, a kernel program or a running snitchd. Tests use Start; the
// development tool tools/fakedaemon uses New and feeds Do from stdin.
//
// Fail-safe implications: none on the host. The stand-in loads no kernel program, decides no
// connection and writes no rule file; a rule edit is only recorded in memory (and printed by
// the tool). It listens only on the socket path it is given, never on /run/snitch/api.sock
// unless asked to, and its trial and rule verbs change only its in-memory facts, never the
// real daemon's state files or mode.
package clienttest

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/rules"
)

// The reasons the real daemon puts on its state lines (examples/api.md "state").
const (
	reasonEnded    = "trial ended by the operator: file removed"
	reasonKept     = "enforce kept"
	reasonUnkept   = "enforce unkept: file removed"
	reasonReloaded = "rules reloaded"
	reasonMode     = "mode set by the stand-in"
)

// Options are the stand-in's parameters. Operator is the uid that may write (root always
// may): the tool passes the invoking user, a test passes another uid to be a reader.
type Options struct {
	Operator uint32
	Now      func() time.Time  // nil: time.Now
	Log      func(string)      // nil: the server's journal lines are dropped
	Record   func(api.Request) // nil: none; called once per accepted rule edit
	// ReloadAfter stands for the daemon's reload poll (up to 2 s): the delay between the reply
	// to a rule edit and its rulesChanged state line. 0: defaultReloadAfter.
	ReloadAfter time.Duration
	// SummaryEvery stands for the daemon's 2 s summary pass (and snapshot cache refresh).
	// 0: defaultSummaryEvery.
	SummaryEvery time.Duration
	// NoRules starts the stand-in with zero rules and zero programs.
	NoRules bool
}

// defaultReloadAfter is short so tests stay fast, yet long enough that the reply leaves first.
const defaultReloadAfter = 100 * time.Millisecond

// StandIn is one stand-in daemon on one socket path. The facts are an immutable Status
// swapped whole; fmu serialises the changes and guards the recorded edits.
type StandIn struct {
	path        string
	o           Options
	table       *api.Table
	srv         *api.Server
	facts       atomic.Pointer[api.Status]
	refuse      atomic.Bool
	cookie      atomic.Uint64
	dropped     atomic.Int64
	fmu         sync.Mutex
	base        *rules.File
	overlay     *rules.File
	merged      *rules.File
	edits       []api.Request
	smu         sync.Mutex
	lastSummary time.Time
	cmu         sync.Mutex
	conns       map[*relayConn]struct{}
	rwg         sync.WaitGroup
	rmu         sync.Mutex // guards stop and done: the serving run
	stop        context.CancelFunc
	done        chan error
	pmu         sync.Mutex      // guards run: Add on pending happens only while run is live
	run         context.Context // the serving run's context; nil while stopped
	pending     sync.WaitGroup  // announcements waiting for the reload delay
}

// New builds a stand-in in monitor mode and serves it on path. A stale socket file left at
// path is removed first; any other file there is an error.
func New(path string, o Options) (*StandIn, error) {
	contract.Require(path != "", "clienttest: a socket path is required")
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Log == nil {
		o.Log = func(string) {}
	}
	if o.ReloadAfter <= 0 {
		o.ReloadAfter = defaultReloadAfter
	}
	if o.SummaryEvery <= 0 {
		o.SummaryEvery = defaultSummaryEvery
	}
	s := &StandIn{path: path, o: o, table: api.NewTable(o.Now),
		lastSummary: o.Now(), conns: map[*relayConn]struct{}{}}
	s.facts.Store(initial(o.Now()))
	s.initRules(o.NoRules)
	s.srv = api.New(api.Deps{Operator: o.Operator, Table: s.table, Facts: s.status,
		Rules:   s.rulesFacts,
		Learned: func() ([]api.Observation, bool) { return nil, s.Facts().Learning },
		Trial:   s.trialOp, RuleEdit: s.ruleEdit, Log: o.Log, Now: o.Now})
	if err := s.Serve(); err != nil {
		return nil, err
	}
	return s, nil
}

// Start is New for a test: a socket in the test's temp dir, stopped when the test ends.
func Start(t testing.TB, o Options) *StandIn {
	t.Helper()
	s, err := New(filepath.Join(t.TempDir(), "api.sock"), o)
	if err != nil {
		t.Fatalf("stand-in: %v", err)
	}
	t.Cleanup(s.Stop)
	return s
}

// initial is the status of a freshly started service daemon (examples/api.md "status").
func initial(now time.Time) *api.Status {
	return &api.Status{Running: true, Pid: os.Getpid(), Version: "fake", Mode: "monitor",
		Source: "files", Rules: api.RulesSummary{Programs: 18, Resolved: 12, Executables: 15,
			Rules: 13, File: "/etc/snitch/rules.toml", Overlay: "/etc/snitch/rules.d/local.toml"},
		Started: now.UTC().Format(time.RFC3339), Counting: true, DNS: &api.DNSStatus{On: true}}
}

// Path is the socket the stand-in serves on.
func (s *StandIn) Path() string { return s.path }

// Serve listens on the path again after Stop (a daemon restart on the same socket); the
// facts and recorded edits survive. Serving twice is a programming error.
func (s *StandIn) Serve() error {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	contract.Require(s.stop == nil, "clienttest: the stand-in is already serving")
	if err := removeStale(s.path); err != nil {
		return err
	}
	l, err := net.Listen("unix", s.path)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(context.Background())
	srvL := newChanListener(l.Addr())
	done := make(chan error, 1)
	go func() { done <- s.srv.Job(srvL)(ctx) }()
	s.stop, s.done = cancel, done
	s.rwg.Add(2)
	go s.acceptRelay(ctx, l, srvL)
	go s.summaryLoop(ctx)
	s.pmu.Lock()
	s.run = ctx
	s.pmu.Unlock()
	return nil
}

// Stop closes the listener and every connection, drops the announcements still waiting and
// waits for all of them: nothing is sent after it returns. A second Stop is a no-op.
func (s *StandIn) Stop() {
	s.rmu.Lock()
	defer s.rmu.Unlock()
	if s.stop == nil {
		return
	}
	s.pmu.Lock()
	s.run = nil // no new announcement from here on
	s.pmu.Unlock()
	s.stop()
	// Join the serving goroutine; the serve error was for the harness to
	// observe while it ran. The blank receive is the one shape errcheck
	// accepts for an error-typed channel; staticcheck's S1005 dislikes
	// exactly that (and S1000 the select alternative), so this one line
	// is adjudicated in .golangci.yaml - the exclusion is scoped to this
	// file and that one check id.
	_ = <-s.done
	s.closeConns()
	s.rwg.Wait()
	s.pending.Wait()
	s.stop, s.done = nil, nil
}

// later runs fn after d unless the serving run ends first; while stopped it does nothing.
func (s *StandIn) later(d time.Duration, fn func()) {
	s.pmu.Lock()
	ctx := s.run
	if ctx == nil {
		s.pmu.Unlock()
		return
	}
	s.pending.Add(1)
	s.pmu.Unlock()
	go func() {
		defer s.pending.Done()
		t := time.NewTimer(d)
		defer t.Stop()
		select {
		case <-ctx.Done():
		case <-t.C:
			if ctx.Err() == nil {
				fn()
			}
		}
	}()
}

// Restart is Stop then Serve: connected clients see the connection end, new ones get in.
func (s *StandIn) Restart() error {
	s.Stop()
	return s.Serve()
}

// removeStale removes a socket file a previous run left behind; anything else is refused.
func removeStale(path string) error {
	fi, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSocket == 0 {
		return errors.New(path + ": exists and is not a socket")
	}
	return os.Remove(path)
}

// Facts is the current status as the stand-in holds it, without the server's counters.
func (s *StandIn) Facts() api.Status { return *s.facts.Load() }

// status is the Facts delegate: the held facts plus the server's and table's own counters.
func (s *StandIn) status() api.Status {
	st := s.Facts()
	st.Clients, st.Dropped = s.srv.Clients(), int(s.srv.Dropped())+int(s.dropped.Load())
	st.Entries, st.Evictions = s.table.Len(), s.table.Evictions()
	return st
}

// change applies fn to a copy of the facts and stores the copy; it returns the new facts.
func (s *StandIn) change(fn func(*api.Status)) api.Status {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	st := *s.facts.Load()
	fn(&st)
	s.facts.Store(&st)
	return st
}

// announce sends the state line the real daemon sends for a change.
func (s *StandIn) announce(st api.Status, reason string, rulesChanged bool) {
	s.srv.StateChanged(api.State{Mode: st.Mode, Trial: st.Trial, Kept: st.Kept,
		RulesChanged: rulesChanged, Reason: reason})
}

// Emit sends an event through the server's table and fan-out; a zero time is now and a zero
// cookie a fresh one.
func (s *StandIn) Emit(e api.Event) {
	if e.Time.IsZero() {
		e.Time = s.o.Now()
	}
	if e.Cookie == 0 {
		e.Cookie = s.cookie.Add(1)
	}
	s.srv.Emit(e)
}

// Edits are the rule edits accepted so far, oldest first.
func (s *StandIn) Edits() []api.Request {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	return append([]api.Request(nil), s.edits...)
}
