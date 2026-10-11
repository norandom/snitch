// server.go: the API's dispatcher. The accept loop is a job, each connection a goroutine that
// reads request lines, the role decided once from the peer's credentials; events, summaries
// and state fan out to subscribers through their non-blocking queues. Fail-safe: Emit has no
// blocking path (Observe holds the table's lock briefly, Send never waits), so a stuck or
// flooded client never delays the pump; an accept error never ends the daemon.
package api

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
	"golang.org/x/sys/unix"
)

// acceptRetry is the pause after an accept error (descriptor exhaustion) before trying again.
const acceptRetry = 100 * time.Millisecond

// Deps are the server's delegates (design "Server"). Table, Facts, Log and Now are required;
// the others may be nil, which makes their requests answer "not available".
type Deps struct {
	Operator uint32 // 0 = none configured; root is always a writer
	Table    *Table
	Facts    func() Status
	Rules    func() ([]RuleView, []ProgramView)
	Learned  func() ([]Observation, bool)                  // bool: learning on
	Trial    func(req Request, who uint32) (string, error) // writer only: trial, keep, unkeep, end
	RuleEdit func(req Request, who uint32) (string, error) // writer only: rule.add, rule.remove
	Log      func(string)
	Now      func() time.Time
}

// Server owns the clients; one per process in the daemon.
type Server struct {
	d        Deps
	creds    func(net.Conn) *unix.Ucred // peer credentials (tests inject)
	every    time.Duration              // summary cadence (tests shorten)
	deadline time.Duration              // per-client write deadline
	mu       sync.RWMutex               // guards clients and gone
	clients  map[*client]struct{}
	gone     int64     // drops of clients that have left
	since    time.Time // last summary; the summary job's own
}

// New checks the required delegates and returns a server with no clients.
func New(d Deps) *Server {
	contract.Require(d.Table != nil, "api: Table is required")
	contract.Require(d.Facts != nil, "api: Facts is required")
	contract.Require(d.Log != nil, "api: Log is required")
	contract.Require(d.Now != nil, "api: Now is required")
	return &Server{d: d, creds: peerCreds, every: SummaryEvery, deadline: WriteDeadline,
		clients: map[*client]struct{}{}, since: d.Now()}
}

// Job serves l until ctx ends: the accept loop and the summary ticker under one run. It
// returns ctx.Err() once the listener is closed.
func (s *Server) Job(l net.Listener) jobs.Job {
	contract.Require(l != nil, "api: nil listener")
	return func(ctx context.Context) error {
		return jobs.Run(ctx, s.accept(l), jobs.Every(s.every, s.tick))
	}
}

// accept never ends on an accept error other than the listener's close: the first error of a
// streak is logged, then it retries every acceptRetry (design "Server").
func (s *Server) accept(l net.Listener) jobs.Job {
	return func(ctx context.Context) error {
		go func() { <-ctx.Done(); _ = l.Close() }()
		var wg sync.WaitGroup
		defer wg.Wait()
		logged := false
		for {
			conn, err := l.Accept()
			if err == nil {
				logged = false
				wg.Go(func() { s.serve(ctx, conn) })
				continue
			}
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return ctx.Err()
			}
			if !logged {
				s.d.Log("api: accept: " + err.Error() + " (retrying)")
				logged = true
			}
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(acceptRetry):
			}
		}
	}
}

// serve is one connection: admission, then the read loop until the peer or the writer side
// closes it; each line yields exactly one reply or error.
func (s *Server) serve(ctx context.Context, conn net.Conn) {
	c := s.admit(conn, s.creds(conn))
	if c == nil {
		refuse(conn, s.deadline)
		return
	}
	defer s.leave(c)
	stop := context.AfterFunc(ctx, c.Close)
	defer stop()
	r := NewLineReader(conn)
	for {
		line, err := r.ReadLine()
		if errors.Is(err, ErrLineTooLong) {
			c.Send(Encode(Error{Type: "error", Error: err.Error()}))
			continue
		}
		if err != nil {
			return
		}
		c.Send(Encode(s.dispatch(c, line)))
	}
}

// admit registers a client unless MaxClients are connected (nil then).
func (s *Server) admit(conn net.Conn, cred *unix.Ucred) *client {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.clients) >= MaxClients {
		return nil
	}
	c := &client{Client: NewClient(conn, RoleFor(cred, s.d.Operator), s.deadline)}
	if cred != nil {
		c.uid = cred.Uid
	}
	s.clients[c] = struct{}{}
	return c
}

// refuse sends the 65th connection one error line and closes it.
func refuse(conn net.Conn, deadline time.Duration) {
	_ = conn.SetWriteDeadline(time.Now().Add(deadline))
	_, _ = conn.Write(Encode(Error{Type: "error", Error: "too many clients"}))
	_ = conn.Close()
}

// leave forgets a client, keeps its drops in the total and logs a writer-side failure.
func (s *Server) leave(c *client) {
	c.Close()
	<-c.Done()
	if err := c.Err(); err != nil {
		s.d.Log("api: client closed: " + err.Error())
	}
	s.mu.Lock()
	delete(s.clients, c)
	s.gone += c.Drops()
	s.mu.Unlock()
}

// peerCreds reads SO_PEERCRED; nil (a reader) when the connection is not a unix socket or
// the read fails.
func peerCreds(conn net.Conn) *unix.Ucred {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil
	}
	var cred *unix.Ucred
	if cerr := raw.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); cerr != nil || err != nil {
		return nil
	}
	return cred
}

// Emit records a decision in the table and, when it is fresh, sends it to the subscribers
// whose filter admits it. It never blocks: the pump calls it (design "An event reaches a
// subscribed client").
func (s *Server) Emit(e Event) {
	contract.Require(!e.Time.IsZero(), "api: an event needs a time")
	if !s.d.Table.Observe(e) {
		return
	}
	e.Type, e.Id = "event", 0
	s.fanout(e, func(c *client) bool { return c.admits(e) })
}

// StateChanged tells every subscriber about a mode, trial or rules change (Req 4.5).
func (s *Server) StateChanged(st State) {
	st.Type, st.Id = "state", 0
	s.fanout(st, func(c *client) bool { return c.subscribed() })
}

// tick is the summary job: the changed entries (which also refreshes the snapshot caches)
// go to every summary subscriber; nothing changed, nothing sent.
func (s *Server) tick(context.Context) error {
	now := s.d.Now()
	entries := s.d.Table.Changed(s.since)
	since := s.since
	s.since = now
	if len(entries) == 0 {
		return nil
	}
	s.fanout(Summary{Type: "summary", Since: stamp(since), Entries: entries},
		func(c *client) bool { return c.wants(subSummary) })
	return nil
}

// fanout marshals msg once, and only if someone wants it, then queues it per client.
func (s *Server) fanout(msg any, want func(*client) bool) {
	s.mu.RLock()
	var to []*client
	for c := range s.clients {
		if want(c) {
			to = append(to, c)
		}
	}
	s.mu.RUnlock()
	if len(to) == 0 {
		return
	}
	b := Encode(msg) // once, outside every lock: a connecting or leaving client never waits on it
	for _, c := range to {
		c.Send(b)
	}
}

// Clients is the number of connected clients (the status facts).
func (s *Server) Clients() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.clients)
}

// Dropped is the number of messages dropped over the server's life, left clients included.
func (s *Server) Dropped() int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := s.gone
	for c := range s.clients {
		n += c.Drops()
	}
	return n
}
