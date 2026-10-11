// dispatch.go: one connected client's subscription flags and the verb table. A parsed request
// goes through the role check (the write set is auth.go's) and then its handler; writes are
// audited with the peer's uid before the reply leaves, refused ones included. Handlers return
// a Reply or an Error and dispatch stamps type and id, so every line gets exactly one answer.
package api

import (
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/norandom/snitch/internal/contract"
)

// Subscription flags (design "Subscribe options").
const (
	subEvents uint32 = 1 << iota
	subLocal
	subSummary
)

// client is a connection: its queue, the peer's uid and what it subscribed to. The flags are
// set by the read loop and read by Emit and the summary job.
type client struct {
	*Client
	uid  uint32
	subs atomic.Uint32
}

func (c *client) wants(flag uint32) bool { return c.subs.Load()&flag != 0 }
func (c *client) subscribed() bool       { return c.subs.Load() != 0 }

// admits is the event filter: events on, and local-net verdicts only when asked for.
func (c *client) admits(e Event) bool {
	return c.wants(subEvents) && (e.Verdict != "allow-local" || c.wants(subLocal))
}

// handler answers one request with a Reply or an Error (type and id are stamped after).
type handler func(*Server, *client, Request) any

// verbs is the verb table; Parse already rejected any type not in it.
var verbs = map[string]handler{
	"status": (*Server).status, "rules": (*Server).rules, "programs": (*Server).programs,
	"learned": (*Server).learned, "snapshot": (*Server).snapshot,
	"subscribe": (*Server).subscribe, "unsubscribe": (*Server).unsubscribe,
	"trial": (*Server).trial, "keep": (*Server).trial, "unkeep": (*Server).trial, "end": (*Server).trial,
	"rule.add": (*Server).ruleEdit, "rule.remove": (*Server).ruleEdit,
}

// dispatch answers one line: parse, role check, handler, audit for writes.
func (s *Server) dispatch(c *client, line []byte) any {
	req, perr := Parse(line)
	if perr != nil {
		return *perr
	}
	run, ok := verbs[req.Type]
	contract.Invariant(ok, "every parsed request type has a handler")
	var out any
	if IsWrite(req.Type) && c.Role != Writer {
		out = Error{Error: req.Type + ": write requires the operator"}
		s.d.Log(journal(c, req) + " refused: write requires the operator")
	} else {
		out = run(s, c, req)
		if IsWrite(req.Type) {
			s.audit(c, req, out)
		}
	}
	return stamped(out, req.Id)
}

// stamped fills the envelope of a handler's answer.
func stamped(out any, id int) any {
	switch v := out.(type) {
	case Reply:
		v.Type, v.Id, v.Ok = "reply", id, true
		return v
	case Error:
		v.Type, v.Id = "error", id
		return v
	}
	contract.Ensure(false, "a handler answers with a Reply or an Error")
	return nil
}

// journal is how every write's log line starts: the request type and the peer's uid. A
// refused write (a reader probing the write verbs) leaves one too, from dispatch.
func journal(c *client, req Request) string {
	return "api: " + req.Type + " by uid " + strconv.FormatUint(uint64(c.uid), 10)
}

// audit is the journal line every delegated write leaves: the user, the request and the
// outcome (Req 5.5).
func (s *Server) audit(c *client, req Request, out any) {
	outcome := "ok"
	switch v := out.(type) {
	case Reply:
		outcome = "ok: " + v.Text
	case Error:
		outcome = "error: " + v.Error
	}
	s.d.Log(journal(c, req) + " " + strings.TrimSpace(string(Encode(req))) + " -> " + outcome)
}

func (s *Server) status(_ *client, _ Request) any {
	st := s.d.Facts()
	return Reply{Status: &st}
}

func (s *Server) rules(_ *client, r Request) any {
	if s.d.Rules == nil {
		return unavailable(r)
	}
	rules, _ := s.d.Rules()
	return Reply{Rules: rules}
}

func (s *Server) programs(_ *client, r Request) any {
	if s.d.Rules == nil {
		return unavailable(r)
	}
	_, programs := s.d.Rules()
	return Reply{Programs: programs}
}

// learned lists the observations; learning off says so in the text (Req 4.4).
func (s *Server) learned(_ *client, r Request) any {
	if s.d.Learned == nil {
		return unavailable(r)
	}
	obs, on := s.d.Learned()
	rep := Reply{Learned: obs, Learning: on}
	if !on {
		rep.Text = "learning is off"
	}
	return rep
}

// windowNames are the spans a snapshot request may name, in Windows' order.
var windowNames = map[string]time.Duration{"15m": 15 * time.Minute, "30m": 30 * time.Minute,
	"1h": time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour}

// snapshot serves the window's cached entries; the cache never takes the table's lock.
func (s *Server) snapshot(_ *client, r Request) any {
	win, ok := windowNames[r.Window]
	if !ok {
		return Error{Error: "unknown window " + r.Window + ": want one of 15m, 30m, 1h, 24h, 7d"}
	}
	entries, err := s.d.Table.Snapshot(win)
	if err != nil {
		return Error{Error: err.Error()}
	}
	return Reply{Entries: entries, Window: r.Window}
}

func (s *Server) subscribe(c *client, r Request) any {
	var flags uint32
	for _, f := range []struct {
		on   bool
		flag uint32
	}{{r.Events, subEvents}, {r.Local, subLocal}, {r.Summary, subSummary}} {
		if f.on {
			flags |= f.flag
		}
	}
	c.subs.Store(flags)
	return Reply{}
}

func (s *Server) unsubscribe(c *client, _ Request) any {
	c.subs.Store(0)
	return Reply{}
}

func (s *Server) trial(c *client, r Request) any    { return call(s.d.Trial, c, r) }
func (s *Server) ruleEdit(c *client, r Request) any { return call(s.d.RuleEdit, c, r) }

// call runs a write delegate for the peer's uid: its text is the reply, its error the
// error line, a missing delegate "not available".
func call(fn func(Request, uint32) (string, error), c *client, r Request) any {
	if fn == nil {
		return unavailable(r)
	}
	text, err := fn(r, c.uid)
	if err != nil {
		return Error{Error: err.Error()}
	}
	return Reply{Text: text}
}

func unavailable(r Request) any { return Error{Error: r.Type + ": not available"} }
