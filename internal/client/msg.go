// Package client is the tray's one connection to the daemon's API (examples/api.md), kept
// alive and turned into messages for the tray's loop: Up and Down for the connection, Facts,
// StateLine and EventLine for what the daemon says, Answered for a request handed in by Send.
//
// Fail-safe implications: none on the kernel side. The client only reads the daemon's state
// through its documented socket and writes only what a caller passes to Send; it never
// requests a snapshot, never retries a write on its own, and a daemon that is gone or silent
// is reported as Down instead of being guessed at.
package client

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/norandom/snitch/internal/api"
)

// The reasons a Down carries and the local reasons an Answered may carry.
const (
	NotRunning   = "not running"
	NotAnswering = "not answering"
	NoSession    = "the daemon is not running"
	NoAnswer     = "the daemon did not answer"
)

// refusal is the daemon's text for a write by a reader (examples/api.md "Authorization").
const refusal = "write requires the operator"

// Msg is what the client tells the tray's loop.
type Msg interface{ isMsg() }

// Up says the session is subscribed; its first status follows as Facts.
type Up struct{}

// Down says the session is lost: Reason is NotRunning or NotAnswering.
type Down struct{ Reason string }

// Facts is a status reply.
type Facts struct{ Status api.Status }

// StateLine is a state line from the subscription.
type StateLine struct{ State api.State }

// EventLine is an event line from the subscription.
type EventLine struct{ Event api.Event }

// Answered is the one answer to a Send: Text on success, otherwise Err (the daemon's error
// or a local reason). Role is true when Err is the daemon's operator refusal.
type Answered struct {
	Token uint64
	Text  string
	Err   string
	Role  bool
}

func (Up) isMsg()        {}
func (Down) isMsg()      {}
func (Facts) isMsg()     {}
func (StateLine) isMsg() {}
func (EventLine) isMsg() {}
func (Answered) isMsg()  {}

// failed is the Answered for an error text; the refusal suffix is the one daemon text the
// tray interprets (a revalidation trigger of the design).
func failed(token uint64, err string) Answered {
	return Answered{Token: token, Err: err, Role: strings.HasSuffix(err, refusal)}
}

// handle turns one daemon line into messages; it returns a reason when the line ends the
// session. Lines that do not parse or have an unknown type are ignored (4.8).
func (s *session) handle(b []byte) string {
	var env struct {
		Type string `json:"type"`
		Id   int    `json:"id"`
	}
	if err := json.Unmarshal(b, &env); err != nil {
		s.ignored(err.Error())
		return ""
	}
	switch env.Type {
	case "reply":
		s.reply(b, env.Id)
	case "error":
		return s.refused(b, env.Id)
	case "event":
		s.event(b)
	case "state":
		s.state(b)
	case "dropped": // the daemon lost lines for us: what we hold may be stale
		s.want = true
	case "summary": // not subscribed to; harmless
	default:
		s.ignored("unknown type " + strconv.Quote(env.Type))
	}
	return ""
}

// decode unmarshals a line of a known type; a line that does not fit is ignored.
func (s *session) decode(b []byte, v any) bool {
	if err := json.Unmarshal(b, v); err != nil {
		s.ignored(err.Error())
		return false
	}
	return true
}

// reply answers the subscribe (Up), the status in flight (Facts) or a caller (Answered).
func (s *session) reply(b []byte, id int) {
	var r api.Reply
	switch {
	case id == 0 || !s.decode(b, &r):
	case id == s.sub:
		s.sub, s.up = 0, true
		s.cfg.Log("daemon: up")
		s.cfg.Sink(Up{})
	case id == s.status:
		s.status = 0
		if r.Status == nil {
			s.ignored("a status reply without a status")
		} else if s.up {
			s.cfg.Sink(Facts{Status: *r.Status})
		}
	default:
		if p, ok := s.calls[id]; ok {
			delete(s.calls, id)
			s.cfg.Sink(Answered{Token: p.token, Text: r.Text})
		}
	}
}

// refused handles an error line: a refused subscribe ends the session, a refused status is
// logged, a caller gets the daemon's text, and an error without an id is logged.
func (s *session) refused(b []byte, id int) string {
	var e api.Error
	if !s.decode(b, &e) {
		return ""
	}
	switch p, ok := s.calls[id]; {
	case id != 0 && id == s.sub:
		s.cfg.Log("daemon: subscribe refused: " + e.Error)
		return NotRunning
	case id != 0 && id == s.status:
		s.status = 0
		s.cfg.Log("daemon: status refused: " + e.Error)
	case ok:
		delete(s.calls, id)
		s.cfg.Sink(failed(p.token, e.Error))
	default:
		s.cfg.Log("daemon: " + e.Error)
	}
	return ""
}

// event passes an event on while the session is up.
func (s *session) event(b []byte) {
	var e api.Event
	if s.decode(b, &e) && s.up {
		s.cfg.Sink(EventLine{Event: e})
	}
}

// state passes a state line on and wants the status it changed.
func (s *session) state(b []byte) {
	var st api.State
	if s.decode(b, &st) && s.up {
		s.cfg.Sink(StateLine{State: st})
		s.want = true
	}
}
