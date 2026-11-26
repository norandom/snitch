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
	noSession    = "the daemon is not running"
	NoAnswer     = "the daemon did not answer"
)

// refusal is the daemon's text for a write by a reader (examples/api.md "Authorization").
// question is the suffix of the daemon's own question (examples/api.md).
const (
	refusal  = "write requires the operator"
	question = "[y/N]"
)

// IsQuestion reports whether a daemon error text is the daemon's own confirmation question.
func IsQuestion(errText string) bool {
	return strings.HasSuffix(errText, question)
}

// Msg is what the client tells the tray's loop.
type Msg interface{ isMsg() }

// Up says the session is subscribed; its first status follows as Facts.
type Up struct {
	PeerUID   uint32
	PeerKnown bool
}

// Down says the session is lost: Reason is NotRunning or NotAnswering.
type Down struct{ Reason string }

// Facts is a status reply.
type Facts struct{ Status api.Status }

// StateLine is a state line from the subscription.
type StateLine struct{ State api.State }

// EventLine is an event line from the subscription.
type EventLine struct{ Event api.Event }

// SummaryLine is a summary line from the subscription (only when Config.Table is true).
type SummaryLine struct{ Entries []api.Entry }

// Dropped is a dropped count line from the subscription (only when Config.Table is true).
type Dropped struct{ Count int }

// Answered is the one answer to a Send: Text on success, otherwise Err (the daemon's error
// or a local reason). Role is true when Err is the daemon's operator refusal. Question is
// true when Err ends in "[y/N]". Reply holds the decoded daemon reply when Config.Table is
// true, and is nil otherwise.
type Answered struct {
	Token    uint64
	Text     string
	Err      string
	Role     bool
	Question bool
	Reply    *api.Reply
}

func (Up) isMsg()          {}
func (Down) isMsg()        {}
func (Facts) isMsg()       {}
func (StateLine) isMsg()   {}
func (EventLine) isMsg()   {}
func (SummaryLine) isMsg() {}
func (Dropped) isMsg()     {}
func (Answered) isMsg()    {}

// failed is the Answered for an error text; the refusal and question suffixes are the only
// two daemon texts the client inspects.
func failed(token uint64, err string) Answered {
	return Answered{
		Token:    token,
		Err:      err,
		Role:     strings.HasSuffix(err, refusal),
		Question: IsQuestion(err),
	}
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
		if s.cfg.Table {
			s.dropped(b)
		}
	case "summary":
		if s.cfg.Table {
			s.summary(b)
		}
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
		s.cfg.Sink(Up{PeerUID: s.peerUID, PeerKnown: s.peerKnown})
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
			var reply *api.Reply
			if s.cfg.Table {
				reply = &r
			}
			s.cfg.Sink(Answered{Token: p.token, Text: r.Text, Reply: reply})
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

// summary passes a summary line on while the session is up.
func (s *session) summary(b []byte) {
	var sm api.Summary
	if s.decode(b, &sm) && s.up {
		s.cfg.Sink(SummaryLine{Entries: sm.Entries})
	}
}

// dropped passes a dropped line's count on while the session is up.
func (s *session) dropped(b []byte) {
	var d api.Dropped
	if s.decode(b, &d) && s.up {
		s.cfg.Sink(Dropped{Count: d.Count})
	}
}
