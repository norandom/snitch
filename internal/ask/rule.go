// rule.go: the rule.add request an answer stands for, by the table in the design's Data
// Contracts: Allow goes to the name when the event has one, else to the address; Block goes to
// the address, also when the event has a name (the API refuses a deny by name); both carry the
// event's protocol and port, the program for a declared program or the path for an unknown one
// (6.2 to 6.5), and a note that says the tray wrote it and when (6.6).
//
// Fail-safe implications: the request is only built here; the tray sends it on an explicit
// click and the daemon validates it. From never makes a question for the local network, so no
// rule built here can name it (8.3). An unknown program without a path cannot be named in a
// rule: Answerable says so, and asking for its rule anyway is a programming error.
package ask

import (
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
)

// Answer is the operator's decision on a question.
type Answer int

const (
	Allow Answer = iota
	Block
)

// NoteLayout is the local time on a rule's note, to the minute.
const NoteLayout = "2006-01-02 15:04"

// Answerable reports whether a rule can name the question's program: false for an unknown
// program without a path.
func Answerable(q Question) bool {
	return q.Event.Program != Unknown || q.Event.Path != ""
}

// RuleFor is the rule.add request of an answer. It requires Answerable(q) and a known answer.
func RuleFor(q Question, a Answer, now time.Time) api.Request {
	contract.Require(Answerable(q), "ask.RuleFor: unknown program without a path")
	contract.Require(a == Allow || a == Block, "ask.RuleFor: unknown answer")
	r := api.Request{
		Type:  "rule.add",
		Proto: q.Event.Protocol,
		Port:  int(q.Event.Port),
		Note:  "snitch tray " + now.Local().Format(NoteLayout),
	}
	if q.Event.Program == Unknown {
		r.Path = q.Event.Path
	} else {
		r.Program = q.Event.Program
	}
	r.To, r.Verdict = q.Event.Addr, "deny"
	if a == Allow {
		r.Verdict = "allow"
		if q.Event.Name != "" {
			r.To = q.Event.Name
		}
	}
	return r
}
