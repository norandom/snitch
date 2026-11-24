// questions.go: asking and answering (5.1, 5.2, 5.6, 6.1 to 6.12, 8.6). An event goes through
// the policy (ask.From) into the waiting list; when no question is open, the next one is posted
// under a token (askToken) until the notification server gives its note id (openNote). A press
// counts only for that note id and only for allow or block: the note is retracted, the rule.add
// of the answer is sent under a fresh token, and the question settles as answered. The daemon's
// answer to that request becomes a notice; an error also lifts the key's snooze, and the
// operator refusal turns the tray into a reader.
//
// Choices recorded here:
//   - Without a notification service (8.6) or while paused (5.10) events ask nothing and
//     nothing waits, so no question surfaces later about a connection long past.
//   - A press is also ignored on a note that was posted without actions (a reader's, an
//     unanswerable one, or one posted without buttons), judged by openActs at post time and not
//     by the capabilities at press time: a forged ActionInvoked never writes (6.9, 6.5).
//
// Fail-safe implications: send is issued only here, only on an explicit Allow or Block for the
// open question's note, and its request is always ask.RuleFor's rule.add (6.12, 8.1); the tray
// itself writes nothing. ask.From never asks about the local network (fail-safe 2).
package tray

import (
	"time"

	"github.com/norandom/snitch/internal/ask"
	"github.com/norandom/snitch/internal/client"
)

// answers are the action keys of a question note and the answers they stand for.
var answers = map[string]ask.Answer{"allow": ask.Allow, "block": ask.Block}

// event offers the question an event stands for and posts it when none is open.
func event(m Model, e client.EventLine, now time.Time) (Model, []any) {
	if m.paused || !m.canNotify {
		return m, nil
	}
	q, ok := ask.From(e.Event, m.opts.Scope)
	if !ok {
		return m, nil
	}
	m.queue = m.queue.Offer(q, now)
	return askNext(m)
}

// askNext posts the oldest waiting question when none is open. The counts are read before
// Next (2.4 note): waiting behind the one now opened, and dropped since none waited.
func askNext(m Model) (Model, []any) {
	st := m.queue.Stats()
	queue, q, ok := m.queue.Next()
	if !ok {
		return m, nil
	}
	m.queue = queue
	m.nextToken++
	m.askToken = m.nextToken
	n := noteQuestion(q, st.Waiting-1, st.Dropped, m.writer && m.canAct, m.writer)
	m.openActs = len(n.Actions) > 0
	return m, []any{post{Token: m.askToken, Note: n}}
}

// postedID takes a note id: the open question's, or a notice's.
func postedID(m Model, p posted, now time.Time) Model {
	if p.Token != m.askToken || m.askToken == 0 {
		return noticePosted(m, p)
	}
	m.askToken, m.openNote, m.openSince = 0, p.NoteID, now
	return m
}

// postFailedNote settles a question whose note could not be posted as failed (no snooze, so it may
// ask again) and posts the next; a notice's token is only forgotten.
func postFailedNote(m Model, p postFailed, now time.Time) (Model, []any) {
	if p.Token != m.askToken || m.askToken == 0 {
		return noticeSettled(m, p.Token), nil
	}
	m.askToken, m.openActs = 0, false
	m.queue = m.queue.Settle(ask.Failed, now)
	return askNext(m)
}

// pressed answers the open question when the press is allow or block on its note (6.11), the
// note was posted with actions, and the user is still a writer.
func pressed(m Model, p Pressed, now time.Time) (Model, []any) {
	a, ok := answers[p.Action]
	q, open := m.queue.Open()
	if !ok || !open || m.openNote == 0 || p.NoteID != m.openNote || !m.writer || !m.openActs || !ask.Answerable(q) {
		return m, nil
	}
	m.nextToken++
	fx := []any{retract{NoteID: m.openNote}, send{Token: m.nextToken, Req: ask.RuleFor(q, a, now)}}
	pending := make(map[uint64]ask.Key, len(m.pending)+1)
	for k, v := range m.pending {
		pending[k] = v
	}
	pending[m.nextToken] = q.Key
	m.pending = pending
	m.queue = m.queue.Settle(ask.Answered, now)
	m.openNote, m.openSince, m.openActs = 0, time.Time{}, false
	m, next := askNext(m)
	return m, append(fx, next...)
}

// answered turns the daemon's answer to a rule.add into a notice (6.7, 6.8). An error lifts the
// snooze so the connection may ask again; the operator refusal makes the tray a reader (6.9).
func answered(m Model, a client.Answered) (Model, []any) {
	key, ok := m.pending[a.Token]
	if !ok {
		return m, nil
	}
	pending := make(map[uint64]ask.Key, len(m.pending))
	for k, v := range m.pending {
		if k != a.Token {
			pending[k] = v
		}
	}
	m.pending = pending
	if a.Err == "" {
		return postNotices(m, []Note{noteRuleAdded(a.Text)})
	}
	m.queue = m.queue.Forget(key)
	if a.Role {
		m.writer = false
	}
	return postNotices(m, []Note{noteRuleFailed(a.Err)})
}

// capabilities records what the notification service can do (8.6).
func capabilities(m Model, c Capabilities) Model {
	m.canNotify, m.canAct = c.Available, c.Actions
	return m
}
