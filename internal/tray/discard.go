// discard.go: how questions end without an answer (5.7, 5.8, 5.10, 6.10, 8.6). Closed for the
// open note and the tray's own 60 s timeout settle it unanswered, which snoozes it (5.4). A
// question whose reason is gone is discarded: a rules reload flushes every waiting one (research
// "a waiting question is discarded on any rules reload"), a mode change flushes the waiting ones
// whose wording (Blocked) no longer fits and retracts an open one that no longer fits, the
// daemon's loss, the pause and the loss of the notification service flush all and retract the
// open one. After every settle the next waiting question is posted.
//
// Choices recorded here:
//   - A question the tray retracts (mode, down, pause, service gone) settles Failed, not
//     Unanswered: the operator never declined it, so it is not snoozed and asks again when the
//     connection happens again. Only the user's or the server's Closed and the timeout snooze.
//   - A question whose note is still being posted (askToken, no note id yet) cannot be
//     retracted; it is judged again when its Posted arrives, by the conditions that last
//     (pause, service, daemon loss). A mode change during that bus call leaves it standing: the
//     window is one bus call and an answer still writes the right rule.
//   - A daemon lost after facts were known counts as gone until the next session's first
//     Facts, so a question posted in between is retracted on its Posted and not snoozed.
//   - Without a notification service nothing is retracted: its notes went with it, and a
//     Retract could hit an unrelated note of a restarted server with the same id.
//
// Fail-safe implications: nothing here sends a request; discarding only drops questions, so a
// discard can never write a rule (6.10, 6.12).
package tray

import (
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/ask"
	"github.com/norandom/snitch/internal/client"
)

// live reports whether questions can stand at all: not paused, a notification service, and
// the daemon not lost.
func live(m Model) bool {
	return !m.paused && m.canNotify && !(m.gone && m.facts != nil)
}

// mode is the daemon's last known mode, "" before any facts.
func mode(m Model) string {
	if m.facts == nil {
		return ""
	}
	return m.facts.Mode
}

// standing is the keep rule after a change: live, and after a mode change only the questions
// whose wording fits it (deny-default in enforce, allow-monitor in monitor).
func standing(m Model, modeChanged bool) func(ask.Question) bool {
	return func(q ask.Question) bool {
		return live(m) && (!modeChanged || q.Blocked == (mode(m) == "enforce"))
	}
}

// discard flushes the waiting questions keep refuses (all of them when all is set), retracts
// the open note when keep refuses its question, and posts the next.
func discard(m Model, now time.Time, all bool, keep func(ask.Question) bool) (Model, []any) {
	if m.queue.Stats().Waiting > 0 {
		m.queue = m.queue.Flush(func(q ask.Question) bool { return !all && keep(q) })
	}
	var fx []any
	if q, open := m.queue.Open(); open && m.openNote != 0 && !keep(q) {
		if m.canNotify {
			fx = append(fx, Retract{NoteID: m.openNote})
		}
		m = settle(m, ask.Failed, now)
	}
	m, next := askAgain(m)
	return m, append(fx, next...)
}

// settle ends the open, shown question with an outcome.
func settle(m Model, o ask.Outcome, now time.Time) Model {
	m.queue = m.queue.Settle(o, now)
	m.openNote, m.openSince, m.openActs = 0, time.Time{}, false
	return m
}

// askAgain posts the next waiting question unless one is being posted; askNext itself does
// nothing while one is open or none waits.
func askAgain(m Model) (Model, []any) {
	if m.askToken != 0 {
		return m, nil
	}
	return askNext(m)
}

// tick is the gone notice's tick and the open question's 60 s timeout (5.7, 6.10).
func tick(m Model, now time.Time) (Model, []any) {
	m, fx := goneTick(m, now)
	if m.openNote == 0 || now.Sub(m.openSince) < questionTime {
		return m, fx
	}
	fx = append(fx, Retract{NoteID: m.openNote})
	m, next := askAgain(settle(m, ask.Unanswered, now))
	return m, append(fx, next...)
}

// closedNote settles the open question unanswered when its note closed (6.10); any other id
// is a notice's or unknown.
func closedNote(m Model, id uint32, now time.Time) (Model, []any) {
	if id == 0 || id != m.openNote {
		return closed(m, id), nil
	}
	return askAgain(settle(m, ask.Unanswered, now))
}

// click toggles the pause (3.4, 5.10); pausing drops every question. Other rows are 3.5's.
func click(m Model, c MenuClick, now time.Time) (Model, []any) {
	if c.Row != RowPause {
		return m, nil
	}
	m.paused = !m.paused
	return discard(m, now, false, standing(m, false))
}

// afterPosted judges a question again once its note id is known (see the choices above).
func afterPosted(m Model, p Posted, now time.Time) (Model, []any) {
	question := p.Token == m.askToken && m.askToken != 0
	m = postedID(m, p, now)
	if !question {
		return m, nil
	}
	return discard(m, now, false, standing(m, false))
}

// afterCaps drops the questions when the notification service went away (8.6).
func afterCaps(m Model, c Capabilities, now time.Time) (Model, []any) {
	m = capabilities(m, c)
	return discard(m, now, false, standing(m, false))
}

// afterDown drops the questions of a lost daemon (5.8).
func afterDown(m Model, d client.Down, now time.Time) (Model, []any) {
	m = down(m, d, now)
	return discard(m, now, false, standing(m, false))
}

// afterFacts drops what a mode change first seen in facts no longer fits.
func afterFacts(m Model, st api.Status, now time.Time) (Model, []any) {
	before := mode(m)
	m, fx := facts(m, st)
	m, more := discard(m, now, false, standing(m, mode(m) != before))
	return m, append(fx, more...)
}

// afterLine drops every waiting question on a rules reload and what a mode change no longer fits.
func afterLine(m Model, s api.State, now time.Time) (Model, []any) {
	before := mode(m)
	m, fx := stateLine(m, s)
	m, more := discard(m, now, s.RulesChanged, standing(m, mode(m) != before))
	return m, append(fx, more...)
}
