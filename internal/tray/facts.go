// facts.go: following the daemon (4.1 to 4.4) and giving notice of its changes (7.1 to 7.8).
// Facts replace the status, a state line updates mode, trial and kept at once; the notices are
// the difference between the last known facts and the new ones, so each change is told once,
// whichever message brings it first. The first facts after start are the baseline (7.7).
//
// Choices recorded here:
//   - A loss begins at the first Down after facts were known; a repeated Down (the reason
//     changes between not running and not answering) only updates the reason (2.1 note).
//     A daemon absent from the start is the state found at start and is never noticed.
//   - Up does not end the loss: the first Facts of the session does (3.1 note), and only then
//     is the daemon's return noticed, and only when its loss was.
//   - Enforcement ended takes the state line's reason; facts carry none, so a change first
//     seen in facts (after a reconnect) is told without one.
//   - One mode notice per change: unkept wins over ended (unkeep returns to monitor) and
//     then says so. A trial starts only from no deadline; a later deadline (snitchd trial
//     extend) is silent, as there is no extension notice in 7.1 to 7.5.
//
// Fail-safe implications: none on the kernel side; this only reads facts and posts notices
// without actions. Notices are posted at once, never behind a question (7.8).
package tray

import (
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/client"
)

// goneAfter is how long a loss lasts before it is noticed (7.6).
const goneAfter = 10 * time.Second

// down marks the daemon gone; the loss's start is kept across repeated Downs.
func down(m Model, d client.Down, now time.Time) Model {
	if m.goneSince.IsZero() && m.facts != nil {
		m.goneSince = now
	}
	m.gone, m.down = true, d.Reason
	return m
}

// facts takes a status: it ends a loss, notices the changes since the last facts, and
// replaces them.
func facts(m Model, st api.Status) (Model, []any) {
	var notes []Note
	if m.gone && m.goneNoticed {
		notes = append(notes, noteBack())
	}
	if m.facts != nil {
		notes = append(notes, changes(*m.facts, st, "", m.loc)...)
	}
	m.facts = &st
	m.gone, m.down, m.goneSince, m.goneNoticed = false, "", time.Time{}, false
	return postNotices(m, notes)
}

// stateLine updates mode, trial and kept at once on a copy of the facts and notices the
// change with the line's reason. Before any facts there is nothing to update.
func stateLine(m Model, s api.State) (Model, []any) {
	m.lastReason = s.Reason
	if m.facts == nil {
		return m, nil
	}
	st := *m.facts
	st.Mode, st.Trial, st.Kept = s.Mode, s.Trial, s.Kept
	notes := changes(*m.facts, st, s.Reason, m.loc)
	m.facts = &st
	return postNotices(m, notes)
}

// goneTick notices a loss once when it has lasted 10 s (7.6).
func goneTick(m Model, now time.Time) (Model, []any) {
	if !m.gone || m.goneNoticed || m.goneSince.IsZero() || now.Sub(m.goneSince) < goneAfter {
		return m, nil
	}
	m.goneNoticed = true
	return postNotices(m, []Note{noteGone(m.down, m.goneSince, m.loc)})
}

// changes are the notices between two facts: the mode's, then kill switch and rules error.
// A reload that changes neither gives none (7.7).
func changes(old, cur api.Status, reason string, loc *time.Location) []Note {
	var notes []Note
	if n, ok := modeChange(old, cur, reason, loc); ok {
		notes = append(notes, n)
	}
	if old.Kill != cur.Kill {
		notes = append(notes, noteKill(cur.Kill))
	}
	switch {
	case cur.RulesError != "" && cur.RulesError != old.RulesError:
		notes = append(notes, noteRulesError(cur.RulesError))
	case cur.RulesError == "" && old.RulesError != "":
		notes = append(notes, noteRulesOK())
	}
	return notes
}

// modeChange is the one notice of a trial started, enforcement ended, kept or unkept.
func modeChange(old, cur api.Status, reason string, loc *time.Location) (Note, bool) {
	switch {
	case cur.Kept && !old.Kept:
		return noteKept(), true
	case old.Kept && !cur.Kept:
		return noteUnkept(reason, cur.Mode != "enforce"), true
	case cur.Trial != "" && old.Trial == "" && !cur.Kept: // a later deadline is an extension, not a start
		return noteTrial(cur.Trial, loc), true
	case old.Mode == "enforce" && cur.Mode != "enforce":
		return noteEnded(reason), true
	}
	return Note{}, false
}

// postNotices turns notices into post effects, each under a fresh token remembered as a notice's
// until its posted or postFailed (a question's token is askToken, questions.go). Without a
// notification service nothing is posted (8.6): the view still shows the state.
func postNotices(m Model, notes []Note) (Model, []any) {
	if len(notes) == 0 || !m.canNotify {
		return m, nil
	}
	posting := make(map[uint64]bool, len(m.posting)+len(notes))
	for k := range m.posting {
		posting[k] = true
	}
	fx := make([]any, 0, len(notes))
	for _, n := range notes {
		m.nextToken++
		posting[m.nextToken] = true
		fx = append(fx, post{Token: m.nextToken, Note: n})
	}
	m.posting = posting
	return m, fx
}

// noticePosted records a notice's note id until its Closed; a token that is no notice's
// is left for the questions (3.3).
func noticePosted(m Model, p posted) Model {
	if !m.posting[p.Token] {
		return m
	}
	m = noticeSettled(m, p.Token)
	notices := make(map[uint32]bool, len(m.notices)+1)
	for k := range m.notices {
		notices[k] = true
	}
	notices[p.NoteID] = true
	m.notices = notices
	return m
}

// noticeSettled forgets a notice's token once its post has an outcome.
func noticeSettled(m Model, token uint64) Model {
	if !m.posting[token] {
		return m
	}
	posting := make(map[uint64]bool, len(m.posting))
	for k := range m.posting {
		if k != token {
			posting[k] = true
		}
	}
	m.posting = posting
	return m
}

// closed forgets a closed notice. The open question's side of Closed is discard.go's closedNote.
func closed(m Model, id uint32) Model {
	if !m.notices[id] {
		return m
	}
	notices := make(map[uint32]bool, len(m.notices))
	for k := range m.notices {
		if k != id {
			notices[k] = true
		}
	}
	m.notices = notices
	return m
}
