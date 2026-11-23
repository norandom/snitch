// queue.go: the waiting list of questions, an immutable value. At most one question is open,
// at most MaxWaiting wait, the oldest first (5.5); an offer for a key that is open, waiting or
// snoozed is ignored, and a settled question snoozes its key for Snooze unless the answer
// failed to reach the daemon (5.4). The counts of waiting and dropped questions are what the
// open notification shows (5.6).
//
// Every method returns a new Queue and builds new slices and maps for what it changes, so an
// older value the caller still holds never sees a later change (copy on write).
//
// Fail-safe implications: none on the kernel's decisions. The queue only orders and limits
// questions; it writes nothing, and a dropped or flushed question writes no rule. The limits
// keep a burst of unknown connections from flooding the desktop with notifications.
package ask

import (
	"slices"
	"time"

	"github.com/norandom/snitch/internal/contract"
)

const (
	// Snooze is how long a settled question's key does not ask again (5.4).
	Snooze = 10 * time.Minute
	// MaxWaiting is how many questions may wait behind the open one (5.5).
	MaxWaiting = 32
)

// Outcome is how the open question ended. Answered and Unanswered snooze its key; Failed (the
// answer did not reach the daemon) does not, so the connection may ask again at once.
type Outcome int

const (
	Answered Outcome = iota
	Unanswered
	Failed
)

// Stats are the counts the open notification shows. Dropped counts the questions dropped
// since the waiting list was last empty: every operation that leaves no question waiting
// resets it to 0.
type Stats struct{ Waiting, Dropped int }

// Queue is the waiting list. The zero value is empty and ready to use.
type Queue struct {
	open    Question
	hasOpen bool
	waiting []Question
	snoozed map[Key]time.Time // key -> the instant it may ask again
	dropped int
}

// Offer adds a question at the end of the waiting list unless its key is open, waiting or
// snoozed at now. Snooze entries that have expired at now are removed. When the list is full,
// the oldest waiting question is dropped and counted.
func (q Queue) Offer(x Question, now time.Time) Queue {
	q.snoozed = unexpired(q.snoozed, now)
	if q.holds(x.Key) {
		return q.checked()
	}
	rest := q.waiting
	if len(rest) == MaxWaiting {
		rest = rest[1:]
		q.dropped++
	}
	q.waiting = append(slices.Clip(slices.Clone(rest)), x)
	return q.checked()
}

// Next opens the oldest waiting question. It returns false, and the queue unchanged, when a
// question is already open or none waits.
func (q Queue) Next() (Queue, Question, bool) {
	if q.hasOpen || len(q.waiting) == 0 {
		return q, Question{}, false
	}
	q.open, q.hasOpen = q.waiting[0], true
	q.waiting = slices.Clone(q.waiting[1:])
	return q.checked(), q.open, true
}

// Open returns the open question, false when none is open.
func (q Queue) Open() (Question, bool) {
	return q.open, q.hasOpen
}

// Settle closes the open question. Answered and Unanswered snooze its key until now+Snooze;
// Failed does not. Settling without an open question is a programming error of the tray.
func (q Queue) Settle(o Outcome, now time.Time) Queue {
	contract.Require(q.hasOpen, "ask.Queue.Settle: no open question")
	contract.Require(o >= Answered && o <= Failed, "ask.Queue.Settle: unknown outcome")
	if o != Failed {
		snoozed := make(map[Key]time.Time, len(q.snoozed)+1)
		for k, t := range q.snoozed {
			snoozed[k] = t
		}
		snoozed[q.open.Key] = now.Add(Snooze)
		q.snoozed = snoozed
	}
	q.open, q.hasOpen = Question{}, false
	return q.checked()
}

// Flush drops the waiting questions for which keep returns false (their reason is gone, 5.8).
// A flushed question is neither snoozed nor counted as dropped.
func (q Queue) Flush(keep func(Question) bool) Queue {
	q.waiting = slices.DeleteFunc(slices.Clone(q.waiting), func(x Question) bool { return !keep(x) })
	return q.checked()
}

// Stats returns the counts of waiting and dropped questions.
func (q Queue) Stats() Stats {
	return Stats{Waiting: len(q.waiting), Dropped: q.dropped}
}

// holds reports whether a key is open, waiting or snoozed (snooze entries are already pruned).
func (q Queue) holds(k Key) bool {
	if q.hasOpen && q.open.Key == k {
		return true
	}
	if _, ok := q.snoozed[k]; ok {
		return true
	}
	return slices.ContainsFunc(q.waiting, func(x Question) bool { return x.Key == k })
}

// unexpired returns the snooze entries still in force at now: a new map when any expired, the
// same map otherwise (it is never written after it is built).
func unexpired(snoozed map[Key]time.Time, now time.Time) map[Key]time.Time {
	expired := false
	for _, t := range snoozed {
		if !now.Before(t) {
			expired = true
			break
		}
	}
	if !expired {
		return snoozed
	}
	kept := make(map[Key]time.Time, len(snoozed))
	for k, t := range snoozed {
		if now.Before(t) {
			kept[k] = t
		}
	}
	return kept
}

// checked resets the dropped count when nothing waits and asserts the invariants: at most
// MaxWaiting wait, and a key is in at most one of open, waiting, snoozed (and once in waiting).
func (q Queue) checked() Queue {
	if len(q.waiting) == 0 {
		q.dropped = 0
	}
	contract.Invariant(len(q.waiting) <= MaxWaiting, "ask.Queue: more than MaxWaiting waiting")
	seen := make(map[Key]bool, len(q.waiting)+1)
	if q.hasOpen {
		seen[q.open.Key] = true
	}
	for _, x := range q.waiting {
		contract.Invariant(!seen[x.Key], "ask.Queue: a key both open and waiting, or waiting twice")
		seen[x.Key] = true
	}
	for k := range q.snoozed {
		contract.Invariant(!seen[k], "ask.Queue: a snoozed key open or waiting")
	}
	return q
}
