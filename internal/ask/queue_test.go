// queue_test.go: the waiting list's rules with a fake time: one open, oldest first, dedupe by
// key, the 10 min snooze (not at 9:59), Failed without a snooze, the 33rd dropping the oldest,
// Flush without a snooze or a count, the dropped reset, old values unchanged after operations on
// new ones, the invariant after every step of a seeded random script, and the contracts.
// No goroutines and no t.Parallel in this package (rule_test.go swaps time.Local).
package ask

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

var t0 = time.Date(2026, 11, 23, 9, 0, 0, 0, time.UTC)

func qn(i int) Question {
	return Question{Key: Key{Who: "firefox", Dest: fmt.Sprint("host", i), Proto: "tcp", Port: 443}}
}

// offered offers qn(0) .. qn(n-1) at t0 to an empty queue.
func offered(n int) Queue {
	var q Queue
	for i := range n {
		q = q.Offer(qn(i), t0)
	}
	return q
}

// next opens the next question and fails the test when none opens.
func next(t *testing.T, q Queue) (Queue, Question) {
	t.Helper()
	q, x, ok := q.Next()
	if !ok {
		t.Fatal("Next: nothing opened")
	}
	return q, x
}

func TestQueueOneOpenOldestFirst(t *testing.T) {
	q := offered(3)
	if _, ok := q.Open(); ok {
		t.Fatal("open before Next")
	}
	q, x := next(t, q)
	if x.Key != qn(0).Key {
		t.Fatalf("opened %v, want the oldest", x.Key)
	}
	if o, ok := q.Open(); !ok || o.Key != x.Key {
		t.Fatalf("Open %v %v", o.Key, ok)
	}
	if _, _, ok := q.Next(); ok {
		t.Fatal("a second question opened while one is open")
	}
	q, x = next(t, q.Settle(Answered, t0))
	if x.Key != qn(1).Key || q.Stats() != (Stats{Waiting: 1}) {
		t.Fatalf("opened %v, stats %+v", x.Key, q.Stats())
	}
	if _, _, ok := (Queue{}).Next(); ok {
		t.Fatal("Next on an empty queue opened something")
	}
}

func TestQueueOfferIgnoresOpenAndWaiting(t *testing.T) {
	q := offered(1).Offer(qn(0), t0)
	if q.Stats().Waiting != 1 {
		t.Fatalf("a waiting key was offered twice: %+v", q.Stats())
	}
	q, _ = next(t, q)
	if q = q.Offer(qn(0), t0); q.Stats().Waiting != 0 {
		t.Fatalf("the open key was offered again: %+v", q.Stats())
	}
}

func TestQueueSnoozeTenMinutes(t *testing.T) {
	for _, o := range []Outcome{Answered, Unanswered} {
		q, _ := next(t, offered(1))
		q = q.Settle(o, t0)
		if got := q.Offer(qn(0), t0.Add(snooze-time.Second)); got.Stats().Waiting != 0 {
			t.Fatalf("outcome %d: asked again at 9:59", o)
		}
		if got := q.Offer(qn(0), t0.Add(snooze)); got.Stats().Waiting != 1 {
			t.Fatalf("outcome %d: did not ask again after 10 min", o)
		}
		if got := q.Offer(qn(1), t0); got.Stats().Waiting != 1 {
			t.Fatalf("outcome %d: another key was snoozed", o)
		}
	}
}

func TestQueueFailedNoSnooze(t *testing.T) {
	q, _ := next(t, offered(1))
	q = q.Settle(Failed, t0)
	if len(q.snoozed) != 0 || q.Offer(qn(0), t0).Stats().Waiting != 1 {
		t.Fatalf("Failed snoozed the key: %v", q.snoozed)
	}
}

func TestQueueExpiredSnoozeRemovedOnOffer(t *testing.T) {
	q, _ := next(t, offered(2))
	q = q.Settle(Answered, t0)
	q, _ = next(t, q)
	q = q.Settle(Answered, t0.Add(5*time.Minute))
	q = q.Offer(qn(9), t0.Add(snooze))
	if _, ok := q.snoozed[qn(0).Key]; ok || len(q.snoozed) != 1 {
		t.Fatalf("snoozed after the first expired: %v", q.snoozed)
	}
}

func TestQueueDropsOldest(t *testing.T) {
	q := offered(MaxWaiting)
	if q.Stats() != (Stats{Waiting: MaxWaiting}) {
		t.Fatalf("32 offered: %+v", q.Stats())
	}
	q = q.Offer(qn(MaxWaiting), t0)
	if q.Stats() != (Stats{Waiting: MaxWaiting, Dropped: 1}) {
		t.Fatalf("33rd offered: %+v", q.Stats())
	}
	q = q.Offer(qn(MaxWaiting+1), t0)
	if q.Stats() != (Stats{Waiting: MaxWaiting, Dropped: 2}) {
		t.Fatalf("34th offered: %+v", q.Stats())
	}
	if _, x := next(t, q); x.Key != qn(2).Key {
		t.Fatalf("opened %v, want host2 (host0 and host1 dropped)", x.Key)
	}
	if q.Offer(qn(0), t0).Stats().Dropped != 3 {
		t.Fatal("a dropped key is snoozed or ignored")
	}
}

func TestQueueDroppedResetsWhenNothingWaits(t *testing.T) {
	q := offered(MaxWaiting + 1)
	for i := range MaxWaiting {
		q, _ = next(t, q)
		q = q.Settle(Failed, t0)
		want := Stats{Waiting: MaxWaiting - 1 - i, Dropped: 1}
		if want.Waiting == 0 {
			want.Dropped = 0
		}
		if q.Stats() != want {
			t.Fatalf("after %d: %+v, want %+v", i+1, q.Stats(), want)
		}
	}
	q = offered(MaxWaiting + 1).Flush(func(Question) bool { return false })
	if q.Stats() != (Stats{}) {
		t.Fatalf("after flushing all: %+v", q.Stats())
	}
}

func TestQueueFlush(t *testing.T) {
	q := offered(MaxWaiting + 1)
	even := func(x Question) bool { return x.Key.Dest[len(x.Key.Dest)-1]%2 == 0 }
	q = q.Flush(even)
	if q.Stats() != (Stats{Waiting: 16, Dropped: 1}) {
		t.Fatalf("after flushing odd: %+v", q.Stats())
	}
	if len(q.snoozed) != 0 || q.Offer(qn(1), t0).Stats().Waiting != 17 {
		t.Fatal("a flushed key is snoozed")
	}
	for range 16 {
		var x Question
		q, x = next(t, q)
		if !even(x) {
			t.Fatalf("flushed %v still waits", x.Key)
		}
		q = q.Settle(Failed, t0)
	}
}

// clone is a deep copy of a queue's state, to compare an old value after later operations.
func clone(q Queue) Queue {
	c := q
	c.waiting = append([]Question(nil), q.waiting...)
	if q.snoozed != nil {
		c.snoozed = make(map[Key]time.Time, len(q.snoozed))
		for k, v := range q.snoozed {
			c.snoozed[k] = v
		}
	}
	return c
}

func TestQueueOldValuesUnchanged(t *testing.T) {
	q, _ := next(t, offered(3))
	q = q.Settle(Answered, t0).Offer(qn(7), t0)
	// Spare capacity, so an Offer that appends without copying would share the backing array.
	q.waiting = append(make([]Question, 0, 8), q.waiting...)
	if cap(q.waiting) <= len(q.waiting) {
		t.Fatalf("no spare capacity: len %d cap %d", len(q.waiting), cap(q.waiting))
	}
	old := clone(q)
	a := q.Offer(qn(8), t0)
	b := q.Offer(qn(9), t0)
	if a.waiting[len(a.waiting)-1].Key != qn(8).Key || b.waiting[len(b.waiting)-1].Key != qn(9).Key {
		t.Fatal("a sibling value sees another's offer")
	}
	a, _ = next(t, a)
	_ = a.Settle(Answered, t0).Flush(func(Question) bool { return false }).Offer(qn(0), t0.Add(snooze))
	_ = b.Offer(qn(0), t0.Add(snooze))
	_ = q.Flush(func(x Question) bool { return x.Key != qn(1).Key })
	_, _, _ = q.Next()
	_ = q.Offer(qn(0), t0.Add(snooze))
	if !reflect.DeepEqual(q, old) {
		t.Fatalf("old value changed:\n%+v\nwant\n%+v", q, old)
	}
	full := offered(MaxWaiting)
	oldFull := clone(full)
	full.Offer(qn(99), t0).Flush(func(Question) bool { return false })
	if !reflect.DeepEqual(full, oldFull) {
		t.Fatal("a full queue changed by a drop on its successor")
	}
}

// consistent checks the invariants from the outside: a key in at most one of open, waiting,
// snoozed and at most once waiting; at most MaxWaiting wait; no dropped count when none waits.
func consistent(t *testing.T, step int, q Queue) {
	t.Helper()
	where := map[Key]string{}
	put := func(k Key, place string) {
		if was, ok := where[k]; ok {
			t.Fatalf("step %d: %v both %s and %s", step, k, was, place)
		}
		where[k] = place
	}
	if x, ok := q.Open(); ok {
		put(x.Key, "open")
	}
	for _, x := range q.waiting {
		put(x.Key, "waiting")
	}
	for k := range q.snoozed {
		put(k, "snoozed")
	}
	s := q.Stats()
	if s.Waiting > MaxWaiting || s.Waiting != len(q.waiting) || (s.Waiting == 0 && s.Dropped != 0) {
		t.Fatalf("step %d: stats %+v", step, s)
	}
}

// step applies one random operation at now.
func step(r *rand.Rand, q Queue, now time.Time) Queue {
	switch r.IntN(8) {
	case 0, 1, 2, 3, 4:
		return q.Offer(qn(r.IntN(200)), now)
	case 5, 6:
		if _, ok := q.Open(); ok {
			return q.Settle(Outcome(r.IntN(3)), now)
		}
		q, _, _ = q.Next()
		return q
	}
	m := 2 + r.IntN(5)
	return q.Flush(func(x Question) bool { return len(x.Key.Dest)%m != 0 || r.IntN(2) == 0 })
}

func TestQueueRandomScriptInvariant(t *testing.T) {
	r := rand.New(rand.NewPCG(2026, 11))
	var q Queue
	now := t0
	drops := 0
	for i := range 5000 {
		now = now.Add(time.Duration(r.IntN(90)) * time.Second)
		before := q.Stats().Dropped
		q = step(r, q, now)
		consistent(t, i, q)
		if q.Stats().Dropped > before {
			drops++
		}
	}
	if drops == 0 {
		t.Fatal("the script never dropped a question; it does not reach the limit")
	}
}

// Contracts: settling with nothing open, or with an unknown outcome, is a programming error of
// the tray; a queue that breaks the invariant is caught by checked.
func TestQueueViolations(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { (Queue{}).Settle(Answered, t0) })
	q, _ := next(t, offered(1))
	contracttest.Panics(t, contract.Precondition, func() { q.Settle(Outcome(7), t0) })
	twice := Queue{waiting: []Question{qn(1), qn(1)}}
	contracttest.Panics(t, contract.InvariantKind, func() { twice.checked() })
	both := Queue{waiting: []Question{qn(1)}, snoozed: map[Key]time.Time{qn(1).Key: t0}}
	contracttest.Panics(t, contract.InvariantKind, func() { both.checked() })
	over := Queue{waiting: make([]Question, MaxWaiting+1)}
	for i := range over.waiting {
		over.waiting[i] = qn(i)
	}
	contracttest.Panics(t, contract.InvariantKind, func() { over.checked() })
}
