// forget_test.go: Forget lifts one key's snooze (6.8) and nothing else: the next offer of that
// key asks at once, other snoozes, the open and the waiting questions stay, and the old value is
// unchanged. No goroutines and no t.Parallel in this package (rule_test.go swaps time.Local).
package ask

import (
	"reflect"
	"testing"
	"time"
)

func TestQueueForgetAsksAgain(t *testing.T) {
	q, _ := next(t, offered(1))
	q = q.Settle(Answered, t0)
	if got := q.Offer(qn(0), t0).Stats().Waiting; got != 0 {
		t.Fatalf("snoozed key waits: %d", got)
	}
	f := q.Forget(qn(0).Key)
	if got := f.Offer(qn(0), t0).Stats().Waiting; got != 1 {
		t.Fatalf("forgotten key does not ask again: waiting %d", got)
	}
	if got := q.Offer(qn(0), t0).Stats().Waiting; got != 0 {
		t.Fatal("Forget changed the old value")
	}
}

func TestQueueForgetLeavesOthers(t *testing.T) {
	q, _ := next(t, offered(1)) // qn(0) open
	q = q.Settle(Unanswered, t0)
	q = q.Offer(qn(1), t0).Offer(qn(2), t0).Offer(qn(3), t0)
	q, _ = next(t, q) // qn(1) open, 2 and 3 wait
	before := q
	for _, k := range []Key{qn(1).Key, qn(2).Key, qn(9).Key} { // open, waiting, unknown
		f := q.Forget(k)
		if !reflect.DeepEqual(f, before) {
			t.Fatalf("Forget(%v) changed the queue: %+v", k, f)
		}
	}
	f := q.Forget(qn(0).Key)
	if o, _ := f.Open(); o.Key != qn(1).Key || f.Stats() != q.Stats() {
		t.Fatalf("Forget touched open or waiting: %v %+v", o.Key, f.Stats())
	}
	if !reflect.DeepEqual(q, before) {
		t.Fatal("Forget changed the old value")
	}
}

// Forget lifts only the given key's snooze: another snoozed key stays snoozed.
func TestQueueForgetOnlyThatKey(t *testing.T) {
	q, _ := next(t, offered(2)) // qn(0) open, qn(1) waits
	q, _ = next(t, q.Settle(Answered, t0))
	q = q.Settle(Answered, t0.Add(time.Minute)) // both snoozed
	f := q.Forget(qn(0).Key)
	if got := f.Offer(qn(1), t0.Add(2*time.Minute)).Stats().Waiting; got != 0 {
		t.Fatalf("Forget lifted another key's snooze: waiting %d", got)
	}
	if got := f.Offer(qn(0), t0.Add(2*time.Minute)).Stats().Waiting; got != 1 {
		t.Fatalf("forgotten key does not ask again: waiting %d", got)
	}
}
