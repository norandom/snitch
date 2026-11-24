// run_test.go: Run's loop under recording delegates: the job owns the model. One hundred idle
// ticks show the view once (8.7); a Post's outcome reaches Update as a message before the next
// one, which these tests read off the retracted note ids and the posts between two events;
// Quit from the menu and Stop retract the open question and the notices, send nothing and end
// the job with nil (1.4); a pause click through the loop shows the checked row (3.4).
package tray

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// result is what one Post returns: the note's id, or the error whose failure the loop feeds
// back into Update as PostFailed.
type result struct {
	id  uint32
	err error
}

// rec are the recording delegates: the loop's goroutine is their only writer, so the slices
// are read only once the job ended, through the done channel's hand-off. shown carries each
// view as it is shown, so a test can wait for one without a clock of its own.
type rec struct {
	at       time.Time
	results  []result
	shown    chan View
	shows    []View
	notes    []Note
	retracts []uint32
	sends    []api.Request
}

// fx builds the delegates. The clock stands still on the package's fixed time, so only a
// message that changes the model can change the view; a Post without a scripted result is a
// harness mistake and panics the loop loudly.
func (r *rec) fx() Effects {
	return Effects{
		Show: func(v View) { r.shows = append(r.shows, v); r.shown <- v },
		Post: func(n Note) (uint32, error) {
			if len(r.results) == 0 {
				panic("run_test: the tray posted without a scripted result")
			}
			out := r.results[0]
			r.results = r.results[1:]
			r.notes = append(r.notes, n)
			return out.id, out.err
		},
		Retract: func(id uint32) { r.retracts = append(r.retracts, id) },
		Send:    func(_ uint64, req api.Request) { r.sends = append(r.sends, req) },
		Now:     func() time.Time { return r.at },
	}
}

// rt is one loop under test: the feeder channel, the recorder, the job's result.
type rt struct {
	t    *testing.T
	in   chan any
	rec  *rec
	done chan error
}

// startRun runs the tray as a writer in the tests' zone with one scripted result per Post the
// test expects; the context's cancel, cleaned up after the test, ends a wedged loop instead
// of leaking it.
func startRun(t *testing.T, results ...result) *rt {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	r := &rt{t: t, in: make(chan any),
		rec:  &rec{at: now, results: results, shown: make(chan View, 16)},
		done: make(chan error, 1)}
	job := Run(r.in, r.rec.fx(), NewModel(Options{Loc: zone, Writer: true}))
	go func() { r.done <- job(ctx) }()
	return r
}

// send hands one message to the loop and waits until the loop has taken it; the take is in
// order, and a message is always handled before the next one is taken.
func (r *rt) send(msg any) {
	r.t.Helper()
	select {
	case r.in <- msg:
	case <-time.After(10 * time.Second):
		r.t.Fatalf("the loop never took %T", msg)
	}
}

// end sends the ending message and waits for the job's result, which is nil when the tray
// quit cleanly.
func (r *rt) end(msg any) error {
	r.t.Helper()
	r.send(msg)
	select {
	case err := <-r.done:
		return err
	case <-time.After(10 * time.Second):
		r.t.Fatal("the loop never ended")
		return nil
	}
}

// view waits for the next shown view.
func (r *rt) view() View {
	r.t.Helper()
	select {
	case v := <-r.rec.shown:
		return v
	case <-time.After(10 * time.Second):
		r.t.Fatal("no view was shown")
		return View{}
	}
}

// want asserts, after the job ended, that the tray wrote nothing and retracted exactly the
// given note ids, the open question first (1.4, 6.12, 8.1).
func (r *rt) want(retracted []uint32) {
	r.t.Helper()
	if len(r.rec.sends) != 0 {
		r.t.Fatalf("sent %+v, want nothing", r.rec.sends)
	}
	if !reflect.DeepEqual(r.rec.retracts, retracted) {
		r.t.Fatalf("retracted %v, want %v", r.rec.retracts, retracted)
	}
}

// 8.7: one hundred ticks that change nothing show the view once; the loop idles between
// ticks instead of painting the tray again.
func TestIdleLoopShowsTheViewOnce(t *testing.T) {
	r := startRun(t)
	r.send(writerCaps)
	r.view() // the gone view: the only one
	for range 100 {
		r.send(Tick{})
	}
	if err := r.end(Stop{}); err != nil {
		t.Fatalf("job ended with %v", err)
	}
	r.want(nil)
	if len(r.rec.shows) != 1 {
		t.Fatalf("%d views shown, want 1", len(r.rec.shows))
	}
}

// openQuestionAndNotice runs a writer's tray with one question open (note 5) and one notice
// standing (note 71). The loop only knows these ids because it fed each Post's outcome back
// into Update as a message before the next one.
func openQuestionAndNotice(t *testing.T) *rt {
	t.Helper()
	r := startRun(t, result{id: 5}, result{id: 71})
	r.send(writerCaps)
	r.send(client.Up{})
	r.send(client.Facts{Status: running()})
	r.send(ev("deny-default"))
	st := running()
	st.Kill = true // the kill switch came on: one notice of it
	r.send(client.Facts{Status: st})
	return r
}

// 1.4: Quit from the menu retracts the open question and the notices, sends nothing and ends
// the job with nil.
func TestQuitRetractsQuestionAndNotices(t *testing.T) {
	r := openQuestionAndNotice(t)
	if err := r.end(MenuClick{Row: RowQuit}); err != nil {
		t.Fatalf("job ended with %v", err)
	}
	r.want([]uint32{5, 71})
}

// 1.4: Stop, a termination signal, ends the tray exactly like Quit from the menu.
func TestStopRetractsQuestionAndNotices(t *testing.T) {
	r := openQuestionAndNotice(t)
	if err := r.end(Stop{}); err != nil {
		t.Fatalf("job ended with %v", err)
	}
	r.want([]uint32{5, 71})
}

// 3.4: a pause click through the loop shows the switch checked and says so in the tooltip.
func TestRunLoopPauseClickChecksTheRow(t *testing.T) {
	r := startRun(t)
	r.send(writerCaps)
	r.view()
	r.send(client.Up{})
	r.send(client.Facts{Status: running()})
	if row(t, r.view().Menu, RowPause).Checked {
		t.Fatal("the pause switch starts checked")
	}
	r.send(MenuClick{Row: RowPause})
	paused := r.view()
	if rc := row(t, paused.Menu, RowPause); !rc.Check || !rc.Checked {
		t.Fatalf("pause row %+v", rc)
	}
	has(t, paused.Tooltip, "questions paused")
	if err := r.end(Stop{}); err != nil {
		t.Fatalf("job ended with %v", err)
	}
	r.want(nil)
}

// The loop feeds each Post's outcome back into Update before the next message: the question
// whose post failed settles, so the next waiting one is posted, and Stop later retracts its
// note. A loop that dropped the outcome would leave the failed one standing as open: the
// second event would wait unposted and Stop would retract nothing.
func TestRunLoopFeedsPostResultsBack(t *testing.T) {
	r := startRun(t, result{err: errors.New("no notification server")}, result{id: 5})
	r.send(writerCaps)
	r.send(client.Up{})
	r.send(client.Facts{Status: running()})
	r.send(to("1.1.1.1"))
	r.send(to("2.2.2.2"))
	if err := r.end(Stop{}); err != nil {
		t.Fatalf("job ended with %v", err)
	}
	r.want([]uint32{5})
	if len(r.rec.notes) != 2 {
		t.Fatalf("%d notes posted, want the failed one and the next question", len(r.rec.notes))
	}
}

// Run requires every delegate (the design's precondition on the tray's loop): a nil one is a
// wiring error the loop would hit at runtime, not an operator's error.
func TestRunRequiresEveryDelegate(t *testing.T) {
	show := func(View) {}
	post := func(Note) (uint32, error) { return 0, nil }
	retract := func(uint32) {}
	send := func(uint64, api.Request) {}
	clock := func() time.Time { return now }
	for _, c := range []struct {
		what string
		fx   Effects
	}{
		{"no Show", Effects{Post: post, Retract: retract, Send: send, Now: clock}},
		{"no Post", Effects{Show: show, Retract: retract, Send: send, Now: clock}},
		{"no Retract", Effects{Show: show, Post: post, Send: send, Now: clock}},
		{"no Send", Effects{Show: show, Post: post, Retract: retract, Now: clock}},
		{"no Now", Effects{Show: show, Post: post, Retract: retract, Send: send}},
	} {
		contracttest.Panics(t, contract.Precondition,
			func() { Run(make(chan any), c.fx, NewModel(Options{Loc: zone})) })
	}
}
