// run.go: Run, the tray's loop as one jobs.Job. It owns the model and the last shown view: it
// reads messages, updates, runs each effect through its delegate, feeds the result of a post
// back into Update as a message before it takes the next one, shows a view only when it
// differs from the last one shown (8.7) and ends with nil after the quit effect (1.4).
//
// Fail-safe implications: the loop never touches the kernel, so a delegate that blocks
// blocks the tray alone and every kernel decision stays as it was. One goroutine runs every
// message in order, and nothing here spins: an idle tray paints nothing, and when the input
// ends, so does the loop (8.7).
package tray

import (
	"context"
	"fmt"
	"slices"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
)

// Run is the tray's loop: messages from in are applied to m through Update, and each effect
// runs through the delegate it names. The job ends with nil after the quit effect, and with
// ctx's error when the run around the tray was cancelled.
func Run(in <-chan any, fx Effects, m Model) jobs.Job {
	contract.Require(fx.Show != nil && fx.Post != nil && fx.Retract != nil && fx.Send != nil && fx.Now != nil,
		"tray.Run requires every Effects delegate")
	return (&loop{in: in, fx: fx, m: m}).job
}

// loop is the loop's own state: the current model and the last view shown. The zero value of
// last stands for "nothing shown yet"; no rendered view is the zero one, so the first view
// always shows.
type loop struct {
	in   <-chan any
	fx   Effects
	m    Model
	last View
}

// job is the loop proper: one message at a time until the quit effect or the run's end. A
// closed input has no messages left in it and would spin, so it ends the loop cleanly.
func (l *loop) job(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case msg, ok := <-l.in:
			if !ok {
				return nil
			}
			if l.handle(msg) {
				return nil
			}
		}
	}
}

// handle applies one message and runs its effects; true says the quit effect ran and the
// tray is over.
func (l *loop) handle(msg any) bool {
	m, fx := Update(l.m, msg, l.fx.Now())
	l.m = m
	for _, e := range fx {
		if l.effect(e) {
			return true
		}
	}
	return false
}

// effect runs one effect through its delegate; true says it was the quit effect. The quit
// ends the message without the trailing show, which would paint an item that quit just
// removed.
func (l *loop) effect(e any) bool {
	switch v := e.(type) {
	case quit:
		return true
	case post:
		return l.post(v)
	case retract:
		l.fx.Retract(v.NoteID)
	case send:
		l.fx.Send(v.Token, v.Req)
	case show:
		l.show(v.View)
	default:
		contract.Require(false, fmt.Sprintf("tray.loop: unknown effect %T", e))
	}
	return false
}

// post runs one post effect and hands its outcome to Update as a message before the loop
// takes the next one from in, so the model knows every note's id and never misses a note of
// its own that was closed or pressed.
func (l *loop) post(p post) bool {
	id, err := l.fx.Post(p.Note)
	if err != nil {
		return l.handle(postFailed{Token: p.Token})
	}
	return l.handle(posted{Token: p.Token, NoteID: id})
}

// show shows a view only when it differs from the last one shown: an idle hour of ticks
// paints the tray not at all.
func (l *loop) show(v View) {
	if sameView(l.last, v) {
		return
	}
	l.last = v
	l.fx.Show(v)
}

// sameView reports whether two views show the same thing. A rendered view is never the zero
// one, so the loop's "nothing shown yet" cannot equal it.
func sameView(a, b View) bool {
	return a.State == b.State && a.Attention == b.Attention && a.Title == b.Title &&
		a.Tooltip == b.Tooltip && slices.Equal(a.Menu, b.Menu)
}
