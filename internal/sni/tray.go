// tray.go: the composed tray of the session bus, the constructor of the design's
// service interface: it exports the StatusNotifierItem with its menu and the
// notification side, subscribes them to their signals, and hands the loop its
// delegates and the adapter's job. Show, Post and Retract are the bus-side
// delegates of tray.Effects — one Show paints the item and the menu from one
// value (3.6) — and the job runs the item's registration and the notification
// side's watch until the bus is lost.
//
// Fail-safe implications: none on egress. This is where the desktop's words are
// served, nothing more: no part of the tray can reach the kernel state. The job
// ends with ErrBusLost when the bus is gone, which ends the tray with exit 1 —
// and the bus daemon releases the names of a dead connection, so a crashed tray
// leaves no item behind and no stale claim in front of the next one.
package sni

import (
	"context"
	"fmt"
	"os"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
	"github.com/norandom/snitch/internal/tray"
)

// Tray is the session bus composed for the loop: the delegates of the design's
// service interface, all of them bounded, and the job that carries the bus's
// signals. It is one per Bus (the constructor's precondition) and it is never
// closed — the bus it sits on is.
type Tray struct {
	item  *item
	menu  *menu
	notes *notifier
}

// Tray exports the item and the menu, subscribes the notification side to the
// service's signals and returns the loop's delegates and the adapter's job; the
// loop's other messages — the menu's clicks, the presses and closes of the
// notes, the capabilities — arrive through the sink. The caller owns one try:
// a failed compose leaves the bus only good for Close, which releases the names
// the constructors already took.
func (b *Bus) Tray(sink func(any), log func(string)) (*Tray, error) {
	contract.Require(b != nil && b.conn != nil, "sni: Tray on a nil bus")
	contract.Require(!b.closed.Load(), "sni: Tray on a closed bus")
	contract.Require(sink != nil, "sni: Tray needs a sink for the loop's messages")
	contract.Require(log != nil, "sni: Tray needs a log delegate")
	b.trayOnce()
	it, err := b.item(log)
	if err != nil {
		return nil, err
	}
	m, err := b.menu(sink, log)
	if err != nil {
		return nil, err
	}
	notes, err := b.notify(sink, log)
	if err != nil {
		return nil, err
	}
	return &Tray{item: it, menu: m, notes: notes}, nil
}

// trayOnce is the design's precondition "Tray is called once per Bus" — one tray
// per connection — told from the bus itself: the item's conventional name is
// per-process and only this process's connection can own it, so an owner that is
// us means this bus already composed its tray (item.go declares the name, and the
// twice-test proves the probe stays honest). A probe that cannot answer stands
// aside: the constructors ahead report a dying bus anyway.
func (b *Bus) trayOnce() {
	owner, owned, err := b.owner(fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", os.Getpid()))
	if err == nil && owned && owner == b.conn.Names()[0] {
		contract.Require(false, "sni: Tray is once per bus, and this bus already has one")
	}
}

// Show paints a view on the item and the menu from the same value (3.6): the
// words the menu says can never disagree with the icon it hangs beside.
func (t *Tray) Show(v tray.View) {
	t.item.show(v)
	t.menu.show(v)
}

// Post puts one note on the desktop and answers the id the service gave it; the
// loop turns the answer into its Posted or PostFailed message itself.
func (t *Tray) Post(n tray.Note) (uint32, error) {
	return t.notes.post(n)
}

// Retract closes the note whose Posted message the loop kept.
func (t *Tray) Retract(id uint32) {
	t.notes.retract(id)
}

// Job is the adapter's job: one jobs.Run holds both watches — the item's
// registration on every new owner of the watcher (1.3), the notification side's
// capabilities, presses and closes (6.10, 8.6) — and the first to end ends the
// tray: a lost bus ends both with ErrBusLost, and the run's end cancels both.
func (t *Tray) Job() jobs.Job {
	return func(ctx context.Context) error {
		return jobs.Run(ctx, t.item.watch, t.notes.watch)
	}
}

// Remove takes the tray off the desktop's lists: the item releases its bus name,
// which makes every watcher drop it — the design's postcondition. The menu and
// the notification subscription end with the bus.
func (t *Tray) Remove() {
	t.item.remove()
}
