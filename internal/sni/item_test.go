// item_test.go: the tray item and its registration (requirements 1.1, 1.3, 2.3)
// on a private dbus-daemon with the fake watcher recording the calls: no
// t.Parallel (t.Setenv owns the bus address). Registration at start and after
// restarts, attention signals, values, the property set, Remove, the lost bus.
package sni

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/sni/snitest"
	"github.com/norandom/snitch/internal/tray"
)

// allSix are the signals one full change of the view announces.
var allSix = []string{itemIface + ".NewIcon", itemIface + ".NewAttentionIcon",
	itemIface + ".NewStatus", itemIface + ".NewTitle", itemIface + ".NewToolTip", pcChanged}

// view is what the tray renders for one state.
func view(s tray.State) tray.View {
	return tray.View{State: s, Attention: s.Attention(), Title: "snitch: " + s.String(),
		Tooltip: "the tooltip of " + s.String()}
}

// showItem is the item on the private bus with a subscriber at its signals. The
// ownership signals of the bus reach that channel too (godbus posts every
// matched message to every channel), so the collectors pick by name.
func showItem(t *testing.T) (*Item, <-chan *dbus.Signal) {
	addr := privateBus(t)
	b := openBus(t)
	it := newItem(t, b)
	conn := snitest.Conn(t, addr)
	ch := make(chan *dbus.Signal, 64)
	conn.Signal(ch)
	for _, iface := range [2]string{propsIface, itemIface} {
		if err := conn.AddMatchSignal(dbus.WithMatchInterface(iface),
			dbus.WithMatchSender(b.conn.Names()[0])); err != nil {
			t.Fatalf("match %s: %v", iface, err)
		}
	}
	return it, ch
}

// newItem builds the item with a quiet log delegate.
func newItem(t *testing.T, b *Bus) *Item {
	t.Helper()
	it, err := b.Item(func(string) {})
	if err != nil {
		t.Fatalf("Item: %v", err)
	}
	return it
}

// watchItem runs the item's signal handling, cancelled at cleanup.
func watchItem(t *testing.T, it *Item) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errc := make(chan error, 1)
	go func() { errc <- it.Watch(ctx) }()
	return errc
}

// itemSignal reports whether the signal is one of the item's announcements.
func itemSignal(s *dbus.Signal) bool {
	return s.Name == pcChanged || strings.HasPrefix(s.Name, itemIface+".")
}

// collectSignals waits for want of the item's own signals within 2 s.
func collectSignals(t *testing.T, ch <-chan *dbus.Signal, want int) []dbus.Signal {
	t.Helper()
	var out []dbus.Signal
	for end := time.After(2 * time.Second); len(out) < want; {
		select {
		case s := <-ch:
			if itemSignal(s) {
				out = append(out, *s)
			}
		case <-end:
			t.Fatalf("wanted %d of the item's signals, saw %d", want, len(out))
		}
	}
	return out
}

// wantTheSix fails unless six collected signals are allSix, each exactly once.
func wantTheSix(t *testing.T, ch <-chan *dbus.Signal) []dbus.Signal {
	t.Helper()
	sigs := collectSignals(t, ch, 6)
	counts := map[string]int{}
	for _, s := range sigs {
		counts[s.Name]++
	}
	for _, w := range allSix {
		if counts[w] != 1 {
			t.Errorf("signal %s seen %d times, want once", w, counts[w])
		}
	}
	return sigs
}

// bodyOf returns the body of the one signal with that name.
func bodyOf(t *testing.T, sigs []dbus.Signal, name string) []any {
	t.Helper()
	for _, s := range sigs {
		if s.Name == name {
			return s.Body
		}
	}
	t.Fatalf("no %s among the signals", name)
	return nil
}

// wantPixmaps fails unless the variant holds the state's own pixmaps (contents,
// not just that something was emitted).
func wantPixmaps(t *testing.T, v dbus.Variant, s tray.State, what string) {
	t.Helper()
	var got []Pixmap
	if err := v.Store(&got); err != nil {
		t.Fatalf("%s: %v", what, err)
	}
	want := Pixmaps(s)
	if len(got) != len(want) {
		t.Fatalf("%s: %d pixmaps, want %d", what, len(got), len(want))
	}
	for i := range want {
		if got[i].W != want[i].W || got[i].H != want[i].H || !bytes.Equal(got[i].ARGB, want[i].ARGB) {
			t.Errorf("%s: pixmap %d is not the %s drawing", what, i, s)
		}
	}
}

// waitUntil polls cond under the 2 s call bound, then fails with msg.
func waitUntil(t *testing.T, cond func() bool, msg string) {
	t.Helper()
	for end := time.Now().Add(2 * time.Second); !cond(); time.Sleep(5 * time.Millisecond) {
		if time.Now().After(end) {
			t.Fatal(msg)
		}
	}
}

// Registers once at start (1.1) and again on every new owner of the watcher
// name; a failed call is retried on the next change (1.3).
func TestItemRegistersAndRegistersAgainAfterRestarts(t *testing.T) {
	addr := privateBus(t)
	w := snitest.StartWatcher(t, addr)
	it := newItem(t, openBus(t))
	if got := w.Registrations(); len(got) != 1 || got[0] != it.name {
		t.Fatalf("registrations = %v, want exactly one with %s", got, it.name)
	}
	watchItem(t, it)
	w.Fail = true // the next registration call is answered with an error
	w.Restart()
	waitUntil(t, func() bool { return len(w.Registrations()) == 2 && len(w.Items()) == 0 },
		"the item did not try again or the failed call registered")
	w.Fail = false
	w.Restart()
	waitUntil(t, func() bool { return len(w.Registrations()) == 3 }, "no registration after the restart")
	if items := w.Items(); len(items) != 1 || items[0] != it.name {
		t.Fatalf("registered items = %v, want [%s]", items, it.name)
	}
}

// Show announces each changed property with the item signals; a repeated view
// announces nothing; an attention view puts NeedsAttention on NewStatus (2.3).
func TestItemShowSignalsWhatChanged(t *testing.T) {
	it, ch := showItem(t)
	it.Show(view(tray.Monitor))
	wantTheSix(t, ch)
	it.Show(view(tray.Monitor)) // nothing changes: no signal at all
	select {
	case s := <-ch:
		if itemSignal(s) {
			t.Fatalf("a repeated view signalled %s", s.Name)
		}
	case <-time.After(150 * time.Millisecond):
	}
	it.Show(view(tray.Gone))
	sigs := wantTheSix(t, ch)
	if s, _ := bodyOf(t, sigs, itemIface+".NewStatus")[0].(string); s != statusNeedsAttention {
		t.Fatalf("NewStatus = %q, want %q", s, statusNeedsAttention)
	}
}

// The PropertiesChanged of a view carries the changed values themselves, so
// the bus asserts contents, not just that something was emitted.
func TestItemShowCarriesTheChangedPropertyValues(t *testing.T) {
	it, ch := showItem(t)
	gone := view(tray.Gone)
	it.Show(view(tray.Monitor))
	collectSignals(t, ch, 6)
	it.Show(gone)
	pc := bodyOf(t, collectSignals(t, ch, 6), pcChanged)
	m, ok := pc[1].(map[string]dbus.Variant)
	if !ok || len(m) != 5 {
		t.Fatalf("the changed properties = %v (shape ok: %v), want the five mutable ones", m, ok)
	}
	if m["Status"].Value() != statusNeedsAttention || m["Title"].Value() != gone.Title {
		t.Errorf("changed Status/Title = %v/%v, want %q/%q", m["Status"].Value(), m["Title"].Value(), statusNeedsAttention, gone.Title)
	}
	wantPixmaps(t, m["IconPixmap"], tray.Gone, "the icon pixmap")
	wantPixmaps(t, m["AttentionIconPixmap"], tray.Gone, "the attention icon pixmap")
	var tip sniToolTip
	if err := m["ToolTip"].Store(&tip); err != nil || tip.Title != gone.Title || tip.Description != gone.Tooltip ||
		tip.IconName != "" || !bytes.Equal(tip.IconPixmaps[0].ARGB, Pixmaps(tray.Gone)[0].ARGB) {
		t.Fatalf("changed ToolTip = %+v, want the view's title and tooltip, no icon name, the state's pixmap", tip)
	}
}

// What a host reads through org.freedesktop.DBus.Properties is the design's
// property set with the view in it, and the inert methods answer nothing.
func TestItemAnswersThePropertiesOfTheView(t *testing.T) {
	privateBus(t)
	b := openBus(t)
	it := newItem(t, b)
	gone := view(tray.Gone)
	it.Show(gone)
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var all map[string]dbus.Variant
	if err := b.conn.Object(it.name, itemPath).CallWithContext(ctx,
		"org.freedesktop.DBus.Properties.GetAll", 0, itemIface).Store(&all); err != nil {
		t.Fatalf("GetAll: %v", err)
	}
	want := map[string]any{"Category": "SystemServices", "Id": "snitch", "Title": gone.Title,
		"Status": statusNeedsAttention, "IconName": "", "ItemIsMenu": true, "Menu": menuPath}
	for name, w := range want {
		if all[name].Value() != w {
			t.Errorf("%s = %v, want %v", name, all[name].Value(), w)
		}
	}
	wantPixmaps(t, all["IconPixmap"], tray.Gone, "the icon pixmap")
	wantPixmaps(t, all["AttentionIconPixmap"], tray.Gone, "the attention pixmap")
	if _, ok := all["ToolTip"]; !ok {
		t.Error("the item lacks the property ToolTip")
	}
	if act := b.conn.Object(it.name, itemPath).CallWithContext(ctx,
		itemIface+".Activate", 0, int32(0), int32(0)); act.Err != nil {
		t.Errorf("Activate, which must do nothing: %v", act.Err)
	}
}

// Remove releases the item's bus name: the bus owns none of it and the
// watcher, which tracks lost names as kded6 does, keeps no registration of it
// (the postcondition for 1.4).
func TestItemRemoveReleasesTheNameAndTheWatcherDropsIt(t *testing.T) {
	addr := privateBus(t)
	w := snitest.StartWatcher(t, addr)
	b := openBus(t)
	it := newItem(t, b)
	waitUntil(t, func() bool { return len(w.Registrations()) == 1 }, "no registration at start")
	if _, ok, err := b.Owner(it.name); !ok || err != nil {
		t.Fatalf("the item name is not owned: %v %v", ok, err)
	}
	it.Remove()
	it.Remove() // twice is harmless: remove sits in defers and on several exit paths
	if _, ok, err := b.Owner(it.name); ok || err != nil {
		t.Fatalf("after Remove the name still has an owner: %v %v", ok, err)
	}
	waitUntil(t, func() bool { return len(w.Items()) == 0 }, "the watcher kept the item")
}

// Losing the bus ends the item's signal handling with an error; the adapter's
// job of 4.4 turns it into the tray's exit.
func TestItemWatchReportsTheLostBusAsAnError(t *testing.T) {
	privateBus(t)
	b := openBus(t)
	errc := watchItem(t, newItem(t, b))
	b.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, ErrBusLost) {
			t.Fatalf("Watch = %v, want the lost-bus error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Watch did not end when the bus was lost")
	}
}

// The constructor's preconditions are wiring bugs like Claim's, each with a
// violation test here.
func TestItemConstructorContracts(t *testing.T) {
	privateBus(t)
	b := openBus(t)
	var nilBus *Bus
	contracttest.Panics(t, contract.Precondition, func() { _, _ = nilBus.Item(func(string) {}) })
	contracttest.Panics(t, contract.Precondition, func() { _, _ = b.Item(nil) })
	b.Close()
	contracttest.Panics(t, contract.Precondition, func() { _, _ = b.Item(func(string) {}) })
	contracttest.Panics(t, contract.Precondition, func() { _, _ = b.WatchOwner(InstanceName) })
}
