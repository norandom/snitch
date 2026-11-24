//go:build live

// live_test.go: the real session bus of the KDE host (chandali), run by hand
// only: go test -tags live ./internal/sni -run LiveItem (and -run LiveMenu for
// the menu) — never in CI, kept compiling there by go vet -tags live. The
// tests put the item into the operator's tray for about two minutes so eyes
// can confirm what a bus assertion cannot: the icon going through the six
// states and, for the menu, clicks that open and read what the rows say
// (research.md records what was seen). It registers with the real watcher,
// asserts the item in the watcher's registered-items list and then holds each
// state for 20 s.
//
// Fail-safe implications: none beyond the item itself (display only). Nothing
// here touches the system bus or launches anything: Open is the NoAutoStartup
// path and skips when there is no session bus at all, and the cleanup releases
// the item, so the icon leaves the panel again.
package sni

import (
	"context"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/norandom/snitch/internal/tray"
)

// holdState is how long each icon stays for the operator to look at.
const holdState = 20 * time.Second

// TestLiveItemOnTheRealSessionBus runs the item against the watcher of the
// desktop this test runs in, in the order of the design's states, gone first so
// the ugly ones are not the last thing remembered.
func TestLiveItemOnTheRealSessionBus(t *testing.T) {
	b, err := Open()
	if err != nil {
		t.Skipf("no desktop session bus here, so nothing live to test: %v", err)
	}
	it, err := b.Item(func(line string) { t.Log("item: " + line) })
	if err != nil {
		b.Close()
		t.Fatalf("the item: %v", err)
	}
	t.Cleanup(func() {
		it.Remove() // the icon should leave the panel with this
		b.Close()
	})
	if _, owned, err := b.Owner(watcherName); err != nil {
		t.Skipf("the system tray's state is unknown, so nothing live to test: %v", err)
	} else if !owned {
		t.Skipf("no %s on this session: a Plasma session with a tray must be up", watcherName)
	}
	assertRegisteredWithTheWatcher(t, b, it)
	for _, s := range allStates {
		it.Show(view(s))
		t.Logf("look at the system tray now: %s, held for %s as of %s",
			s, holdState, time.Now().Format("15:04:05"))
		time.Sleep(holdState)
	}
	t.Log("the live run ends: the item is released and its icon disappears from the panel")
}

// assertRegisteredWithTheWatcher reads the watcher's RegisteredStatusNotifierItems
// property and fails unless this item is in it; bounded like every call.
func assertRegisteredWithTheWatcher(t *testing.T, b *Bus, it *Item) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	var v dbus.Variant
	err := b.conn.Object(watcherName, watcherPath).CallWithContext(ctx,
		"org.freedesktop.DBus.Properties.Get", 0, watcherName,
		"RegisteredStatusNotifierItems").Store(&v)
	if err != nil {
		t.Fatalf("read the watcher's registered items: %v", err)
	}
	names, _ := v.Value().([]string)
	entry := it.name + string(itemPath) // the real watcher lists each item as bus name plus object path, verified live
	for _, name := range names {
		if name == entry {
			t.Logf("the watcher lists the item: %s", name)
			return
		}
	}
	t.Fatalf("the watcher's registered items %v lack this item: %s", names, entry)
}

// liveMenuView is what a running daemon's menu looks like: the row texts of
// tray.Render, hand-copied because the live test has no daemon to render from.
// The rules file row carries an underscore on purpose so the operator can see
// it doubled on the desktop, not swallowed as a mnemonic marker.
func liveMenuView() tray.View {
	return tray.View{State: tray.Monitor, Title: "snitch: monitor", Menu: []tray.Row{
		{ID: tray.RowHeader, Label: "snitch: monitor"},
		{ID: tray.RowMode, Label: "Mode: monitor"},
		{ID: tray.RowTrial, Label: "Trial: no trial"},
		{ID: tray.RowKept, Label: "Enforce kept: yes"},
		{ID: tray.RowKill, Label: "Kill switch: clear"},
		{ID: tray.RowLearning, Label: "Learning: off"},
		{ID: tray.RowCounts, Label: "Loaded: 3 programs, 12 rules"},
		{ID: tray.RowRulesFile, Label: "Rules file: /etc/snitch/rules_1.yaml"},
		{ID: tray.RowDNS, Label: "DNS tap: on, 2 names, 2 compiled"},
		{ID: tray.RowDaemon, Label: "snitchd 0.9.0, started 2026-11-24 09:00"},
		{ID: tray.RowRole, Label: "Role: operator, can answer questions"},
		{ID: tray.RowSeparator, Separator: true},
		{ID: tray.RowPause, Label: "Pause questions", Enabled: true, Check: true, Checked: true},
		{ID: tray.RowQuit, Label: "Quit", Enabled: true},
	}}
}

// TestLiveMenuOnTheRealSessionBus runs the item with its menu against the
// desktop's watcher and holds a row set up for the operator to click through:
// the menu must open on a left click and on a right click, the rows must be
// readable, and a click on Pause or Quit prints here (the sink does nothing to
// the test — this run checks the menu is real; the loop that obeys the clicks
// is 4.4's).
func TestLiveMenuOnTheRealSessionBus(t *testing.T) {
	b, err := Open()
	if err != nil {
		t.Skipf("no desktop session bus here, so nothing live to test: %v", err)
	}
	it, err := b.Item(func(line string) { t.Log("item: " + line) })
	if err != nil {
		b.Close()
		t.Fatalf("the item: %v", err)
	}
	m, err := b.Menu(func(msg any) {
		if c, ok := msg.(tray.MenuClick); ok {
			t.Logf("menu click: row %d", c.Row)
		}
	}, func(line string) { t.Log("menu: " + line) })
	if err != nil {
		it.Remove()
		b.Close()
		t.Fatalf("the menu: %v", err)
	}
	t.Cleanup(func() {
		it.Remove()
		b.Close()
	})
	if _, owned, err := b.Owner(watcherName); err != nil {
		t.Skipf("the system tray's state is unknown, so nothing live to test: %v", err)
	} else if !owned {
		t.Skipf("no %s on this session: a Plasma session with a tray must be up", watcherName)
	}
	assertRegisteredWithTheWatcher(t, b, it) // the watcher lists name/path (4.2's live fact)
	v := liveMenuView()
	it.Show(v) // the icon, from the same single view: it is what gets clicked
	m.Show(v)  // the rows, from the same single view
	for range 3 {
		t.Logf("open the menu now: LEFT-click the icon, then RIGHT-click it; the rows must "+
			"read (the rules file row shows rules_1.yaml with its underscore); clicks on "+
			"Pause questions and Quit print here; held %s as of %s",
			holdState, time.Now().Format("15:04:05"))
		time.Sleep(holdState)
	}
	t.Log("the live menu run ends: the item is released and its icon leaves the panel")
}
