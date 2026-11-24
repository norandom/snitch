//go:build live

// live_test.go: the real session bus of the KDE host (chandali), run by hand
// only: go test -tags live ./internal/sni -run LiveItem — never in CI, kept
// compiling there by go vet -tags live. The test puts the item into the
// operator's tray for about two minutes so eyes can confirm what a bus
// assertion cannot: the icon going through the six states (research.md records
// what was seen). It registers with the real watcher, asserts the item in the
// watcher's registered-items list and then holds each state for 20 s.
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
	for _, name := range names {
		if name == it.name {
			t.Logf("the watcher lists the item: %s", name)
			return
		}
	}
	t.Fatalf("the watcher's registered items %v lack this item: %s", names, it.name)
}
