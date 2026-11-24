// notify_test.go: the notification side of the composed tray (requirements 6.10,
// 8.6) on the private bus of snitest, against the fake notification server: no
// t.Parallel (t.Setenv owns the bus address). The five proofs of the task's
// done-when (allow-and-block keys, escaped path, silence for a foreign id,
// buttonless capabilities, no service not available), beside the tray's wiring,
// the contracts and the lost bus.
package sni

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/sni/snitest"
	"github.com/norandom/snitch/internal/tray"
)

// question is a note as the loop of 3.3 posts it: two answers, a minute, urgent.
func question(body string) tray.Note {
	return tray.Note{Summary: "snitch: a connection asks", Body: body,
		Actions: []tray.Action{{Key: "allow", Label: "Allow"}, {Key: "block", Label: "Block"}},
		Timeout: 60 * time.Second, Urgent: true}
}

// trayOn builds the composed tray on the private bus at addr and runs its job:
// the messages land in the inbox, the job's error in errc, both end with the test.
func trayOn(t *testing.T, addr string) (*Bus, *Tray, chan any, <-chan error) {
	t.Helper()
	b := openBus(t)
	inbox := make(chan any, 16)
	tr, err := b.Tray(func(msg any) { inbox <- msg }, func(string) {})
	if err != nil {
		t.Fatalf("Tray: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	errc := make(chan error, 1)
	go func() { errc <- tr.Job()(ctx) }()
	return b, tr, inbox, errc
}

// wantCapabilities waits for the message that says what the service can do (8.6).
func wantCapabilities(t *testing.T, in <-chan any, want tray.Capabilities) {
	t.Helper()
	select {
	case msg := <-in:
		if c, ok := msg.(tray.Capabilities); !ok || c != want {
			t.Fatalf("inbox message %v, want the capabilities %v", msg, want)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("no capabilities message, want %v", want)
	}
}

// wantPressed waits for the press of one of our notes.
func wantPressed(t *testing.T, in <-chan any, id uint32, key string) {
	t.Helper()
	select {
	case msg := <-in:
		if p, ok := msg.(tray.Pressed); !ok || p != (tray.Pressed{NoteID: id, Action: key}) {
			t.Fatalf("inbox message %v, want the press of %d as %s", msg, id, key)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("no press of the note %d", id)
	}
}

// wantClosed waits for the close of one of our notes.
func wantClosed(t *testing.T, in <-chan any, id uint32) {
	t.Helper()
	select {
	case msg := <-in:
		if c, ok := msg.(tray.Closed); !ok || c.NoteID != id {
			t.Fatalf("inbox message %v, want the close of %d", msg, id)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("no close of the note %d", id)
	}
}

// noMessage fails if anything arrives within a moment: the proof of a silence.
func noMessage(t *testing.T, in <-chan any) {
	t.Helper()
	select {
	case msg := <-in:
		t.Fatalf("inbox message %v, want nothing", msg)
	case <-time.After(150 * time.Millisecond):
	}
}

// The question on the wire: its answers as key and label pairs and nothing else,
// never the default key of the body click (6.10), with the design's words and hints.
func TestNotifyPostsAQuestionAsAllowAndBlockExactly(t *testing.T) {
	addr := privateBus(t)
	server := snitest.StartNotifications(t, addr, "body", "body-markup", "actions")
	_, tr, in, _ := trayOn(t, addr)
	wantCapabilities(t, in, tray.Capabilities{Available: true, Actions: true})
	if _, err := tr.Post(question("may curl connect?")); err != nil {
		t.Fatalf("Post: %v", err)
	}
	waitUntil(t, func() bool { return len(server.Calls()) == 1 }, "the server saw no note")
	call := server.Calls()[0]
	want := []string{"allow", "Allow", "block", "Block"}
	if !slices.Equal(call.Actions, want) {
		t.Fatalf("actions = %v, want %v", call.Actions, want)
	}
	if call.AppName != "snitch" || call.AppIcon != "security-medium" || call.ReplacesID != 0 {
		t.Fatalf("app fields = %q %q %d", call.AppName, call.AppIcon, call.ReplacesID)
	}
	if v, _ := call.Hints["urgency"].Value().(byte); v != 2 {
		t.Fatalf("urgency = %v, want 2 (critical)", v)
	}
	if v, _ := call.Hints["transient"].Value().(bool); !v {
		t.Fatalf("transient = %v, want true", v)
	}
	if v, _ := call.Hints["desktop-entry"].Value().(string); v != "snitch-tray" {
		t.Fatalf("desktop-entry = %v, want snitch-tray", v)
	}
	if call.TimeoutMs != 60000 {
		t.Fatalf("timeout = %d ms, want 60000", call.TimeoutMs)
	}
}

// A path's markup words must stand escaped in the body: the services parse the
// body as markup even where it looks like plain text (research.md).
func TestNotifyEscapesTheMarkUpWordsOfAPath(t *testing.T) {
	addr := privateBus(t)
	server := snitest.StartNotifications(t, addr, "body", "body-markup")
	_, tr, in, _ := trayOn(t, addr)
	wantCapabilities(t, in, tray.Capabilities{Available: true, Actions: false})
	if _, err := tr.Post(question("/opt/my<tool>& lib")); err != nil {
		t.Fatalf("Post: %v", err)
	}
	waitUntil(t, func() bool { return len(server.Calls()) == 1 }, "the server saw no note")
	if got := server.Calls()[0].Body; got != "/opt/my&lt;tool&gt;&amp; lib" {
		t.Fatalf("body = %q, want the escaped path", got)
	}
}

// 6.10's own guarantee in the adapter: a note wrongly offering the default key
// never puts it on the wire.
func TestNotifyNeverSendsADefaultKey(t *testing.T) {
	addr := privateBus(t)
	server := snitest.StartNotifications(t, addr, "body", "actions")
	_, tr, in, _ := trayOn(t, addr)
	wantCapabilities(t, in, tray.Capabilities{Available: true, Actions: true})
	doomed := question("")
	doomed.Actions = []tray.Action{{Key: "default", Label: "Open"},
		{Key: "allow", Label: "Allow"}, {Key: "block", Label: "Block"}}
	if _, err := tr.Post(doomed); err != nil {
		t.Fatalf("Post: %v", err)
	}
	waitUntil(t, func() bool { return len(server.Calls()) == 1 }, "the server saw no note")
	want := []string{"allow", "Allow", "block", "Block"}
	if got := server.Calls()[0].Actions; !slices.Equal(got, want) {
		t.Fatalf("actions = %v, want %v without the default", got, want)
	}
}

// The two signals become messages for our notes alone: a foreign id's press and
// close arrive first and prove the silence, because a forwarded one shows up first.
func TestNotifyIgnoresTheSignalsOfForeignIds(t *testing.T) {
	addr := privateBus(t)
	server := snitest.StartNotifications(t, addr, "body", "actions")
	_, tr, in, _ := trayOn(t, addr)
	wantCapabilities(t, in, tray.Capabilities{Available: true, Actions: true})
	id, err := tr.Post(question("may curl connect?"))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	server.Invoked(9999, "allow") // another application's note
	server.Closed(9999, 2)
	server.Invoked(id, "allow") // ours
	wantPressed(t, in, id, "allow")
	server.Closed(id, 3)
	wantClosed(t, in, id)
}

// Retract calls CloseNotification for the id (the design's wire words).
func TestNotifyRetractClosesTheNote(t *testing.T) {
	addr := privateBus(t)
	server := snitest.StartNotifications(t, addr, "body", "actions")
	_, tr, _, _ := trayOn(t, addr)
	id, err := tr.Post(question("may curl connect?"))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	tr.Retract(id)
	waitUntil(t, func() bool { return slices.Equal(server.Closes(), []uint32{id}) },
		"the server saw no retraction")
}

// No notification service at start: not available (8.6).
func TestCapabilitiesOfNoServiceSayNotAvailable(t *testing.T) {
	addr := privateBus(t)
	_, _, in, _ := trayOn(t, addr)
	wantCapabilities(t, in, tray.Capabilities{})
}

// A service that offers no buttons: available, actions off (8.6).
func TestCapabilitiesOfAButtonlessServiceKeepActionsOff(t *testing.T) {
	addr := privateBus(t)
	snitest.StartNotifications(t, addr, "body", "body-markup")
	_, _, in, _ := trayOn(t, addr)
	wantCapabilities(t, in, tray.Capabilities{Available: true, Actions: false})
}

// The capabilities arrive at start and on every change of the service's owner —
// and a new owner's ids start over, so our earlier note's id is foreign now.
func TestCapabilitiesOnEveryChangeOfOwner(t *testing.T) {
	addr := privateBus(t)
	_, tr, in, _ := trayOn(t, addr)
	wantCapabilities(t, in, tray.Capabilities{})
	first := snitest.StartNotifications(t, addr, "body", "actions")
	wantCapabilities(t, in, tray.Capabilities{Available: true, Actions: true})
	id, err := tr.Post(question("may curl connect?"))
	if err != nil {
		t.Fatalf("Post: %v", err)
	}
	first.Stop()
	wantCapabilities(t, in, tray.Capabilities{})
	second := snitest.StartNotifications(t, addr, "body")
	wantCapabilities(t, in, tray.Capabilities{Available: true, Actions: false})
	second.Invoked(id, "allow") // our id in a foreign epoch
	noMessage(t, in)
}

// The composed tray through the delegates of tray.Effects — the literal compiles
// only because they fit the fields: one show paints the title and the menu from
// one value (3.6), and remove releases the item's name (its postcondition).
func TestTrayThroughItsEffectsShowsAndRemoves(t *testing.T) {
	addr := privateBus(t)
	b, tr, _, _ := trayOn(t, addr)
	fx := tray.Effects{Show: tr.Show, Post: tr.Post, Retract: tr.Retract,
		Send: func(uint64, api.Request) {}, Now: time.Now}
	v := fullMenu()
	fx.Show(v)
	c := snitest.Conn(t, addr)
	wantLayout(t, c, tr.item.name, v, 1)
	var val dbus.Variant
	err := c.Object(tr.item.name, itemPath).
		Call(propsIface+".Get", 0, itemIface, "Title").Store(&val)
	if err != nil {
		t.Fatalf("read the item's title: %v", err)
	}
	if s, _ := val.Value().(string); s != v.Title {
		t.Fatalf("item title = %q, want %q", s, v.Title)
	}
	tr.Remove()
	if _, ok, err := b.owner(tr.item.name); ok || err != nil {
		t.Fatalf("after remove the item name still has an owner")
	}
}

// The adapter's job ends with ErrBusLost when the session bus is gone: the exit
// path of the tray (1.5: the desktop is where it lives).
func TestTrayJobEndsWithTheLostBus(t *testing.T) {
	addr := privateBus(t)
	b, _, _, errc := trayOn(t, addr)
	b.Close()
	select {
	case err := <-errc:
		if !errors.Is(err, ErrBusLost) {
			t.Fatalf("job = %v, want the lost-bus error", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the job did not end when the bus was lost")
	}
}

// Tray's input bugs are contract violations like item's and menu's (the service interface).
func TestTrayConstructorContracts(t *testing.T) {
	privateBus(t)
	b := openBus(t)
	var nilBus *Bus
	contracttest.Panics(t, contract.Precondition,
		func() { _, _ = nilBus.Tray(func(any) {}, func(string) {}) })
	contracttest.Panics(t, contract.Precondition,
		func() { _, _ = b.Tray(nil, func(string) {}) })
	contracttest.Panics(t, contract.Precondition,
		func() { _, _ = b.Tray(func(any) {}, nil) })
	b.Close()
	contracttest.Panics(t, contract.Precondition,
		func() { _, _ = b.Tray(func(any) {}, func(string) {}) })
}

// The design's precondition "Tray is called once per Bus": twice panics.
func TestTrayTwiceOnOneBusIsAContractViolation(t *testing.T) {
	addr := privateBus(t)
	b, _, _, _ := trayOn(t, addr)
	contracttest.Panics(t, contract.Precondition,
		func() { _, _ = b.Tray(func(any) {}, func(string) {}) })
}
