// notifications.go: a fake org.freedesktop.Notifications for the private test bus:
// the posting partner of the tray's notification adapter. It answers Notify by
// recording every argument and handing out ids, answers CloseNotification by
// recording the id, answers GetCapabilities with the list it was started with
// (so the adapter is provable against both a server with buttons and one
// without), and can emit the service's two signals on demand, ActionInvoked and
// NotificationClosed, for any id — which is how the adapter's filter for its own
// notes is tested. Stop ends its connection, which releases the name: to the
// tray the notification service is gone, exactly as when the desktop's server
// dies, and the NameOwnerChanged the tray re-asks on is the bus's own signal.
//
// Fail-safe implications: none on the host. The fake lives on a test's private
// dbus-daemon only; like the rest of snitest it imports godbus and nothing of
// snitch, so the adapter under test stays the only snitch code that speaks
// D-Bus.
package snitest

import (
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
)

// notificationsName is the well-known name of the notification service the fake
// claims on the test bus.
const notificationsName = "org.freedesktop.Notifications"

const (
	notificationsPath  = dbus.ObjectPath("/org/freedesktop/Notifications")
	notificationsIface = "org.freedesktop.Notifications"
)

// NotifyCall records one Notify call with every argument as the adapter sent it.
type NotifyCall struct {
	AppName    string
	ReplacesID uint32
	AppIcon    string
	Summary    string
	Body       string
	Actions    []string
	Hints      map[string]dbus.Variant
	TimeoutMs  int32
}

// Notifications is the fake notification server of one test bus: the calls it
// has seen, the ids it has handed out and closed, and the capabilities it
// answers with, all under the lock, because godbus answers each call in a
// goroutine of its own.
type Notifications struct {
	t    testing.TB
	addr string

	mu     sync.Mutex
	conn   *dbus.Conn
	seen   []NotifyCall
	closed []uint32
	caps   []string
	next   uint32
}

// StartNotifications claims the notification service's name on the private bus
// at addr and returns the fake answering GetCapabilities with caps. The name is
// claimed before the fake is handed over, so a tray that starts after it sees
// the owner at once; the connection dies with the test.
func StartNotifications(t testing.TB, addr string, caps ...string) *Notifications {
	t.Helper()
	n := &Notifications{t: t, addr: addr, caps: caps}
	n.start()
	t.Cleanup(n.Stop)
	return n
}

// start brings one server up: the three methods and the name claim.
func (n *Notifications) start() {
	conn, err := dbus.Connect(n.addr)
	if err != nil {
		n.t.Fatalf("snitest notifications: connect: %v", err)
	}
	n.mu.Lock()
	n.conn = conn
	n.mu.Unlock()
	table := map[string]any{
		"Notify":            n.notify,
		"CloseNotification": n.closeNotification,
		"GetCapabilities":   n.getCapabilities,
	}
	if err := conn.ExportMethodTable(table, notificationsPath, notificationsIface); err != nil {
		n.t.Fatalf("snitest notifications: export the methods: %v", err)
	}
	reply, err := conn.RequestName(notificationsName, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		n.t.Fatalf("snitest notifications: claim %s: %v %v", notificationsName, reply, err)
	}
}

// notify records the call and answers with the next id, counting from 1 like the
// real servers; the adapter turns that id into the note the loop keeps open.
func (n *Notifications) notify(appName string, replacesID uint32, appIcon, summary,
	body string, actions []string, hints map[string]dbus.Variant,
	timeout int32) (uint32, *dbus.Error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	// The hints map is the adapter's own fresh value, so the record keeps it as it was.
	n.seen = append(n.seen, NotifyCall{AppName: appName, ReplacesID: replacesID,
		AppIcon: appIcon, Summary: summary, Body: body,
		Actions: append([]string(nil), actions...), Hints: hints, TimeoutMs: timeout})
	n.next++
	return n.next, nil
}

// closeNotification records the retraction; what the server's own NotificationClosed
// signal does is the test's to emit, so the two can be told apart.
func (n *Notifications) closeNotification(id uint32) *dbus.Error {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.closed = append(n.closed, id)
	return nil
}

// getCapabilities answers the list the server was started with.
func (n *Notifications) getCapabilities() ([]string, *dbus.Error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.caps...), nil
}

// Invoked emits ActionInvoked for one note: a button pressed. Any id goes, so a
// foreign id's silence on the tray side is testable.
func (n *Notifications) Invoked(id uint32, key string) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conn == nil {
		n.t.Fatalf("snitest notifications: emit ActionInvoked after Stop")
	}
	_ = n.conn.Emit(notificationsPath, notificationsIface+".ActionInvoked", id, key)
}

// Closed emits NotificationClosed for one note, with the spec's reason: 1 expired,
// 2 dismissed, 3 closed by a call.
func (n *Notifications) Closed(id uint32, reason uint32) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conn == nil {
		n.t.Fatalf("snitest notifications: emit NotificationClosed after Stop")
	}
	_ = n.conn.Emit(notificationsPath, notificationsIface+".NotificationClosed", id, reason)
}

// Calls is every Notify call the server has seen, oldest first, as copies.
func (n *Notifications) Calls() []NotifyCall {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]NotifyCall(nil), n.seen...)
}

// Closes is every id CloseNotification has got, in order.
func (n *Notifications) Closes() []uint32 {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]uint32(nil), n.closed...)
}

// Stop ends the server's connection, which releases the name: to the tray the
// service is gone. Calling it twice is harmless; it sits in t.Cleanup.
func (n *Notifications) Stop() {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.conn != nil {
		_ = n.conn.Close()
		n.conn = nil
	}
}
