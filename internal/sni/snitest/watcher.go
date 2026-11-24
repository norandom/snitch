// watcher.go: a fake org.kde.StatusNotifierWatcher for the private test bus: the
// registration partner of the tray item. It answers RegisterStatusNotifierItem by
// recording the call, keeps the RegisteredStatusNotifierItems property current,
// drops the items whose bus name was released (the real kded6 watcher does the
// same), and can restart: the old connection closes, the name drops, and a new
// connection claims it — the NameOwnerChanged the item re-registers on. Fail
// makes the next registration call answer with an error, to test the tray's
// retry on the watcher's next change.
//
// Fail-safe implications: none on the host. The fake lives on a test's private
// dbus-daemon only; like the rest of snitest it imports godbus and nothing of
// snitch, so the adapter under test stays the only snitch code that speaks D-Bus.
package snitest

import (
	"sort"
	"sync"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"
)

// watcherName and the object below are what the real kded6 watcher owns on the
// session bus; the mirror here answers on the same names.
const (
	watcherName  = "org.kde.StatusNotifierWatcher"
	watcherPath  = dbus.ObjectPath("/StatusNotifierWatcher")
	watcherIface = "org.kde.StatusNotifierWatcher"
)

// Watcher is the fake watcher of one test bus. It keeps its recorded calls and
// its properties across its own restarts, but loses its registered items with
// every restart, as kded6 does.
type Watcher struct {
	t    testing.TB
	addr string

	mu    sync.Mutex
	conn  *dbus.Conn
	props *prop.Properties
	seen  []string        // the service name of every register call, in order
	items map[string]bool // the items whose names are up right now
	Fail  bool            // answer the next register call with an error
}

// StartWatcher claims the watcher name on the private bus at addr and returns
// the fake; the connection dies with the test.
func StartWatcher(t testing.TB, addr string) *Watcher {
	t.Helper()
	w := &Watcher{t: t, addr: addr}
	w.start()
	t.Cleanup(w.stop)
	return w
}

// start brings one watcher connection up: the properties, the register method,
// the watch on released item names and the name claim. A restart calls it again
// on a fresh connection.
func (w *Watcher) start() {
	conn, err := dbus.Connect(w.addr)
	if err != nil {
		w.t.Fatalf("snitest watcher: connect: %v", err)
	}
	w.mu.Lock()
	w.conn = conn
	w.items = map[string]bool{}
	w.mu.Unlock()
	p, err := prop.Export(conn, watcherPath, prop.Map{watcherIface: {
		"RegisteredStatusNotifierItems":  {Value: []string{}, Emit: prop.EmitFalse},
		"IsStatusNotifierHostRegistered": {Value: true, Emit: prop.EmitFalse},
		"ProtocolVersion":                {Value: int32(0), Emit: prop.EmitFalse},
	}})
	if err != nil {
		w.t.Fatalf("snitest watcher: export properties: %v", err)
	}
	w.mu.Lock()
	w.props = p
	w.mu.Unlock()
	table := map[string]any{"RegisterStatusNotifierItem": w.register}
	if err := conn.ExportMethodTable(table, watcherPath, watcherIface); err != nil {
		w.t.Fatalf("snitest watcher: export the register method: %v", err)
	}
	ch := make(chan *dbus.Signal, 16)
	conn.Signal(ch)
	// No arg filter: every ownership change is worth one check, the bus is small.
	if err := conn.AddMatchSignal(dbus.WithMatchInterface("org.freedesktop.DBus"),
		dbus.WithMatchMember("NameOwnerChanged")); err != nil {
		w.t.Fatalf("snitest watcher: watch name owners: %v", err)
	}
	go w.watchReleased(ch)
	reply, err := conn.RequestName(watcherName, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		w.t.Fatalf("snitest watcher: claim %s: %v %v", watcherName, reply, err)
	}
}

// register is the watcher's one method: a call in its own goroutine, hence the
// lock; a failed call is recorded as seen but adds no item.
func (w *Watcher) register(service string) *dbus.Error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.seen = append(w.seen, service)
	if w.Fail {
		return dbus.NewError("org.kde.StatusNotifierWatcher.Error.TestFailure", nil)
	}
	w.items[service] = true
	w.props.SetMust(watcherIface, "RegisteredStatusNotifierItems", w.itemList())
	return nil
}

// watchReleased forgets the items whose bus name was released; it ends when the
// watcher's connection closes and the channel with it.
func (w *Watcher) watchReleased(ch <-chan *dbus.Signal) {
	for sig := range ch {
		if sig.Name != "org.freedesktop.DBus.NameOwnerChanged" || len(sig.Body) < 3 {
			continue
		}
		if owner, _ := sig.Body[2].(string); owner == "" {
			w.forget(sig.Body[0])
		}
	}
}

// forget drops one released name from the registered items.
func (w *Watcher) forget(name any) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if s, ok := name.(string); ok {
		delete(w.items, s)
	}
	w.props.SetMust(watcherIface, "RegisteredStatusNotifierItems", w.itemList())
}

// Restart simulates the host's watcher dying and coming back: the old connection
// closes (the name drops and the registrations are lost) and a fresh one claims
// the same name again.
func (w *Watcher) Restart() {
	w.mu.Lock()
	old := w.conn
	w.mu.Unlock()
	_ = old.Close()
	w.start()
}

// Registrations is the service name of every register call the fake has seen, in
// order, including the ones it answered with an error and across restarts.
func (w *Watcher) Registrations() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.seen...)
}

// Items is what the watcher's RegisteredStatusNotifierItems property says now.
func (w *Watcher) Items() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.itemList()
}

// stop ends the current connection; the test bus dies with it in any case.
func (w *Watcher) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.conn != nil {
		_ = w.conn.Close()
	}
}

// itemList is the sorted property value; a copy, so the caller can hold on to it.
func (w *Watcher) itemList() []string {
	out := make([]string, 0, len(w.items))
	for name := range w.items {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
