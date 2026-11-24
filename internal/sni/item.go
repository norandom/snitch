// item.go: the StatusNotifierItem object and its registration with the watcher
// (requirements 1.1, 1.3, 2.3). The item owns the conventional bus name
// org.kde.StatusNotifierItem-<pid>-1, answers the interface of the design with
// inert methods, and shows a view by setting the properties and announcing each
// one that changed — once through the standard PropertiesChanged, with the
// values, and once with the StatusNotifierItem signal the hosts listen for.
//
// Fail-safe implications: none on egress. The item only ever appears on the
// user's session bus; a watcher that is absent, dies or never answers leaves the
// tray running, and the item re-registers on the next owner of the watcher name.
// No signal of the item, no property and no method can reach the kernel state.
package sni

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/tray"
)

// The StatusNotifierItem words of the design, as the hosts on this desktop
// speak them (research.md, "StatusNotifierItem on this host").
const (
	itemIface = "org.kde.StatusNotifierItem"
	itemPath  = dbus.ObjectPath("/StatusNotifierItem")
	menuPath  = dbus.ObjectPath("/StatusNotifierItem/menu")

	watcherName = "org.kde.StatusNotifierWatcher"
	watcherPath = dbus.ObjectPath("/StatusNotifierWatcher")

	propsIface           = "org.freedesktop.DBus.Properties"
	pcChanged            = propsIface + ".PropertiesChanged"
	statusActive         = "Active"
	statusNeedsAttention = "NeedsAttention"
)

// ErrBusLost is what the item's signal handling ends with when this process's
// connection to the session bus is gone: the adapter's job turns it into the
// tray's exit, and the bus daemon releases the names of a dead connection
// anyway, which drops the item from every host.
var ErrBusLost = errors.New("the session bus was lost")

// item is the tray's StatusNotifierItem on the session bus. show pictures a
// view, watch keeps the registration alive, remove ends the item.
type item struct {
	bus     *Bus
	log     func(string)
	props   *prop.Properties
	owners  <-chan string // the watcher name's owner changes
	name    string        // org.kde.StatusNotifierItem-<pid>-1
	view    tray.View     // the last shown view; the diff base of the signals
	shown   bool          // whether a view was shown at all yet
	removed atomic.Bool
}

// item puts the item object on the bus and owns its conventional name, then
// registers with the watcher when there is one at start; the log delegate is
// where registration trouble is spoken, because a failed call is retried on the
// next change and nothing polls.
func (b *Bus) item(log func(string)) (*item, error) {
	contract.Require(b != nil && b.conn != nil, "sni: item on a nil bus")
	contract.Require(!b.closed.Load(), "sni: item on a closed bus")
	contract.Require(log != nil, "sni: item needs a log delegate")
	it := &item{bus: b, log: log, name: fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", os.Getpid())}
	if err := it.own(); err != nil {
		return nil, err
	}
	if err := it.export(); err != nil {
		return nil, err
	}
	owners, err := b.watchOwner(watcherName)
	if err != nil {
		return nil, err
	}
	it.owners = owners
	if _, owned, err := b.owner(watcherName); err != nil {
		it.log("no system tray yet (its state is unknown: " + err.Error() + ")")
	} else if owned {
		it.registerAtStart()
	} else {
		it.log("no system tray yet; the item appears when one does")
	}
	return it, nil
}

// registerAtStart is the one registration of a fresh item; the outcome is spoken
// either way — the success is the Monitoring line "registration with the watcher" —
// and a failure is not fatal: the next watcher change retries it.
func (it *item) registerAtStart() {
	if err := it.register(); err != nil {
		it.log("tray registration failed, retried when the system tray changes: " + err.Error())
	} else {
		it.log("tray item registered with the system tray as " + it.name)
	}
}

// own takes the conventional item bus name without queueing: only this tray
// process may own it, and the watcher drops items whose name is not owned.
func (it *item) own() error {
	var reply uint32
	err := it.bus.call("org.freedesktop.DBus.RequestName", it.name,
		uint32(dbus.NameFlagDoNotQueue)).Store(&reply)
	if err != nil {
		return fmt.Errorf("claim the item bus name %s: %w", it.name, err)
	}
	switch r := dbus.RequestNameReply(reply); r {
	case dbus.RequestNameReplyPrimaryOwner, dbus.RequestNameReplyAlreadyOwner:
		return nil
	default:
		return fmt.Errorf("claim the item bus name %s: reply %v", it.name, r)
	}
}

// export puts the item on the bus: the properties through prop (EmitFalse — the
// hosts listen for the item's own signals, and a failing auto-emit would panic
// prop.SetMust), and the four inert methods beside them on the same object.
func (it *item) export() error {
	p, err := prop.Export(it.bus.conn, itemPath, prop.Map{itemIface: {
		"Category":            {Value: "SystemServices", Emit: prop.EmitFalse},
		"Id":                  {Value: "snitch", Emit: prop.EmitFalse},
		"Title":               {Value: "", Emit: prop.EmitFalse},
		"Status":              {Value: statusActive, Emit: prop.EmitFalse},
		"IconName":            {Value: "", Emit: prop.EmitFalse},
		"IconPixmap":          {Value: []Pixmap{}, Emit: prop.EmitFalse},
		"AttentionIconPixmap": {Value: []Pixmap{}, Emit: prop.EmitFalse},
		"ToolTip":             {Value: sniToolTip{}, Emit: prop.EmitFalse},
		"ItemIsMenu":          {Value: true, Emit: prop.EmitFalse},
		"Menu":                {Value: menuPath, Emit: prop.EmitFalse},
	}})
	if err != nil {
		return fmt.Errorf("export the item properties: %w", err)
	}
	it.props = p
	if err := it.bus.conn.Export(itemMethods{}, itemPath, itemIface); err != nil {
		return fmt.Errorf("export the item methods: %w", err)
	}
	return nil
}

// sniToolTip is the ToolTip wire struct, sa(iiay)ss: an icon by name or by
// pixmap, a bold title and a gray description.
type sniToolTip struct {
	IconName    string
	IconPixmaps []Pixmap
	Title       string
	Description string
}

// itemMethods are the callable side of the item: they exist because the hosts
// call them (a left click opens the menu already, ItemIsMenu) and do nothing.
type itemMethods struct{}

func (itemMethods) Activate(x, y int32) *dbus.Error            { return nil }
func (itemMethods) SecondaryActivate(x, y int32) *dbus.Error   { return nil }
func (itemMethods) ContextMenu(x, y int32) *dbus.Error         { return nil }
func (itemMethods) Scroll(delta int32, dir string) *dbus.Error { return nil }

// show pictures the view: every property gets the view's value, and each one
// that changed is announced (3.6 diffs views before showing, so a repeated view
// announces nothing).
func (it *item) show(v tray.View) {
	status := itemStatus(v.Attention)
	pix := Pixmaps(v.State)
	tip := sniToolTip{IconPixmaps: pix, Title: v.Title, Description: v.Tooltip}
	it.props.SetMust(itemIface, "Title", v.Title)
	it.props.SetMust(itemIface, "Status", status)
	it.props.SetMust(itemIface, "IconPixmap", pix)
	it.props.SetMust(itemIface, "AttentionIconPixmap", pix)
	it.props.SetMust(itemIface, "ToolTip", tip)
	it.emit(v, status, pix, tip)
	it.view, it.shown = v, true
}

// itemStatus is the status of a view: attention asks for it (2.3).
func itemStatus(attention bool) string {
	if attention {
		return statusNeedsAttention
	}
	return statusActive
}

// emit announces what differs from the last shown view: one PropertiesChanged
// with the new values, and the StatusNotifierItem signal per changed property —
// the signals the hosts actually listen for.
func (it *item) emit(v tray.View, status string, pix []Pixmap, tip sniToolTip) {
	c := it.diff(v)
	if c.none() {
		return
	}
	changed := map[string]dbus.Variant{}
	if c.icon {
		changed["IconPixmap"] = dbus.MakeVariant(pix)
		changed["AttentionIconPixmap"] = dbus.MakeVariant(pix)
		it.signal(itemIface + ".NewIcon")
		it.signal(itemIface + ".NewAttentionIcon")
	}
	if c.attn {
		changed["Status"] = dbus.MakeVariant(status)
		it.signal(itemIface+".NewStatus", status)
	}
	if c.title {
		changed["Title"] = dbus.MakeVariant(v.Title)
		it.signal(itemIface + ".NewTitle")
	}
	if c.tip {
		changed["ToolTip"] = dbus.MakeVariant(tip)
		it.signal(itemIface + ".NewToolTip")
	}
	it.signal(pcChanged, itemIface, changed, []string{})
}

// itemDiff says which of the shown properties changed against the last view.
type itemDiff struct{ icon, attn, title, tip bool }

func (d itemDiff) none() bool { return !d.icon && !d.attn && !d.title && !d.tip }

// diff compares the view with the last shown one. The tooltip carries the icon
// and the title, so it changes with them.
func (it *item) diff(v tray.View) (d itemDiff) {
	first := !it.shown
	d.icon = first || it.view.State != v.State
	d.attn = first || it.view.Attention != v.Attention
	d.title = first || it.view.Title != v.Title
	text := first || it.view.Tooltip != v.Tooltip
	d.tip = d.icon || d.title || text
	return d
}

// signal emits one interface signal of the item. A signal asks nothing of the
// bus (it is fire and forget), but a dead bus is spoken, not hidden.
func (it *item) signal(name string, body ...any) {
	if err := it.bus.conn.Emit(itemPath, name, body...); err != nil {
		it.log("tray item: emit " + name + ": " + err.Error())
	}
}

// watch is the item's signal handling: it registers with every new owner of the
// watcher name (and only then: nothing polls), skips the watcher's releases, and
// ends with ErrBusLost when this connection loses the bus — the adapter's job of
// 4.4 turns that into the tray's exit.
func (it *item) watch(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case owner, ok := <-it.owners:
			if !ok {
				return ErrBusLost
			}
			if owner == "" || it.removed.Load() {
				continue
			}
			if err := it.register(); err != nil {
				it.log("tray registration failed, retried when the system tray changes: " + err.Error())
			} else { // the re-registration after a watcher restart is the same news (Monitoring)
				it.log("tray item registered with the system tray as " + it.name)
			}
		}
	}
}

// register tells the watcher about this item by its bus name; the call is bounded
// like every call, and its failure is data for the log, not the end of the tray.
func (it *item) register() error {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	return it.bus.conn.Object(watcherName, watcherPath).CallWithContext(ctx,
		watcherName+".RegisterStatusNotifierItem", 0, it.name).Err
}

// remove ends the item: it releases the item bus name, which makes every watcher
// drop it (a crash does the same, for the bus daemon releases the names of a
// dead connection). Safe on a nil item and twice: it sits on several exit paths.
func (it *item) remove() {
	if it == nil || it.removed.Swap(true) {
		return
	}
	var reply uint32
	err := it.bus.call("org.freedesktop.DBus.ReleaseName", it.name).Store(&reply)
	if err != nil {
		it.log("releasing the item bus name: " + err.Error())
		return
	}
	if r := dbus.ReleaseNameReply(reply); r != dbus.ReleaseNameReplyReleased {
		it.log(fmt.Sprintf("releasing the item bus name: reply %v", r))
	}
}
