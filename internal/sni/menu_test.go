// menu_test.go: the flat dbusmenu object (requirements 3.4, 3.6) on the private
// bus of snitest: no t.Parallel (t.Setenv owns the bus address). The layout
// returns the rows of a shown view in order with their properties, a changed
// row set bumps the revision and announces LayoutUpdated, and clicks become
// tray.MenuClick only for enabled rows; the other reads and the contracts too.
package sni

import (
	"context"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/sni/snitest"
	"github.com/norandom/snitch/internal/tray"
)

// fullMenu is a running daemon's rows, one label carrying an underscore on purpose.
func fullMenu() tray.View {
	return tray.View{State: tray.Monitor, Title: "snitch: monitor", Menu: []tray.Row{
		{ID: tray.RowHeader, Label: "snitch: monitor"},
		{ID: tray.RowMode, Label: "Mode: monitor"},
		{ID: tray.RowRulesFile, Label: "Rules file: /etc/snitch/rules_1.yaml"},
		{ID: tray.RowSeparator, Separator: true},
		{ID: tray.RowPause, Label: "Pause questions", Enabled: true, Check: true, Checked: true},
		{ID: tray.RowQuit, Label: "Quit", Enabled: true},
	}}
}

// goneMenu is 3.3's reduced set with the pause switch unchecked.
func goneMenu() tray.View {
	return tray.View{State: tray.Gone, Title: "snitch: daemon not running", Menu: []tray.Row{
		{ID: tray.RowHeader, Label: "snitch: daemon not running"},
		{ID: tray.RowSeparator, Separator: true},
		{ID: tray.RowPause, Label: "Pause questions", Enabled: true, Check: true},
		{ID: tray.RowQuit, Label: "Quit", Enabled: true},
	}}
}

// servingMenu is the menu on the private bus plus a raw client of the item's
// bus name, subscribed to the menu's own signals.
func servingMenu(t *testing.T, sink func(any)) (*menu, *dbus.Conn, string, <-chan *dbus.Signal) {
	t.Helper()
	addr := privateBus(t)
	b := openBus(t)
	dest := newItem(t, b).name
	m, err := b.menu(sink, func(string) {})
	if err != nil {
		t.Fatalf("Menu: %v", err)
	}
	c := snitest.Conn(t, addr)
	ch := make(chan *dbus.Signal, 64)
	c.Signal(ch)
	if err := c.AddMatchSignal(dbus.WithMatchInterface(menuIface), dbus.WithMatchSender(b.conn.Names()[0])); err != nil {
		t.Fatalf("match the menu's signals: %v", err)
	}
	return m, c, dest, ch
}

// menuCall is one raw call at the menu, bounded like every call.
func menuCall(c *dbus.Conn, dest, method string, args ...any) *dbus.Call {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	return c.Object(dest, menuPath).CallWithContext(ctx, method, 0, args...)
}

// wantLayout fails unless the layout is the view's rows in order at the revision.
func wantLayout(t *testing.T, c *dbus.Conn, dest string, v tray.View, rev uint32) {
	t.Helper()
	var gotRev uint32
	var layout menuLayout
	if err := menuCall(c, dest, menuIface+".GetLayout", int32(0), int32(-1), []string{}).Store(&gotRev, &layout); err != nil {
		t.Fatalf("GetLayout: %v", err)
	}
	if gotRev != rev {
		t.Fatalf("layout revision %d, want %d", gotRev, rev)
	}
	rows := make([]menuLayout, 0, len(layout.Children))
	for _, ch := range layout.Children {
		var row menuLayout
		if err := ch.Store(&row); err != nil {
			t.Fatalf("layout child: %v", err)
		}
		rows = append(rows, row)
	}
	if len(rows) != len(v.Menu) {
		t.Fatalf("layout has %d rows, want %d", len(rows), len(v.Menu))
	}
	for i, row := range v.Menu {
		wantRowProps(t, row, rows[i])
	}
}

// wantRowProps fails unless the wire row says what the tray row says: the id
// and the design's property words per kind of row.
func wantRowProps(t *testing.T, row tray.Row, wire menuLayout) {
	t.Helper()
	if wire.ID != int32(row.ID) {
		t.Fatalf("row id %d, want %d", wire.ID, row.ID)
	}
	want := map[string]any{}
	if row.Separator {
		want["type"], want["visible"] = rowSeparator, true
	} else {
		want["label"], want["enabled"], want["visible"] = labelOnWire(row.Label), row.Enabled, true
		if row.Check {
			state := int32(0)
			if row.Checked {
				state = 1
			}
			want["toggle-type"], want["toggle-state"] = rowCheckmark, state
		}
	}
	for name, w := range want {
		if got := wire.Props[name].Value(); got != w {
			t.Errorf("row %d: %s = %v, want %v", row.ID, name, got, w)
		}
	}
}

// labelOnWire spells out the doubled form of the one test label with an
// underscore: the adapter's own escaper cannot vouch for itself.
func labelOnWire(label string) string {
	if label == "Rules file: /etc/snitch/rules_1.yaml" {
		return "Rules file: /etc/snitch/rules__1.yaml"
	}
	return label
}

// layoutUpdate waits for one LayoutUpdated and answers revision and parent.
func layoutUpdate(t *testing.T, ch <-chan *dbus.Signal) (uint32, int32) {
	t.Helper()
	for end := time.After(2 * time.Second); ; {
		select {
		case s := <-ch:
			if s.Name != layoutUpdated {
				continue
			}
			return s.Body[0].(uint32), s.Body[1].(int32)
		case <-end:
			t.Fatal("no LayoutUpdated within 2 s")
		}
	}
}

// wantClick waits for the sink's message and fails unless it is that row.
func wantClick(t *testing.T, clicks <-chan any, row tray.RowID) {
	t.Helper()
	select {
	case msg := <-clicks:
		if mc, ok := msg.(tray.MenuClick); !ok || mc.Row != row {
			t.Fatalf("sink message %v, want tray.MenuClick{Row: %d}", msg, row)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("no menu message for row %d", row)
	}
}

// noClick fails if any message shows up within a moment.
func noClick(t *testing.T, clicks <-chan any) {
	t.Helper()
	select {
	case msg := <-clicks:
		t.Fatalf("sink message %v, want nothing", msg)
	case <-time.After(150 * time.Millisecond):
	}
}

// The layout returns the rows of the shown view in order with their properties.
func TestMenuLayoutReturnsTheRowsOfTheViewInOrder(t *testing.T) {
	m, c, dest, _ := servingMenu(t, func(any) {})
	v := fullMenu()
	m.show(v)
	wantLayout(t, c, dest, v, 1) // the first shown view bumps the revision from zero
}

// A changed row set bumps the revision and announces LayoutUpdated with the
// root as parent; the same rows bump nothing (the pause state travels too).
func TestMenuChangedRowsBumpTheRevisionAndAnnounceTheLayout(t *testing.T) {
	m, c, dest, ch := servingMenu(t, func(any) {})
	m.show(fullMenu())
	rev, parent := layoutUpdate(t, ch)
	if parent != 0 {
		t.Fatalf("LayoutUpdated's parent = %d, want the root 0", parent)
	}
	m.show(goneMenu())
	bumped, _ := layoutUpdate(t, ch)
	if bumped != rev+1 {
		t.Fatalf("the changed row set bumped the revision to %d, want %d", bumped, rev+1)
	}
	wantLayout(t, c, dest, goneMenu(), bumped)
	m.show(goneMenu()) // the same rows again: the revision stands still
	wantLayout(t, c, dest, goneMenu(), bumped)
}

// A click on an enabled row becomes tray.MenuClick through the sink; a disabled
// row and an unknown id are silence, and EventGroup reports unknown ids.
func TestMenuClicksBecomeMenuClicksAndOthersNothing(t *testing.T) {
	clicks := make(chan any, 16)
	m, c, dest, _ := servingMenu(t, func(msg any) { clicks <- msg })
	m.show(fullMenu())
	click := func(id int32, name string) {
		if err := menuCall(c, dest, menuIface+".Event", id, name,
			dbus.MakeVariant(uint32(0)), uint32(0)).Err; err != nil {
			t.Fatalf("Event(%d, %q): %v", id, name, err)
		}
	}
	click(int32(tray.RowQuit), "clicked")
	wantClick(t, clicks, tray.RowQuit)
	click(int32(tray.RowHeader), "clicked") // a fact row is disabled
	noClick(t, clicks)
	click(42, "clicked") // no such row
	noClick(t, clicks)
	click(int32(tray.RowQuit), "hovered") // quiet events are not clicks
	noClick(t, clicks)
	events := []menuEvent{
		{ID: int32(tray.RowQuit), Name: "clicked", Data: dbus.MakeVariant(uint32(0))},
		{ID: 42, Name: "clicked", Data: dbus.MakeVariant(uint32(0))},
	}
	var errs []int32
	if err := menuCall(c, dest, menuIface+".EventGroup", events).Store(&errs); err != nil {
		t.Fatalf("EventGroup: %v", err)
	}
	wantClick(t, clicks, tray.RowQuit)
	if len(errs) != 1 || errs[0] != 42 {
		t.Fatalf("EventGroup's errors = %v, want [42]", errs)
	}
}

// The interface reads: the design's three properties answer Get, and
// AboutToShow says no relayout is needed in both forms.
func TestMenuAnswersItsInterfaceReads(t *testing.T) {
	m, c, dest, _ := servingMenu(t, func(any) {})
	m.show(fullMenu())
	var all map[string]dbus.Variant
	if err := menuCall(c, dest, propsIface+".GetAll", menuIface).Store(&all); err != nil {
		t.Fatalf("GetAll the menu's properties: %v", err)
	}
	if got := all["Version"].Value(); got != menuVersion {
		t.Errorf("Version = %v (uint32: %T), want %d", got, got, menuVersion)
	}
	if got := all["Status"].Value(); got != menuStatus {
		t.Errorf("Status = %v, want %q", got, menuStatus)
	}
	if got := all["TextDirection"].Value(); got != menuDirection {
		t.Errorf("TextDirection = %v, want %q", got, menuDirection)
	}
	var need bool
	if err := menuCall(c, dest, menuIface+".AboutToShow", int32(0)).Store(&need); err != nil {
		t.Fatalf("AboutToShow: %v", err)
	}
	if need {
		t.Error("AboutToShow says a relayout is needed, want false")
	}
	var upd, errs []int32
	if err := menuCall(c, dest, menuIface+".AboutToShowGroup", []int32{int32(tray.RowQuit)}).Store(&upd, &errs); err != nil {
		t.Fatalf("AboutToShowGroup: %v", err)
	}
	if len(upd) != 0 || len(errs) != 0 {
		t.Errorf("AboutToShowGroup said %v %v, want nothing of either", upd, errs)
	}
}

// The row reads, single and grouped: a name filter narrows the dict, unknown ids are skipped.
func TestMenuAnswersPropertyReadsSingleAndGroup(t *testing.T) {
	m, c, dest, _ := servingMenu(t, func(any) {})
	m.show(fullMenu())
	var rows []idProps
	if err := menuCall(c, dest, menuIface+".GetGroupProperties", []int32{int32(tray.RowMode), 42, int32(tray.RowPause)},
		[]string{"label", "toggle-state"}).Store(&rows); err != nil {
		t.Fatalf("GetGroupProperties: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("GetGroupProperties answered %d rows, want 2 with the unknown id skipped", len(rows))
	}
	if len(rows[1].Props) != 2 || rows[1].Props["toggle-state"].Value() != int32(1) {
		t.Errorf("the filtered dict = %v, want the label and the checked toggle-state", rows[1].Props)
	}
	var label dbus.Variant
	if err := menuCall(c, dest, menuIface+".GetProperty", int32(tray.RowQuit), "label").Store(&label); err != nil {
		t.Fatalf("GetProperty: %v", err)
	}
	if label.Value() != "Quit" {
		t.Errorf("GetProperty(Quit, label) = %v, want Quit", label.Value())
	}
}

// The constructor's preconditions are wiring bugs, each with a violation test.
func TestMenuConstructorContracts(t *testing.T) {
	privateBus(t)
	b := openBus(t)
	contracttest.Panics(t, contract.Precondition, func() { _, _ = (*Bus)(nil).menu(func(any) {}, func(string) {}) })
	contracttest.Panics(t, contract.Precondition, func() { _, _ = b.menu(nil, func(string) {}) })
	contracttest.Panics(t, contract.Precondition, func() { _, _ = b.menu(func(any) {}, nil) })
	b.Close()
	contracttest.Panics(t, contract.Precondition, func() { _, _ = b.menu(func(any) {}, func(string) {}) })
}
