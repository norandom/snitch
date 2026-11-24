// menu.go: the flat com.canonical.dbusmenu object of the tray item
// (requirements 3.4, 3.6), on the path the item's Menu property already
// advertises. The host reads the rows (GetLayout, GetGroupProperties,
// GetProperty), says it is about to show (AboutToShow, AboutToShowGroup) and
// reports what was activated (Event, EventGroup); a changed row set bumps a
// revision and announces it with LayoutUpdated, and the read path is one
// picture with the write path: the last shown view, in order.
//
// Fail-safe implications: none on egress. The menu shows text the daemon
// already printed, and the only interactive rows are the pause switch and Quit
// of the tray process itself; a click on a disabled row or an unknown id is
// silence, so a wrongly rendered menu cannot fake an action.
package sni

import (
	"fmt"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/godbus/dbus/v5"
	"github.com/godbus/dbus/v5/prop"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/tray"
)

// The dbusmenu words of the design, as the two shipped implementations of the
// protocol on this host speak them (research.md, "4.3 additions").
const (
	menuIface      = "com.canonical.dbusmenu"
	layoutUpdated  = menuIface + ".LayoutUpdated"
	invalidArgs    = "org.freedesktop.DBus.Error.InvalidArgs"
	menuClickEvent = "clicked"   // the one event that is an activation
	menuStatus     = "normal"    // the interface property Status
	menuDirection  = "ltr"       // the interface property TextDirection
	menuVersion    = uint32(3)   // the interface property Version
	rowType        = "type"      // the property that says a row is a separator
	rowSeparator   = "separator" // the value of type on a separator row
	rowCheckmark   = "checkmark" // the value of toggle-type on a check row
)

// menu is the dbusmenu object of the tray: the last shown view's rows with the
// revision they were set at. The loop writes; the hosts read.
type menu struct {
	bus   *Bus
	sink  func(any) // where a click arrives as tray.MenuClick
	log   func(string)
	props *prop.Properties
	state atomic.Pointer[menuState]
}

// menuState is one immutable picture of show's last write; an atomic pointer
// to it is the whole sharing between the loop's writes and the hosts' reads.
type menuState struct {
	rows     []tray.Row
	revision uint32
}

// menu puts the flat menu object on the bus at menuPath. The sink is where a
// click on an enabled row arrives as tray.MenuClick — the sink the loop reads,
// which 4.4 wires through — and the log speaks emission trouble on a dead bus.
func (b *Bus) menu(sink func(any), log func(string)) (*menu, error) {
	contract.Require(b != nil && b.conn != nil, "sni: menu on a nil bus")
	contract.Require(!b.closed.Load(), "sni: menu on a closed bus")
	contract.Require(sink != nil, "sni: menu needs a sink for the clicks")
	contract.Require(log != nil, "sni: menu needs a log delegate")
	p, err := prop.Export(b.conn, menuPath, prop.Map{menuIface: {
		"Version":       {Value: menuVersion, Emit: prop.EmitFalse},
		"Status":        {Value: menuStatus, Emit: prop.EmitFalse},
		"TextDirection": {Value: menuDirection, Emit: prop.EmitFalse},
	}})
	if err != nil {
		return nil, fmt.Errorf("export the menu properties: %w", err)
	}
	m := &menu{bus: b, sink: sink, log: log, props: p}
	m.state.Store(&menuState{})
	if err := b.conn.Export(menuMethods{m}, menuPath, menuIface); err != nil {
		return nil, fmt.Errorf("export the menu methods: %w", err)
	}
	return m, nil
}

// show is the menu's write path: a view whose rows differ from the last shown
// ones replace them, bump the revision and announce the layout with the root as
// parent; a repeated row set announces nothing, like the item's repeated view.
// The icon and the rows of one view never disagree (3.6): one show feeds both.
func (m *menu) show(v tray.View) {
	before := m.state.Load()
	if slices.Equal(before.rows, v.Menu) {
		return
	}
	after := &menuState{rows: slices.Clone(v.Menu), revision: before.revision + 1}
	m.state.Store(after)
	m.signal(layoutUpdated, after.revision, int32(0))
}

// signal emits one signal of the menu, fire and forget like the item's; a dead
// bus is spoken, not hidden.
func (m *menu) signal(name string, body ...any) {
	if err := m.bus.conn.Emit(menuPath, name, body...); err != nil {
		m.log("tray menu: emit " + name + ": " + err.Error())
	}
}

// menuMethods is the callable side of the menu: the seven methods as the
// shipped dbusmenu implementations describe them — the types are the letters.
type menuMethods struct{ m *menu }

// menuLayout is the wire tuple (ia{sv}av): an id, its properties and its
// children. The menu is flat, so only the root ever has children.
type menuLayout struct {
	ID       int32
	Props    map[string]dbus.Variant
	Children []dbus.Variant
}

// idProps is GetGroupProperties' wire row, a(ia{sv}).
type idProps struct {
	ID    int32
	Props map[string]dbus.Variant
}

// menuEvent is EventGroup's wire event, a(isvu): Event's four in a struct.
type menuEvent struct {
	ID   int32
	Name string
	Data dbus.Variant
	Time uint32
}

// GetLayout answers the menu from parentID down: the root with the rows of the
// last view as children, or one row alone (depth 0 means the node only). The
// revision and the rows are one snapshot; an empty propertyNames means all.
func (x menuMethods) GetLayout(parentID int32, depth int32, names []string,
) (uint32, menuLayout, *dbus.Error) {
	st := x.m.state.Load()
	if parentID == 0 {
		root := menuLayout{Props: map[string]dbus.Variant{}}
		if depth != 0 {
			root.Children = childrenOf(st.rows, names)
		}
		return st.revision, root, nil
	}
	i := rowIndex(st.rows, parentID)
	if i < 0 {
		return st.revision, menuLayout{Props: map[string]dbus.Variant{}}, unknownRow(parentID)
	}
	row := st.rows[i]
	return st.revision, menuLayout{ID: int32(row.ID), Props: rowProps(row, names)}, nil
}

// childrenOf wraps each row as one variant of the same tuple, in view order
// (the hosts unwrap the variants themselves).
func childrenOf(rows []tray.Row, names []string) []dbus.Variant {
	out := make([]dbus.Variant, len(rows))
	for i, row := range rows {
		out[i] = dbus.MakeVariant(menuLayout{ID: int32(row.ID), Props: rowProps(row, names)})
	}
	return out
}

// GetGroupProperties answers the asked-for properties of the asked-for rows;
// ids this menu does not know are skipped, the same silence as everywhere.
func (x menuMethods) GetGroupProperties(ids []int32, names []string) ([]idProps, *dbus.Error) {
	st := x.m.state.Load()
	var out []idProps
	for _, id := range ids {
		if i := rowIndex(st.rows, id); i >= 0 {
			out = append(out, idProps{ID: int32(st.rows[i].ID), Props: rowProps(st.rows[i], names)})
		}
	}
	return out, nil
}

// GetProperty answers one property of one row. This menu does not pretend to
// properties it does not have: a row that lacks the asked-for name, or an id
// it does not know, is an argument error.
func (x menuMethods) GetProperty(id int32, name string) (dbus.Variant, *dbus.Error) {
	st := x.m.state.Load()
	i := rowIndex(st.rows, id)
	if i < 0 {
		return dbus.Variant{}, unknownRow(id)
	}
	p := rowProps(st.rows[i], []string{name})
	if len(p) == 0 {
		return dbus.Variant{}, dbus.NewError(invalidArgs,
			[]any{fmt.Sprintf("no %q on row %d", name, id)})
	}
	return p[name], nil
}

// Event is the activation path of one row: only the clicked event on a known,
// enabled row becomes tray.MenuClick through the sink; a disabled row, an
// unknown id and every quiet event are silence.
func (x menuMethods) Event(id int32, name string, data dbus.Variant, ts uint32) *dbus.Error {
	x.m.click(x.m.state.Load(), id, name)
	return nil
}

// EventGroup is Event's group form with the interface's error channel: the
// ids this menu does not know come back as the group's errors.
func (x menuMethods) EventGroup(events []menuEvent) ([]int32, *dbus.Error) {
	st := x.m.state.Load()
	var errs []int32
	for _, e := range events {
		if !x.m.click(st, e.ID, e.Name) {
			errs = append(errs, e.ID)
		}
	}
	return errs, nil
}

// click routes one event and reports whether the menu knows the row at all.
func (m *menu) click(st *menuState, id int32, name string) (known bool) {
	i := rowIndex(st.rows, id)
	if i < 0 {
		return false
	}
	row := st.rows[i]
	if row.Enabled && name == menuClickEvent {
		m.sink(tray.MenuClick{Row: row.ID})
	}
	return true
}

// AboutToShow: the layout of this menu is always current, because show
// announces every change, so no relayout is ever needed, whatever the id.
func (x menuMethods) AboutToShow(id int32) (bool, *dbus.Error) {
	return false, nil
}

// AboutToShowGroup is AboutToShow for several ids; the unknown ones are the
// errors the interface asks for.
func (x menuMethods) AboutToShowGroup(ids []int32) ([]int32, []int32, *dbus.Error) {
	st := x.m.state.Load()
	var errs []int32
	for _, id := range ids {
		if rowIndex(st.rows, id) < 0 {
			errs = append(errs, id)
		}
	}
	return nil, errs, nil
}

// rowProps is the row half of the mapping: the label with every underscore
// doubled (dbusmenu reads a single one as a mnemonic marker), enablement,
// visibility, the separator's type and the checkmark with its state. A
// non-empty names list limits the dict to the asked-for properties.
func rowProps(row tray.Row, names []string) map[string]dbus.Variant {
	p := map[string]dbus.Variant{"visible": dbus.MakeVariant(true)}
	if row.Separator {
		p[rowType] = dbus.MakeVariant(rowSeparator)
		return keep(p, names)
	}
	p["label"] = dbus.MakeVariant(escapeLabel(row.Label))
	p["enabled"] = dbus.MakeVariant(row.Enabled)
	if row.Check {
		p["toggle-type"] = dbus.MakeVariant(rowCheckmark)
		p["toggle-state"] = dbus.MakeVariant(toggleState(row))
	}
	return keep(p, names)
}

// escapeLabel doubles every underscore of a row's label for dbusmenu.
func escapeLabel(label string) string {
	return strings.ReplaceAll(label, "_", "__")
}

// toggleState is 1 when the check row is checked, else 0, the dbusmenu words.
func toggleState(row tray.Row) int32 {
	if row.Checked {
		return 1
	}
	return 0
}

// keep narrows the dict to the asked-for names; an empty list means all.
func keep(p map[string]dbus.Variant, names []string) map[string]dbus.Variant {
	if len(names) == 0 {
		return p
	}
	out := map[string]dbus.Variant{}
	for _, n := range names {
		if v, ok := p[n]; ok {
			out[n] = v
		}
	}
	return out
}

// rowIndex finds a row by its wire id: the tray's RowID integers, 0 the root only.
func rowIndex(rows []tray.Row, id int32) int {
	return slices.IndexFunc(rows, func(r tray.Row) bool { return int32(r.ID) == id })
}

// unknownRow is the error of a read for an id this menu does not know.
func unknownRow(id int32) *dbus.Error {
	return dbus.NewError(invalidArgs, []any{fmt.Sprintf("no row %d", id)})
}
