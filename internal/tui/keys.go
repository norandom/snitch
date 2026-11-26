// keys.go holds the single key table of the design, key dispatch, and the five
// action-key guards (repeat, 50 ms burst, 0.6 s confirmation gate, foreign socket,
// daemon down). No key decides on inbound connections.
//
// Fail-safe implications: action keys (x, space, T, K, E, U, y) are gated so held keys,
// non-bracketed pastes, early confirmation answers, foreign sockets, and unreachable
// daemons cannot trigger writes or mode changes.
package tui

import (
	"time"

	"github.com/norandom/snitch/internal/clean"
)

const (
	burstWindow = 50 * time.Millisecond
	confirmGate = 600 * time.Millisecond
)

type keyWhere int

const (
	whereOverview keyWhere = iota
	whereBoth
	whereConfirm
)

type keyEntry struct {
	name   string
	where  keyWhere
	action bool
	handle func(Model, Key, time.Time) (Model, []Effect)
}

var keyTable = []keyEntry{
	{name: "up", where: whereOverview, handle: onMove},
	{name: "down", where: whereOverview, handle: onMove},
	{name: "pgup", where: whereOverview, handle: onMove},
	{name: "pgdown", where: whereOverview, handle: onMove},
	{name: "home", where: whereOverview, handle: onMove},
	{name: "end", where: whereOverview, handle: onMove},
	{name: "enter", where: whereOverview, handle: onOpen},
	{name: "right", where: whereOverview, handle: onOpen},
	{name: "l", where: whereOverview, handle: onOpen},
	{name: "left", where: whereOverview, handle: onClose},
	{name: "h", where: whereOverview, handle: onClose},
	{name: "x", where: whereOverview, action: true, handle: onBlock},
	{name: "space", where: whereOverview, action: true, handle: onBlock},
	{name: "t", where: whereBoth, handle: onWindow},
	{name: "1", where: whereBoth, handle: onWindow},
	{name: "2", where: whereBoth, handle: onWindow},
	{name: "3", where: whereBoth, handle: onWindow},
	{name: "4", where: whereBoth, handle: onWindow},
	{name: "5", where: whereBoth, handle: onWindow},
	{name: "6", where: whereBoth, handle: onWindow},
	{name: "7", where: whereBoth, handle: onWindow},
	{name: "8", where: whereBoth, handle: onWindow},
	{name: "9", where: whereBoth, handle: onWindow},
	{name: "s", where: whereOverview, handle: onSort},
	{name: "S", where: whereOverview, handle: onSort},
	{name: "/", where: whereOverview, handle: onSearchOpen},
	{name: "esc", where: whereOverview, handle: onSearchClear},
	{name: "e", where: whereBoth, handle: onGraph},
	{name: "T", where: whereBoth, action: true, handle: onTrial},
	{name: "K", where: whereBoth, action: true, handle: onKeep},
	{name: "E", where: whereBoth, action: true, handle: onEnd},
	{name: "U", where: whereBoth, action: true, handle: onUnkeep},
	{name: "y", where: whereConfirm, action: true, handle: onConfirmYes},
	{name: "q", where: whereBoth, handle: onQuit},
	{name: "ctrl+c", where: whereBoth, handle: onQuit},
}

var keyIndex = buildKeyIndex()

func buildKeyIndex() map[string]keyEntry {
	idx := make(map[string]keyEntry, len(keyTable))
	for _, entry := range keyTable {
		idx[entry.name] = entry
	}
	return idx
}

func lookupKey(name string) (keyEntry, bool) {
	entry, ok := keyIndex[name]
	return entry, ok
}

func onKey(m Model, k Key, now time.Time) (Model, []Effect) {
	at := keyTime(k, now)
	burst := isBurst(m, at)
	m.lastKeyAt = at
	m = disarmOtherKey(m, k)
	if m.tooSmall() {
		if k.Name == "q" {
			return onQuit(m, k, now)
		}
		return m, nil
	}
	if m.confirm != nil {
		return onConfirmKey(m, k, at, burst, now)
	}
	if m.search != nil {
		return onSearchInput(m, k, now)
	}
	entry, ok := lookupKey(k.Name)
	if !ok || !inScope(m, entry.where) {
		return m, nil
	}
	if entry.action {
		var pass bool
		m, pass = guardAction(m, k, at, burst)
		if !pass {
			return m, nil
		}
	}
	return entry.handle(m, k, now)
}

func keyTime(k Key, now time.Time) time.Time {
	if !k.At.IsZero() {
		return k.At
	}
	return now
}

func isBurst(m Model, at time.Time) bool {
	if m.lastKeyAt.IsZero() {
		return false
	}
	d := at.Sub(m.lastKeyAt)
	return d >= 0 && d < burstWindow
}

func inScope(m Model, w keyWhere) bool {
	switch w {
	case whereOverview:
		return !m.graph
	case whereConfirm:
		return m.confirm != nil
	default:
		return true
	}
}

func guardAction(m Model, k Key, at time.Time, burst bool) (Model, bool) {
	if k.Repeat || burst {
		return m, false
	}
	if m.confirm != nil && at.Sub(m.confirm.openedAt) < confirmGate {
		return m, false
	}
	if m.foreign {
		m.notice = clean.Const("not the system daemon: writes are off")
		return m, false
	}
	if !m.up {
		m.notice = clean.Const("the daemon is not reachable")
		return m, false
	}
	return m, true
}

func onConfirmKey(m Model, k Key, at time.Time, burst bool, now time.Time) (Model, []Effect) {
	if at.Sub(m.confirm.openedAt) < confirmGate {
		return m, nil
	}
	if k.Name != "y" {
		if k.Repeat || burst {
			return m, nil
		}
		return onConfirmCancel(m, k, now)
	}
	var pass bool
	m, pass = guardAction(m, k, at, burst)
	if !pass {
		return m, nil
	}
	return onConfirmYes(m, k, now)
}

func onSearchInput(m Model, k Key, now time.Time) (Model, []Effect) {
	switch k.Name {
	case "ctrl+c":
		return onQuit(m, k, now)
	case "esc":
		return onSearchClear(m, k, now)
	case "enter":
		return onSearchApply(m, k, now)
	default:
		return onSearchText(m, k, now)
	}
}

func onQuit(m Model, _ Key, _ time.Time) (Model, []Effect) {
	return m, []Effect{Quit{}}
}

func disarmOtherKey(m Model, k Key) Model {
	if m.tooSmall() || m.confirm != nil || m.search != nil || (k.Name != "x" && k.Name != "space") {
		m.armed = ""
	}
	return m
}

// Named key stubs filled by tasks 5.5 and 5.8.
func onGraph(m Model, _ Key, _ time.Time) (Model, []Effect)         { return m, nil }
func onTrial(m Model, _ Key, _ time.Time) (Model, []Effect)         { return m, nil }
func onKeep(m Model, _ Key, _ time.Time) (Model, []Effect)          { return m, nil }
func onEnd(m Model, _ Key, _ time.Time) (Model, []Effect)           { return m, nil }
func onUnkeep(m Model, _ Key, _ time.Time) (Model, []Effect)        { return m, nil }
func onConfirmYes(m Model, _ Key, _ time.Time) (Model, []Effect)    { return m, nil }
func onConfirmCancel(m Model, _ Key, _ time.Time) (Model, []Effect) { return m, nil }
