// update.go is the single entry point Update for the TUI state machine. It dispatches
// every inbound message type to its handler and panics by contract on unknown message
// types so wiring errors cannot slip past silently.
//
// Fail-safe implications: none on kernel egress. Unknown messages trigger a contract
// violation; pasted text can reach only an open search line through clean.Text.
package tui

import (
	"fmt"
	"maps"
	"time"

	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/contract"
)

// Update applies msg to m at now and returns the updated Model and any outbound effects.
func Update(m Model, msg any, now time.Time) (Model, []Effect) {
	var next Model
	var fx []Effect
	switch v := msg.(type) {
	case client.Msg:
		next, fx = updateClient(m, v, now)
	case Key:
		next, fx = onKey(m, v, now)
	case Paste:
		next = onPaste(m, v)
	case Resize:
		next = onResize(m, v)
	case Tick:
		next, fx = onTick(m, now)
	case LogFailed:
		next = onLogFailed(m, v)
	case Inspected:
		next = onInspected(m, v)
		return next, nil
	default:
		contract.Require(false, fmt.Sprintf("tui.Update: unknown message %T", msg))
		return m, nil
	}
	return emitInspectIfNeeded(next, fx)
}

func updateClient(m Model, msg client.Msg, now time.Time) (Model, []Effect) {
	switch v := msg.(type) {
	case client.Up:
		return onUp(m, v, now)
	case client.Down:
		return onDown(m, v, now)
	case client.Facts:
		return onFacts(m, v, now)
	case client.StateLine:
		return onStateLine(m, v, now)
	case client.EventLine:
		return onEventLine(m, v, now)
	case client.SummaryLine:
		return onSummaryLine(m, v, now)
	case client.Dropped:
		return onDropped(m, v, now)
	case client.Answered:
		return onAnswered(m, v, now)
	default:
		contract.Require(false, fmt.Sprintf("tui.Update: unknown client message %T", msg))
		return m, nil
	}
}

func onPaste(m Model, p Paste) Model {
	if m.tooSmall() || m.confirm != nil || m.search == nil {
		return m
	}
	next := *m.search + string(clean.Text(p.Text))
	m.search = &next
	return m
}

func onResize(m Model, r Resize) Model {
	m.size = termSize{W: r.W, H: r.H}
	return m
}

func onInspected(m Model, in Inspected) Model {
	if cur, ok := m.inspected[in.Path]; in.Path == "" || (ok && cur == in.Loose) {
		return m
	}
	next := maps.Clone(m.inspected)
	if next == nil {
		next = make(map[string]bool, 1)
	}
	next[in.Path] = in.Loose
	m.inspected = next
	return m
}
