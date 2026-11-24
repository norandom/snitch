// update.go: Update, the one entry of the tray's behaviour. It only dispatches by message type
// (facts.go, questions.go and discard.go hold the logic) and ends every effect list
// with the view of the new model, which the loop shows only when it changed (8.7).
//
// Fail-safe implications: a message type outside the design's list is a wiring error and a
// contract violation, so an adapter can never slip an unhandled command into the core.
package tray

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/contract"
)

// Update is the model after msg at now and the effects to run, a Show last.
func Update(m Model, msg any, now time.Time) (Model, []any) {
	var fx []any
	switch v := msg.(type) {
	case client.Msg:
		m, fx = fromDaemon(m, v, now)
	case Tick:
		m, fx = tick(m, now)
	case Posted:
		m, fx = afterPosted(m, v, now)
	case PostFailed:
		m, fx = postFailed(m, v, now)
	case Pressed:
		m, fx = pressed(m, v, now)
	case Capabilities:
		m, fx = afterCaps(m, v, now)
	case Closed:
		m, fx = closedNote(m, v.NoteID, now)
	case MenuClick:
		m, fx = menuClick(m, v, now)
	case Stop: // a signal ends the tray like Quit in the menu does (1.4)
		m, fx = quitAll(m)
	default:
		contract.Require(false, fmt.Sprintf("tray.Update: unknown message %T", msg))
	}
	return m, append(fx, Show{View: Render(m, now)})
}

// menuClick routes the menu (3.4): Quit ends the tray, the pause switch is discard.go's, and
// the fact rows and the header show facts without acting on them (3.5).
func menuClick(m Model, c MenuClick, now time.Time) (Model, []any) {
	if c.Row == RowQuit {
		return quitAll(m)
	}
	return click(m, c, now)
}

// quitAll composes the end of the tray (1.4): every note still open — the question first, then
// the notices, ordered so an adapter and a test see the same list — is retracted before the
// Quit effect removes the item, so no notification outlives its tray. A note whose post has
// no id yet cannot be retracted; it goes with the item instead, and no Send of the model's
// past is left (6.12, 8.1). The model itself does not change: it ends with the tray.
func quitAll(m Model) (Model, []any) {
	var fx []any
	if m.openNote != 0 {
		fx = append(fx, Retract{NoteID: m.openNote})
	}
	for _, id := range slices.Sorted(maps.Keys(m.notices)) {
		fx = append(fx, Retract{NoteID: id})
	}
	return m, append(fx, Quit{})
}

// fromDaemon dispatches the client's messages.
func fromDaemon(m Model, msg client.Msg, now time.Time) (Model, []any) {
	switch v := msg.(type) {
	case client.Up: // the loss ends with the session's first Facts, not here (3.1 note)
	case client.Down:
		return afterDown(m, v, now)
	case client.Facts:
		return afterFacts(m, v.Status, now)
	case client.StateLine:
		return afterLine(m, v.State, now)
	case client.EventLine:
		return event(m, v, now)
	case client.Answered:
		return answered(m, v)
	default:
		contract.Require(false, fmt.Sprintf("tray.Update: unknown client message %T", msg))
	}
	return m, nil
}
