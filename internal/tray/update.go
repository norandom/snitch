// update.go: Update, the one entry of the tray's behaviour. It only dispatches by message type
// (facts.go, questions.go and discard.go hold the logic) and ends every effect list
// with the view of the new model, which the loop shows only when it changed (8.7).
//
// Fail-safe implications: a message type outside the design's list is a wiring error and a
// contract violation, so an adapter can never slip an unhandled command into the core.
package tray

import (
	"fmt"
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
		m, fx = click(m, v, now)
	case Stop: // quit: 3.5
	default:
		contract.Require(false, fmt.Sprintf("tray.Update: unknown message %T", msg))
	}
	return m, append(fx, Show{View: Render(m, now)})
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
