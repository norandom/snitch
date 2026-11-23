// update.go: Update, the one entry of the tray's behaviour. It only dispatches by message type
// (facts.go, and the question files of later tasks hold the logic) and ends every effect list
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
		m, fx = goneTick(m, now)
	case Posted:
		m = noticePosted(m, v)
	case PostFailed:
		m = noticeSettled(m, v.Token)
	case Closed:
		m = closed(m, v.NoteID)
	case Pressed, MenuClick, Capabilities, Stop: // questions, pause, quit: 3.3 to 3.5
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
		return down(m, v, now), nil
	case client.Facts:
		return facts(m, v.Status)
	case client.StateLine:
		return stateLine(m, v.State)
	case client.EventLine, client.Answered: // questions: 3.3
	default:
		contract.Require(false, fmt.Sprintf("tray.Update: unknown client message %T", msg))
	}
	return m, nil
}
