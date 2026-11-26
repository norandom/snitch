// input.go translates Bubble Tea terminal input messages into tui messages while
// dropping paste start/end markers and unsupported terminal events.
//
// Fail-safe implications: none on kernel egress. Bracketed pastes become tui.Paste
// (never tui.Key) so pasted text cannot fire action keys.
package term

import (
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/norandom/snitch/internal/tui"
)

func translateMsg(msg tea.Msg, now time.Time) (any, bool) {
	switch m := msg.(type) {
	case tea.KeyPressMsg:
		return tui.Key{
			Name:   m.String(),
			Text:   m.Text,
			Repeat: m.IsRepeat,
			At:     now,
		}, true
	case tea.PasteMsg:
		return tui.Paste{Text: m.Content}, true
	case tea.WindowSizeMsg:
		return tui.Resize{W: m.Width, H: m.Height}, true
	case tea.PasteStartMsg, tea.PasteEndMsg:
		return nil, false
	default:
		return nil, false
	}
}
