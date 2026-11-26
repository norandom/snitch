// paint.go translates tui.Screen lines and semantic tui.Style values into Lip Gloss
// styled strings using the 16 ANSI colours and the btop-style bar gradient.
//
// Fail-safe implications: none on kernel egress. Only clean.Safe spans reach Lip Gloss
// and Bubble Tea downsamples colours and honours NO_COLOR automatically.
package term

import (
	"strings"

	"charm.land/lipgloss/v2"

	"github.com/norandom/snitch/internal/tui"
)

var styles = [...]lipgloss.Style{
	tui.Plain:   lipgloss.NewStyle(),
	tui.Dim:     lipgloss.NewStyle().Faint(true),
	tui.Bold:    lipgloss.NewStyle().Bold(true),
	tui.Good:    lipgloss.NewStyle().Foreground(lipgloss.Green),
	tui.Bad:     lipgloss.NewStyle().Foreground(lipgloss.Red),
	tui.Warn:    lipgloss.NewStyle().Foreground(lipgloss.Yellow),
	tui.Head:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Green),
	tui.Cursor:  lipgloss.NewStyle().Reverse(true),
	tui.BarLow:  lipgloss.NewStyle().Foreground(lipgloss.RGBColor{R: 80, G: 220, B: 80}),
	tui.BarMid:  lipgloss.NewStyle().Foreground(lipgloss.RGBColor{R: 255, G: 220, B: 80}),
	tui.BarHigh: lipgloss.NewStyle().Foreground(lipgloss.RGBColor{R: 255, G: 100, B: 80}),
}

func styleFor(s tui.Style) lipgloss.Style {
	if int(s) < 0 || int(s) >= len(styles) {
		return styles[tui.Plain]
	}
	return styles[s]
}

func renderSpan(sp tui.Span) string {
	if sp.Text == "" {
		return ""
	}
	if sp.Style == tui.Plain {
		return string(sp.Text)
	}
	return styleFor(sp.Style).Render(string(sp.Text))
}

func renderLine(line tui.Line) string {
	if len(line) == 0 {
		return ""
	}
	var b strings.Builder
	for _, sp := range line {
		b.WriteString(renderSpan(sp))
	}
	return b.String()
}

func renderScreen(scr tui.Screen) string {
	if len(scr.Lines) == 0 {
		return ""
	}
	lines := make([]string, len(scr.Lines))
	for i, line := range scr.Lines {
		lines[i] = renderLine(line)
	}
	return strings.Join(lines, "\n")
}
