// screen.go defines the terminal-agnostic Screen, Line, Span, and Style types and
// switches Render between the too-small notice, the egress graph, and the overview.
//
// Fail-safe implications: none on kernel egress. Every rendered text span carries
// clean.Safe so untrusted daemon strings cannot emit escape sequences.
package tui

import (
	"fmt"
	"time"

	"github.com/norandom/snitch/internal/clean"
)

const (
	minWidth      = 80
	minHeight     = 20
	defaultHeight = 24
)

var appTitle = clean.Const("snitch")

// Style selects the semantic terminal style applied by the adapter.
type Style int

const (
	Plain Style = iota
	Dim
	Bold
	Good
	Bad
	Warn
	Head
	Cursor
	BarLow
	BarMid
	BarHigh
)

// Span is a styled run of sanitised text on a Screen line.
type Span struct {
	Text  clean.Safe
	Style Style
}

// Line is one row of styled spans on a Screen.
type Line []Span

// Screen is the complete rendered frame returned to the terminal adapter.
type Screen struct {
	Lines []Line
	Title clean.Safe
}

// Render draws m at now as a Screen, switching between the too-small notice, the egress
// graph, and the connection overview.
func Render(m Model, now time.Time) Screen {
	if m.tooSmall() {
		return renderTooSmall(m)
	}
	if m.graph {
		return renderGraph(m, now)
	}
	return renderOverview(m, now)
}

func renderTooSmall(m Model) Screen {
	msg := clean.Text(fmt.Sprintf("terminal too small (%dx%d): need at least %dx%d (q to quit)",
		m.size.W, m.size.H, minWidth, minHeight))
	return Screen{
		Title: appTitle,
		Lines: []Line{{{Text: msg, Style: Warn}}},
	}
}

// renderGraph is filled by 5.8.
func renderGraph(m Model, now time.Time) Screen {
	return Screen{
		Title: appTitle,
		Lines: []Line{{{Text: clean.Const("egress"), Style: Head}}},
	}
}

// renderOverview is filled by 5.7.
func renderOverview(m Model, now time.Time) Screen {
	return drawOverview(m, now)
}
