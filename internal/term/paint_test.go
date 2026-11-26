package term

import (
	"strings"
	"testing"

	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/tui"
)

func TestPaintAllStylesDistinct(t *testing.T) {
	all := []tui.Style{
		tui.Plain, tui.Dim, tui.Bold, tui.Good, tui.Bad,
		tui.Warn, tui.Head, tui.Cursor, tui.BarLow, tui.BarMid, tui.BarHigh,
	}
	seen := make(map[string]tui.Style, len(all))
	for _, st := range all {
		got := styleFor(st).Render("X")
		if got == "" {
			t.Fatalf("style %v rendered empty", st)
		}
		if prev, ok := seen[got]; ok {
			t.Fatalf("styles %v and %v rendered identically: %q", prev, st, got)
		}
		seen[got] = st
	}
	if styleFor(tui.Style(999)).Render("X") != styleFor(tui.Plain).Render("X") {
		t.Fatalf("unknown style did not fall back to Plain")
	}
}

func TestPaintANSIColoursAndGradient(t *testing.T) {
	if styleFor(tui.Good).GetForeground() != lipgloss.Green {
		t.Fatalf("Good fg = %v, want lipgloss.Green", styleFor(tui.Good).GetForeground())
	}
	if styleFor(tui.Bad).GetForeground() != lipgloss.Red {
		t.Fatalf("Bad fg = %v, want lipgloss.Red", styleFor(tui.Bad).GetForeground())
	}
	if styleFor(tui.Warn).GetForeground() != lipgloss.Yellow {
		t.Fatalf("Warn fg = %v, want lipgloss.Yellow", styleFor(tui.Warn).GetForeground())
	}
	if !styleFor(tui.Head).GetBold() {
		t.Fatalf("Head is not bold")
	}
	if !styleFor(tui.Cursor).GetReverse() {
		t.Fatalf("Cursor is not reverse")
	}
	if !styleFor(tui.Dim).GetFaint() {
		t.Fatalf("Dim is not faint")
	}
	for _, st := range []tui.Style{tui.BarLow, tui.BarMid, tui.BarHigh} {
		if styleFor(st).GetForeground() == nil {
			t.Fatalf("bar style %v has nil foreground", st)
		}
	}
}

func TestPaintRenderScreenPreservesLinesAndText(t *testing.T) {
	scr := tui.Screen{
		Title: clean.Const("snitch"),
		Lines: []tui.Line{
			{
				{Text: clean.Const("head"), Style: tui.Head},
				{Text: clean.Const(" "), Style: tui.Plain},
				{Text: clean.Const("ok"), Style: tui.Good},
			},
			{},
			{
				{Text: clean.Const("low"), Style: tui.BarLow},
				{Text: clean.Const("mid"), Style: tui.BarMid},
				{Text: clean.Const("hi"), Style: tui.BarHigh},
			},
		},
	}
	got := renderScreen(scr)
	lines := strings.Split(got, "\n")
	if len(lines) != 3 {
		t.Fatalf("got %d lines, want 3: %q", len(lines), got)
	}
	if ansi.Strip(lines[0]) != "head ok" {
		t.Fatalf("line 0 stripped = %q, want %q", ansi.Strip(lines[0]), "head ok")
	}
	if lines[1] != "" {
		t.Fatalf("line 1 = %q, want empty", lines[1])
	}
	if ansi.Strip(lines[2]) != "lowmidhi" {
		t.Fatalf("line 2 stripped = %q, want %q", ansi.Strip(lines[2]), "lowmidhi")
	}
}
