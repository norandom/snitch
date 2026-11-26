package tui

import (
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/clean"
)

func TestSmallTerminalNoticeAndOnlyQActs(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	for _, sz := range []Resize{{79, 20}, {80, 19}, {0, 0}, {40, 10}} {
		m, _ := Update(New(Options{}), sz, now)
		scr := Render(m, now)
		if len(scr.Lines) != 1 {
			t.Fatalf("size %+v: got %d lines, want 1", sz, len(scr.Lines))
		}
		line := flattenLine(scr.Lines[0])
		if !strings.Contains(line, "80") || !strings.Contains(line, "20") {
			t.Fatalf("size %+v: line %q does not state 80x20 needed", sz, line)
		}
		if scr.Title != clean.Const("snitch") {
			t.Fatalf("Title = %q, want snitch", scr.Title)
		}

		// When too small, keys other than q do nothing (including ctrl+c, action keys, paste).
		m.up = true
		for i, msg := range []any{
			Key{Name: "x", At: now.Add(time.Second)},
			Key{Name: "T", At: now.Add(2 * time.Second)},
			Key{Name: "e", At: now.Add(3 * time.Second)},
			Key{Name: "down", At: now.Add(4 * time.Second)},
			Key{Name: "ctrl+c", At: now.Add(5 * time.Second)},
			Paste{Text: "q"},
		} {
			next, fx := Update(m, msg, now.Add(time.Duration(i+1)*time.Second))
			if len(fx) != 0 || next.notice != "" {
				t.Fatalf("size %+v msg %#v acted when too small: fx=%#v notice=%q", sz, msg, fx, next.notice)
			}
		}

		// Only q quits when too small.
		_, fx := Update(m, Key{Name: "q", At: now.Add(10 * time.Second)}, now.Add(10*time.Second))
		assertQuitEffect(t, "q", fx)
	}
}

func TestRenderSwitchesBetweenViews(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

	over := Render(New(Options{}), now)
	graph := Render(New(Options{Egress: true}), now)
	if flattenScreen(over) == flattenScreen(graph) {
		t.Fatalf("overview and graph rendered identical screens: %q", flattenScreen(over))
	}

	mSmall, _ := Update(New(Options{Egress: true}), Resize{W: 79, H: 20}, now)
	small := Render(mSmall, now)
	if len(small.Lines) != 1 || flattenScreen(small) == flattenScreen(graph) {
		t.Fatalf("too small did not override graph: %#v", small)
	}

	mOk, _ := Update(mSmall, Resize{W: 80, H: 20}, now)
	restored := Render(mOk, now)
	if flattenScreen(restored) != flattenScreen(graph) {
		t.Fatalf("80x20 did not restore graph: got %q, want %q", flattenScreen(restored), flattenScreen(graph))
	}
}

func TestScreenStylesDistinct(t *testing.T) {
	styles := []Style{Plain, Dim, Bold, Good, Bad, Warn, Head, Cursor, BarLow, BarMid, BarHigh}
	seen := make(map[Style]bool, len(styles))
	for _, s := range styles {
		if seen[s] {
			t.Fatalf("duplicate Style value %d", s)
		}
		seen[s] = true
	}
}

func flattenLine(l Line) string {
	var b strings.Builder
	for _, sp := range l {
		b.WriteString(string(sp.Text))
	}
	return b.String()
}

func flattenScreen(s Screen) string {
	lines := make([]string, len(s.Lines))
	for i, l := range s.Lines {
		lines[i] = flattenLine(l)
	}
	return strings.Join(lines, "\n")
}
