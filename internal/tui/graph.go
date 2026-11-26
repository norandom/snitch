// graph.go implements the egress graph view toggle, 2 s flow recomputation, and Screen
// rendering (totals heading, logarithmic eighth-cell bars, collecting and counting-off states).
//
// Fail-safe implications: none on kernel egress. Pure state transitions and rendering over
// clean.Safe values; never reads files or triggers writes.
package tui

import (
	"fmt"
	"math"
	"slices"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/table"
)

const (
	graphTop          = 10
	graphPer          = 5
	graphRefreshEvery = 2 * time.Second
)

type destItem struct {
	name   clean.Safe
	bytes  uint64
	isMore bool
}

func toggleGraph(m Model, now time.Time) Model {
	m.graph = !m.graph
	m.armed = ""
	if m.graph {
		return recomputeFlows(m, now)
	}
	if m.dirty {
		return rebuildRows(m, now)
	}
	return m
}

func refreshGraphIfDue(m Model, now time.Time) Model {
	if !m.graph {
		return m
	}
	if !m.flowsAt.IsZero() && now.Sub(m.flowsAt) < graphRefreshEvery {
		return m
	}
	return recomputeFlows(m, now)
}

func recomputeFlows(m Model, now time.Time) Model {
	m.flows, m.flowsBytes, m.flowsAll = computeFlows(m.store)
	m.flowsAt = now
	return m
}

func computeFlows(s table.Store) ([]table.Flow, uint64, int) {
	flows := table.Flows(s, graphTop, graphPer)
	if len(flows) == 0 {
		return nil, 0, 0
	}
	if len(flows) < graphTop || s.Len() <= graphTop {
		return flows, sumFlowBytes(flows), len(flows)
	}
	all := table.Flows(s, s.Len(), 0)
	return flows, sumFlowBytes(all), len(all)
}

func sumFlowBytes(flows []table.Flow) uint64 {
	var total uint64
	for _, f := range flows {
		total += f.Total
	}
	return total
}

func drawGraph(m Model, now time.Time) Screen {
	w := max(minWidth, m.size.W)
	sep := []Line{{{Text: clean.Text(strings.Repeat("─", w)), Style: Dim}}}
	head := []Line{overviewHeader(m, now)}
	body := graphBody(m, w)
	return Screen{Title: appTitle, Lines: slices.Concat(head, body, sep, overviewBottom(m))}
}

func graphBody(m Model, w int) []Line {
	flows, totalBytes, totalProgs := graphData(m)
	lines := graphHeading(m, totalBytes, totalProgs)
	switch {
	case m.status != nil && !m.status.Counting:
		lines = append(lines, Line{{Text: clean.Const(" byte counting is off"), Style: Warn}}, Line{})
	case len(flows) == 0 && !m.up && m.status == nil:
		lines = append(lines, Line{{Text: clean.Const(" connecting ..."), Style: Dim}}, Line{})
	case len(flows) == 0:
		lines = append(lines, Line{{Text: clean.Const(" collecting ... (nothing sent in this time window yet)"), Style: Dim}}, Line{})
	default:
		lines = append(lines, renderFlows(flows, w)...)
		lines = append(lines, Line{})
	}
	return lines
}

func graphData(m Model) ([]table.Flow, uint64, int) {
	if !m.flowsAt.IsZero() {
		return m.flows, m.flowsBytes, m.flowsAll
	}
	return computeFlows(m.store)
}

func graphHeading(m Model, totalBytes uint64, totalProgs int) []Line {
	var title string
	if m.status != nil && !m.status.Counting {
		title = fmt.Sprintf(" EGRESS  last %s   byte counting is off", m.window)
	} else {
		progLbl := map[bool]string{true: "1 program", false: fmt.Sprintf("%d programs", totalProgs)}[totalProgs == 1]
		title = fmt.Sprintf(" EGRESS  last %s   %s sent by %s   bars: log scale", m.window, clean.Size(totalBytes), progLbl)
	}
	sub := fmt.Sprintf(" totals: connections active in last %s, bytes counted since first seen", m.window)
	return []Line{
		{{Text: clean.Text(title), Style: Head}},
		{{Text: clean.Text(sub), Style: Dim}},
		{},
	}
}

func renderFlows(flows []table.Flow, w int) []Line {
	lw, dw, bw := graphDims(w)
	biggest := flows[0].Total
	var lines []Line
	for i, f := range flows {
		lines = append(lines, renderFlow(f, biggest, lw, dw, bw)...)
		if i < len(flows)-1 {
			lines = append(lines, Line{})
		}
	}
	return lines
}

func graphDims(w int) (lw, dw, bw int) {
	avail := max(52, w-28)
	lw = min(30, max(16, avail/4))
	dw = min(34, max(20, avail*3/8))
	bw = max(6, (avail-lw-dw)/2)
	return lw, dw, bw
}

func renderFlow(f table.Flow, biggest uint64, lw, dw, bw int) []Line {
	dests := flowDestItems(f)
	lines := make([]Line, 0, len(dests))
	for i, d := range dests {
		var line Line
		if i == 0 {
			line = flowSenderPrefix(f, biggest, lw, bw)
		} else {
			line = Line{{Text: clean.Text(strings.Repeat(" ", 1+lw+7+bw+10)), Style: Plain}}
		}
		line = append(line, destArrowSpan(i, len(dests)))
		line = append(line, destTailSpans(d, biggest, dw, bw)...)
		lines = append(lines, line)
	}
	return lines
}

func flowDestItems(f table.Flow) []destItem {
	items := make([]destItem, 0, len(f.Dests)+1)
	for _, d := range f.Dests {
		items = append(items, destItem{name: d.Name, bytes: d.Bytes})
	}
	if f.More > 0 {
		items = append(items, destItem{
			name:   clean.Text(fmt.Sprintf("+ %d more", f.More)),
			bytes:  f.MoreBytes,
			isMore: true,
		})
	}
	return items
}

func flowSenderPrefix(f table.Flow, biggest uint64, lw, bw int) Line {
	sender := padSafeRight(clean.Middle(f.Sender, lw-1), lw)
	sizeStr := clean.Text(fmt.Sprintf("%6s ", clean.Size(f.Total)))
	bar, barW := barSpans(table.Scale(f.Total, biggest), bw)
	pad := clean.Text(strings.Repeat(" ", max(0, bw-barW)))
	rateStr := clean.Text(fmt.Sprintf(" %8s ", formatFlowRate(f.Rate)))
	line := Line{
		{Text: clean.Const(" "), Style: Plain},
		{Text: sender, Style: Bold},
		{Text: sizeStr, Style: Plain},
	}
	line = append(line, bar...)
	return append(line, Span{Text: pad, Style: Plain}, Span{Text: rateStr, Style: Warn})
}

func destArrowSpan(idx, total int) Span {
	arrow := clean.Const("┣▶ ")
	switch {
	case total == 1:
		arrow = clean.Const("━▶ ")
	case idx == 0:
		arrow = clean.Const("┳▶ ")
	case idx == total-1:
		arrow = clean.Const("┗▶ ")
	}
	return Span{Text: arrow, Style: Good}
}

func destTailSpans(d destItem, biggest uint64, dw, bw int) []Span {
	nameStyle := Plain
	if d.isMore {
		nameStyle = Dim
	}
	name := padSafeRight(clean.Middle(d.name, dw-1), dw)
	sizeStr := clean.Text(fmt.Sprintf("%6s ", clean.Size(d.bytes)))
	bar, _ := barSpans(table.Scale(d.bytes, biggest), bw)
	out := []Span{
		{Text: name, Style: nameStyle},
		{Text: sizeStr, Style: Plain},
	}
	return append(out, bar...)
}

func barSpans(frac float64, bw int) ([]Span, int) {
	bar := table.Bar(frac, bw)
	if bar == "" {
		return nil, 0
	}
	runes := []rune(string(bar))
	var spans []Span
	curStyle := barCellStyle(0, bw)
	start := 0
	for i := 1; i < len(runes); i++ {
		if st := barCellStyle(i, bw); st != curStyle {
			spans = append(spans, Span{Text: clean.Text(string(runes[start:i])), Style: curStyle})
			curStyle = st
			start = i
		}
	}
	spans = append(spans, Span{Text: clean.Text(string(runes[start:])), Style: curStyle})
	return spans, len(runes)
}

func barCellStyle(idx, width int) Style {
	if idx*3 >= width*2 {
		return BarHigh
	}
	if idx*3 >= width {
		return BarMid
	}
	return BarLow
}

func formatFlowRate(rate float64) string {
	if rate < 1 {
		return ""
	}
	return string(clean.Size(uint64(math.Round(rate)))) + "/s"
}

func padSafeRight(s clean.Safe, width int) clean.Safe {
	pad := max(0, width-clean.Width(s))
	if pad == 0 {
		return s
	}
	return clean.Join(s, clean.Text(strings.Repeat(" ", pad)))
}
