// overview.go renders the overview Screen (header, connection table, detail pane,
// log pane, prompt/notice, key line) and emits once-per-path Inspect effects.
//
// Fail-safe implications: none on kernel egress. Pure rendering over clean.Safe values;
// directory inspection uses Inspect effects and never touches the filesystem directly.
package tui

import (
	"fmt"
	"maps"
	"math"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/ask"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/table"
)

func emitInspectIfNeeded(m Model, fx []Effect) (Model, []Effect) {
	if m.graph || m.tooSmall() || slices.ContainsFunc(fx, func(e Effect) bool { _, ok := e.(Quit); return ok }) {
		return m, fx
	}
	row, ok := m.currentRow()
	_, path := rowProgAndPath(m, row)
	if _, asked := m.inspected[path]; !ok || path == "" || asked {
		return m, fx
	}
	next := maps.Clone(m.inspected)
	if next == nil {
		next = map[string]bool{}
	}
	next[path] = false
	m.inspected = next
	return m, append(fx, Inspect{Path: path})
}

func drawOverview(m Model, now time.Time) Screen {
	w := max(minWidth, m.size.W)
	titleW := max(20, w-50)
	sep := []Line{{{Text: clean.Text(strings.Repeat("─", w)), Style: Dim}}}
	head := []Line{overviewHeader(m, now),
		{{Text: clean.Text(fmt.Sprintf("      %-*s   last    sent    ok/denied  verdict", titleW, "connection")), Style: Dim}}}
	return Screen{Title: appTitle, Lines: slices.Concat(head, overviewTableRows(m, now, titleW), sep, overviewDetail(m, now), sep, overviewBottom(m))}
}

func overviewHeader(m Model, now time.Time) Line {
	nProg, sortStr := 0, "name"
	for _, r := range m.rows {
		if r.Level == table.Program {
			nProg++
		}
	}
	if !m.view.Sort.ByName {
		res := m.resorts()
		sortStr = fmt.Sprintf("activity %ds", int64(res[m.resortIdx%len(res)]/time.Second))
	}
	progLbl := map[bool]string{true: "1 program", false: fmt.Sprintf("%d programs", nProg)}[nProg == 1]
	out := Line{{Text: clean.Text(fmt.Sprintf(" snitch | last %s | %s | sort: %s | mode: %s", m.window, progLbl, sortStr, modeLabel(m, now))), Style: Head}}
	sep := Span{Text: clean.Const(" | "), Style: Dim}
	if m.view.Search != "" {
		out = append(out, sep, Span{Text: clean.Text("search: " + m.view.Search), Style: Bold})
	}
	if m.foreign {
		out = append(out, sep, Span{Text: clean.Const("FOREIGN (not root)"), Style: Warn})
	}
	if m.stale {
		txt := "STALE" + map[bool]string{true: fmt.Sprintf(" (%s)", m.downReason)}[!m.up && m.downReason != ""]
		out = append(out, sep, Span{Text: clean.Text(txt), Style: Warn})
	}
	if r := allAllowedReason(m, now); r != "" {
		out = append(out, sep, Span{Text: clean.Join(clean.Const("ALL ALLOWED ("), r, clean.Const(")")), Style: Bad})
	}
	if m.socket != "" {
		out = append(out, sep, Span{Text: clean.Middle(m.socket, 32), Style: Dim})
	}
	return out
}

func allAllowedReason(m Model, now time.Time) clean.Safe {
	switch kill, beat := m.killEvent || (m.status != nil && m.status.Kill), m.staleHeartbeat(now); {
	case kill && beat:
		return clean.Const("kill switch, stale heartbeat")
	case kill:
		return clean.Const("kill switch")
	case beat:
		return clean.Const("stale heartbeat")
	}
	return ""
}

func modeLabel(m Model, now time.Time) clean.Safe {
	mode, trial, kept := "", "", false
	if m.state != nil && m.state.Mode != "" {
		mode, trial, kept = m.state.Mode, m.state.Trial, m.state.Kept
	} else if m.status != nil {
		mode, trial, kept = m.status.Mode, m.status.Trial, m.status.Kept
	}
	if mode == "enforce" && kept {
		return clean.Const("enforce (kept)")
	}
	if mode == "enforce" && trial != "" {
		if dl, err := time.Parse(time.RFC3339Nano, trial); err == nil {
			return clean.Text(fmt.Sprintf("enforce (trial until %s, %s left)", dl.In(m.location()).Format("15:04"), max(0, dl.Sub(now)).Round(time.Second)))
		}
	}
	return clean.Text(map[bool]string{true: "-", false: mode}[mode == ""])
}

func overviewTableRows(m Model, now time.Time, titleW int) []Line {
	page := m.pageSize()
	lines := make([]Line, page)
	if len(m.rows) == 0 {
		msg := map[bool]clean.Safe{true: clean.Const("  (no matching rows)"), false: clean.Const("  (no connections in window)")}[m.view.Search != ""]
		lines[0] = Line{{Text: map[bool]clean.Safe{true: clean.Const("  (connecting...)"), false: msg}[m.view.Search == "" && !m.up && m.status == nil], Style: Dim}}
		return lines
	}
	for i, r := range m.rows[m.top:min(len(m.rows), m.top+page)] {
		lines[i] = renderTableRow(r, r.ID == m.cursor, now, titleW)
	}
	return lines
}

func renderTableRow(r table.Row, cur bool, now time.Time, titleW int) Line {
	mark := map[bool]clean.Safe{true: clean.Const("[x]"), false: clean.Const("[ ]")}[r.Blocked]
	arrow := map[bool]string{true: map[bool]string{true: "v ", false: "> "}[r.Open], false: "  "}[r.HasKids]
	prefix := clean.Text(strings.Repeat("│ ", r.Depth) + arrow)
	title := clean.Join(prefix, clean.Middle(r.Title, max(1, titleW-clean.Width(prefix))))
	title = clean.Join(title, clean.Text(strings.Repeat(" ", max(0, titleW-clean.Width(title)))))
	tail := clean.Text(fmt.Sprintf("  %5s  %6s  %11s  ", clean.Age(r.Last, now), clean.Size(r.Sent), fmt.Sprintf("%d/%d", r.Allow, r.Deny)))
	verd := clean.Middle(r.Verdict, 13)
	if cur {
		return Line{{Text: clean.Join(clean.Const(" "), mark, clean.Const("  "), title, tail, verd), Style: Cursor}}
	}
	return Line{
		{Text: clean.Const(" "), Style: Plain}, {Text: mark, Style: map[bool]Style{true: Bad, false: Good}[r.Blocked]},
		{Text: clean.Const("  "), Style: Plain}, {Text: title, Style: map[bool]Style{true: Bad, false: Plain}[r.Blocked]},
		{Text: tail, Style: Plain}, {Text: verd, Style: map[bool]Style{true: Bad, false: Dim}[r.Deny > 0 || strings.HasPrefix(string(r.Verdict), "deny")]},
	}
}

func overviewDetail(m Model, now time.Time) []Line {
	row, ok := m.currentRow()
	if !ok {
		return append([]Line{{{Text: clean.Const(" no row selected"), Style: Dim}}}, make([]Line, 6)...)
	}
	prog, execPath := rowProgAndPath(m, row)
	progLine := Line{{Text: clean.Text(fmt.Sprintf(" program   %s  %s", prog, map[bool]string{true: execPath, false: "-"}[execPath != ""])), Style: Plain}}
	if row.Level == table.Bucket || prog == "" || prog == ask.Unknown ||
		!slices.ContainsFunc(m.rules.Programs, func(p api.ProgramView) bool { return p.Name == prog }) {
		progLine = append(progLine, Span{Text: clean.Const("  [undeclared]"), Style: Warn})
	}
	if execPath != "" && m.inspected[execPath] {
		progLine = append(progLine, Span{Text: clean.Const("  [writable dir]"), Style: Warn})
	}
	modeTxt := modeLabel(m, now)
	if r := allAllowedReason(m, now); r != "" {
		modeTxt = clean.Join(modeTxt, clean.Const(" (all allowed: "), r, clean.Const(")"))
	}
	remote, traffic := detailConnLines(m, row, now)
	return append([]Line{{{Text: clean.Join(clean.Const(" path      "), rowDetailPath(m.rows, row)), Style: Plain}},
		progLine, remote, traffic, {{Text: clean.Join(clean.Const(" mode      "), modeTxt), Style: Plain}}}, detailRulesLines(m, row)...)
}

func detailConnLines(m Model, row table.Row, now time.Time) (Line, Line) {
	var sets [4][]string
	var allowAt, denyAt time.Time
	for _, k := range row.Keys {
		e, _ := m.store.Get(k)
		for i, v := range []string{map[bool]string{true: string(clean.Name(e.Name))}[e.Name != ""], k.Addr, map[bool]string{true: strconv.Itoa(int(k.Port))}[k.Port > 0], k.Proto} {
			if v != "" && !slices.Contains(sets[i], v) {
				sets[i] = append(sets[i], v)
			}
		}
		allowAt, denyAt = maxTS(allowAt, e.LastAllowed), maxTS(denyAt, e.LastBlocked)
	}
	rateStr := map[bool]string{true: fmt.Sprintf("%.1fB/s", row.Rate), false: "0B/s"}[row.Rate > 0]
	if row.Rate >= 1 {
		rateStr = string(clean.Size(uint64(math.Round(row.Rate)))) + "/s"
	}
	return Line{{Text: clean.Text(fmt.Sprintf(" remote    %s  addr %s  port %s  %s", pickField(sets[0]), pickField(sets[1]), pickField(sets[2]), pickField(sets[3]))), Style: Plain}},
		Line{{Text: clean.Text(fmt.Sprintf(" traffic   sent %s  rate %s  last allowed %s  last denied %s", clean.Size(row.Sent), rateStr, clean.Age(allowAt, now), clean.Age(denyAt, now))), Style: Plain}}
}

func maxTS(cur time.Time, raw string) time.Time {
	if t, err := time.Parse(time.RFC3339Nano, raw); err == nil && t.After(cur) {
		return t
	}
	return cur
}

func detailRulesLines(m Model, row table.Row) []Line {
	rules := programRules(m, row)
	if len(rules) == 0 {
		return []Line{{{Text: clean.Const(" rule      (none)"), Style: Dim}}, {}}
	}
	out := make([]Line, 2)
	for i := 0; i < 2 && i < len(rules); i++ {
		rv := rules[i]
		pp := map[bool]string{true: "", false: rv.Protocol}[rv.Protocol == "any"]
		if pp != "" && rv.Port > 0 {
			pp += "/" + strconv.Itoa(rv.Port)
		}
		s := strings.TrimSpace(strings.Join([]string{rv.Verdict, rv.To, pp}, " ")) +
			map[bool]string{true: " · " + rv.Note}[rv.Note != ""] + map[bool]string{true: " (" + rv.Source + ")"}[rv.Source != ""]
		if i == 1 && len(rules) > 2 {
			s += fmt.Sprintf(" (+%d more)", len(rules)-2)
		}
		out[i] = Line{{Text: clean.Text(" rule      " + s), Style: Plain}}
	}
	return out
}

func overviewBottom(m Model) []Line {
	lines := make([]Line, 7)
	for i, entry := range m.log[max(0, len(m.log)-5):] {
		lines[i] = Line{{Text: clean.Join(clean.Const(" "), entry), Style: Dim}}
	}
	switch {
	case m.confirm != nil:
		lines[5] = Line{{Text: clean.Join(clean.Const(" "), m.confirm.prompt), Style: Warn}}
	case m.search != nil:
		lines[5] = Line{{Text: clean.Text(fmt.Sprintf(" /%s_  (enter: apply, esc: clear)", *m.search)), Style: Bold}}
	case m.notice != "":
		lines[5] = Line{{Text: clean.Join(clean.Const(" "), m.notice), Style: Warn}}
	}
	lines[6] = Line{{Text: clean.Const(" ↑↓:move →:open ←:close x:block t:win s/S:sort /:search e:graph T/K/E/U q:quit"), Style: Dim}}
	return lines
}

func rowProgAndPath(m Model, row table.Row) (string, string) {
	if row.Level == table.Bucket || len(row.Keys) == 0 {
		return ask.Unknown, ""
	}
	prog, path := "", ""
	for _, k := range row.Keys {
		e, _ := m.store.Get(k)
		path = map[bool]string{true: e.Path, false: path}[path == "" && e.Path != ""]
		prog = map[bool]string{true: e.Program, false: prog}[prog == "" && e.Program != ""]
	}
	if prog == "" && !strings.HasPrefix(row.Keys[0].Who, "/") && row.Keys[0].Who != "" {
		prog = row.Keys[0].Who
	}
	return map[bool]string{true: ask.Unknown, false: prog}[prog == ""], path
}

func rowDetailPath(rows []table.Row, row table.Row) clean.Safe {
	out := row.Title
	for idx := rowIndex(rows, row.Parent); row.Parent != "" && idx >= 0; idx = rowIndex(rows, row.Parent) {
		row = rows[idx]
		out = clean.Join(row.Title, clean.Const(" › "), out)
	}
	return out
}

func programRules(m Model, row table.Row) []api.RuleView {
	if row.Level == table.Bucket {
		return nil
	}
	prog, execPath := rowProgAndPath(m, row)
	names := map[string]bool{prog: prog != "" && prog != ask.Unknown, execPath: execPath != ""}
	for _, p := range m.rules.Programs {
		if p.Name != "" && (p.Name == prog || matchExec(p.Paths, execPath)) {
			names[p.Name] = true
		}
	}
	var out []api.RuleView
	for _, rv := range m.rules.Views {
		if rv.Program != "" && names[rv.Program] {
			out = append(out, rv)
		}
	}
	return out
}

func matchExec(paths []string, execPath string) bool {
	for _, pat := range paths {
		if ok, _ := filepath.Match(pat, execPath); execPath != "" && (ok || pat == execPath) {
			return true
		}
	}
	return false
}

func pickField(vals []string) string {
	if len(vals) > 1 {
		return fmt.Sprintf("multiple (%d)", len(vals))
	}
	if len(vals) == 1 {
		return vals[0]
	}
	return "-"
}
