// view.go: Render, the pure picture of one model at one time: the state by the order of 2.2,
// attention (2.3), the title, the tooltip (2.4 to 2.6) and the closed set of menu rows (3.1 to
// 3.5). Icon, tooltip and menu come from the same call, so they never disagree (3.6).
//
// Choices recorded here:
//   - Enforce that is neither kept nor has a deadline (a daemon started with -mode enforce,
//     which reports trial "" and kept false) shows as Trial with "no deadline": the kernel
//     denies, so the icon must not say monitor, and the six states have no other enforce.
//   - Kept with a trial deadline still set shows Kept; the deadline is listed as another
//     condition that holds.
//   - Without facts (gone, or connected but no status yet) the state is Gone and no fact is
//     shown: the tray never shows a stale or guessed fact (3.3).
//   - Minutes left are rounded up (59 s left reads 1 min), so the tooltip is never behind the
//     deadline; the 1 s tick of the loop keeps it current (2.5).
//
// Fail-safe implications: display only. Only Pause and Quit are enabled rows; no row starts,
// keeps, unkeeps or ends a trial, touches the kill switch or changes the mode (3.5).
package tray

import (
	"strconv"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/client"
)

// cond is one condition of 2.2 and the words the tooltip says for it.
type cond struct {
	state State
	text  string
}

// Render is the view of m at now.
func Render(m Model, now time.Time) View {
	cs := m.conditions(now)
	s := cs[0].state
	return View{
		State:     s,
		Attention: s.Attention(),
		Title:     "snitch: " + s.String(),
		Tooltip:   m.tooltip(cs),
		Menu:      m.menu(s, now),
	}
}

// known is the status to show, or nil when there is none that is current.
func (m Model) known() *api.Status {
	if m.gone {
		return nil
	}
	return m.facts
}

// conditions lists every condition of 2.2 that holds, in order; the first is the state.
func (m Model) conditions(now time.Time) []cond {
	st := m.known()
	if st == nil {
		return []cond{{Gone, Gone.String()}}
	}
	trial := st.Trial != "" || (st.Mode == "enforce" && !st.Kept)
	var cs []cond
	add := func(ok bool, s State, text string) {
		if ok {
			cs = append(cs, cond{s, text})
		}
	}
	add(hookInactive(st), Blind, Blind.String())
	add(st.Kill, Kill, Kill.String())
	add(st.RulesError != "", RulesError, RulesError.String())
	add(st.Kept, Kept, Kept.String())
	add(trial, Trial, Trial.String()+" "+m.until(st.Trial, now))
	add(!st.Kept && !trial, Monitor, Monitor.String())
	return cs
}

// tooltip is the conditions, then learning, paused and not answering, one per line.
func (m Model) tooltip(cs []cond) string {
	lines := make([]string, 0, len(cs)+3)
	for _, c := range cs {
		lines = append(lines, c.text)
	}
	if st := m.known(); st != nil && st.Learning {
		lines = append(lines, "learning")
	}
	if m.paused {
		lines = append(lines, "questions paused")
	}
	if m.gone && m.down == client.NotAnswering {
		lines = append(lines, client.NotAnswering)
	}
	return strings.Join(lines, "\n")
}

// until is a trial deadline in local time with the minutes left, rounded up.
func (m Model) until(trial string, now time.Time) string {
	if trial == "" {
		return "(no deadline)"
	}
	t, err := time.Parse(time.RFC3339, trial)
	if err != nil {
		return "until " + trial
	}
	left := "ending"
	if d := t.Sub(now); d > 0 {
		mins := (d + time.Minute - time.Nanosecond) / time.Minute
		left = strconv.Itoa(int(mins)) + " min left"
	}
	return "until " + t.In(m.loc).Format("15:04") + " (" + left + ")"
}

// stamp is an RFC 3339 time in local time, or the text itself when it does not parse.
func (m Model) stamp(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return s
	}
	return t.In(m.loc).Format("2006-01-02 15:04")
}

// menu is the closed row set: header, the facts while the daemon runs, separator, pause, quit.
func (m Model) menu(s State, now time.Time) []Row {
	rows := []Row{info(RowHeader, "snitch: "+s.String())}
	if st := m.known(); st != nil {
		rows = append(rows, m.factRows(*st, now)...)
		if !m.canNotify || !m.canAct {
			rows = append(rows, info(RowNoAnswer, "Questions cannot be answered here"))
		}
	}
	return append(rows,
		Row{ID: RowSeparator, Separator: true},
		Row{ID: RowPause, Label: "Pause questions", Enabled: true, Check: true, Checked: m.paused},
		Row{ID: RowQuit, Label: "Quit", Enabled: true})
}

// factRows are the daemon's facts as disabled rows (3.1), and its rules error in full (3.2).
func (m Model) factRows(st api.Status, now time.Time) []Row {
	trial := "no trial"
	if st.Trial != "" {
		trial = m.until(st.Trial, now)
	}
	rows := []Row{
		info(RowMode, "Mode: "+st.Mode),
		info(RowTrial, "Trial: "+trial),
		info(RowKept, "Enforce kept: "+choose(st.Kept, "yes", "no")),
		info(RowKill, "Kill switch: "+choose(st.Kill, "set", "clear")),
		info(RowLearning, "Learning: "+choose(st.Learning, "on", "off")),
		info(RowCounts, "Loaded: "+strconv.Itoa(st.Rules.Programs)+" programs, "+
			strconv.Itoa(st.Rules.Rules)+" rules"),
		info(RowRulesFile, "Rules file: "+choose(st.Rules.File != "", st.Rules.File, "none")),
		info(RowOverlay, "Overlay file: "+choose(st.Rules.Overlay != "", st.Rules.Overlay, "none")),
		info(RowDNS, "DNS tap: "+dns(st.DNS)),
		info(RowDaemon, "snitchd "+st.Version+", started "+m.stamp(st.Started)),
		info(RowRole, "Role: "+choose(m.writer, "operator, can answer questions",
			"read only, only the operator can answer")),
	}
	if st.RulesError != "" {
		rows = append(rows, info(RowRulesError, "Rules error: "+st.RulesError))
	}
	if r, ok := hookRow(st); ok {
		rows = append(rows, r)
	}
	return rows
}

// dns is the tap as on with its names and compiled counts, or off with the daemon's reason.
func dns(d *api.DNSStatus) string {
	switch {
	case d == nil:
		return "not reported by this daemon"
	case d.On:
		return "on, " + strconv.FormatUint(d.Names, 10) + " names, " +
			strconv.FormatUint(d.Compiled, 10) + " compiled"
	case d.Reason != "":
		return "off (" + d.Reason + ")"
	}
	return "off"
}

// info is a fact row: shown, never clickable.
func info(id RowID, label string) Row { return Row{ID: id, Label: label} }

func choose(ok bool, yes, no string) string {
	if ok {
		return yes
	}
	return no
}
