// nav.go implements overview navigation, row disclosure, time-window switching,
// activity/name sorting with periodic re-ranking, incremental search, and 500 ms
// throttled row rebuilds over cached table rows.
//
// Fail-safe implications: none on kernel egress. Pure state transitions over Model;
// movement keys never trigger row rebuilds or daemon requests.
package tui

import (
	"fmt"
	"maps"
	"slices"
	"time"
	"unicode/utf8"

	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/conf"
	"github.com/norandom/snitch/internal/table"
)

const (
	rebuildEvery     = 500 * time.Millisecond
	tableChromeLines = 18
)

func rerankIfDue(m Model, now time.Time) Model {
	if m.view.Sort.ByName || m.store.Len() == 0 {
		return m
	}
	resorts := m.resorts()
	if !m.rankedAt.IsZero() && now.Sub(m.rankedAt) < resorts[m.resortIdx%len(resorts)] {
		return m
	}
	m.view.Sort.Rank = table.Rank(m.store)
	m.rankedAt = now
	m.dirty = true
	return m
}

func rebuildIfDue(m Model, now time.Time) Model {
	if !m.dirty || (!m.builtAt.IsZero() && now.Sub(m.builtAt) < rebuildEvery) {
		return m
	}
	return rebuildRows(m, now)
}

func rebuildRows(m Model, now time.Time) Model {
	prevID := m.cursor
	prevIdx := rowIndex(m.rows, prevID)
	m.rows = table.Rows(m.store, m.rules, m.view)
	m.dirty = false
	m.builtAt = now
	m.rebuilds++
	if len(m.rows) == 0 {
		m.cursor, m.top, m.armed = "", 0, ""
		return m
	}
	idx := rowIndex(m.rows, prevID)
	if prevID == "" || idx < 0 {
		idx = max(0, min(len(m.rows)-1, prevIdx))
	}
	return setCursorIndex(m, idx, m.rows[idx].ID != prevID)
}

func setCursorIndex(m Model, idx int, disarm bool) Model {
	m.cursor = m.rows[idx].ID
	m.top = clampTop(m.top, idx, len(m.rows), m.pageSize())
	if disarm {
		m.armed = ""
	}
	return m
}

func onMove(m Model, k Key, _ time.Time) (Model, []Effect) {
	if len(m.rows) == 0 {
		m.cursor, m.top = "", 0
		return m, nil
	}
	idx := max(0, rowIndex(m.rows, m.cursor))
	next := moveIndex(idx, k.Name, len(m.rows), m.pageSize())
	return setCursorIndex(m, next, true), nil
}

func moveIndex(idx int, key string, n, page int) int {
	switch key {
	case "up":
		return max(0, idx-1)
	case "down":
		return min(n-1, idx+1)
	case "pgup":
		return max(0, idx-page)
	case "pgdown":
		return min(n-1, idx+page)
	case "home":
		return 0
	case "end":
		return n - 1
	default:
		return idx
	}
}

func onOpen(m Model, _ Key, now time.Time) (Model, []Effect) {
	row, ok := m.currentRow()
	if !ok || !row.HasKids || row.Open {
		return m, nil
	}
	open := maps.Clone(m.view.Open)
	if open == nil {
		open = make(map[table.RowID]bool, 1)
	}
	open[row.ID] = true
	m.view.Open = open
	m.armed = ""
	return rebuildRows(m, now), nil
}

func onClose(m Model, _ Key, now time.Time) (Model, []Effect) {
	row, ok := m.currentRow()
	if !ok {
		return m, nil
	}
	if row.Open {
		open := maps.Clone(m.view.Open)
		delete(open, row.ID)
		m.view.Open = open
		m.armed = ""
		return rebuildRows(m, now), nil
	}
	if pIdx := rowIndex(m.rows, row.Parent); row.Parent != "" && pIdx >= 0 {
		return setCursorIndex(m, pIdx, true), nil
	}
	return m, nil
}

func onWindow(m Model, k Key, now time.Time) (Model, []Effect) {
	nextWin, ok := nextWindow(m.periods(), m.window, k.Name)
	if !ok || nextWin == m.window {
		return m, nil
	}
	m.window = nextWin
	m.armed = ""
	if !m.up {
		return m, nil
	}
	m, eff := requestSnapshot(m, now)
	return m, []Effect{eff}
}

func nextWindow(periods []string, cur, key string) (string, bool) {
	if len(periods) == 0 {
		return "", false
	}
	if key == "t" {
		idx := slices.Index(periods, cur)
		return periods[(idx+1)%len(periods)], true
	}
	if len(key) == 1 && key[0] >= '1' && key[0] <= '9' {
		pos := int(key[0] - '1')
		if pos < len(periods) {
			return periods[pos], true
		}
	}
	return "", false
}

func onSort(m Model, k Key, now time.Time) (Model, []Effect) {
	m.armed = ""
	if k.Name == "S" {
		m.view.Sort.ByName = true
		m.notice = clean.Const("sorted by name")
		return rebuildRows(m, now), nil
	}
	resorts := m.resorts()
	if !m.view.Sort.ByName {
		m.resortIdx = (m.resortIdx + 1) % len(resorts)
	} else if m.resortIdx >= len(resorts) {
		m.resortIdx = 0
	}
	m.view.Sort.ByName = false
	m.view.Sort.Rank = table.Rank(m.store)
	m.rankedAt = time.Time{}
	if m.store.Len() > 0 {
		m.rankedAt = now
	}
	sec := int64(resorts[m.resortIdx] / time.Second)
	m.notice = clean.Text(fmt.Sprintf("sorted by activity, re-sorted every %ds", sec))
	return rebuildRows(m, now), nil
}

func onSearchOpen(m Model, _ Key, _ time.Time) (Model, []Effect) {
	s := m.view.Search
	m.search = &s
	m.armed = ""
	return m, nil
}

func onSearchClear(m Model, _ Key, now time.Time) (Model, []Effect) {
	hadFilter := m.view.Search != ""
	m.search = nil
	m.view.Search = ""
	m.armed = ""
	if hadFilter {
		return rebuildRows(m, now), nil
	}
	return m, nil
}

func onSearchApply(m Model, _ Key, now time.Time) (Model, []Effect) {
	query := ""
	if m.search != nil {
		query = *m.search
	}
	m.search = nil
	m.armed = ""
	if m.view.Search == query {
		return m, nil
	}
	m.view.Search = query
	return rebuildRows(m, now), nil
}

func onSearchText(m Model, k Key, _ time.Time) (Model, []Effect) {
	if m.search == nil {
		return m, nil
	}
	cur := *m.search
	if k.Name == "backspace" {
		if cur == "" {
			return m, nil
		}
		_, size := utf8.DecodeLastRuneInString(cur)
		next := cur[:len(cur)-size]
		m.search = &next
		return m, nil
	}
	if add := searchKeyText(k); add != "" {
		next := cur + string(clean.Text(add))
		m.search = &next
	}
	return m, nil
}

func searchKeyText(k Key) string {
	if k.Text != "" {
		return k.Text
	}
	if k.Name == "space" {
		return " "
	}
	if utf8.RuneCountInString(k.Name) == 1 {
		return k.Name
	}
	return ""
}

func (m Model) pageSize() int {
	return max(1, m.size.H-tableChromeLines)
}

func (m Model) currentRow() (table.Row, bool) {
	if idx := rowIndex(m.rows, m.cursor); idx >= 0 {
		return m.rows[idx], true
	}
	return table.Row{}, false
}

func (m Model) periods() []string {
	if len(m.conf.Periods) > 0 {
		return m.conf.Periods
	}
	return conf.Default().Periods
}

func (m Model) resorts() []time.Duration {
	if len(m.conf.Resort) > 0 {
		return m.conf.Resort
	}
	return conf.Default().Resort
}

func rowIndex(rows []table.Row, id table.RowID) int {
	for i, r := range rows {
		if r.ID == id {
			return i
		}
	}
	return -1
}

func clampTop(top, idx, n, page int) int {
	if idx < top {
		top = idx
	} else if idx >= top+page {
		top = idx - page + 1
	}
	return max(0, min(top, max(0, n-page)))
}
