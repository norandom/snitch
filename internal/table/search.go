// search.go filters connection tree rows by case-insensitive substring match against
// each row's path (program › host › address), retaining matching rows and their parents.
//
// Fail-safe implications: none on kernel egress. Pure data filtering over table rows.
package table

import (
	"slices"
	"strings"
)

const pathSep = " › "

// Filter returns the rows whose path (program › host › address) contains query without
// regard to case, together with their parent rows, preserving relative order.
func Filter(rows []Row, query string) []Row {
	if len(rows) == 0 || query == "" {
		return slices.Clone(rows)
	}
	needle := strings.ToLower(query)
	indexByID := make(map[RowID]int, len(rows))
	for i, r := range rows {
		indexByID[r.ID] = i
	}
	paths := make([]string, len(rows))
	keep := make([]bool, len(rows))
	for i := range rows {
		if strings.Contains(rowPathLower(rows, indexByID, paths, i), needle) {
			markWithParents(rows, indexByID, keep, i)
		}
	}
	out := make([]Row, 0, len(rows))
	for i, r := range rows {
		if keep[i] {
			out = append(out, r)
		}
	}
	return out
}

func rowPathLower(rows []Row, indexByID map[RowID]int, cache []string, idx int) string {
	if cache[idx] != "" {
		return cache[idx]
	}
	var parts []string
	cur := idx
	for range len(rows) {
		r := rows[cur]
		parts = append(parts, strings.ToLower(string(r.Title)))
		if r.Parent == "" {
			break
		}
		pIdx, ok := indexByID[r.Parent]
		if !ok {
			break
		}
		cur = pIdx
	}
	slices.Reverse(parts)
	cache[idx] = strings.Join(parts, pathSep)
	return cache[idx]
}

func markWithParents(rows []Row, indexByID map[RowID]int, keep []bool, idx int) {
	cur := idx
	for range len(rows) {
		if keep[cur] {
			return
		}
		keep[cur] = true
		p := rows[cur].Parent
		if p == "" {
			return
		}
		pIdx, ok := indexByID[p]
		if !ok {
			return
		}
		cur = pIdx
	}
}
