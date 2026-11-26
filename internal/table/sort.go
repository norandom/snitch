// sort.go freezes activity order into a Rank map and provides level sorting by frozen
// activity (placing rows that appeared since the last re-sort on top) or by title
// without regard to case.
//
// Fail-safe implications: none on kernel egress. Pure data ordering over table rows.
package table

import (
	"cmp"
	"slices"
	"strings"
)

// Rank returns the frozen activity rank of every row across all levels of s, ordered with
// the most recently active rows first. Rows absent from the returned map are treated as
// new and sort ahead of ranked rows until the next Rank call.
func Rank(s Store) map[RowID]int {
	if s.Len() == 0 {
		return nil
	}
	progs, bucket := groupEntries(s)
	tops := topRows(progs, bucket, nil)
	all := make([]Row, 0, len(tops)+s.Len()*2)
	all = append(all, tops...)
	for _, top := range tops {
		if top.Level != Program {
			continue
		}
		pg := progs[top.Keys[0].Who]
		mids, midLeaves := midRows(pg, top.ID, nil)
		all = append(all, mids...)
		for _, mid := range mids {
			all = append(all, leafRows(midLeaves[mid.ID], mid.ID)...)
		}
	}
	slices.SortFunc(all, compareRow)
	rank := make(map[RowID]int, len(all))
	for i, r := range all {
		rank[r.ID] = i
	}
	return rank
}

func sortRows(rows []Row, s Sort) []Row {
	out := slices.Clone(rows)
	slices.SortFunc(out, compareSort(s))
	return out
}

func compareSort(s Sort) func(a, b Row) int {
	if s.ByName {
		return compareByName
	}
	return func(a, b Row) int {
		return compareByActivity(s.Rank, a, b)
	}
}

func compareByName(a, b Row) int {
	return cmp.Or(
		cmp.Compare(strings.ToLower(string(a.Title)), strings.ToLower(string(b.Title))),
		cmp.Compare(string(a.Title), string(b.Title)),
		cmp.Compare(a.ID, b.ID),
	)
}

func compareByActivity(rank map[RowID]int, a, b Row) int {
	ra, okA := rank[a.ID]
	rb, okB := rank[b.ID]
	if !okA && !okB {
		return compareRow(a, b)
	}
	if !okA {
		return -1
	}
	if !okB {
		return 1
	}
	return cmp.Or(cmp.Compare(ra, rb), compareRow(a, b))
}
