// tree.go builds the three-level connection tree (program -> host / IP Addresses -> address)
// plus the unknown bucket from a Store. Titles and verdicts are sanitised via internal/clean,
// while RowIDs and Keys preserve the raw daemon values.
//
// Fail-safe implications: none on kernel egress. Pure data transformation over store entries.
package table

import (
	"cmp"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/ask"
	"github.com/norandom/snitch/internal/clean"
)

// RowID uniquely and stably identifies a row across snapshots and summaries.
type RowID string

// Level names the depth/kind of a row in the connection tree.
type Level int

const (
	Program Level = iota
	Host
	Group
	Address
	Bucket
)

// Row is one visible line of the connection tree with aggregated counts and sanitised text.
type Row struct {
	ID, Parent    RowID
	Level         Level
	Depth         int
	Title         clean.Safe
	Open, HasKids bool
	Last          time.Time
	Sent          uint64
	Rate          float64
	Allow, Deny   uint64
	Verdict       clean.Safe
	Blocked       bool
	Keys          []Key
}

// Sort configures row ordering within each level.
type Sort struct {
	ByName bool
	Rank   map[RowID]int
}

// View configures which rows are open, how they are sorted, and the active search filter.
type View struct {
	Open   map[RowID]bool
	Sort   Sort
	Search string
}

// Rules holds the daemon's effective rules and declared programs for block-marker lookup.
type Rules struct {
	Views    []api.RuleView
	Programs []api.ProgramView
	Overlay  string
}

type leaf struct {
	key   Key
	entry api.Entry
	last  time.Time
}

type progGroup struct {
	who          string
	isPath       bool
	all, unnamed []leaf
	hosts        map[string][]leaf
}

// Rows returns the visible rows of s in tree order for v, sorted at each level, filtered by
// v.Search, and marked Blocked where an effective deny rule covers the row.
func Rows(s Store, r Rules, v View) []Row {
	if s.Len() == 0 {
		return nil
	}
	progs, bucket := groupEntries(s)
	searching := v.Search != ""
	tops := sortRows(topRows(progs, bucket, v.Open), v.Sort)
	out := make([]Row, 0, len(tops))
	for _, top := range tops {
		top.Blocked = rowBlocked(top, s, r)
		if searching && top.HasKids {
			top.Open = true
		}
		out = append(out, top)
		if top.Level != Program || !top.Open {
			continue
		}
		out = appendChildren(out, progs[top.Keys[0].Who], top.ID, s, r, v)
	}
	if searching {
		return Filter(out, v.Search)
	}
	return out
}

func appendChildren(out []Row, pg *progGroup, parent RowID, s Store, r Rules, v View) []Row {
	searching := v.Search != ""
	mids, midLeaves := midRows(pg, parent, v.Open)
	for _, mid := range sortRows(mids, v.Sort) {
		mid.Blocked = rowBlocked(mid, s, r)
		if searching && mid.HasKids {
			mid.Open = true
		}
		out = append(out, mid)
		if !mid.Open {
			continue
		}
		for _, lf := range sortRows(leafRows(midLeaves[mid.ID], mid.ID), v.Sort) {
			lf.Blocked = rowBlocked(lf, s, r)
			out = append(out, lf)
		}
	}
	return out
}

func rowBlocked(row Row, s Store, r Rules) bool {
	if len(r.Views) == 0 || len(row.Keys) == 0 || row.Level == Bucket {
		return false
	}
	if row.Level == Program {
		return progBlocked(row.Keys, r)
	}
	for _, k := range row.Keys {
		e, _ := s.Get(k)
		if !isBlocked(r, k, e.Name, Address) {
			return false
		}
	}
	return true
}

func progBlocked(keys []Key, r Rules) bool {
	who := keys[0].Who
	has4, has6 := rowFamilies(keys)
	if !has4 && !has6 {
		return isBlocked(r, Key{Who: who}, "", Program)
	}
	return (!has4 || isBlocked(r, Key{Who: who, Addr: "0.0.0.0"}, "", Program)) &&
		(!has6 || isBlocked(r, Key{Who: who, Addr: "::"}, "", Program))
}

func isBlocked(r Rules, k Key, name string, at Level) bool {
	if at == Address {
		if addr, ok := parseKeyAddr(k.Addr); ok && ask.Local(addr) {
			return false
		}
	}
	cov := Cover(r, k, name, at)
	return cov.Found && cov.Rule.Verdict == "deny"
}

func groupEntries(s Store) (map[string]*progGroup, []leaf) {
	progs := make(map[string]*progGroup)
	var bucket []leaf
	for k, e := range s.entries {
		lf := leaf{key: k, entry: e, last: parseLastSeen(e.LastSeen)}
		if isBucket(e) {
			bucket = append(bucket, lf)
			continue
		}
		pg := progs[k.Who]
		if pg == nil {
			pg = &progGroup{who: k.Who, isPath: e.Program == ask.Unknown && e.Path != "", hosts: make(map[string][]leaf)}
			progs[k.Who] = pg
		}
		pg.all = append(pg.all, lf)
		if e.Name != "" {
			pg.hosts[e.Name] = append(pg.hosts[e.Name], lf)
		} else {
			pg.unnamed = append(pg.unnamed, lf)
		}
	}
	return progs, bucket
}

func topRows(progs map[string]*progGroup, bucket []leaf, open map[RowID]bool) []Row {
	rows := make([]Row, 0, len(progs)+1)
	for _, pg := range progs {
		id := tupleID("P", pg.who)
		rows = append(rows, makeRow(id, "", Program, 0, progTitle(pg.who, pg.isPath), open[id], true, pg.all))
	}
	if len(bucket) > 0 {
		rows = append(rows, makeRow("B:unknown", "", Bucket, 0, clean.Const("unknown"), false, false, bucket))
	}
	slices.SortFunc(rows, compareRow)
	return rows
}

func midRows(pg *progGroup, parent RowID, open map[RowID]bool) ([]Row, map[RowID][]leaf) {
	rows := make([]Row, 0, len(pg.hosts)+1)
	byID := make(map[RowID][]leaf, len(pg.hosts)+1)
	for name, leaves := range pg.hosts {
		id := tupleID("H", pg.who, name)
		rows = append(rows, makeRow(id, parent, Host, 1, clean.Name(name), open[id], true, leaves))
		byID[id] = leaves
	}
	if len(pg.unnamed) > 0 {
		id := tupleID("G", pg.who)
		rows = append(rows, makeRow(id, parent, Group, 1, clean.Const("IP Addresses"), open[id], true, pg.unnamed))
		byID[id] = pg.unnamed
	}
	slices.SortFunc(rows, compareRow)
	return rows, byID
}

func leafRows(leaves []leaf, parent RowID) []Row {
	rows := make([]Row, 0, len(leaves))
	for _, lf := range leaves {
		id := tupleID("A", lf.key.Who, lf.key.Addr, lf.key.Proto, strconv.Itoa(int(lf.key.Port)))
		rows = append(rows, makeRow(id, parent, Address, 2, addrTitle(lf.key), false, false, []leaf{lf}))
	}
	slices.SortFunc(rows, compareRow)
	return rows
}

func makeRow(id, parent RowID, lvl Level, depth int, title clean.Safe, open, hasKids bool, leaves []leaf) Row {
	sorted := slices.Clone(leaves)
	slices.SortFunc(sorted, compareLeaf)
	r := Row{
		ID: id, Parent: parent, Level: lvl, Depth: depth, Title: title,
		Open: open && hasKids, HasKids: hasKids, Keys: make([]Key, len(sorted)),
	}
	for i, lf := range sorted {
		r.Keys[i] = lf.key
		r.Sent += lf.entry.BytesSent
		r.Rate += lf.entry.Rate
		r.Allow += lf.entry.AllowCount
		r.Deny += lf.entry.DenyCount
		if lf.last.After(r.Last) {
			r.Last = lf.last
		}
		if r.Verdict == "" && lf.entry.Verdict != "" {
			r.Verdict = clean.Text(lf.entry.Verdict)
		}
	}
	return r
}

func isBucket(e api.Entry) bool {
	return e.Program == ask.Unknown && e.Path == "" && e.Addr == ""
}

func parseLastSeen(s string) time.Time {
	t, _ := time.Parse(time.RFC3339Nano, s)
	return t
}

func progTitle(who string, isPath bool) clean.Safe {
	if isPath {
		return clean.Path(who)
	}
	return clean.Text(who)
}

func addrTitle(k Key) clean.Safe {
	hp := net.JoinHostPort(k.Addr, strconv.Itoa(int(k.Port)))
	if k.Proto == "" {
		return clean.Text(hp)
	}
	return clean.Text(hp + " " + k.Proto)
}

func tupleID(prefix string, parts ...string) RowID {
	var b strings.Builder
	b.WriteString(prefix)
	for _, p := range parts {
		b.WriteByte(':')
		b.WriteString(strconv.Itoa(len(p)))
		b.WriteByte(':')
		b.WriteString(p)
	}
	return RowID(b.String())
}

func compareLeaf(a, b leaf) int {
	return cmp.Or(b.last.Compare(a.last), cmp.Compare(a.key.Who, b.key.Who),
		cmp.Compare(a.key.Addr, b.key.Addr), cmp.Compare(a.key.Proto, b.key.Proto), cmp.Compare(a.key.Port, b.key.Port))
}

func compareRow(a, b Row) int {
	return cmp.Or(b.Last.Compare(a.Last), cmp.Compare(a.ID, b.ID))
}
