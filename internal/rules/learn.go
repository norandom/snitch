package rules

import (
	"fmt"
	"net/netip"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/contract"
)

// Observation is one connection the kernel allowed in monitor mode that no rule covered.
type Observation struct {
	Path    string // executable path, "" when the process was gone before it could be read
	Exe     ExeKey
	Program string // configured program name when one maps the executable, else ""
	Addr    netip.Addr
	Proto   Proto
	Port    uint16
	At      time.Time
}

// subject is the executable a learned rule is attributed to: its path, or its kernel identity
// when the path was unknown. The configured program name, if any, is kept apart as the name
// to print, so the key never depends on how the operator named the program.
type subject struct {
	path string
	exe  ExeKey // only when path == ""
}

type learnKey struct {
	subject
	addr  netip.Addr
	proto Proto
	port  uint16
}

type learnEntry struct {
	count       uint64
	first, last time.Time
}

// Learned aggregates observations; File projects them to a loadable rules file. A working set,
// mutated only through Observe; callers hold the only reference.
type Learned struct {
	entries map[learnKey]*learnEntry
	names   map[subject]string // configured names, preferred over derived ones
	dirty   bool
}

// exeNote is how a program without a path keeps its identity in the file (its note field).
const exeNote = "exe ino=%d dev=%d"

// NewLearned starts from an earlier learned file (nil for none), so counts continue.
func NewLearned(seed *File) *Learned {
	l := &Learned{entries: map[learnKey]*learnEntry{}, names: map[subject]string{}}
	if seed == nil {
		return l
	}
	subjects := map[string]subject{}
	for _, p := range seed.Programs {
		s := seedSubject(p)
		subjects[p.Name] = s
		if p.Name != derivedName(s) && !isSuffixed(p.Name, derivedName(s)) {
			l.names[s] = p.Name
		}
	}
	for _, r := range seed.Rules {
		var port uint16
		if len(r.Ports) > 0 {
			port = r.Ports[0]
		}
		k := learnKey{subjects[r.Program], r.To.Addr(), r.Proto, port}
		l.entries[k] = &learnEntry{count: max(r.Count, 1), first: r.First, last: r.Last}
	}
	return l
}

// seedSubject recovers a program's executable: its first path, or the identity in its note.
func seedSubject(p Program) subject {
	if len(p.Paths) > 0 {
		return subject{path: p.Paths[0]}
	}
	var s subject
	if n, _ := fmt.Sscanf(p.Note, exeNote, &s.exe.Ino, &s.exe.Dev); n != 2 {
		// the note was edited away: the derived name still carries the identity
		fmt.Sscanf(p.Name, "unknown-%d-%d", &s.exe.Ino, &s.exe.Dev) //nolint:errcheck // zero identity when absent
	}
	return s
}

// isSuffixed reports whether name is base-<digits>, the shape of a collision-suffixed name.
func isSuffixed(name, base string) bool {
	rest, ok := strings.CutPrefix(name, base+"-")
	if !ok || rest == "" {
		return false
	}
	return strings.Trim(rest, "0123456789") == ""
}

// Observe records o and reports whether the state changed (it always does: the count grows).
// Times are kept at second precision, which is what the file carries.
func (l *Learned) Observe(o Observation) bool {
	contract.Require(o.Addr.IsValid(), "an observation needs a destination address")
	s := subjectOf(o)
	if o.Program != "" {
		l.names[s] = o.Program
	}
	at := o.At.Truncate(time.Second)
	k := learnKey{s, o.Addr.Unmap(), o.Proto, o.Port}
	e, ok := l.entries[k]
	if !ok {
		e = &learnEntry{first: at, last: at}
		l.entries[k] = e
	}
	e.count++
	if at.Before(e.first) || e.first.IsZero() {
		e.first = at
	}
	if at.After(e.last) {
		e.last = at
	}
	l.dirty = true
	return true
}

func subjectOf(o Observation) subject {
	if o.Path != "" {
		return subject{path: o.Path}
	}
	return subject{exe: o.Exe}
}

// Dirty reports whether something was observed since the last File().
func (l *Learned) Dirty() bool { return l.dirty }

// File projects the learned entries to a rules file: one program per subject, one allow rule
// per destination. Deterministic (sorted) and valid for Parse; clears the dirty flag.
func (l *Learned) File() *File {
	names := l.programNames()
	f := &File{}
	for _, s := range sortedSubjects(names) {
		p := Program{Name: names[s], Paths: pathsOf(s), ID: uint32(len(f.Programs) + 1)}
		if s.path == "" {
			p.Note = fmt.Sprintf(exeNote, s.exe.Ino, s.exe.Dev)
		}
		f.Programs = append(f.Programs, p)
	}
	for _, k := range l.sortedKeys(names) {
		e := l.entries[k]
		r := Rule{Program: names[k.subject], To: netip.PrefixFrom(k.addr, k.addr.BitLen()), Proto: k.proto,
			Verdict: Allow, Count: e.count, First: e.first, Last: e.last, ID: uint32(len(f.Rules) + 1)}
		if k.port != 0 {
			r.Ports = []uint16{k.port}
		}
		f.Rules = append(f.Rules, r)
	}
	l.dirty = false
	return f
}

func pathsOf(s subject) []string {
	if s.path == "" {
		return []string{}
	}
	return []string{s.path}
}

// programNames gives every subject a unique, valid program name: the configured name, else
// the path's base name ("-2", "-3" on collision, in path order), else unknown-<ino>-<dev>.
func (l *Learned) programNames() map[subject]string {
	subjects := map[subject]bool{}
	for k := range l.entries {
		subjects[k.subject] = true
	}
	names := map[subject]string{}
	taken := map[string]bool{}
	for _, s := range sortedSubjects(subjects) {
		base := l.names[s]
		if base == "" {
			base = derivedName(s)
		}
		name := base
		for n := 2; taken[name]; n++ {
			name = fmt.Sprintf("%s-%d", base, n)
		}
		taken[name], names[s] = true, name
	}
	return names
}

// derivedName is the name a subject gets without a configured one.
func derivedName(s subject) string {
	if s.path == "" {
		return fmt.Sprintf("unknown-%d-%d", s.exe.Ino, s.exe.Dev)
	}
	if b := path.Base(s.path); b != anyProgram {
		return b
	}
	return anyProgram + "-exe"
}

func sortedSubjects[V any](m map[subject]V) []subject {
	out := make([]subject, 0, len(m))
	for s := range m {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.path != b.path {
			return a.path < b.path
		}
		return a.exe.Ino < b.exe.Ino || (a.exe.Ino == b.exe.Ino && a.exe.Dev < b.exe.Dev)
	})
	return out
}

func (l *Learned) sortedKeys(names map[subject]string) []learnKey {
	out := make([]learnKey, 0, len(l.entries))
	for k := range l.entries {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if names[a.subject] != names[b.subject] {
			return names[a.subject] < names[b.subject]
		}
		if c := a.addr.Compare(b.addr); c != 0 {
			return c < 0
		}
		return a.proto < b.proto || (a.proto == b.proto && a.port < b.port)
	})
	return out
}
