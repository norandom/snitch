package main

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync/atomic"

	"github.com/cilium/ebpf"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/rules"
)

// snapshot is one consistent view of the rules: the resolved file and its kernel entries.
// Immutable once published; a reload builds a new one.
type snapshot struct {
	res *rules.Resolved
	ent rules.Entries
}

// state hands the current snapshot to the event pump without locks.
type state struct{ cur atomic.Pointer[snapshot] }

func (s *state) current() *snapshot { return s.cur.Load() }
func (s *state) publish(snap *snapshot) {
	contract.Require(snap != nil && snap.res != nil, "publish needs a built snapshot")
	s.cur.Store(snap)
}

// putDel is the two map operations apply needs, as delegates so tests use a recorder.
type putDel struct {
	put func(key, val any) error
	del func(key any) error
}

func mapOps(m *ebpf.Map) putDel { return putDel{put: m.Put, del: m.Delete} }

// apply writes a change set to the kernel maps: every put first, then the deletes, so a
// reload never has a moment with neither the old nor the new rule in place. Stops at the
// first error and leaves the rest untouched; the caller keeps its previous snapshot.
func apply(programs, rules putDel, ch rules.Changes) error {
	for k, id := range ch.PutPrograms {
		if err := programs.put(exeKey(k), id); err != nil {
			return fmt.Errorf("programs: %w", err)
		}
	}
	for k, v := range ch.PutRules {
		if err := rules.put(k, v); err != nil {
			return fmt.Errorf("rules: %w", err)
		}
	}
	for _, k := range ch.DelPrograms {
		if err := programs.del(exeKey(k)); err != nil {
			return fmt.Errorf("programs: %w", err)
		}
	}
	for _, k := range ch.DelRules {
		if err := rules.del(k); err != nil {
			return fmt.Errorf("rules: %w", err)
		}
	}
	return nil
}

// loadRules reads, resolves and encodes the rules file. A missing file is an empty snapshot
// with a notice; an invalid file is the parser's error (file:line: reason).
func loadRules(path string, notice func(string)) (*snapshot, error) {
	f, err := rules.Load(path)
	if errors.Is(err, fs.ErrNotExist) {
		notice(fmt.Sprintf("no rules loaded: %s does not exist (everything is reported, nothing denied by rule)", path))
		f, err = &rules.File{}, nil
	}
	if err != nil {
		return nil, err
	}
	res, err := rules.Resolve(f, rules.OSFS(notice))
	if err != nil {
		return nil, err
	}
	return &snapshot{res: res, ent: rules.Encode(res)}, nil
}

// summary is the one line printed after every successful apply. A program counts as resolved
// when at least one of its executables is mapped; patterns that matched nothing are listed.
func summary(snap *snapshot) string {
	res := snap.res
	mapped := map[uint32]bool{}
	for _, id := range res.Programs {
		mapped[id] = true
	}
	var unresolved, unmatched []string
	for _, p := range res.File.Programs {
		if !mapped[p.ID] {
			unresolved = append(unresolved, p.Name)
		}
	}
	for _, u := range res.Unresolved {
		unmatched = append(unmatched, u.Program+":"+u.Pattern)
	}
	sort.Strings(unmatched)
	s := fmt.Sprintf("rules: %d programs (%d resolved, %d unresolved%s)", len(res.File.Programs),
		len(res.File.Programs)-len(unresolved), len(unresolved), names(unresolved))
	if len(unmatched) > 0 {
		s += fmt.Sprintf(", %d patterns unmatched%s", len(unmatched), names(unmatched))
	}
	return s + fmt.Sprintf(", %d executables mapped, %d rules effective (%d entries)", len(snap.ent.Programs), len(res.File.Rules), len(snap.ent.Rules))
}

func names(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return " (" + strings.Join(list, ", ") + ")"
}
