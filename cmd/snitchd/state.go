// File rules keep precedence over compiled allows; a failed write retains the
// previous snapshot, and contract failures detach enforcement and fail open.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strings"
	"sync/atomic"
	"syscall"

	"github.com/cilium/ebpf"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/rules"
)

// snapshot is one consistent view of the rules: the resolved file and its kernel entries.
// Immutable once published; a reload builds a new one. rulesErr is the startup fallback's
// record: the overlay was invalid when this snapshot was built, so it holds the base alone
// (Req 5.4: an API write must never refuse the next start); the reloader reports it in the
// facts until a good full reload replaces the snapshot. A reload never publishes one with it.
type snapshot struct {
	res      *rules.Resolved
	ent      rules.Entries
	rulesErr error
}

// state hands the current snapshot to the event pump without locks. onPublish, set once
// before the jobs start, is the API's state event on every publish after it (nil = none).
type state struct {
	cur       atomic.Pointer[snapshot]
	onPublish func()
}

func (s *state) current() *snapshot { return s.cur.Load() }
func (s *state) publish(snap *snapshot) {
	contract.Require(snap != nil && snap.res != nil, "publish needs a built snapshot")
	s.cur.Store(snap)
	if s.onPublish != nil {
		s.onPublish()
	}
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
	return applyWith(programs, rules, ch, nil)
}

// applyWith gives file rules one retry after compiled allows release capacity.
func applyWith(programs, rules putDel, ch rules.Changes, onFull func() bool) error {
	for k, id := range ch.PutPrograms {
		if err := programs.put(exeKey(k), id); err != nil {
			return fmt.Errorf("programs: %w", err)
		}
	}
	for k, v := range ch.PutRules {
		if err := putFile(rules, k, v, onFull); err != nil {
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

// loadRules reads, merges, resolves and encodes the rules: the base file (missing = an empty
// snapshot with a notice; invalid = the parser's error file:line: reason, the operator's
// mistake) and, when overlay is set and exists, the overlay merged over it with precedence.
// An invalid overlay is not an error here: the base alone is returned with the overlay's
// error in snapshot.rulesErr, so startup continues and the reloader decides (it keeps the
// previous rules instead).
func loadRules(path, overlay string, notice func(string)) (*snapshot, error) {
	contract.Require(path != "", "loadRules needs the rules path")
	f, err := rules.Load(path)
	if errors.Is(err, fs.ErrNotExist) {
		notice(fmt.Sprintf("no rules loaded: %s does not exist (everything is reported, nothing denied by rule)", path))
		f, err = &rules.File{}, nil
	}
	if err != nil {
		return nil, err
	}
	f, overlayErr := mergeOverlay(f, overlay)
	res, err := rules.Resolve(f, rules.OSFS(notice))
	if err != nil {
		return nil, err
	}
	return &snapshot{res: res, ent: rules.Encode(res), rulesErr: overlayErr}, nil
}

// mergeOverlay lays the overlay file over base. No overlay path or no file: base unchanged.
// An unreadable or invalid overlay, or one Merge rejects (an unknown program, a duplicate
// name): base unchanged and the error returned for the caller to record.
func mergeOverlay(base *rules.File, overlay string) (*rules.File, error) {
	if overlay == "" {
		return base, nil
	}
	ov, err := rules.LoadOverlay(overlay)
	if errors.Is(err, fs.ErrNotExist) {
		return base, nil
	}
	if err != nil {
		return base, err
	}
	merged, err := rules.Merge(base, ov)
	if err != nil {
		return base, fmt.Errorf("%s: %w", overlay, err)
	}
	return merged, nil
}

// summary is the one line printed after every successful apply. A program counts as resolved
// when at least one of its executables is mapped; patterns that matched nothing are listed.
func summary(snap *snapshot) string { return summaryWith(snap, 0) }

func summaryWith(snap *snapshot, compiled int) string {
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
	s += fmt.Sprintf(", %d executables mapped, %d rules effective (%d entries)", len(snap.ent.Programs), len(res.File.Rules), len(snap.ent.Rules))
	if compiled > 0 {
		s += fmt.Sprintf(" + %d compiled", compiled)
	}
	return s
}

func names(list []string) string {
	if len(list) == 0 {
		return ""
	}
	return " (" + strings.Join(list, ", ") + ")"
}

func putFile(ops putDel, k rules.RuleKey, v rules.RuleVal, onFull func() bool) error {
	err := ops.put(k, v)
	if errors.Is(err, syscall.ENOSPC) && onFull != nil && onFull() {
		return ops.put(k, v)
	}
	return err
}
