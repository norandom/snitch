package main

import (
	"context"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
	"github.com/norandom/snitch/internal/rules"
)

const (
	filePollPeriod  = 2 * time.Second  // Req 4.1: a changed file applies within 5 s
	reResolvePeriod = 10 * time.Second // Req 4.3: a replaced executable is matched within 10 s
)

// reloader rebuilds the snapshot from the rules files (base plus overlay) or from a fresh
// resolution of the same files, applies the difference to the maps and publishes; on any
// failure the previous snapshot stays current and the error is kept for the facts until a
// full reload succeeds. Delegates for the maps, the loader and the clock keep it testable.
type reloader struct {
	mu        sync.Mutex // one reload at a time: the diff is computed against the current base
	path      string
	overlay   string
	paths     []string // the files the watch stamps: rules and overlay (the operator file has its own watch)
	st        *state
	programs  putDel
	rules     putDel
	load      func(path, overlay string, notice func(string)) (*snapshot, error)
	log       func(string)
	now       func() time.Time // nil = time.Now
	stamps    []fileStamp
	lastErr   error // the last failed reload; nil after a successful full reload
	lastErrAt time.Time
}

// rulesError is the facts' view (Req 5.4): the last failed reload, or, when every reload
// since succeeded or none ran, the startup fallback recorded on the current snapshot.
func (r *reloader) rulesError() (time.Time, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.lastErr != nil {
		return r.lastErrAt, r.lastErr
	}
	if cur := r.st.current(); cur != nil && cur.rulesErr != nil {
		return time.Time{}, cur.rulesErr
	}
	return time.Time{}, nil
}

func (r *reloader) clock() time.Time {
	if r.now == nil {
		return time.Now()
	}
	return r.now()
}

// fileStamp is what a poll compares: editors replace files (new inode) or rewrite them.
type fileStamp struct {
	mtime time.Time
	size  int64
	ino   uint64
}

func stampOf(path string) (fileStamp, bool) {
	st, err := os.Stat(path)
	if err != nil {
		return fileStamp{}, false
	}
	ino, _ := st.Sys().(*syscall.Stat_t)
	s := fileStamp{mtime: st.ModTime(), size: st.Size()}
	if ino != nil {
		s.ino = ino.Ino
	}
	return s, true
}

// reload builds a new snapshot (full: re-read the files; otherwise re-resolve the current
// ones), applies the diff and publishes. Returns whether a new snapshot is current. On a
// reload an invalid overlay is a failure like an invalid base (the previous rules stay, the
// loader's startup fallback is not taken); any failure is recorded for the facts and a
// successful full reload clears it (a re-resolve reads no file, so it leaves the record).
func (r *reloader) reload(full bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.st.current()
	next, ch, err := r.next(cur, full)
	if err == nil && !full && ch.Empty() {
		return true // a re-resolve that changed nothing: no apply, no publish, no summary line
	}
	if err == nil {
		err = apply(r.programs, r.rules, ch)
	}
	if err != nil {
		r.lastErr, r.lastErrAt = err, r.clock()
		r.log(fmt.Sprintf("reload failed, keeping the previous rules: %v", err))
		return false
	}
	contract.Invariant(r.st.current() == cur, "the base snapshot moved during a reload")
	if full {
		r.lastErr = nil
	}
	r.st.publish(next)
	fmt.Println(summary(next))
	return true
}

// next builds the candidate snapshot (a full load, or a re-resolve of the current file) and
// the map diff against the current one; an invalid overlay counts as an error on a full load.
func (r *reloader) next(cur *snapshot, full bool) (*snapshot, rules.Changes, error) {
	var next *snapshot
	var err error
	if full || cur == nil {
		next, err = r.load(r.path, r.overlay, r.log)
	} else {
		next, err = reresolve(cur, r.log)
	}
	if err == nil && next.rulesErr != nil && full {
		err = next.rulesErr
	}
	if err != nil {
		return nil, rules.Changes{}, err
	}
	return next, rules.Diff(cur.ent, next.ent), nil
}

// reresolve keeps the parsed file (and its startup record) and only looks at the executables
// again.
func reresolve(cur *snapshot, notice func(string)) (*snapshot, error) {
	res, err := rules.Resolve(cur.res.File, rules.OSFS(notice))
	if err != nil {
		return nil, err
	}
	return &snapshot{res: res, ent: rules.Encode(res), rulesErr: cur.rulesErr}, nil
}

// watchFile polls every path in r.paths and reloads fully when one changed (or appeared or
// vanished): a removed overlay reloads to the base alone.
func (r *reloader) watchFile() jobs.Job {
	r.stampAll()
	return jobs.Every(filePollPeriod, r.pollFiles)
}

func (r *reloader) stampAll() {
	contract.Require(len(r.paths) > 0, "watchFile needs the paths to watch")
	r.stamps = make([]fileStamp, len(r.paths))
	for i, p := range r.paths {
		r.stamps[i], _ = stampOf(p)
	}
}

func (r *reloader) pollFiles(context.Context) error {
	changed := false
	for i, p := range r.paths {
		if now, _ := stampOf(p); now != r.stamps[i] {
			r.stamps[i], changed = now, true
		}
	}
	if changed {
		r.reload(true)
	}
	return nil
}

// reResolve re-checks the executables so an upgraded tool is matched again.
func (r *reloader) reResolve() jobs.Job {
	return jobs.Every(reResolvePeriod, func(context.Context) error { r.reload(false); return nil })
}

// onHUP reloads fully on SIGHUP.
func (r *reloader) onHUP() jobs.Job {
	return jobs.OnSignal(func(os.Signal) error { r.reload(true); return nil }, syscall.SIGHUP)
}
