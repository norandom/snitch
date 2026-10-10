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

// reloader rebuilds the snapshot from the rules file or from a fresh resolution of the same
// file, applies the difference to the maps and publishes; on any failure the previous
// snapshot stays current. Delegates for the maps and the loader keep it testable.
type reloader struct {
	mu       sync.Mutex // one reload at a time: the diff is computed against the current base
	path     string
	st       *state
	programs putDel
	rules    putDel
	load     func(path string, notice func(string)) (*snapshot, error)
	log      func(string)
	stamp    fileStamp
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

// reload builds a new snapshot (full: re-read the file; otherwise re-resolve the current
// file), applies the diff and publishes. Returns whether a new snapshot is current.
func (r *reloader) reload(full bool) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	cur := r.st.current()
	var next *snapshot
	var err error
	if full || cur == nil {
		next, err = r.load(r.path, r.log)
	} else {
		next, err = reresolve(cur, r.log)
	}
	if err == nil {
		err = apply(r.programs, r.rules, rules.Diff(cur.ent, next.ent))
	}
	if err != nil {
		r.log(fmt.Sprintf("reload failed, keeping the previous rules: %v", err))
		return false
	}
	contract.Invariant(r.st.current() == cur, "the base snapshot moved during a reload")
	r.st.publish(next)
	fmt.Println(summary(next))
	return true
}

// reresolve keeps the parsed file and only looks at the executables again.
func reresolve(cur *snapshot, notice func(string)) (*snapshot, error) {
	res, err := rules.Resolve(cur.res.File, rules.OSFS(notice))
	if err != nil {
		return nil, err
	}
	return &snapshot{res: res, ent: rules.Encode(res)}, nil
}

// watchFile polls the rules file and reloads fully when it changed (or appeared/vanished).
func (r *reloader) watchFile() jobs.Job {
	r.stamp, _ = stampOf(r.path)
	return jobs.Every(filePollPeriod, func(context.Context) error {
		now, _ := stampOf(r.path)
		if now != r.stamp {
			r.stamp = now
			r.reload(true)
		}
		return nil
	})
}

// reResolve re-checks the executables so an upgraded tool is matched again.
func (r *reloader) reResolve() jobs.Job {
	return jobs.Every(reResolvePeriod, func(context.Context) error { r.reload(false); return nil })
}

// onHUP reloads fully on SIGHUP.
func (r *reloader) onHUP() jobs.Job {
	return jobs.OnSignal(func(os.Signal) error { r.reload(true); return nil }, syscall.SIGHUP)
}
