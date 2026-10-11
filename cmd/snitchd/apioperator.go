// apioperator.go: the operator file followed at runtime (design "Operator": re-read on the
// 2 s file stamp like the rules file). The stamp is everything acceptance depends on (inode,
// size, mtime, owner, mode, presence): a change re-reads the file through operatorUID, with
// its refusals and their one log line, and hands the uid to the server for the connections
// from then on. An unchanged file is never re-read, so the journal stays quiet. Fail-safe: a
// loose file demotes to root-only, it never promotes.
package main

import (
	"context"
	"os"
	"syscall"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
)

type operatorWatch struct {
	path   string
	stat   func(string) (os.FileInfo, error)
	lookup func(string) (uint32, error)
	log    func(string)
	set    func(uint32) // the server's SetOperator
	last   opStamp
}

// opStamp is what a poll compares; absent is the zero value.
type opStamp struct {
	present bool
	mtime   time.Time
	size    int64
	mode    os.FileMode
	ino     uint64
	uid     uint32
}

func (w *operatorWatch) require() {
	contract.Require(w.path != "" && w.stat != nil && w.lookup != nil && w.log != nil && w.set != nil,
		"operatorWatch: incomplete delegates")
}

// job stamps the file as the startup read saw it, then polls.
func (w *operatorWatch) job() jobs.Job {
	w.require()
	w.last = w.stamp()
	return jobs.Every(filePollPeriod, w.tick)
}

func (w *operatorWatch) tick(context.Context) error {
	w.require()
	if now := w.stamp(); now != w.last {
		w.last = now
		w.set(operatorUID(w.path, w.lookup, w.stat, w.log))
	}
	return nil
}

func (w *operatorWatch) stamp() opStamp {
	info, err := w.stat(w.path)
	if err != nil {
		return opStamp{}
	}
	s := opStamp{present: true, mtime: info.ModTime(), size: info.Size(), mode: info.Mode()}
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		s.ino, s.uid = st.Ino, st.Uid
	}
	return s
}

// operatorJob is the watch over the real file for the installed server.
func (d *daemon) operatorJob(path string) jobs.Job {
	contract.Require(d.api.server != nil, "operatorJob needs the installed server")
	w := &operatorWatch{path: path, stat: os.Stat, lookup: lookupUID, log: d.log, set: d.api.server.SetOperator}
	return w.job()
}
