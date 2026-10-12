package main

import (
	"context"
	"os"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
	"github.com/norandom/snitch/internal/status"
	"github.com/norandom/snitch/internal/trial"
)

// follower makes the daemon's mode follow the trial and kept files (source files): one
// decision at startup, then one per heartbeat tick. Delegates so tests run it on a memory
// store with a fake clock; last is the previous decision, for the transition log lines.
type follower struct {
	store trial.Store
	boot  string
	now   func() time.Time
	learn bool                     // learning never denies: passed to every decision (Req 2.4)
	apply func(trial.Mode, string) // d.setMode
	log   func(string)
	last  trial.Decision
}

func (f *follower) require() {
	contract.Require(f.boot != "" && f.now != nil && f.apply != nil && f.log != nil, "follower: incomplete delegates")
}

// job is the follow job: a decision on every heartbeat tick, so a file written by the CLI or
// removed from a console changes the mode within one period (Req 2.1, 3.4, 5.4).
func (f *follower) job() jobs.Job { return jobs.Every(heartbeatPeriod, f.tick) }

func (f *follower) tick(context.Context) error { f.require(); f.decide(f.now()); return nil }

// decide is one tick: Read → Decide → remove the spent trial → apply on a change (the same
// decision again is silent) → clear the kept file's problem → remember. The spent trial goes
// before apply: the state event apply sends (daemon-api Req 4.5) reads the store and must not
// carry a deadline that just passed; its removal failure is logged after the mode line, where
// the journal has it. Learning removes nothing: the files are not read for their meaning, so
// a trial started by mistake is still there to be ended.
func (f *follower) decide(now time.Time) {
	f.require()
	st := f.store.Read()
	dec := trial.Decide(now, f.boot, st, f.learn)
	var spent error
	if !f.learn && dec.ClearTrial {
		spent = f.store.ClearTrial()
	}
	if f.changed(dec) {
		f.apply(dec.Mode, f.reason(st, dec))
	}
	if !f.learn {
		f.failed(spent, f.store.TrialPath())
		f.clearKept(st, dec)
	}
	f.last = dec
}

// changed says whether a decision deserves a line: the first one, a mode change, another
// enforce (an extended deadline, a kept trial; the same kept enforce once its broken trial
// file is gone is not another one), or monitor spending a file that appeared. Monitor on an
// empty directory after monitor is the continuation of an end already logged.
func (f *follower) changed(dec trial.Decision) bool {
	switch {
	case dec == f.last:
		return false
	case f.last.Reason == "" || dec.Mode != f.last.Mode:
		return true
	case dec.Mode == trial.Enforce:
		return family(dec.Reason) != family(f.last.Reason)
	}
	return dec.ClearTrial
}

// family is a reason without the trial-file problem Decide appends after "; ".
func family(reason string) string {
	head, _, _ := strings.Cut(reason, "; ")
	return head
}

// reason is Decide's reason, except for the transition Decide cannot see: enforce was on and
// the directory is now empty, which is the operator's doing (rm from a console, `snitchd end`
// or `unkeep`; Req 3.4, 5.4) and the journal says so instead of "no trial".
func (f *follower) reason(st trial.State, dec trial.Decision) string {
	empty := st.Trial == nil && !st.Kept && len(st.Problems) == 0
	if f.last.Mode != trial.Enforce || dec.Mode != trial.Monitor || !empty {
		return dec.Reason
	}
	if strings.HasPrefix(f.last.Reason, "enforce kept") {
		return "enforce unkept: file removed"
	}
	return "trial ended by the operator: file removed"
}

// clearKept removes a kept file that Read reported as a Problem (Decide only ever clears the
// trial, decide removed it already: ended, foreign boot, malformed, superseded by keep). A
// problem the reason does not already carry (a broken kept file next to a live trial) gets
// its own line when the file goes (Req 3.5: log what was found). A failed removal is logged
// and retried on the next tick; the mode is already the safe one.
func (f *follower) clearKept(st trial.State, dec trial.Decision) {
	for _, p := range st.Problems {
		if !strings.HasPrefix(p, f.store.KeptPath()+":") {
			continue
		}
		if !f.failed(f.store.ClearKept(), f.store.KeptPath()) && !strings.Contains(dec.Reason, p) {
			f.log("file removed: " + p)
		}
	}
}

// failed logs a removal's error (nil is a success, or nothing removed) and says whether it failed.
func (f *follower) failed(err error, path string) bool {
	if err == nil {
		return false
	}
	f.log("remove " + path + ": " + err.Error())
	return true
}

// statusWriter rewrites the status file on every heartbeat tick: what the CLI shows and
// checks (Req 7.1, 2.4, 2.7). A failed write is logged once per streak and never ends the
// run; the file is for the operator, the kernel does not need it.
type statusWriter struct {
	path      string
	rulesFile string
	source    modeSource
	learn     bool
	pid       int
	store     trial.Store
	mode      func() trial.Mode
	snap      func() *snapshot
	dns       func() string
	now       func() time.Time
	write     func(string, status.Record) error // status.Write
	log       func(string)
	lastErr   string
}

func (w *statusWriter) job() jobs.Job { return jobs.Every(heartbeatPeriod, w.tick) }

func (w *statusWriter) tick(context.Context) error {
	contract.Require(w.path != "" && w.mode != nil && w.snap != nil && w.now != nil && w.write != nil && w.log != nil,
		"status writer: incomplete delegates")
	msg := ""
	if err := w.write(w.path, w.record()); err != nil {
		msg = "status " + w.path + ": " + err.Error()
		if msg != w.lastErr {
			w.log(msg)
		}
	}
	w.lastErr = msg
	return nil
}

// record builds the status record from the current snapshot's numbers, the mode the heartbeat
// carries, the run's source and learning flag, the files as they are now, and the build
// (the version variable, through the same check that prints it: Req 1.2 of deploy-service).
func (w *statusWriter) record() status.Record {
	st := w.store.Read()
	dns := ""
	if w.dns != nil {
		dns = w.dns()
	}
	r := status.Record{PID: w.pid, Mode: modeName(w.mode()), Source: string(w.source), Learning: w.learn,
		Kept: st.Kept, RulesFile: w.rulesFile, Written: w.now(), Version: mustVersion(version), DNS: dns}
	if st.Trial != nil {
		r.Trial = st.Trial.End.UTC().Format(time.RFC3339)
	}
	r.Programs, r.Resolved, r.Executables, r.Rules = counts(w.snap())
	return r
}

// counts are the summary's numbers (programs, of them resolved, executables mapped, rules
// effective); a program is resolved when at least one of its executables is mapped. Nil
// (no snapshot published yet) is all zeros.
func counts(snap *snapshot) (programs, resolved, executables, rules int) {
	if snap == nil {
		return 0, 0, 0, 0
	}
	mapped := map[uint32]bool{}
	for _, id := range snap.res.Programs {
		mapped[id] = true
	}
	for _, p := range snap.res.File.Programs {
		if mapped[p.ID] {
			resolved++
		}
	}
	return len(snap.res.File.Programs), resolved, len(snap.ent.Programs), len(snap.res.File.Rules)
}

// modeJobs are the follow and status jobs: only when the files decide the mode (startMode
// built a follower); the bounded -mode run never reads or writes them (Req 3.6).
func (d *daemon) modeJobs() []jobs.Job {
	if d.follow == nil {
		return nil
	}
	w := &statusWriter{path: d.cfg.status, rulesFile: d.cfg.rules, source: d.cfg.source, learn: d.cfg.learn,
		pid: os.Getpid(), store: d.follow.store, mode: func() trial.Mode { return trial.Mode(d.mode.Load()) },
		snap: d.st.current, dns: d.dns.recordLine, now: time.Now, write: status.Write, log: d.log}
	return []jobs.Job{d.follow.job(), w.job()}
}
