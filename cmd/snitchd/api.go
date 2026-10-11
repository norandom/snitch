// api.go: the daemon's side of the local API (design "Facts and state hooks"): the operator
// file, the listener, the facts behind a status reply, the state hooks and the wiring of the
// server into the job list. Fail-safe: the API is optional (no -api, or a listener that cannot
// be created, leaves the daemon protecting the host without it, Req 1.9); the server holds no
// map and no store, it only reads delegates; the write verbs (apiwrite.go, apiwrite_rules.go)
// reach the trial files only through trialOps and the rules only through the overlay file.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/cilium/ebpf"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
	"github.com/norandom/snitch/internal/trial"
)

// operatorPath names the one user who may write over the API besides root (Req 1.3).
const operatorPath = "/etc/snitch/operator"

// apiState is what the API adds to the daemon: the server and its table, and the facts'
// delegates (the kill switch, the reloader's error) so tests fake them. Set by installAPI.
type apiState struct {
	server   *api.Server
	table    *api.Table
	operator uint32
	kill     func() bool
	rulesErr func() (time.Time, error)
	started  time.Time
}

// apiJobs is the one line daemon.go adds: nothing without -api; otherwise the listener (a
// failure is logged and the API skipped, Req 1.9), the server with the daemon's delegates,
// its job and the operator file's watch (apioperator.go).
func (d *daemon) apiJobs(r *reloader) []jobs.Job {
	if d.cfg.api == "" {
		return nil
	}
	contract.Require(r != nil, "apiJobs needs the reloader")
	l, ok := listenAPI(d.cfg.api, d.log)
	if !ok {
		return nil
	}
	d.installAPI(apiState{operator: operatorUID(operatorPath, lookupUID, os.Stat, d.log),
		kill: killOf(d.objs.Kill), rulesErr: r.rulesError, started: time.Now()})
	return append([]jobs.Job{d.api.server.Job(l), d.operatorJob(operatorPath)}, d.sweepJobs()...)
}

// installAPI builds the table and the server over the daemon's delegates and installs the
// hooks: the pump's emit, the state event on every setMode and on every published snapshot.
func (d *daemon) installAPI(a apiState) {
	contract.Require(a.kill != nil && a.rulesErr != nil && !a.started.IsZero(), "installAPI: incomplete state")
	a.table = api.NewTable(time.Now)
	a.server = api.New(api.Deps{Operator: a.operator, Table: a.table, Facts: d.facts, Rules: d.rulesFacts,
		Learned: d.learnedFacts, Log: d.log, Now: time.Now,
		Trial: d.apiTrial, RuleEdit: d.apiRuleEdit})
	d.api = a
	d.emit = a.server.Emit
	d.onMode = func(m trial.Mode, reason string) { a.server.StateChanged(d.stateEvent(m, reason, false)) }
	d.st.onPublish = func() { a.server.StateChanged(d.stateEvent(trial.Mode(d.mode.Load()), "rules reloaded", true)) }
}

// stateEvent is the state message (Req 4.5): the mode, what the store says about the trial
// and kept, and whether the rules changed.
func (d *daemon) stateEvent(m trial.Mode, reason string, rulesChanged bool) api.State {
	deadline, kept := d.trialFacts()
	return api.State{Type: "state", Mode: modeName(m), Trial: deadline, Kept: kept, RulesChanged: rulesChanged, Reason: reason}
}

// facts is the status reply (Req 4.1), from memory: nothing waits on a file or a map except
// the kill lookup. A -mode daemon has no follower: trial none, kept false, source flag.
func (d *daemon) facts() api.Status {
	a := d.api
	contract.Require(a.server != nil && a.table != nil && a.kill != nil && a.rulesErr != nil, "facts: the API is not installed")
	deadline, kept := d.trialFacts()
	s := api.Status{Running: true, Pid: os.Getpid(), Version: mustVersion(version), Mode: modeName(trial.Mode(d.mode.Load())),
		Source: string(d.cfg.source), Trial: deadline, Kept: kept, Kill: a.kill(), Learning: d.cfg.learn,
		Rules: api.RulesSummary{File: d.cfg.rules, Overlay: d.cfg.overlay}, RulesError: rulesErrorText(a.rulesErr()),
		Clients: a.server.Clients(), Dropped: int(a.server.Dropped()), Entries: a.table.Len(), Evictions: a.table.Evictions(),
		Started: a.started.UTC().Format(time.RFC3339), Counting: d.counting}
	s.Rules.Programs, s.Rules.Resolved, s.Rules.Executables, s.Rules.Rules = counts(d.st.current())
	return s
}

// trialFacts reads the follower's store like the status writer does: the deadline (RFC 3339,
// UTC) and kept; none without a follower.
func (d *daemon) trialFacts() (deadline string, kept bool) {
	if d.follow == nil {
		return "", false
	}
	st := d.follow.store.Read()
	if st.Trial != nil {
		deadline = st.Trial.End.UTC().Format(time.RFC3339)
	}
	return deadline, st.Kept
}

// rulesErrorText is the facts' view of the reloader's error: "<time>: <err>" for a failed
// reload, the error alone for the startup fallback (no time), "" when there is none.
func rulesErrorText(at time.Time, err error) string {
	switch {
	case err == nil:
		return ""
	case at.IsZero():
		return err.Error()
	}
	return at.UTC().Format(time.RFC3339) + ": " + err.Error()
}

func (d *daemon) rulesFacts() ([]api.RuleView, []api.ProgramView) { return rulesView(d.st.current()) }

// learnedFacts: the learned set without touching its write cycle (Req 4.4); off = no learner.
func (d *daemon) learnedFacts() ([]api.Observation, bool) {
	if d.learn == nil {
		return nil, false
	}
	return learnedView(d.learn.observations()), true
}

// killOf reads the kill switch from the pinned map; a failed read is "clear" like the CLI's.
func killOf(m *ebpf.Map) func() bool {
	return func() bool {
		var v uint32
		return m.Lookup(uint32(0), &v) == nil && v != 0
	}
}

// listenAPI creates the socket (design "Listener"): the directory 0755 so any local user
// reaches it, a stale socket removed, the socket 0666 (Req 1.1), unlinked on close (Req 1.2).
// A failure is one "api off" line and false: the daemon runs without the API (Req 1.9).
func listenAPI(path string, log func(string)) (net.Listener, bool) {
	contract.Require(path != "" && log != nil, "listenAPI needs the socket path and the log")
	l, err := listenUnix(path)
	if err != nil {
		log("api off: " + err.Error())
		return nil, false
	}
	return l, true
}

func listenUnix(path string) (*net.UnixListener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		return nil, err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, 0o666); err != nil {
		l.Close()
		return nil, err
	}
	l.SetUnlinkOnClose(true)
	return l, nil
}

// operatorUID reads the operator file: one user name, looked up to a uid. No file is no
// operator (root alone writes). A file not owned by root or writable by group or others is
// ignored with one line, like a loose sudoers file: a mode cannot promote a user. Delegates
// for the lookup and the stat so tests run without root; the daemon passes the real ones.
func operatorUID(path string, lookup func(string) (uint32, error), stat func(string) (os.FileInfo, error), log func(string)) uint32 {
	contract.Require(path != "" && lookup != nil && stat != nil && log != nil, "operatorUID: incomplete delegates")
	ignored := func(why string) uint32 {
		log(fmt.Sprintf("operator file %s ignored: %s", path, why))
		return 0
	}
	info, err := stat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return 0
	}
	if err != nil {
		return ignored(err.Error())
	}
	if why := operatorFileProblem(info); why != "" {
		return ignored(why)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return ignored(err.Error())
	}
	name, _, _ := strings.Cut(string(b), "\n")
	name = strings.TrimSpace(name)
	uid, err := lookup(name)
	if err != nil {
		return ignored(fmt.Sprintf("%q: %v", name, err))
	}
	return uid
}

// operatorFileProblem is why a file cannot name the operator ("" when it can).
func operatorFileProblem(info os.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	switch {
	case !info.Mode().IsRegular():
		return "not a regular file"
	case !ok || st.Uid != 0:
		return "not owned by root"
	case info.Mode().Perm()&0o022 != 0:
		return fmt.Sprintf("mode %04o is writable by group or others", info.Mode().Perm())
	}
	return ""
}

// lookupUID is the real lookup: the passwd database through os/user (pure Go, no cgo).
func lookupUID(name string) (uint32, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return 0, err
	}
	id, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("uid of %s: %w", name, err)
	}
	return uint32(id), nil
}
