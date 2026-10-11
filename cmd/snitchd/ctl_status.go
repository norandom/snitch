// ctl_status.go: `snitchd status` (Req 7). One line per fact with a stable key, so a script
// can grep it: daemon, mode, trial, kept, kill, learning, rules, status, version. Every source is read
// once (two map lookups, the two state files, the status record): nothing waits, nothing
// retries, so the command is done well within a second. Exit 1 when the daemon is not running
// (no pinned maps or a heartbeat older than 15 s); the files and the kill switch print anyway.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/status"
	"github.com/norandom/snitch/internal/trial"
)

func isNotExist(err error) bool { return errors.Is(err, fs.ErrNotExist) }

// statusFacts is everything status prints, gathered once through the delegates.
type statusFacts struct {
	age     time.Duration // heartbeat age from the control map
	mapMode uint32        // the control map's mode: 0 monitor, 1 enforce
	mapOK   bool          // the control map exists
	kill    bool
	rec     status.Record
	recErr  error
	recPath string
	store   trial.Store
	st      trial.State
	boot    string
	bootErr error
	now     time.Time
}

func (c *ctl) gather() statusFacts {
	f := statusFacts{kill: c.probes.kill(), recPath: c.status, store: c.deps.store(c.stateDir), now: c.deps.now()}
	f.age, f.mapMode, _, f.mapOK = c.probes.control()
	f.rec, f.recErr = c.deps.readStatus(c.status)
	f.st = f.store.Read()
	f.boot, f.bootErr = c.deps.bootID()
	return f
}

// running is the kernel's view: a heartbeat within staleAfter; older or absent, the BPF
// program already allows everything.
func (f statusFacts) running() bool { return f.mapOK && f.age <= staleAfter }

func (f statusFacts) recordAge() time.Duration { return f.now.Sub(f.rec.Written).Round(time.Second) }

// notFollowing is why a running daemon is not the one following the trial files: no record,
// an unreadable or stale one (its writer is gone), or a daemon started with -mode.
func (f statusFacts) notFollowing() string {
	switch {
	case f.recErr != nil && isNotExist(f.recErr):
		return "no status record at " + f.recPath
	case f.recErr != nil:
		return f.recErr.Error()
	case f.recordAge() > staleAfter:
		return fmt.Sprintf("status record %v old", f.recordAge())
	case f.rec.Source != "files":
		return "started with -mode"
	}
	return ""
}

func (f statusFacts) daemonLine() string {
	switch {
	case !f.mapOK:
		return "not running (no pinned maps: never ran since boot)"
	case !f.running():
		return fmt.Sprintf("not running (last heartbeat %v ago)", f.age.Round(time.Second))
	case f.notFollowing() != "":
		return fmt.Sprintf("running (heartbeat %v ago, not following the files: %s)", f.age.Round(time.Second), f.notFollowing())
	}
	return fmt.Sprintf("running (heartbeat %v ago, pid %d, source %s)", f.age.Round(time.Second), f.rec.PID, f.rec.Source)
}

// modeLine: the control map while the daemon runs (what the kernel enforces); the last record
// otherwise, with its age; unknown when neither exists.
func (f statusFacts) modeLine() string {
	switch {
	case f.running() && f.mapMode == 0:
		return modeMonitor + " (control map)"
	case f.running() && f.mapMode == 1:
		return modeEnforce + " (control map)"
	case f.running():
		return fmt.Sprintf("unknown (control map mode %d)", f.mapMode)
	case f.recErr == nil && f.rec.Mode != "":
		return fmt.Sprintf("%s (last record, %v old)", f.rec.Mode, f.recordAge())
	case f.mapOK: // a stale map still holds a mode, but the kernel allows everything: not the truth
		return "unknown (heartbeat stale, no status record)"
	}
	return "unknown (no control map, no status record)"
}

// trialLine reads the store, not the record (the record may lag a tick): a live trial with
// the time left, else why the file does not count (the daemon removes it within 5 s).
func (f statusFacts) trialLine() string {
	if p := problemOf(f.st, f.store.TrialPath()); p != "" {
		return "unreadable: " + p + " (snitchd end removes it)"
	}
	if f.st.Trial == nil {
		return "none"
	}
	end := f.st.Trial.End.Local().Format(time.RFC3339)
	switch {
	case f.bootErr != nil:
		return fmt.Sprintf("file until %s, boot id unknown: %v", end, f.bootErr)
	case liveTrial(f.st, f.boot, f.now) != nil:
		return fmt.Sprintf("until %s (%v left)", end, f.st.Trial.End.Sub(f.now).Round(time.Second))
	case f.st.Trial.Boot != f.boot:
		return "ended (file from another boot, the daemon clears it)"
	}
	return fmt.Sprintf("expired (deadline %s passed, the daemon clears it)", end)
}

func (f statusFacts) keptLine() string {
	if p := problemOf(f.st, f.store.KeptPath()); p != "" {
		return "unreadable: " + p + " (snitchd unkeep removes it)"
	}
	if f.st.Kept {
		return "yes (" + f.store.KeptPath() + ")"
	}
	return "no"
}

// problemOf is the Problem Read recorded for path ("" when the file is fine or absent).
func problemOf(st trial.State, path string) string {
	for _, p := range st.Problems {
		if strings.HasPrefix(p, path+":") {
			return p
		}
	}
	return ""
}

func (f statusFacts) killLine() string {
	if f.kill {
		return "set (everything allowed; clear it with scripts/fail-open.sh or the bpftool line in CLAUDE.md)"
	}
	return "clear"
}

func (f statusFacts) learningLine() string {
	switch {
	case f.recErr != nil:
		return "unknown (no status record)"
	case f.rec.Learning:
		return "yes"
	}
	return "no"
}

func (f statusFacts) rulesLine() string {
	if f.recErr != nil {
		return "unknown (no status record)"
	}
	r := f.rec
	return fmt.Sprintf("%d programs (%d resolved), %d executables mapped, %d rules effective (%s)",
		r.Programs, r.Resolved, r.Executables, r.Rules, r.RulesFile)
}

// versionLine is the record's build (spec deploy-service, Req 1.2): what runs, not what the
// command line is (the binary is the same file).
func (f statusFacts) versionLine() string {
	if f.recErr != nil {
		return "unknown (no status record)"
	}
	return f.rec.Version
}

func (f statusFacts) statusLine() string {
	switch {
	case f.recErr != nil && isNotExist(f.recErr):
		return f.recPath + " missing"
	case f.recErr != nil:
		return f.recPath + " unreadable: " + f.recErr.Error()
	case f.recordAge() > staleAfter:
		return fmt.Sprintf("%s stale (written %v ago)", f.recPath, f.recordAge())
	}
	return fmt.Sprintf("%s written %v ago", f.recPath, f.recordAge())
}

// lines is the output in print order: the keys are the documented interface.
func (f statusFacts) lines() [][2]string {
	return [][2]string{
		{"daemon", f.daemonLine()}, {"mode", f.modeLine()}, {"trial", f.trialLine()}, {"kept", f.keptLine()},
		{"kill", f.killLine()}, {"learning", f.learningLine()}, {"rules", f.rulesLine()}, {"status", f.statusLine()},
		{"version", f.versionLine()},
	}
}

func statusUsage(f *flag.FlagSet) func() {
	return func() {
		fmt.Fprint(f.Output(), `usage: snitchd status [flags]
  one line per fact, a stable key each: daemon: mode: trial: kept: kill: learning: rules: status: version:
  exit 1 when the daemon is not running (no pinned maps or a heartbeat older than 15 s), 0 otherwise
`)
		f.PrintDefaults()
	}
}

// runStatus: gather, print, exit by the heartbeat (Req 7.1 to 7.4).
func runStatus(c *ctl, args []string) int {
	c.require()
	if code, done := c.parseVerb(args, func(f *flag.FlagSet) { f.Usage = statusUsage(f) }); done {
		return code
	}
	f := c.gather()
	for _, l := range f.lines() {
		fmt.Fprintf(c.out, "%-10s %s\n", l[0]+":", l[1])
	}
	if !f.running() {
		return exitRefused
	}
	return exitOK
}
