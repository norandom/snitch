// ctl_verbs.go: the verbs that write the trial and kept-enforce files: trial, keep, unkeep,
// end. They write only files under -state-dir, which the daemon follows within 5 s. The kill
// and control maps are read (trial refuses while the kill switch is set), never written.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/status"
	"github.com/norandom/snitch/internal/trial"
)

const (
	exitOK      = 0
	exitRefused = 1                // a clear sentence on stderr, nothing written
	staleAfter  = 15 * time.Second // the kernel's HEARTBEAT_MAX_NS: older = daemon wedged or gone, everything allowed
)

// require: a handler needs every delegate; a ctl built by newCtl has them all.
func (c *ctl) require() {
	d := c.deps
	contract.Require(c.out != nil && c.errw != nil && c.probes.control != nil && c.probes.kill != nil,
		"ctl: incomplete writers or probes")
	contract.Require(d.store != nil && d.dirExists != nil && d.readStatus != nil && d.bootID != nil &&
		d.now != nil && d.confirm != nil, "ctl: incomplete deps")
}

// refuse is every refusal: one sentence on stderr, exit 1.
func (c *ctl) refuse(msg string) int {
	fmt.Fprintf(c.errw, "snitchd %s: %s\n", c.name, msg)
	return exitRefused
}

// parseVerb maps parse's outcome to an exit code; done says the handler must stop (help or
// a usage error, both already printed).
func (c *ctl) parseVerb(args []string, add func(*flag.FlagSet)) (code int, done bool) {
	err := c.parse(args, add)
	switch {
	case err == nil:
		return exitOK, false
	case errors.Is(err, flag.ErrHelp):
		return exitOK, true
	}
	return exitUsage, true
}

func noStateDir(dir string) string {
	return "state directory " + dir + " does not exist (is the daemon installed? mkdir -m 700 " + dir + ")"
}

type trialArgs struct {
	extend, yes bool
	d           time.Duration
}

// trialFlags parses `trial [-extend] [-y] [duration]`: Go duration syntax only (10m, 90s),
// within trial.Bounds, default DefaultTrial. Flags come before the duration.
func (c *ctl) trialFlags(args []string) (a trialArgs, code int, done bool) {
	var set *flag.FlagSet
	code, done = c.parseVerb(args, func(f *flag.FlagSet) {
		set = f
		f.BoolVar(&a.extend, "extend", false, "move a running trial's deadline to now plus the duration (start moves too)")
		f.BoolVar(&a.yes, "y", false, "start without the confirmation asked when no rules are loaded")
		f.Usage = func() {
			fmt.Fprintf(c.errw, "usage: snitchd trial [-extend] [-y] [duration]\n  duration in Go syntax (10m, 90s), %v to %v, default %v\n",
				trial.MinTrial, trial.MaxTrial, trial.DefaultTrial)
			f.PrintDefaults()
		}
	})
	if done {
		return a, code, true
	}
	a.d = trial.DefaultTrial
	if rest := set.Args(); len(rest) > 1 {
		fmt.Fprintf(c.errw, "snitchd trial: one duration at most, got %q (flags go before it)\n", rest)
		return a, exitUsage, true
	} else if len(rest) == 1 {
		d, err := time.ParseDuration(rest[0])
		if err != nil {
			fmt.Fprintf(c.errw, "snitchd trial: duration %q: use Go syntax such as 10m or 90s\n", rest[0])
			return a, exitUsage, true
		}
		a.d = d
	}
	if err := trial.Bounds(a.d); err != nil {
		fmt.Fprintf(c.errw, "snitchd trial: %v\n", err)
		return a, exitUsage, true
	}
	return a, exitOK, false
}

// followingDaemon is the trial's view of the daemon, in refusal order: kill switch clear, a
// fresh heartbeat, a fresh status record (the file outlives its writer: a heartbeat from a
// later -mode run next to a stale record would otherwise pass), source files, not learning.
func (c *ctl) followingDaemon() (status.Record, string) {
	if c.probes.kill() {
		return status.Record{}, "the kill switch is set: enforce would have no effect until it is cleared (scripts/fail-open.sh, or the bpftool line in CLAUDE.md)"
	}
	if age, _, _, ok := c.probes.control(); !ok {
		return status.Record{}, "the daemon is not running (no pinned control map): a deadline nobody follows would surprise you when it comes up"
	} else if age > staleAfter {
		return status.Record{}, fmt.Sprintf("the daemon is not running (last heartbeat %v ago): start it before a trial", age.Round(time.Second))
	}
	rec, err := c.deps.readStatus(c.status)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return rec, "no status file at " + c.status + ": the daemon runs with -mode or another -status, it does not follow trial files"
	case err != nil:
		return rec, err.Error()
	case c.deps.now().Sub(rec.Written) > staleAfter:
		return rec, fmt.Sprintf("the daemon is not following the files (status record is %v old): a deadline nobody follows would surprise you when it comes up",
			c.deps.now().Sub(rec.Written).Round(time.Second))
	case rec.Source != "files":
		return rec, "the daemon runs with -mode, it does not follow trial files"
	case rec.Learning:
		return rec, "the daemon is learning (-learn): learning never denies, restart it without -learn before a trial"
	}
	return rec, ""
}

// trialRefusal is the store's side of the checks (the status record may lag a tick): a kept
// enforce, or a running trial without -extend.
func trialRefusal(store trial.Store, st trial.State, boot string, now time.Time, extend bool) string {
	if st.Kept {
		return "enforce is already kept (" + store.KeptPath() + "): snitchd unkeep or snitchd end first"
	}
	if live := liveTrial(st, boot, now); live != nil && !extend {
		return fmt.Sprintf("a trial is already running until %s (%v left): snitchd trial -extend <duration> moves the deadline, snitchd end ends it",
			live.End.Local().Format(time.RFC3339), live.End.Sub(now).Round(time.Second))
	}
	return ""
}

// confirmed is the zero-rules gate (Req 2.7): with rules loaded or -y nothing is asked;
// otherwise the operator hears what a trial means before it starts.
func (c *ctl) confirmed(rec status.Record, a trialArgs) bool {
	if rec.Rules > 0 || a.yes {
		return true
	}
	return c.deps.confirm(fmt.Sprintf(
		"No rules are loaded: every connection outside the local network will be denied for %v. Start the trial? [y/N]", a.d))
}

// runTrial: `trial [-extend] [-y] [duration]` (Req 2); checks before the write, an extend
// rewrites the file with start = now (the MaxTrial cap is relative to start).
func runTrial(c *ctl, args []string) int {
	c.require()
	a, code, done := c.trialFlags(args)
	if done {
		return code
	}
	if !c.deps.dirExists(c.stateDir) {
		return c.refuse(noStateDir(c.stateDir))
	}
	rec, msg := c.followingDaemon()
	if msg != "" {
		return c.refuse(msg)
	}
	boot, err := c.deps.bootID()
	if err != nil {
		return c.refuse(err.Error())
	}
	store, now := c.deps.store(c.stateDir), c.deps.now()
	st := store.Read()
	if msg := trialRefusal(store, st, boot, now, a.extend); msg != "" {
		return c.refuse(msg)
	}
	if !c.confirmed(rec, a) {
		return c.refuse("declined")
	}
	end := now.Add(a.d)
	if err := store.StartTrial(trial.Deadline{Start: now, End: end, Boot: boot}); err != nil {
		return c.refuse(err.Error())
	}
	what := "enforce"
	if liveTrial(st, boot, now) != nil {
		what = "trial extended: enforce"
	}
	fmt.Fprintf(c.out, "%s until %s (%v); end early: snitchd end\ntrial file: %s\n",
		what, end.Local().Format(time.RFC3339), a.d, store.TrialPath())
	return exitOK
}

// runKeep: `keep` records enforce as kept and removes the trial (Req 5.1, 5.2, 5.5). Only a
// running trial can be kept (the store is read first: a missing directory holds no trial);
// an already kept enforce is reported, not an error.
func runKeep(c *ctl, args []string) int {
	c.require()
	if code, done := c.parseVerb(args, nil); done {
		return code
	}
	boot, err := c.deps.bootID()
	if err != nil {
		return c.refuse(err.Error())
	}
	store, now := c.deps.store(c.stateDir), c.deps.now()
	st := store.Read()
	switch {
	case st.Kept:
		fmt.Fprintf(c.out, "enforce is already kept: %s\n", store.KeptPath())
	case liveTrial(st, boot, now) == nil:
		return c.refuse("enforce can only be kept during a trial (snitchd trial starts one)")
	case !c.deps.dirExists(c.stateDir):
		return c.refuse(noStateDir(c.stateDir))
	default:
		if err := store.Keep(now); err != nil {
			return c.refuse(err.Error())
		}
		fmt.Fprintf(c.out, "enforce kept: %s\n", store.KeptPath())
	}
	fmt.Fprintf(c.out, "the way back: rm %s (or: snitchd unkeep, snitchd end, scripts/fail-open.sh)\n", store.KeptPath())
	return exitOK
}

// runUnkeep: `unkeep` removes the kept marker, a malformed one included (Req 5.4). No state
// directory means nothing is kept.
func runUnkeep(c *ctl, args []string) int {
	c.require()
	if code, done := c.parseVerb(args, nil); done {
		return code
	}
	store := c.deps.store(c.stateDir)
	if _, kept := present(store, store.Read()); !kept {
		fmt.Fprintln(c.out, "nothing was kept")
		return exitOK
	}
	if err := store.ClearKept(); err != nil {
		return c.refuse(err.Error())
	}
	fmt.Fprintf(c.out, "enforce unkept: %s removed (monitor within 5 s)\n", store.KeptPath())
	return exitOK
}

// runEnd: `end [-at-boot]` removes the trial and, unless at boot, the kept marker (Req 6).
// Nothing recorded is already monitor, exit 0. The kill switch is not touched.
func runEnd(c *ctl, args []string) int {
	c.require()
	var atBoot bool
	code, done := c.parseVerb(args, func(f *flag.FlagSet) {
		f.BoolVar(&atBoot, "at-boot", false, "the boot-time end: remove only the trial, a kept enforce stays")
	})
	if done {
		return code
	}
	store := c.deps.store(c.stateDir)
	hadTrial, hadKept := present(store, store.Read())
	if err := store.ClearTrial(); err != nil {
		return c.refuse(err.Error())
	}
	if !atBoot {
		if err := store.ClearKept(); err != nil {
			return c.refuse(err.Error())
		}
	}
	fmt.Fprintln(c.out, endReport(store, hadTrial, hadKept, atBoot))
	return exitOK
}

func endReport(store trial.Store, hadTrial, hadKept, atBoot bool) string {
	switch {
	case !hadTrial && !hadKept:
		return "already monitor: no trial, nothing kept"
	case atBoot && !hadTrial:
		return "no trial to end at boot; enforce stays kept: " + store.KeptPath()
	case atBoot:
		report := "trial ended at boot: " + store.TrialPath() + " removed"
		if hadKept {
			report += "; enforce stays kept: " + store.KeptPath()
		}
		return report
	}
	var parts []string
	if hadTrial {
		parts = append(parts, "trial ended: "+store.TrialPath()+" removed")
	}
	if hadKept {
		parts = append(parts, "enforce unkept: "+store.KeptPath()+" removed")
	}
	return strings.Join(parts, "; ") + " (monitor within 5 s)"
}
