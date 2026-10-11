// trialops.go: the seam the CLI verbs and the API both call for the trial and kept-enforce
// files: start, keep, unkeep, end. It holds the file operations and their texts, and every
// refusal that depends only on the store, learning, the kill switch, whether the daemon follows
// the files and the rule count. The caller keeps what needs its own probes (the CLI: the daemon
// running, the status record's age, the state directory; the API: nothing) and its prompt,
// which turns into `yes`. Rule 5 of the fail-safes: nothing here weakens a refusal, and the
// kill switch is only ever read.
package main

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/trial"
)

type trialOps struct {
	store     trial.Store
	now       func() time.Time
	boot      func() (string, error)
	learning  bool
	kill      func() bool
	following bool       // false when the daemon runs with -mode: nobody follows the files
	rules     func() int // effective rule count: zero needs the explicit yes
}

// usageErr marks a refusal the CLI reports as a usage error (exit 2): the bounds.
type usageErr struct{ error }

// needsYes is the zero-rules gate (persistent-trial Req 2.7): its text is the question the
// caller asks before it calls start again with yes.
type needsYes struct{ question string }

func (e needsYes) Error() string { return e.question }

func (o trialOps) require() {
	contract.Require(o.store.Dir != "", "trialOps: empty store directory")
	contract.Require(o.now != nil && o.boot != nil && o.kill != nil && o.rules != nil, "trialOps: incomplete delegates")
}

// start writes the trial file for d from now (persistent-trial Req 2); an extend rewrites it
// with start = now (the MaxTrial cap is relative to start). Checks come before the write.
func (o trialOps) start(d time.Duration, extend, yes bool) (string, error) {
	o.require()
	if err := trial.Bounds(d); err != nil {
		return "", usageErr{err}
	}
	if msg := o.daemonRefusal(); msg != "" {
		return "", errors.New(msg)
	}
	boot, err := o.boot()
	if err != nil {
		return "", err
	}
	now, st := o.now(), o.store.Read()
	if msg := trialRefusal(o.store, st, boot, now, extend); msg != "" {
		return "", errors.New(msg)
	}
	if o.rules() == 0 && !yes {
		return "", needsYes{fmt.Sprintf(
			"No rules are loaded: every connection outside the local network will be denied for %v. Start the trial? [y/N]", d)}
	}
	end := now.Add(d)
	if err := o.store.StartTrial(trial.Deadline{Start: now, End: end, Boot: boot}); err != nil {
		return "", err
	}
	what := "enforce"
	if liveTrial(st, boot, now) != nil {
		what = "trial extended: enforce"
	}
	return fmt.Sprintf("%s until %s (%v); end early: snitchd end\ntrial file: %s",
		what, end.Local().Format(time.RFC3339), d, o.store.TrialPath()), nil
}

// daemonRefusal is the daemon's side of start, in refusal order: kill switch clear, following
// the files, not learning.
func (o trialOps) daemonRefusal() string {
	switch {
	case o.kill():
		return "the kill switch is set: enforce would have no effect until it is cleared (scripts/fail-open.sh, or the bpftool line in CLAUDE.md)"
	case !o.following:
		return "the daemon runs with -mode, it does not follow trial files"
	case o.learning:
		return "the daemon is learning (-learn): learning never denies, restart it without -learn before a trial"
	}
	return ""
}

// trialRefusal is the store's side of start: a kept enforce, or a running trial without extend.
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

// keep records enforce as kept and removes the trial (persistent-trial Req 5.1, 5.2, 5.5).
// Only a running trial can be kept; an already kept enforce is reported, not an error.
func (o trialOps) keep() (string, error) {
	o.require()
	boot, err := o.boot()
	if err != nil {
		return "", err
	}
	now, st := o.now(), o.store.Read()
	var first string
	switch {
	case st.Kept:
		first = "enforce is already kept: " + o.store.KeptPath()
	case liveTrial(st, boot, now) == nil:
		return "", errors.New("enforce can only be kept during a trial (snitchd trial starts one)")
	default:
		if err := o.store.Keep(now); err != nil {
			return "", err
		}
		first = "enforce kept: " + o.store.KeptPath()
	}
	return first + "\nthe way back: rm " + o.store.KeptPath() + " (or: snitchd unkeep, snitchd end, scripts/fail-open.sh)", nil
}

// unkeep removes the kept marker, a malformed one included (persistent-trial Req 5.4).
func (o trialOps) unkeep() (string, error) {
	o.require()
	if _, kept := present(o.store, o.store.Read()); !kept {
		return "nothing was kept", nil
	}
	if err := o.store.ClearKept(); err != nil {
		return "", err
	}
	return "enforce unkept: " + o.store.KeptPath() + " removed (monitor within 5 s)", nil
}

// end removes the trial and, unless at boot, the kept marker (persistent-trial Req 6). Nothing
// recorded is already monitor, not an error. The kill switch is not touched.
func (o trialOps) end(atBoot bool) (string, error) {
	o.require()
	hadTrial, hadKept := present(o.store, o.store.Read())
	if err := o.store.ClearTrial(); err != nil {
		return "", err
	}
	if !atBoot {
		if err := o.store.ClearKept(); err != nil {
			return "", err
		}
	}
	return endReport(o.store, hadTrial, hadKept, atBoot), nil
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
