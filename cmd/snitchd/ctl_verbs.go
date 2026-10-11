// ctl_verbs.go: the verbs that write the trial and kept-enforce files: trial, keep, unkeep,
// end. They write only files under -state-dir, which the daemon follows within 5 s, and only
// through trialOps (trialops.go), the seam the API calls too. The kill and control maps are
// read (trial refuses while the kill switch is set), never written.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
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

// ops is the seam over the parsed -state-dir and the status record's facts (zero for the
// verbs that read no record: keep, unkeep and end check none of them).
func (c *ctl) ops(rec status.Record) trialOps {
	return trialOps{store: c.deps.store(c.stateDir), now: c.deps.now, boot: c.deps.bootID,
		learning: rec.Learning, kill: c.probes.kill, following: rec.Source == "files",
		rules: func() int { return rec.Rules }}
}

// report prints the seam's outcome: the text on stdout (exit 0), a refusal on stderr (exit 1),
// a bounds error as usage (exit 2).
func (c *ctl) report(text string, err error) int {
	var usage usageErr
	switch {
	case errors.As(err, &usage):
		fmt.Fprintf(c.errw, "snitchd %s: %v\n", c.name, err)
		return exitUsage
	case err != nil:
		return c.refuse(err.Error())
	}
	fmt.Fprintln(c.out, text)
	return exitOK
}

type trialArgs struct {
	extend, yes bool
	d           time.Duration
}

// trialFlags parses `trial [-extend] [-y] [duration]`: Go duration syntax only (10m, 90s),
// default DefaultTrial; the bounds are the seam's. Flags come before the duration.
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
	return a, exitOK, false
}

// followingDaemon is the CLI's view of the daemon, the checks that need its probes: a fresh
// heartbeat, then a fresh status record (the file outlives its writer: a heartbeat from a
// later -mode run next to a stale record would otherwise pass). What the record says (source,
// learning, rules) and the kill switch are the seam's refusals.
func (c *ctl) followingDaemon() (status.Record, string) {
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
	}
	return rec, ""
}

// runTrial: `trial [-extend] [-y] [duration]` (Req 2). The seam's zero-rules gate (Req 2.7)
// comes back as the question; the operator's yes repeats the call with yes set, a no is
// "declined".
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
	ops := c.ops(rec)
	text, err := ops.start(a.d, a.extend, a.yes)
	var ask needsYes
	if errors.As(err, &ask) {
		if !c.deps.confirm(ask.question) {
			return c.refuse("declined")
		}
		text, err = ops.start(a.d, a.extend, true)
	}
	return c.report(text, err)
}

// runKeep: `keep` records enforce as kept and removes the trial (Req 5.1, 5.2, 5.5). The
// state directory is checked first (the store would create it; the CLI refuses instead).
func runKeep(c *ctl, args []string) int {
	c.require()
	if code, done := c.parseVerb(args, nil); done {
		return code
	}
	if !c.deps.dirExists(c.stateDir) {
		return c.refuse(noStateDir(c.stateDir))
	}
	return c.report(c.ops(status.Record{}).keep())
}

// runUnkeep: `unkeep` removes the kept marker, a malformed one included (Req 5.4). No state
// directory means nothing is kept.
func runUnkeep(c *ctl, args []string) int {
	c.require()
	if code, done := c.parseVerb(args, nil); done {
		return code
	}
	return c.report(c.ops(status.Record{}).unkeep())
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
	return c.report(c.ops(status.Record{}).end(atBoot))
}
