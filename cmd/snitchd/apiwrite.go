// apiwrite.go: the trial verbs behind the API (design "trialOps", Req 5.1). They go through
// trialOps, the seam the CLI uses, built from the daemon's own facts: its follower's store,
// boot and clock, the learning flag, the kill reader, whether it follows the files at all and
// the effective rule count. So every outcome text and refusal is the CLI's, the zero-rules
// question included (it comes back as the error until the request carries yes). The
// dispatcher audits every write before it replies (dispatch.go), nothing here logs a second
// line. Fail-safe: a daemon started with -mode has no follower and refuses a trial with the
// CLI's sentence; the kill switch is only ever read; the rule edits are apiwrite_rules.go.
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/trial"
)

// apiTrial is the server's Trial delegate: trial, keep, unkeep and end for a writer (the
// server refused readers already; who is the dispatcher's to audit).
func (d *daemon) apiTrial(req api.Request, _ uint32) (string, error) {
	ops := d.trialOps()
	switch req.Type {
	case "trial":
		dur, err := trialDuration(req.Duration)
		if err != nil {
			return "", err
		}
		return ops.start(dur, req.Extend, req.Yes)
	case "keep":
		return ops.keep()
	case "unkeep":
		return ops.unkeep()
	case "end":
		return ops.end(false)
	}
	return "", fmt.Errorf("%s: not a trial verb", req.Type)
}

// trialOps is the seam over the daemon's facts. The store, boot and clock are the follower's;
// a -mode daemon has none and gets a store on its state directory, which only keep, unkeep
// and end reach (start is refused first: nobody follows the files).
func (d *daemon) trialOps() trialOps {
	o := trialOps{store: trial.OSStore(d.cfg.stateDir), now: time.Now,
		boot:     func() (string, error) { return trial.BootID(os.ReadFile) },
		learning: d.cfg.learn, kill: d.api.kill, following: d.follow != nil,
		rules: func() int { _, _, _, n := counts(d.st.current()); return n }}
	if f := d.follow; f != nil {
		o.store, o.now, o.boot = f.store, f.now, func() (string, error) { return f.boot, nil }
	}
	return o
}

// trialDuration parses the request's duration the way the CLI parses its word: empty is the
// default, Go syntax only; the bounds are the seam's.
func trialDuration(s string) (time.Duration, error) {
	if s == "" {
		return trial.DefaultTrial, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("duration %q: use Go syntax such as 10m or 90s", s)
	}
	return d, nil
}
