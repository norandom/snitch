package clienttest

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/trial"
)

const (
	trialFilePath = "/var/lib/snitch/trial"
	keptFilePath  = "/var/lib/snitch/enforce"
)

func (s *StandIn) trialOp(req api.Request, _ uint32) (string, error) {
	if s.refuse.Load() {
		return "", errors.New(req.Type + ": refused by the stand-in")
	}
	switch req.Type {
	case "trial":
		return s.apiTrialStart(req)
	case "keep":
		return s.apiKeep()
	case "unkeep":
		return s.apiUnkeep()
	case "end":
		return s.apiEnd()
	}
	return "", fmt.Errorf("%s: not a trial verb", req.Type)
}

func (s *StandIn) apiTrialStart(req api.Request) (string, error) {
	d, err := parseTrialDuration(req.Duration)
	if err != nil {
		return "", err
	}
	if err := trial.Bounds(d); err != nil {
		return "", err
	}
	now := s.o.Now()
	s.fmu.Lock()
	st := *s.facts.Load()
	if msg := trialStartRefusal(st, len(s.merged.Rules), d, now, req.Extend, req.Yes); msg != "" {
		s.fmu.Unlock()
		return "", errors.New(msg)
	}
	what := "enforce"
	if liveDeadline(st.Trial, now) {
		what = "trial extended: enforce"
	}
	end := now.Add(d)
	st.Mode, st.Trial = "enforce", end.UTC().Format(time.RFC3339)
	s.facts.Store(&st)
	s.fmu.Unlock()
	s.later(s.o.ReloadAfter, func() { s.announce(st, "trial until "+end.Local().Format(time.RFC3339), false) })
	return fmt.Sprintf("%s until %s (%v); end early: snitchd end\ntrial file: %s",
		what, end.Local().Format(time.RFC3339), d, trialFilePath), nil
}

func parseTrialDuration(raw string) (time.Duration, error) {
	if raw == "" {
		return trial.DefaultTrial, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("duration %q: use Go syntax such as 10m or 90s", raw)
	}
	return d, nil
}

func trialStartRefusal(st api.Status, rules int, d time.Duration, now time.Time, extend, yes bool) string {
	switch {
	case st.Kill:
		return "the kill switch is set: enforce would have no effect until it is cleared (scripts/fail-open.sh, or the bpftool line in CLAUDE.md)"
	case st.Source != "files":
		return "the daemon runs with -mode, it does not follow trial files"
	case st.Learning:
		return "the daemon is learning (-learn): learning never denies, restart it without -learn before a trial"
	case st.Kept:
		return "enforce is already kept (" + keptFilePath + "): snitchd unkeep or snitchd end first"
	}
	if end, ok := parsedDeadline(st.Trial, now); ok && !extend {
		return fmt.Sprintf("a trial is already running until %s (%v left): snitchd trial -extend <duration> moves the deadline, snitchd end ends it",
			end.Local().Format(time.RFC3339), end.Sub(now).Round(time.Second))
	}
	if rules == 0 && !yes {
		return fmt.Sprintf("No rules are loaded: every connection outside the local network will be denied for %v. Start the trial? [y/N]", d)
	}
	return ""
}

func (s *StandIn) apiKeep() (string, error) {
	now := s.o.Now()
	s.fmu.Lock()
	st := *s.facts.Load()
	if st.Kept {
		s.fmu.Unlock()
		return "enforce is already kept: " + keptFilePath + keepWayBack(), nil
	}
	if !liveDeadline(st.Trial, now) {
		s.fmu.Unlock()
		return "", errors.New("enforce can only be kept during a trial (snitchd trial starts one)")
	}
	st.Mode, st.Trial, st.Kept = "enforce", "", true
	s.facts.Store(&st)
	s.fmu.Unlock()
	s.later(s.o.ReloadAfter, func() { s.announce(st, reasonKept, false) })
	return "enforce kept: " + keptFilePath + keepWayBack(), nil
}

func keepWayBack() string {
	return "\nthe way back: rm " + keptFilePath + " (or: snitchd unkeep, snitchd end, scripts/fail-open.sh)"
}

func (s *StandIn) apiUnkeep() (string, error) {
	now := s.o.Now()
	s.fmu.Lock()
	st := *s.facts.Load()
	if !st.Kept {
		s.fmu.Unlock()
		return "nothing was kept", nil
	}
	st.Kept, st.Mode = false, "monitor"
	if liveDeadline(st.Trial, now) {
		st.Mode = "enforce"
	}
	s.facts.Store(&st)
	s.fmu.Unlock()
	s.later(s.o.ReloadAfter, func() { s.announce(st, reasonUnkept, false) })
	return "enforce unkept: " + keptFilePath + " removed (monitor within 5 s)", nil
}

func (s *StandIn) apiEnd() (string, error) {
	s.fmu.Lock()
	st := *s.facts.Load()
	hadTrial, hadKept := st.Trial != "", st.Kept
	if !hadTrial && !hadKept {
		s.fmu.Unlock()
		return "already monitor: no trial, nothing kept", nil
	}
	st.Mode, st.Trial, st.Kept = "monitor", "", false
	s.facts.Store(&st)
	s.fmu.Unlock()
	s.later(s.o.ReloadAfter, func() { s.announce(st, reasonEnded, false) })
	return endReport(hadTrial, hadKept), nil
}

func endReport(hadTrial, hadKept bool) string {
	var parts []string
	if hadTrial {
		parts = append(parts, "trial ended: "+trialFilePath+" removed")
	}
	if hadKept {
		parts = append(parts, "enforce unkept: "+keptFilePath+" removed")
	}
	return strings.Join(parts, "; ") + " (monitor within 5 s)"
}

func parsedDeadline(raw string, now time.Time) (time.Time, bool) {
	if raw == "" {
		return time.Time{}, false
	}
	end, err := time.Parse(time.RFC3339, raw)
	return end, err == nil && end.After(now)
}

func liveDeadline(raw string, now time.Time) bool {
	_, ok := parsedDeadline(raw, now)
	return ok
}
