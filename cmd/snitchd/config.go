package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"time"
)

const (
	modeMonitor = "monitor"
	modeEnforce = "enforce"

	defaultRules   = "/etc/snitch/rules.toml"
	defaultLearned = "/var/lib/snitch/learned.toml"
)

// config is everything the command line decides. Checked before any kernel object is loaded.
type config struct {
	rules    string
	learned  string
	learn    bool
	mode     string
	duration time.Duration
}

// usageError is an operator mistake on the command line: exit 2, nothing was touched.
type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }
func (e *usageError) exitCode() int { return 2 }

func parseFlags(args []string) (config, error) {
	return parseFlagsTo(args, io.Discard)
}

func parseFlagsTo(args []string, usage io.Writer) (config, error) {
	var cfg config
	fs := flag.NewFlagSet("snitchd", flag.ContinueOnError)
	fs.SetOutput(usage)
	fs.StringVar(&cfg.rules, "rules", defaultRules, "rules file; missing = no rules (everything is reported, nothing denied)")
	fs.BoolVar(&cfg.learn, "learn", false, "learning mode: monitor and record connections no rule covers")
	fs.StringVar(&cfg.learned, "learned", defaultLearned, "where learning mode writes its rules file")
	fs.StringVar(&cfg.mode, "mode", modeMonitor, "monitor (allow + report) or enforce (deny what no rule allows; needs -duration)")
	fs.DurationVar(&cfg.duration, "duration", 0, "exit after this long (0: run until signalled)")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return cfg, err
		}
		return cfg, &usageError{err.Error()}
	}
	return cfg, check(cfg)
}

// check is fail-safe 5 in this phase: enforce only bounded, and learning can never deny.
func check(cfg config) error {
	switch {
	case cfg.mode != modeMonitor && cfg.mode != modeEnforce:
		return &usageError{fmt.Sprintf("-mode %q: want monitor or enforce", cfg.mode)}
	case cfg.duration < 0:
		return &usageError{"-duration must not be negative"}
	case cfg.mode == modeEnforce && cfg.duration == 0:
		return &usageError{"-mode enforce needs -duration: enforce mode only runs bounded in this phase (fail-safe 5)"}
	case cfg.mode == modeEnforce && cfg.learn:
		return &usageError{"-learn with -mode enforce: learning never denies, run it in monitor mode"}
	case cfg.learn && cfg.learned == cfg.rules:
		return &usageError{"-learned must not be the live rules file: learning never writes it"}
	}
	return nil
}
