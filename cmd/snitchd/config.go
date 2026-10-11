package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"
)

const (
	modeMonitor = "monitor"
	modeEnforce = "enforce"

	defaultRules    = "/etc/snitch/rules.toml"
	defaultOverlay  = "/etc/snitch/rules.d/local.toml" // the operator's local rules, written by the API; merged over the rules file
	defaultLearned  = "/var/lib/snitch/learned.toml"
	defaultAPI      = "/run/snitch/api.sock" // the local API socket (RuntimeDirectory); "" turns the API off
	defaultStateDir = "/var/lib/snitch"      // the trial and kept-enforce files (systemd StateDirectory)
	defaultStatus   = "/run/snitch/status"   // the daemon's facts for the command line (RuntimeDirectory)
)

// modeSource says where the daemon's mode comes from: the -mode flag, fixed for the run (the
// bounded enforce test), or the trial and kept files under the state directory (the service).
type modeSource string

const (
	sourceFlag  modeSource = "flag"
	sourceFiles modeSource = "files"
)

// config is everything the command line decides. Checked before any kernel object is loaded.
type config struct {
	rules    string
	overlay  string // "" = no overlay
	learned  string
	api      string // "" = no API
	learn    bool
	mode     string
	source   modeSource
	stateDir string
	status   string
	duration time.Duration
	version  bool // -version: print the build and exit, nothing else is checked
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
	fs.StringVar(&cfg.overlay, "overlay", defaultOverlay, "local rules file merged over -rules with precedence; missing = none, invalid = reported and skipped")
	fs.StringVar(&cfg.api, "api", defaultAPI, "unix socket of the local API; empty disables it")
	fs.BoolVar(&cfg.learn, "learn", false, "learning mode: monitor and record connections no rule covers")
	fs.StringVar(&cfg.learned, "learned", defaultLearned, "where learning mode writes its rules file")
	fs.StringVar(&cfg.mode, "mode", modeMonitor, "monitor (allow + report) or enforce (deny what no rule allows; needs -duration)")
	fs.StringVar(&cfg.stateDir, "state-dir", defaultStateDir, "directory of the trial and kept-enforce files that decide the mode when -mode is not given")
	fs.StringVar(&cfg.status, "status", defaultStatus, "status file the daemon writes for the command line")
	fs.DurationVar(&cfg.duration, "duration", 0, "exit after this long (0: run until signalled)")
	fs.BoolVar(&cfg.version, "version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return cfg, err
		}
		return cfg, &usageError{err.Error()}
	}
	if cfg.version {
		printVersion(stdout, version)
		return cfg, errVersion
	}
	cfg.source = sourceOf(fs)
	return cfg, check(cfg)
}

// sourceOf: a -mode flag on the command line fixes the mode for the run; without one the
// files decide (Req 3.6: the bounded run never reads them).
func sourceOf(fs *flag.FlagSet) modeSource {
	src := sourceFiles
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "mode" {
			src = sourceFlag
		}
	})
	return src
}

// check is fail-safe 5 in this phase: enforce only bounded, and learning can never deny;
// then the file checks.
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
	}
	return checkFiles(cfg)
}

// checkFiles: the files the daemon writes (learned, overlay) are never the file it is deployed
// with, nor each other while learning writes.
func checkFiles(cfg config) error {
	switch {
	case cfg.rules == "":
		return &usageError{"-rules must name a file (a missing one is fine: no rules are loaded)"}
	case cfg.learn && cfg.learned == cfg.rules:
		return &usageError{"-learned must not be the live rules file: learning never writes it"}
	case cfg.overlay == cfg.rules:
		return &usageError{"-overlay must not be the rules file: the overlay is merged over it"}
	case cfg.learn && cfg.overlay == cfg.learned:
		return &usageError{"-overlay must not be the learned file: learning writes it"}
	case cfg.api != "" && under(cfg.api, cfg.stateDir):
		return &usageError{"-api must not be under -state-dir: the socket's directory is made world-traversable"}
	}
	return nil
}

// under says whether path lies inside dir (the API socket's directory is re-moded to 0755).
func under(path, dir string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, "../")
}
