package main

import (
	"errors"
	"flag"
	"strings"
	"testing"
	"time"
)

func TestParseFlagsDefaults(t *testing.T) {
	cfg, err := parseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.rules != "/etc/snitch/rules.toml" || cfg.learned != "/var/lib/snitch/learned.toml" || cfg.learn ||
		cfg.mode != modeMonitor || cfg.duration != 0 {
		t.Fatalf("defaults wrong: %+v", cfg)
	}
}

func TestParseFlagsValues(t *testing.T) {
	cfg, err := parseFlags([]string{"-rules", "/tmp/r.toml", "-learn", "-learned", "/tmp/l.toml", "-mode", "monitor", "-duration", "10s"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.rules != "/tmp/r.toml" || !cfg.learn || cfg.learned != "/tmp/l.toml" || cfg.duration != 10*time.Second {
		t.Fatalf("values wrong: %+v", cfg)
	}
}

func TestChecksRefuseUnsafeCombinations(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"enforce without duration", []string{"-mode", "enforce"}, "needs -duration"},
		{"learn with enforce", []string{"-mode", "enforce", "-duration", "10s", "-learn"}, "learning never denies"},
		{"unknown mode", []string{"-mode", "panic"}, "mode"},
		{"negative duration", []string{"-duration", "-5s"}, "duration"},
		{"learned is the live file", []string{"-learn", "-rules", "/tmp/r.toml", "-learned", "/tmp/r.toml"}, "live rules file"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := parseFlags(c.args)
			var ue *usageError
			if !errors.As(err, &ue) || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("want a usage error containing %q, got %v", c.want, err)
			}
		})
	}
}

func TestChecksAcceptSafeCombinations(t *testing.T) {
	for _, args := range [][]string{
		{"-mode", "enforce", "-duration", "90s"},
		{"-learn", "-duration", "60s"},
		{"-mode", "monitor"},
	} {
		if _, err := parseFlags(args); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
}

func TestUsageErrorExitCodeIsTwo(t *testing.T) {
	if (&usageError{"x"}).exitCode() != 2 {
		t.Fatal("usage errors exit 2, before any kernel object is loaded")
	}
}

func TestHelpIsNotAUsageError(t *testing.T) {
	_, err := parseFlags([]string{"-h"})
	var ue *usageError
	if !errors.Is(err, flag.ErrHelp) || errors.As(err, &ue) {
		t.Fatalf("-h must surface flag.ErrHelp (exit 0), got %v", err)
	}
}

func TestSourceIsFlagOnlyWhenModeIsGiven(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want modeSource
	}{
		{"no -mode: the files decide", nil, sourceFiles},
		{"-mode monitor", []string{"-mode", "monitor"}, sourceFlag},
		{"-mode enforce bounded", []string{"-mode", "enforce", "-duration", "10s"}, sourceFlag},
		{"other flags keep the files", []string{"-learn", "-duration", "10s", "-state-dir", "/tmp/s"}, sourceFiles},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			cfg, err := parseFlags(c.args)
			if err != nil {
				t.Fatal(err)
			}
			if cfg.source != c.want {
				t.Fatalf("want source %q, got %q", c.want, cfg.source)
			}
		})
	}
}

func TestSourcePathsHaveTheDesignDefaultsAndTakeFlags(t *testing.T) {
	cfg, err := parseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.stateDir != "/var/lib/snitch" || cfg.status != "/run/snitch/status" {
		t.Fatalf("defaults wrong: state dir %q, status %q", cfg.stateDir, cfg.status)
	}
	cfg, err = parseFlags([]string{"-state-dir", "/tmp/x/state", "-status", "/tmp/x/status"})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.stateDir != "/tmp/x/state" || cfg.status != "/tmp/x/status" {
		t.Fatalf("values wrong: state dir %q, status %q", cfg.stateDir, cfg.status)
	}
}
