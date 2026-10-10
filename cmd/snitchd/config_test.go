package main

import (
	"errors"
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
