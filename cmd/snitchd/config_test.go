package main

import (
	"bytes"
	"errors"
	"flag"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
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

// -version is answered on the command line like -h: printed to stdout, main exits 0, and the
// configuration check is never reached (Req 1.2).
func TestVersionFlagPrintsAndExitsBeforeTheCheck(t *testing.T) {
	for _, args := range [][]string{{"-version"}, {"-version", "-mode", "bogus"}, {"-mode", "enforce", "-version"}} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out bytes.Buffer
			defer swapStdout(&out)()
			_, err := parseFlagsTo(args, io.Discard)
			var ue *usageError
			if !errors.Is(err, errVersion) || !errors.Is(err, flag.ErrHelp) || errors.As(err, &ue) {
				t.Fatalf("want errVersion on main's exit-0 path (flag.ErrHelp), got %v", err)
			}
			if out.String() != version+"\n" {
				t.Fatalf("want %q on stdout, got %q", version+"\n", out.String())
			}
		})
	}
}

func TestVersionIsDevUnlessLinked(t *testing.T) {
	if version != "dev" {
		t.Fatalf("a plain go build carries %q, got %q", "dev", version)
	}
	var out bytes.Buffer
	printVersion(&out, "v9.9.9")
	if out.String() != "v9.9.9\n" {
		t.Fatalf("want the linked value and a newline, got %q", out.String())
	}
}

// A link with -X main.version= would print an empty line: the contract trips instead.
func TestVersionContractRefusesAnEmptyVersion(t *testing.T) {
	v := contracttest.Panics(t, contract.Postcondition, func() { printVersion(io.Discard, "") })
	if v.Msg != "version: empty" {
		t.Fatalf("want message %q, got %q", "version: empty", v.Msg)
	}
	contracttest.Panics(t, contract.Postcondition, func() { startupLine("", modeMonitor, sourceFiles) })
}

func swapStdout(w io.Writer) func() {
	old := stdout
	stdout = w
	return func() { stdout = old }
}
