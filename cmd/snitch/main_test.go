package main

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// run calls the command line with args and returns the exit code and both outputs.
func run(args ...string) (int, string, string) {
	var out, errOut bytes.Buffer
	code := runMain(args, &out, &errOut)
	return code, out.String(), errOut.String()
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

func TestVersionFlagPrintsAndExitsZero(t *testing.T) {
	for _, flag := range []string{"-version", "--version"} {
		code, out, errOut := run(flag)
		if code != 0 || out != "dev\n" || errOut != "" {
			t.Fatalf("%s: want 0, %q, no stderr; got %d, %q, %q", flag, "dev\n", code, out, errOut)
		}
	}
}

// A link with -X main.version= would print an empty line: the contract trips instead.
func TestVersionContractRefusesAnEmptyVersion(t *testing.T) {
	v := contracttest.Panics(t, contract.Postcondition, func() { printVersion(io.Discard, "") })
	if v.Msg != "version: empty" {
		t.Fatalf("want message %q, got %q", "version: empty", v.Msg)
	}
}

// Requirement 1.6 through main's own handler: the violation ends the process with 70 and
// the stack on stderr, nothing on stdout.
func TestVersionViolationExits70WithTheStack(t *testing.T) {
	old := version
	version = ""
	defer func() { version = old }()
	code, out, errOut := run("-version")
	if code != exitViolation || out != "" {
		t.Fatalf("want exit %d and no stdout, got %d, %q", exitViolation, code, out)
	}
	if !strings.Contains(errOut, "contract ensure: version: empty") ||
		!strings.Contains(errOut, "runtime/debug.Stack") {
		t.Fatalf("want the violation and the stack on stderr, got %q", errOut)
	}
}

func TestUsageErrorsExitTwo(t *testing.T) {
	cases := [][]string{
		nil, {"nonsense"}, {"-bogus"}, {"-version", "extra"}, {"Tray"}, {""},
	}
	for _, args := range cases {
		code, out, errOut := run(args...)
		if code != exitUsage || out != "" || !strings.Contains(errOut, "usage: snitch") {
			t.Fatalf("%q: want exit 2, no stdout, the usage line; got %d, %q, %q", args, code, out, errOut)
		}
	}
}

// The tray verb is known (not a usage error) but not built yet: it says so and exits 1.
func TestUsageTrayIsAKnownVerbNotBuiltYet(t *testing.T) {
	code, out, errOut := run("tray")
	if code != exitFail || out != "" || errOut != "snitch tray: not built yet\n" {
		t.Fatalf("want 1, no stdout, the placeholder line; got %d, %q, %q", code, out, errOut)
	}
}

// A panic that is not a contract violation is not ours to turn into an exit code.
func TestUsageOtherPanicsAreNotSwallowed(t *testing.T) {
	defer func() {
		if r := recover(); r != "boom" {
			t.Fatalf("want the panic to go on, got %v", r)
		}
	}()
	runMain(nil, io.Discard, panicWriter{})
}

type panicWriter struct{}

func (panicWriter) Write([]byte) (int, error) { panic("boom") }
