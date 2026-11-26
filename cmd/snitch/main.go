// snitch: the user side of snitchd. No argument opens the overview; `egress`, `status`,
// `default` and `tray` are its verbs; `-version` prints the build.
//
// Fail-safe note: this binary runs as the ordinary user, never as root, and decides nothing.
// It only talks to the daemon's API; it imports none of the BPF, rules, trial or dns
// packages (imports_test.go pins that). Whatever it does or fails to do, the kernel's
// decisions stay the kernel's; a crash or a contract violation here (exit 70) changes no
// verdict.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"strings"

	"github.com/norandom/snitch/internal/contract"
)

const (
	exitFail      = 1
	exitUsage     = 2
	exitViolation = 70 // a programming error ended the tray; the daemon and the kernel go on as before
)

const usage = "usage: snitch [egress | status | default | tray] | snitch -version"

func main() { os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr)) }

// runMain is the whole command line: it hardens the process, dispatches args and returns
// the exit code. A contract violation anywhere below is turned into exit 70 with the stack
// on stderr; any other panic is not ours to hide and goes on.
func runMain(args []string, stdout, stderr io.Writer) (code int) {
	defer func() {
		if r := recover(); r != nil {
			var v *contract.Violation
			if err, ok := r.(error); ok && errors.As(err, &v) {
				// The console print is best-effort: this handler exists to report the
				// panic, and a writer that cannot take the report has nowhere better
				// to send an error about it.
				_, _ = fmt.Fprintf(stderr, "snitch: %v\n%s", v, debug.Stack())
				code = exitViolation
				return
			}
			panic(r)
		}
	}()
	if err := harden(); err != nil {
		_, _ = fmt.Fprintf(stderr, "snitch: %v\n", err)
		return exitFail
	}
	return dispatch(args, stdout, stderr)
}

// dispatch reads the first word: no argument opens the overview; `-version` (or `--version`)
// alone prints the build; `egress`, `status`, `default`, and `tray` select their verbs.
// Everything else is a usage error.
func dispatch(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 || isOverviewFlag(args[0]) {
		return runOverview(args, os.Stdin, stdout, stderr)
	}
	switch args[0] {
	case "-version", "--version":
		if len(args) != 1 {
			_, _ = fmt.Fprintln(stderr, "snitch: -version takes no arguments\n"+usage)
			return exitUsage
		}
		printVersion(stdout, version)
		return 0
	case "egress":
		return runEgress(args[1:], os.Stdin, stdout, stderr)
	case "status":
		return runStatus(args[1:], stdout, stderr)
	case "default":
		return runDefault(args[1:], os.Stdin, stdout, stderr)
	case "tray":
		return runTray(args[1:], stderr)
	}
	_, _ = fmt.Fprintf(stderr, "snitch: unknown command %q\n%s\n", args[0], usage)
	return exitUsage
}

func isOverviewFlag(arg string) bool {
	name, _, _ := strings.Cut(arg, "=")
	switch name {
	case "-api", "--api", "-since", "--since":
		return true
	}
	return false
}
