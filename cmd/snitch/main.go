// snitch: the user side of snitchd. `snitch tray` puts the daemon's state in the desktop's
// system tray; `snitch -version` prints the build.
//
// Fail-safe note: this binary runs as the ordinary user, never as root, and decides nothing.
// It only reads the daemon's API; it imports none of the BPF, rules, trial or dns packages
// (imports_test.go pins that). Whatever it does or fails to do, the kernel's decisions stay
// the kernel's; a crash or a contract violation here (exit 70) changes no verdict.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"runtime/debug"

	"github.com/norandom/snitch/internal/contract"
)

const (
	exitFail      = 1
	exitUsage     = 2
	exitViolation = 70 // a programming error ended the tray; the daemon and the kernel go on as before
)

const usage = "usage: snitch tray | snitch -version"

func main() { os.Exit(runMain(os.Args[1:], os.Stdout, os.Stderr)) }

// runMain is the whole command line: it dispatches args and returns the exit code. A
// contract violation anywhere below is turned into exit 70 with the stack on stderr; any
// other panic is not ours to hide and goes on.
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
	return dispatch(args, stdout, stderr)
}

// dispatch reads the first word: `-version` (or `--version`) alone, or the verb `tray`.
// Everything else, including no word at all, is a usage error.
func dispatch(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		_, _ = fmt.Fprintln(stderr, usage)
		return exitUsage
	}
	switch args[0] {
	case "-version", "--version":
		if len(args) != 1 {
			_, _ = fmt.Fprintln(stderr, "snitch: -version takes no arguments\n"+usage)
			return exitUsage
		}
		printVersion(stdout, version)
		return 0
	case "tray":
		return runTray(args[1:], stderr)
	}
	_, _ = fmt.Fprintf(stderr, "snitch: unknown command %q\n%s\n", args[0], usage)
	return exitUsage
}
