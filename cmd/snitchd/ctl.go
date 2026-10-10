// ctl.go: the command line of snitchd. `snitchd <verb> [flags]` talks to the running daemon
// through its files and the pinned maps instead of starting a daemon. Exit codes: 0 ok, 1
// refused or daemon down, 2 usage (an unknown word, a bad flag, not root).
//
// Fail-safe note: the verbs only ever read the kill map; nothing here writes the control or
// kill map (the kernel's fail-safes stay the kernel's and the serial console's).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/contract"
)

// verb is one command-line word and its handler. The handler parses its own flags through
// c.parse (which carries the shared -state-dir and -status) and returns the exit code.
type verb struct {
	name string
	run  func(c *ctl, args []string) int
}

// verbs is the table main consults; the handlers of 4.2 (trial, keep, unkeep, end) and 4.3
// (status) replace the stubs.
var verbs = []verb{
	{"trial", notImplemented},
	{"keep", notImplemented},
	{"unkeep", notImplemented},
	{"end", notImplemented},
	{"status", notImplemented},
}

// probes read the kernel side: the pinned control map (heartbeat age on the monotonic clock,
// mode, flags; ok false when the map is absent) and the kill map. Fakes replace them in tests.
type probes struct {
	control func() (age time.Duration, mode, flags uint32, ok bool)
	kill    func() bool
}

func realProbes() probes { return probes{control: controlState, kill: killSet} }

// ctl is one invocation: the verb, the shared flag values, where it prints, and its delegates.
type ctl struct {
	name     string
	stateDir string
	status   string
	out      io.Writer
	errw     io.Writer
	euid     func() int
	probes   probes
}

func newCtl(out, errw io.Writer, p probes) *ctl {
	return &ctl{stateDir: defaultStateDir, status: defaultStatus, out: out, errw: errw, euid: os.Geteuid, probes: p}
}

// parse reads the verb's flags: the shared -state-dir and -status plus the verb's own, which
// the handler registers through add. Usage goes to c.errw; a bad flag is the error.
func (c *ctl) parse(args []string, add func(*flag.FlagSet)) error {
	fs := flag.NewFlagSet("snitchd "+c.name, flag.ContinueOnError)
	fs.SetOutput(c.errw)
	fs.StringVar(&c.stateDir, "state-dir", defaultStateDir, "directory of the trial and kept-enforce files (the daemon's -state-dir)")
	fs.StringVar(&c.status, "status", defaultStatus, "status file the daemon writes (the daemon's -status)")
	if add != nil {
		add(fs)
	}
	return fs.Parse(args)
}

func isVerb(name string) bool {
	for _, v := range verbs {
		if v.name == name {
			return true
		}
	}
	return false
}

func verbNames(table []verb) string {
	names := make([]string, 0, len(table))
	for _, v := range table {
		names = append(names, v.name)
	}
	return strings.Join(names, ", ")
}

// runCtl is main's entry: the first argument is the verb (or a bare word that is not one).
func runCtl(args []string) int {
	return dispatch(verbs, newCtl(os.Stdout, os.Stderr, realProbes()), args)
}

// dispatch finds the verb, insists on root (the pinned maps and the state files need it) and
// runs the handler. An unknown word is a usage error that names the verbs.
func dispatch(table []verb, c *ctl, args []string) int {
	contract.Require(len(args) > 0, "dispatch: a verb is required")
	for _, v := range table {
		if v.name != args[0] {
			continue
		}
		c.name = v.name
		if c.euid() != 0 {
			fmt.Fprintf(c.errw, "snitchd %s: run as root (the pinned maps and the state files need it)\n", c.name)
			return exitUsage
		}
		return v.run(c, args[1:])
	}
	fmt.Fprintf(c.errw, "snitchd: %q is not a command; commands: %s (flags alone run the daemon, -h lists them)\n",
		args[0], verbNames(table))
	return exitUsage
}

// notImplemented holds a verb's place until its task fills it in: the shared flags parse
// (-h prints usage, exit 0), then a clear refusal.
func notImplemented(c *ctl, args []string) int {
	if err := c.parse(args, nil); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return exitUsage
	}
	fmt.Fprintf(c.errw, "snitchd %s: not implemented yet\n", c.name)
	return exitUsage
}
