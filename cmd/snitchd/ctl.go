// ctl.go: the command line of snitchd. `snitchd <verb> [flags]` talks to the running daemon
// through its files and the pinned maps instead of starting a daemon. Exit codes: 0 ok, 1
// refused or daemon down, 2 usage (an unknown word, a bad flag, not root).
//
// Fail-safe note: the verbs only ever read the kill map; nothing here writes the control or
// kill map (the kernel's fail-safes stay the kernel's and the serial console's).
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/status"
	"github.com/norandom/snitch/internal/trial"
)

// verb is one command-line word and its handler. The handler parses its own flags through
// c.parse (which carries the shared -state-dir and -status) and returns the exit code. root
// says dispatch must refuse a non-root caller (the pinned maps and the state files need it).
type verb struct {
	name string
	run  func(c *ctl, args []string) int
	root bool
}

// verbs is the table main consults; the writing handlers live in ctl_verbs.go, status in
// ctl_status.go, check (the only verb without root) in ctl_check.go.
var verbs = []verb{
	{"trial", runTrial, true},
	{"keep", runKeep, true},
	{"unkeep", runUnkeep, true},
	{"end", runEnd, true},
	{"status", runStatus, true},
	{"check", runCheck, false},
}

// probes read the kernel side: the pinned control map (heartbeat age on the monotonic clock,
// mode, flags; ok false when the map is absent) and the kill map. Fakes replace them in tests.
type probes struct {
	control func() (age time.Duration, mode, flags uint32, ok bool)
	kill    func() bool
}

func realProbes() probes { return probes{control: controlState, kill: killSet} }

// deps are the verbs' other delegates, so every message is tested without root or a daemon:
// the store over the parsed -state-dir, whether that directory exists (the store would create
// it; the CLI refuses instead), the status record, the boot id, the clock and the y/N prompt.
type deps struct {
	store      func(dir string) trial.Store
	dirExists  func(dir string) bool
	readStatus func(path string) (status.Record, error)
	bootID     func() (string, error)
	now        func() time.Time
	confirm    func(question string) bool
}

func realDeps(in io.Reader, out io.Writer) deps {
	return deps{
		store:      trial.OSStore,
		dirExists:  func(dir string) bool { fi, err := os.Stat(dir); return err == nil && fi.IsDir() },
		readStatus: status.Read,
		bootID:     func() (string, error) { return trial.BootID(os.ReadFile) },
		now:        time.Now,
		confirm:    askYN(in, out),
	}
}

// askYN prints the question and reads one line: "y" or "yes" in any case is a yes; anything
// else, a closed stdin included, is a no (the safe answer: nothing starts).
func askYN(in io.Reader, out io.Writer) func(string) bool {
	r := bufio.NewReader(in)
	return func(question string) bool {
		fmt.Fprint(out, question, " ")
		line, _ := r.ReadString('\n')
		answer := strings.ToLower(strings.TrimSpace(line))
		return answer == "y" || answer == "yes"
	}
}

// ctl is one invocation: the verb, the shared flag values, where it prints, and its delegates.
type ctl struct {
	name     string
	stateDir string
	status   string
	out      io.Writer
	errw     io.Writer
	euid     func() int
	probes   probes
	deps     deps
}

func newCtl(out, errw io.Writer, p probes) *ctl {
	return &ctl{stateDir: defaultStateDir, status: defaultStatus, out: out, errw: errw,
		euid: os.Geteuid, probes: p, deps: realDeps(os.Stdin, out)}
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

// dispatch finds the verb, insists on root where the verb needs it (the pinned maps and the
// state files) and runs the handler. An unknown word is a usage error that names the verbs.
func dispatch(table []verb, c *ctl, args []string) int {
	contract.Require(len(args) > 0, "dispatch: a verb is required")
	for _, v := range table {
		if v.name != args[0] {
			continue
		}
		c.name = v.name
		if v.root && c.euid() != 0 {
			fmt.Fprintf(c.errw, "snitchd %s: run as root (the pinned maps and the state files need it)\n", c.name)
			return exitUsage
		}
		return v.run(c, args[1:])
	}
	fmt.Fprintf(c.errw, "snitchd: %q is not a command; commands: %s (flags alone run the daemon, -h lists them)\n",
		args[0], verbNames(table))
	return exitUsage
}

// liveTrial is the trial the daemon is following: this boot's, before its deadline (Decide's
// rule, clock cap included); a foreign-boot or expired file counts as none (the daemon clears
// it). The kept marker is left out so a kept enforce does not read as a trial.
func liveTrial(st trial.State, boot string, now time.Time) *trial.Deadline {
	if st.Trial == nil || trial.Decide(now, boot, trial.State{Trial: st.Trial}, false).Mode != trial.Enforce {
		return nil
	}
	return st.Trial
}

// present says which files exist, a malformed one included (Read names it in a Problem), so
// end and unkeep report what they removed.
func present(store trial.Store, st trial.State) (trialFile, keptFile bool) {
	trialFile, keptFile = st.Trial != nil, st.Kept
	for _, p := range st.Problems {
		trialFile = trialFile || strings.HasPrefix(p, store.TrialPath()+":")
		keptFile = keptFile || strings.HasPrefix(p, store.KeptPath()+":")
	}
	return trialFile, keptFile
}
