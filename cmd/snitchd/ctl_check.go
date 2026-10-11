// ctl_check.go: `snitchd check [-rules F]` (spec deploy-service, Req 3.1) loads a rules file the
// way the daemon does, parse, resolve through the OS seams, encode, without root or BPF, so
// the VM repo's CI and the operator see the daemon's summary before the file reaches a host.
// Exit 0: valid, stdout the daemon's summary line plus one `unresolved:` line per pattern
// without a match. Exit 1: the parser's or resolver's error (file:line: reason) on stderr; a
// missing file is an error here ("does not exist"), unlike the daemon, which starts empty: a
// deploy must not ship a missing file. Exit 2: usage.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/rules"
)

func checkUsage(f *flag.FlagSet) func() {
	return func() {
		fmt.Fprint(f.Output(), `usage: snitchd check [-rules /etc/snitch/rules.toml]
  loads the rules file as the daemon would, without root: exit 0 and the summary when it is
  valid (one unresolved: line per pattern that matched no executable), 1 and file:line: reason
  on stderr when it is not (a missing file included), 2 on a usage error
`)
		f.PrintDefaults()
	}
}

// checkFlags parses `check [-rules F]`: the daemon's default path, no positional words, an
// empty path is an operator mistake (the contract below is for the programming error).
func (c *ctl) checkFlags(args []string) (path string, code int, done bool) {
	var set *flag.FlagSet
	code, done = c.parseVerb(args, func(f *flag.FlagSet) {
		set = f
		f.StringVar(&path, "rules", defaultRules, "rules file to check (the daemon's -rules)")
		f.Usage = checkUsage(f)
	})
	switch {
	case done:
		return "", code, true
	case len(set.Args()) > 0:
		fmt.Fprintf(c.errw, "snitchd check: takes no words, got %q (flags only)\n", set.Args())
		return "", exitUsage, true
	case path == "":
		fmt.Fprintln(c.errw, "snitchd check: -rules must not be empty")
		return "", exitUsage, true
	}
	return path, exitOK, false
}

// checkRules is the verb's work: Load, Resolve and Encode as the daemon's loadRules does, with
// a missing file refused instead of read as empty. Resolver warnings (the mountinfo fallback)
// go to stderr like the refusals; the summary and the unresolved lines are the stdout.
func (c *ctl) checkRules(path string) int {
	contract.Require(path != "", "check: empty rules path")
	contract.Require(c.out != nil && c.errw != nil, "check: incomplete writers")
	f, err := rules.Load(path)
	if errors.Is(err, fs.ErrNotExist) {
		return c.refuse(path + ": does not exist")
	}
	if err != nil {
		return c.refuse(err.Error())
	}
	warn := func(msg string) { fmt.Fprintf(c.errw, "snitchd check: %s\n", msg) }
	res, err := rules.Resolve(f, rules.OSFS(warn))
	if err != nil {
		return c.refuse(err.Error())
	}
	fmt.Fprintln(c.out, summary(&snapshot{res: res, ent: rules.Encode(res)}))
	for _, u := range res.Unresolved {
		fmt.Fprintln(c.out, unresolvedLine(u))
	}
	return exitOK
}

// unresolvedLine: `unresolved: <program> <pattern> (<reason>)`; a program without paths has
// no pattern to show.
func unresolvedLine(u rules.Unresolved) string {
	if u.Pattern == "" {
		return fmt.Sprintf("unresolved: %s (%s)", u.Program, u.Reason)
	}
	return fmt.Sprintf("unresolved: %s %s (%s)", u.Program, u.Pattern, u.Reason)
}

// runCheck: `check [-rules F]`, exit 0 valid, 1 invalid or missing, 2 usage (Req 3.1).
func runCheck(c *ctl, args []string) int {
	path, code, done := c.checkFlags(args)
	if done {
		return code
	}
	return c.checkRules(path)
}
