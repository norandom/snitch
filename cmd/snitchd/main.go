// snitchd: egress control in the kernel (BPF LSM). The daemon configures, the kernel decides.
//
// Fail-safes live in the BPF program (see bpf/snitch.bpf.c); here: the heartbeat the program
// needs to enforce at all, bounded enforce mode, and a process that ends (and so detaches the
// hooks) on any contract violation.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"runtime/debug"

	"github.com/norandom/snitch/internal/contract"
)

const (
	exitUsage     = 2
	exitViolation = 70 // a programming error ended the daemon: the hooks are detached, fail open
)

func main() {
	cfg, err := parseFlagsTo(os.Args[1:], os.Stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, "snitchd:", err)
		os.Exit(exitUsage)
	}
	os.Exit(run(cfg))
}

// run is the daemon's life: startup sequence, then the jobs until one ends the run.
func run(cfg config) (code int) {
	defer func() {
		var v *contract.Violation
		if r := recover(); r != nil {
			if err, ok := r.(error); ok && errors.As(err, &v) {
				fmt.Fprintf(os.Stderr, "snitchd: %v\n%s", v, debug.Stack())
				code = exitViolation
				return
			}
			panic(r)
		}
	}()
	d, err := startup(cfg)
	if err != nil {
		fmt.Fprintln(os.Stderr, "snitchd:", err)
		return 1
	}
	defer d.close()
	return d.serve()
}
