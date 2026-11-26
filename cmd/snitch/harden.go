// harden.go: process-level anti-attach hardening (requirement 13.11, design cmd/snitch).
// Marks the running process non-dumpable via PR_SET_DUMPABLE = 0 before dispatching any
// verb so same-user processes cannot attach via ptrace or read /proc/<pid>/mem.
//
// Fail-safe implications: runs as an ordinary user with no elevated privileges (12.6);
// if hardening fails, the binary refuses to proceed and exits 1 with one line on stderr.
package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

var setNonDumpable = func() error {
	return unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0)
}

// harden marks the process non-dumpable before any verb runs.
func harden() error {
	if err := setNonDumpable(); err != nil {
		return fmt.Errorf("harden: %w", err)
	}
	return nil
}
