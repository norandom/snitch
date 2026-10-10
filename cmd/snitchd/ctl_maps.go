// ctl_maps.go: the command line's view of the pinned maps under /sys/fs/bpf/snitch. Reads
// only: the control map for the heartbeat age (on CLOCK_MONOTONIC, the clock beat() writes),
// mode and flags, and the kill map. An absent pin means no daemon has run since boot: not
// running, kill clear. Root is needed to open the pins; dispatch checks that first.
package main

import (
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"golang.org/x/sys/unix"

	snitchbpf "github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/contract"
)

// lookupFn reads one key of a pinned map into out; an absent pin is an error.
type lookupFn func(name string, key uint32, out any) error

func openPinned(name string) (*ebpf.Map, error) {
	return ebpf.LoadPinnedMap(filepath.Join(pinDir, name), nil)
}

// lookupPinned is the real lookupFn: open the pin, read the key, close.
func lookupPinned(name string, key uint32, out any) error {
	m, err := openPinned(name)
	if err != nil {
		return err
	}
	defer m.Close()
	return m.Lookup(key, out)
}

// monotonicNow is the daemon's heartbeat clock as a duration since boot.
func monotonicNow() time.Duration {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return 0
	}
	return time.Duration(ts.Nano())
}

// controlFrom builds the control reader from its delegates; controlState is the real one.
func controlFrom(lookup lookupFn, now func() time.Duration) func() (time.Duration, uint32, uint32, bool) {
	contract.Require(lookup != nil && now != nil, "controlFrom: lookup and clock are required")
	return func() (age time.Duration, mode, flags uint32, ok bool) {
		var c snitchbpf.SnitchControlState
		if err := lookup("control", 0, &c); err != nil {
			return 0, 0, 0, false
		}
		return now() - time.Duration(c.HeartbeatNs), c.Mode, c.Flags, true
	}
}

// killFrom builds the kill reader from its delegate; killSet is the real one.
func killFrom(lookup lookupFn) func() bool {
	contract.Require(lookup != nil, "killFrom: lookup is required")
	return func() bool {
		var v uint32
		if err := lookup("kill", 0, &v); err != nil {
			return false
		}
		return v != 0
	}
}

func controlState() (age time.Duration, mode, flags uint32, ok bool) {
	return controlFrom(lookupPinned, monotonicNow)()
}

func killSet() bool { return killFrom(lookupPinned)() }
