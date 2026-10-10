// Package trial decides the daemon's mode from two files on disk: a trial deadline and a
// kept-enforce marker (fail-safe rule 5: deny mode only as a timed trial with a boot revert).
//
// Decide is pure: it never touches the clock, the files or the kernel. Every path that is not
// a live trial on this boot, or an explicitly kept enforce, is monitor. A trial from another
// boot, a passed deadline, a trial older than MaxTrial on the wall clock (a backward clock
// jump cannot extend one) and a malformed file all end in monitor with the file marked spent,
// so the daemon removes it and the denial cannot come back on its own.
package trial

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/contract"
)

// Mode is the value written into the kernel's control map: Monitor 0, Enforce 1.
type Mode uint8

const (
	Monitor Mode = 0
	Enforce Mode = 1
)

// The trial bounds: a longer enforce needs the keep step.
const (
	MinTrial     = time.Minute
	MaxTrial     = time.Hour
	DefaultTrial = 10 * time.Minute
)

// Deadline is the content of the trial file.
type Deadline struct {
	Start time.Time // when the trial was started (clock-jump cap)
	End   time.Time
	Boot  string // boot id when started
}

// State is what Store.Read found on disk.
type State struct {
	Trial    *Deadline // nil: no trial file
	Kept     bool      // the enforce file exists
	Problems []string  // malformed files found by Read (the daemon logs and clears them)
}

// Decision is a mode with the log line that explains it.
type Decision struct {
	Mode       Mode
	Reason     string // the log line on a transition
	ClearTrial bool   // the trial file is spent (ended, foreign boot, malformed, superseded)
}

// Decide applies the design's decision table to the files as read at now on the given boot.
// Requires a non-zero now and a boot id; ensures ClearTrial only when a trial file exists.
func Decide(now time.Time, bootID string, st State, learning bool) Decision {
	contract.Require(!now.IsZero(), "decide: zero time")
	contract.Require(bootID != "", "decide: empty boot id")
	return spent(st, decide(now, bootID, st, learning))
}

// decide is the table itself, in row order; later rows never see a kept or learning state.
func decide(now time.Time, bootID string, st State, learning bool) Decision {
	present := st.Trial != nil || len(st.Problems) > 0
	switch {
	case learning: // learning never denies, whatever the files say
		return Decision{Monitor, "learning: trial/kept files ignored", false}
	case st.Kept: // keep supersedes: a left-over trial file is removed, a broken one named
		return Decision{Enforce, keptReason(st), present}
	case st.Trial == nil && len(st.Problems) > 0:
		return Decision{Monitor, "trial file unreadable: " + strings.Join(st.Problems, "; ") + ", removed", true}
	case st.Trial == nil:
		return Decision{Monitor, "no trial", false}
	case st.Trial.Boot != bootID: // a reboot ends an open trial, deadline past or ahead
		return Decision{Monitor, "trial ended at boot", true}
	case over(now, *st.Trial):
		return Decision{Monitor, "trial ended at its deadline", true}
	}
	return Decision{Enforce, "trial until " + st.Trial.End.Format(time.RFC3339), false}
}

// over caps the trial twice: at its End and at MaxTrial after its Start, so a wall clock
// that jumped backwards after the start cannot keep enforce beyond the bound.
func over(now time.Time, d Deadline) bool {
	return !now.Before(d.End) || now.Sub(d.Start) > MaxTrial
}

// spent is the postcondition: a trial is only reported spent when there is a file to remove.
func spent(st State, d Decision) Decision {
	contract.Ensure(!d.ClearTrial || st.Trial != nil || len(st.Problems) > 0,
		"decide: clear trial without a trial file")
	return d
}

// Bounds checks a requested trial duration against MinTrial and MaxTrial.
func Bounds(d time.Duration) error {
	if d < MinTrial || d > MaxTrial {
		return fmt.Errorf("trial duration %v: must be between %v and %v", d, MinTrial, MaxTrial)
	}
	return nil
}

// bootIDPath is the kernel's boot id, a new uuid on every boot.
const bootIDPath = "/proc/sys/kernel/random/boot_id"

// BootID reads the boot id through read (os.ReadFile in the daemon) and trims it.
func BootID(read func(string) ([]byte, error)) (string, error) {
	b, err := read(bootIDPath)
	if err != nil {
		return "", fmt.Errorf("boot id: %w", err)
	}
	id := strings.TrimSpace(string(b))
	if id == "" {
		return "", errors.New("boot id: " + bootIDPath + " is empty")
	}
	return id, nil
}

// keptReason is "enforce kept", with what a broken trial file held appended (Req 3.5 wants it
// logged) so the "enforce kept" prefix still matches.
func keptReason(st State) string {
	if len(st.Problems) == 0 {
		return "enforce kept"
	}
	return "enforce kept; trial file unreadable: " + strings.Join(st.Problems, "; ") + ", removed"
}
