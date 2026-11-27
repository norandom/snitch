// Package lsm probes whether the kernel's active LSM list includes bpf and, when it does
// not, whether the running kernel supports BPF LSM and whether the next GRUB boot is
// configured for it.
//
// Fail-safe implications: Probe is strictly read-only over an injected reader and never
// returns an error; unreadable inputs become Unknown or CanTell=false. Nothing here can
// deny a connection, change the daemon mode, or touch the kill switch.
package lsm

import (
	"bytes"
	"compress/gzip"
	"io"
	"strings"

	"github.com/norandom/snitch/internal/contract"
)

// State is whether the kernel's active LSM list contains bpf.
type State string

const (
	Active   State = "active"
	Inactive State = "inactive"
	Unknown  State = "unknown"
)

// ListPath is the securityfs file listing the kernel's active LSMs in boot order.
const ListPath = "/sys/kernel/security/lsm"

const (
	osReleasePath    = "/proc/sys/kernel/osrelease"
	bootConfigPrefix = "/boot/config-"
	procConfigPath   = "/proc/config.gz"
)

var grubPaths = []string{"/boot/grub/grub.cfg", "/boot/grub2/grub.cfg"}

const (
	sentenceActive      = "kernel hook active"
	sentencePending     = "kernel hook inactive: reboot to activate it; until then connections are neither seen nor blocked"
	sentenceUnconfig    = "kernel hook inactive: bpf is not in the kernel's LSM list and the next boot is not configured for it; connections are neither seen nor blocked"
	sentenceUnsupported = "kernel hook unavailable: this kernel is built without BPF LSM support, so no reboot can activate it; connections are neither seen nor blocked"
	sentenceCannotTell  = "kernel hook inactive: connections are neither seen nor blocked; run as root to see whether a reboot is pending"
	sentenceUnknown     = "kernel hook not checked: the kernel's LSM list could not be read"
)

// Hook is what the kernel will do with the daemon's LSM programs.
type Hook struct {
	State   State
	Pending bool // Inactive only: the generated boot configuration already carries bpf
	CanTell bool // Inactive only: false when the boot configuration could not be read
	// Unsupported: the running kernel's build configuration has no CONFIG_BPF_LSM=y, so no
	// reboot into this kernel can activate the hook. Read from /boot/config-<release>
	// (release from /proc/sys/kernel/osrelease), falling back to /proc/config.gz; when
	// neither is readable, support is not claimed either way and Unsupported stays false.
	Unsupported bool
}

// Probe reads ListPath and, when bpf is not active, the running kernel configuration and
// GRUB configurations. read is os.ReadFile in production. It never returns an error: an
// unreadable list is Unknown.
func Probe(read func(string) ([]byte, error)) Hook {
	contract.Require(read != nil, "lsm.Probe: nil reader")
	raw, err := read(ListPath)
	if err != nil {
		return Hook{State: Unknown}
	}
	if hasToken(string(raw), "bpf") {
		return Hook{State: Active}
	}
	if kernelUnsupported(read) {
		return Hook{State: Inactive, Unsupported: true}
	}
	pending, canTell := grubPending(read)
	return Hook{State: Inactive, Pending: pending, CanTell: canTell}
}

// Sentence is the one human-readable line for h, fixed wording, no OS error text.
func (h Hook) Sentence() string {
	switch h.State {
	case Active:
		return sentenceActive
	case Inactive:
		return inactiveSentence(h)
	default:
		return sentenceUnknown
	}
}

func inactiveSentence(h Hook) string {
	switch {
	case h.Unsupported:
		return sentenceUnsupported
	case h.Pending:
		return sentencePending
	case h.CanTell:
		return sentenceUnconfig
	default:
		return sentenceCannotTell
	}
}

func kernelUnsupported(read func(string) ([]byte, error)) bool {
	if raw, err := read(osReleasePath); err == nil {
		if rel := strings.TrimSpace(string(raw)); rel != "" {
			if cfg, err := read(bootConfigPrefix + rel); err == nil {
				return !hasConfigBPFLSM(cfg)
			}
		}
	}
	gz, err := read(procConfigPath)
	if err != nil {
		return false
	}
	cfg, err := gunzip(gz)
	if err != nil {
		return false
	}
	return !hasConfigBPFLSM(cfg)
}

func gunzip(data []byte) ([]byte, error) {
	r, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}

func hasConfigBPFLSM(cfg []byte) bool {
	for line := range strings.SplitSeq(string(cfg), "\n") {
		if strings.TrimSpace(line) == "CONFIG_BPF_LSM=y" {
			return true
		}
	}
	return false
}

func grubPending(read func(string) ([]byte, error)) (pending, canTell bool) {
	for _, p := range grubPaths {
		raw, err := read(p)
		if err != nil {
			continue
		}
		canTell = true
		if grubHasBPFLSM(string(raw)) {
			return true, true
		}
	}
	return false, canTell
}

func grubHasBPFLSM(cfg string) bool {
	for line := range strings.SplitSeq(cfg, "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || (fields[0] != "linux" && fields[0] != "linuxefi") {
			continue
		}
		for _, arg := range fields[1:] {
			if val, ok := strings.CutPrefix(stripQuotes(arg), "lsm="); ok && hasToken(stripQuotes(val), "bpf") {
				return true
			}
		}
	}
	return false
}

func stripQuotes(s string) string {
	for _, q := range []byte{'"', '\''} {
		if len(s) >= 2 && s[0] == q && s[len(s)-1] == q {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func hasToken(list, want string) bool {
	for tok := range strings.SplitSeq(strings.TrimSpace(list), ",") {
		if strings.TrimSpace(tok) == want {
			return true
		}
	}
	return false
}
