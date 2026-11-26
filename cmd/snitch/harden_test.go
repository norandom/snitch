package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func readDumpableFlag(t *testing.T) int {
	t.Helper()
	v, err := unix.PrctlRetInt(unix.PR_GET_DUMPABLE, 0, 0, 0, 0)
	if err != nil {
		t.Fatalf("PR_GET_DUMPABLE: %v", err)
	}
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		t.Fatalf("read /proc/self/status: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Dumpable:") {
			fields := strings.Fields(line)
			if len(fields) != 2 || (v == 0 && fields[1] != "0") || (v != 0 && fields[1] == "0") {
				t.Fatalf("PR_GET_DUMPABLE=%d disagrees with /proc/self/status %q", v, line)
			}
			return v
		}
	}
	return v
}

func setDumpableForTest(t *testing.T, v uintptr) {
	t.Helper()
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, v, 0, 0, 0); err != nil {
		t.Fatalf("PR_SET_DUMPABLE(%d): %v", v, err)
	}
}

func TestHardenSetsNonDumpable(t *testing.T) {
	setDumpableForTest(t, 1)
	t.Cleanup(func() { _ = unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0) })

	if got := readDumpableFlag(t); got == 0 {
		t.Fatalf("precondition failed: expected dumpable != 0 before harden()")
	}
	if err := harden(); err != nil {
		t.Fatalf("harden(): %v", err)
	}
	if got := readDumpableFlag(t); got != 0 {
		t.Fatalf("want dumpable == 0 after harden(), got %d", got)
	}
}

func TestHardenRunsBeforeEveryVerb(t *testing.T) {
	t.Cleanup(func() { _ = unix.Prctl(unix.PR_SET_DUMPABLE, 1, 0, 0, 0) })
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+filepath.Join(t.TempDir(), "no-bus"))

	verbs := [][]string{
		nil,
		{"-version"},
		{"tray"},
		{"egress"},
		{"status"},
		{"default"},
		{"unknown-verb"},
	}
	for _, args := range verbs {
		setDumpableForTest(t, 1)
		_, _, _ = run(args...)
		if got := readDumpableFlag(t); got != 0 {
			t.Fatalf("run(%q): want dumpable == 0, got %d", args, got)
		}
	}
}
