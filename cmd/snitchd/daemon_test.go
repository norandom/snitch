package main

import (
	"context"
	"errors"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
	"github.com/norandom/snitch/internal/trial"
)

func TestRunJobsViolationInsideAJobExits70WithAStack(t *testing.T) {
	var logs []string
	code := runJobs(func(m string) { logs = append(logs, m) },
		func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() },
		func(context.Context) error { contract.Invariant(false, "ids drifted"); return nil },
	)
	if code != exitViolation {
		t.Fatalf("want exit %d, got %d", exitViolation, code)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "contract invariant: ids drifted") || !strings.Contains(logs[0], "goroutine") {
		t.Fatalf("want the violation and a stack, got %q", logs)
	}
}

func TestRunJobsOutcomes(t *testing.T) {
	quiet := func(string) {}
	if code := runJobs(quiet, jobs.After(1)); code != 0 { // 1 ns deadline
		t.Fatalf("deadline: want 0, got %d", code)
	}
	if code := runJobs(quiet, func(context.Context) error { return errStop }); code != 0 {
		t.Fatalf("stop: want 0, got %d", code)
	}
	if code := runJobs(quiet, func(context.Context) error { return errors.New("heartbeat: EIO") }); code != 1 {
		t.Fatalf("error: want 1, got %d", code)
	}
}

func TestGuardLetsOtherPanicsThrough(t *testing.T) {
	defer func() {
		if r := recover(); r != "boom" {
			t.Fatalf("want the original panic, got %v", r)
		}
	}()
	guard(func(context.Context) error { panic("boom") })(context.Background())
}

func TestSetModeLogsAChangeAndIsSilentWithoutOne(t *testing.T) {
	var logs []string
	d := &daemon{log: func(m string) { logs = append(logs, m) }}
	d.setMode(trial.Monitor, "no trial")
	d.setMode(trial.Monitor, "no trial") // the same decision again: silent
	d.setMode(trial.Enforce, "trial until 2026-10-10T12:00:00Z")
	d.setMode(trial.Enforce, "trial until 2026-10-10T12:00:00Z")
	if d.mode.Load() != 1 {
		t.Fatalf("want the control map's enforce value 1, got %d", d.mode.Load())
	}
	d.setMode(trial.Enforce, "enforce kept") // same mode, another reason: the journal says why
	d.setMode(trial.Monitor, "trial ended at its deadline")
	want := []string{
		"mode: monitor (no trial)",
		"mode: enforce (trial until 2026-10-10T12:00:00Z)",
		"mode: enforce (enforce kept)",
		"mode: monitor (trial ended at its deadline)",
	}
	if !slices.Equal(logs, want) {
		t.Fatalf("want %q, got %q", want, logs)
	}
}

// memFS is a trial.Store on a map, so the startup decision runs without a disk or root.
type memFS struct{ files map[string]string }

func (m *memFS) store() trial.Store {
	return trial.Store{Dir: "/state", FS: trial.FS{
		ReadFile: func(p string) ([]byte, error) {
			b, ok := m.files[p]
			if !ok {
				return nil, fs.ErrNotExist
			}
			return []byte(b), nil
		},
		WriteFile: func(p string, b []byte) error { m.files[p] = string(b); return nil },
		Remove: func(p string) error {
			if _, ok := m.files[p]; !ok {
				return fs.ErrNotExist
			}
			delete(m.files, p)
			return nil
		},
	}}
}

type startupCase struct {
	name     string
	files    map[string]string
	learn    bool
	wantMode uint32
	wantLog  string
	wantLeft []string // files still there afterwards
}

// startupCases: the decision table as the daemon sees it at startup, on boot "this-boot" at now.
func startupCases(now time.Time) []startupCase {
	trialFile := func(boot string) string {
		return "start=" + now.Add(-time.Minute).Format(time.RFC3339) + "\nend=" + now.Add(5*time.Minute).Format(time.RFC3339) + "\nboot=" + boot + "\n"
	}
	kept := map[string]string{"/state/enforce": "kept=2026-10-09T10:00:00Z\n"}
	return []startupCase{
		{"no files: monitor", map[string]string{}, false, 0, "mode: monitor (no trial)", nil},
		{"kept: enforce from the first beat", kept, false, 1, "mode: enforce (enforce kept)", []string{"/state/enforce"}},
		{"trial from another boot: cleared, monitor", map[string]string{"/state/trial": trialFile("other-boot")}, false, 0,
			"mode: monitor (trial ended at boot)", nil},
		{"trial from this boot: enforce", map[string]string{"/state/trial": trialFile("this-boot")}, false, 1,
			"mode: enforce (trial until " + now.Add(5*time.Minute).Format(time.RFC3339) + ")", []string{"/state/trial"}},
		{"kept while learning: monitor, files ignored", kept, true, 0,
			"mode: monitor (learning: trial/kept files ignored)", []string{"/state/enforce"}},
		{"malformed kept file: monitor, both removed", map[string]string{"/state/enforce": "nonsense\n", "/state/trial": "garbage"}, false, 0,
			"mode: monitor (trial file unreadable: /state/trial: line \"garbage\" is not key=value; /state/enforce: line \"nonsense\" is not key=value, removed)", nil},
	}
}

func TestStartupDecisionFromTheFiles(t *testing.T) {
	now := time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	for _, c := range startupCases(now) {
		t.Run(c.name, func(t *testing.T) {
			var logs []string
			m := &memFS{files: c.files}
			d := &daemon{cfg: config{learn: c.learn}, log: func(s string) { logs = append(logs, s) }}
			d.decideOnce(m.store(), "this-boot", now)
			if d.mode.Load() != c.wantMode {
				t.Fatalf("want mode %d, got %d", c.wantMode, d.mode.Load())
			}
			if !slices.Equal(logs, []string{c.wantLog}) {
				t.Fatalf("want log %q, got %q", c.wantLog, logs)
			}
			left := slices.Sorted(maps.Keys(m.files))
			if !slices.Equal(left, c.wantLeft) {
				t.Fatalf("want files %q left, got %q", c.wantLeft, left)
			}
		})
	}
}

func TestStartupDecisionWithTheFlagNeverReadsTheFiles(t *testing.T) {
	var logs []string
	stateDir := filepath.Join(t.TempDir(), "state")
	d := &daemon{cfg: config{source: sourceFlag, mode: modeEnforce, stateDir: stateDir},
		log: func(s string) { logs = append(logs, s) }}
	if err := d.startMode(); err != nil {
		t.Fatal(err)
	}
	if d.mode.Load() != 1 || !slices.Equal(logs, []string{"mode: enforce (-mode enforce)"}) {
		t.Fatalf("want enforce from the flag, got mode %d, logs %q", d.mode.Load(), logs)
	}
	if _, err := os.Stat(stateDir); err == nil {
		t.Fatal("the bounded run must not create the state directory")
	}
}
