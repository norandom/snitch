package main

import (
	"errors"
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/status"
	"github.com/norandom/snitch/internal/trial"
)

var statusKeys = []string{"daemon:", "mode:", "trial:", "kept:", "kill:", "learning:", "rules:", "status:"}

// fullRecord is the record a daemon following the files with examples/rules.toml writes.
var fullRecord = status.Record{PID: 1234, Mode: "monitor", Source: "files", RulesFile: "examples/rules.toml",
	Programs: 3, Resolved: 3, Executables: 5, Rules: 6, Written: tNow}

// line is the output line that starts with key ("" when absent).
func line(out, key string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.HasPrefix(l, key) {
			return l
		}
	}
	return ""
}

func TestStatusRunningShowsEveryFieldAndExitsZero(t *testing.T) {
	f := newFake(nil)
	f.rec = fullRecord
	code, out, errw := f.run(t, "status")
	if code != 0 || errw != "" {
		t.Fatalf("exit %d err %q, want 0 and nothing on stderr", code, errw)
	}
	want := map[string]string{
		"daemon:":   "daemon:    running (heartbeat 2s ago, pid 1234, source files)",
		"mode:":     "mode:      monitor (control map)",
		"trial:":    "trial:     none",
		"kept:":     "kept:      no",
		"kill:":     "kill:      clear",
		"learning:": "learning:  no",
		"rules:":    "rules:     3 programs (3 resolved), 5 executables mapped, 6 rules effective (examples/rules.toml)",
		"status:":   "status:    /run/snitch/status written 0s ago",
	}
	for _, key := range statusKeys {
		if got := line(out, key); got != want[key] {
			t.Errorf("%s line %q, want %q", key, got, want[key])
		}
	}
}

func TestStatusDownExitsOneAndStillShowsFilesAndKill(t *testing.T) {
	cases := []struct {
		name, want string
		set        func(*fake)
	}{
		{"no pinned maps", "daemon:    not running (no pinned maps: never ran since boot)", func(f *fake) { f.mapOK = false }},
		{"stale heartbeat", "daemon:    not running (last heartbeat 16s ago)", func(f *fake) { f.age = 16 * time.Second }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(map[string]string{"trial": liveTrialFile, "enforce": "kept=2026-10-10T11:00:00Z\n"})
			f.rec, f.kill = fullRecord, true
			f.rec.Mode, f.rec.Written = "enforce", tNow.Add(-26*time.Minute)
			tc.set(f)
			code, out, errw := f.run(t, "status")
			if code != 1 || errw != "" {
				t.Fatalf("exit %d err %q, want 1 and nothing on stderr", code, errw)
			}
			for key, want := range map[string]string{
				"daemon:": tc.want,
				"mode:":   "mode:      enforce (last record, 26m0s old)",
				"trial:":  "trial:     until " + tNow.Add(5*time.Minute).Local().Format(time.RFC3339) + " (5m0s left)",
				"kept:":   "kept:      yes (" + keptPath + ")",
				"kill:":   "kill:      set (everything allowed; clear it with scripts/fail-open.sh or the bpftool line in CLAUDE.md)",
				"status:": "status:    /run/snitch/status stale (written 26m0s ago)",
			} {
				if got := line(out, key); got != want {
					t.Errorf("%s line %q, want %q", key, got, want)
				}
			}
		})
	}
}

func TestStatusWithoutARecordSaysUnknown(t *testing.T) {
	f := newFake(nil)
	f.mapOK = false
	f.recErr = &fs.PathError{Op: "open", Path: "/run/snitch/status", Err: fs.ErrNotExist}
	code, out, _ := f.run(t, "status")
	if code != 1 {
		t.Fatalf("exit %d, want 1", code)
	}
	for key, want := range map[string]string{
		"mode:":     "mode:      unknown (no control map, no status record)",
		"learning:": "learning:  unknown (no status record)",
		"rules:":    "rules:     unknown (no status record)",
		"status:":   "status:    /run/snitch/status missing",
	} {
		if got := line(out, key); got != want {
			t.Errorf("%s line %q, want %q", key, got, want)
		}
	}
}

func TestStatusRunningButNotFollowingTheFilesExitsZero(t *testing.T) {
	notExist := &fs.PathError{Op: "open", Path: "/run/snitch/status", Err: fs.ErrNotExist}
	cases := []struct {
		name, daemon, record string
		set                  func(*fake)
	}{
		{"no status file", "no status record at /run/snitch/status", "missing", func(f *fake) { f.recErr = notExist }},
		{"stale record", "status record 16s old", "stale (written 16s ago)", func(f *fake) { f.rec.Written = tNow.Add(-16 * time.Second) }},
		{"source flag", "started with -mode", "written 0s ago", func(f *fake) { f.rec.Source = "flag" }},
		{"unreadable", "status: bad line", "unreadable: status: bad line", func(f *fake) { f.recErr = errors.New("status: bad line") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(nil)
			f.rec = fullRecord
			tc.set(f)
			code, out, _ := f.run(t, "status")
			if code != 0 {
				t.Fatalf("exit %d, want 0: a fresh heartbeat is a running daemon", code)
			}
			if got := line(out, "daemon:"); got != "daemon:    running (heartbeat 2s ago, not following the files: "+tc.daemon+")" {
				t.Errorf("daemon line %q", got)
			}
			if got := line(out, "status:"); got != "status:    /run/snitch/status "+tc.record {
				t.Errorf("status line %q", got)
			}
			if got := line(out, "mode:"); got != "mode:      monitor (control map)" {
				t.Errorf("mode line %q: the control map is the mode of a running daemon", got)
			}
		})
	}
}

func TestStatusLearningFromTheRecord(t *testing.T) {
	f := newFake(nil)
	f.rec = fullRecord
	f.rec.Learning = true
	_, out, _ := f.run(t, "status")
	if got := line(out, "learning:"); got != "learning:  yes" {
		t.Errorf("learning line %q", got)
	}
}

// facts builds the status facts of a running daemon over the given state files.
func facts(files map[string]string) statusFacts {
	f := newFake(files)
	st := f.m.store()
	return statusFacts{age: 2 * time.Second, mapOK: true, rec: fullRecord, recPath: "/run/snitch/status",
		store: st, st: st.Read(), boot: tBoot, now: tNow}
}

func TestStatusTrialLineFromTheStore(t *testing.T) {
	live := tNow.Add(5 * time.Minute)
	cases := []struct {
		name, want string
		files      map[string]string
		bootErr    error
	}{
		{"none", "none", nil, nil},
		{"running", "until " + live.Local().Format(time.RFC3339) + " (5m0s left)", map[string]string{"trial": liveTrialFile}, nil},
		{"foreign boot", "ended (file from another boot, the daemon clears it)", map[string]string{"trial": trialBody(tNow.Add(-time.Minute), live, "b0")}, nil},
		{"expired", "expired (deadline " + tNow.Add(-time.Minute).Local().Format(time.RFC3339) + " passed, the daemon clears it)", map[string]string{"trial": trialBody(tNow.Add(-2*time.Minute), tNow.Add(-time.Minute), tBoot)}, nil},
		{"clock cap", "expired (deadline " + live.Local().Format(time.RFC3339) + " passed, the daemon clears it)", map[string]string{"trial": trialBody(tNow.Add(-61*time.Minute), live, tBoot)}, nil},
		{"malformed", "unreadable: " + trialPath + ": ", map[string]string{"trial": "junk"}, nil},
		{"boot id unknown", "file until " + live.Local().Format(time.RFC3339) + ", boot id unknown: boot id: gone", map[string]string{"trial": liveTrialFile}, errors.New("boot id: gone")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := facts(tc.files)
			fx.bootErr = tc.bootErr
			if got := fx.trialLine(); !strings.HasPrefix(got, tc.want) {
				t.Fatalf("trial %q, want prefix %q", got, tc.want)
			}
		})
	}
}

func TestStatusKeptLineFromTheStore(t *testing.T) {
	cases := []struct {
		name, want string
		files      map[string]string
	}{
		{"no", "no", nil},
		{"yes", "yes (" + keptPath + ")", map[string]string{"enforce": "kept=2026-10-10T11:00:00Z\n"}},
		{"malformed", "unreadable: " + keptPath + ": ", map[string]string{"enforce": "junk"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := facts(tc.files).keptLine()
			if !strings.HasPrefix(got, tc.want) || (tc.name == "malformed" && !strings.Contains(got, "snitchd unkeep")) {
				t.Fatalf("kept %q, want prefix %q", got, tc.want)
			}
		})
	}
}

func TestStatusModeLine(t *testing.T) {
	cases := []struct {
		name, want string
		set        func(*statusFacts)
	}{
		{"monitor", "monitor (control map)", func(*statusFacts) {}},
		{"enforce", "enforce (control map)", func(f *statusFacts) { f.mapMode = 1 }},
		{"unknown value", "unknown (control map mode 7)", func(f *statusFacts) { f.mapMode = 7 }},
		{"down with record", "monitor (last record, 0s old)", func(f *statusFacts) { f.mapOK = false }},
		{"down without record", "unknown (no control map, no status record)", func(f *statusFacts) { f.mapOK = false; f.recErr = errors.New("gone") }},
		{"stale heartbeat with record", "monitor (last record, 0s old)", func(f *statusFacts) { f.age = time.Minute }},
		{"stale heartbeat without record", "unknown (heartbeat stale, no status record)", func(f *statusFacts) { f.age = time.Minute; f.recErr = errors.New("gone") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fx := facts(nil)
			tc.set(&fx)
			if got := fx.modeLine(); got != tc.want {
				t.Fatalf("mode %q, want %q", got, tc.want)
			}
		})
	}
}

func TestStatusUsageNamesTheKeysAndTheExitCode(t *testing.T) {
	f := newFake(nil)
	code, out, errw := f.run(t, "status", "-h")
	if code != 0 || out != "" {
		t.Fatalf("-h: exit %d out %q", code, out)
	}
	for _, want := range append(statusKeys, "exit 1", "-state-dir", "-status") {
		if !strings.Contains(errw, want) {
			t.Errorf("usage %q lacks %q", errw, want)
		}
	}
	if code, _, _ := f.run(t, "status", "-bogus"); code != 2 {
		t.Fatalf("unknown flag: exit %d, want 2", code)
	}
}

func TestStatusReadsEachSourceOnce(t *testing.T) {
	f := newFake(nil)
	control, kill, reads := 0, 0, 0
	c, out, _ := testCtl(t, probes{
		control: func() (time.Duration, uint32, uint32, bool) { control++; return 2 * time.Second, 0, 0, true },
		kill:    func() bool { kill++; return false }})
	c.deps = deps{
		store:      func(string) trial.Store { reads++; return f.m.store() },
		dirExists:  func(string) bool { return true },
		readStatus: func(string) (status.Record, error) { reads++; return fullRecord, nil },
		bootID:     func() (string, error) { return tBoot, nil },
		now:        func() time.Time { return tNow },
		confirm:    func(string) bool { return false },
	}
	if code := dispatch(verbs, c, []string{"status"}); code != 0 || control != 1 || kill != 1 || reads != 2 {
		t.Fatalf("exit %d, control %d kill %d store+record %d reads, want 0 and one each (output %q)", code, control, kill, reads, out.String())
	}
}

func TestContractStatusNeedsACompleteCtl(t *testing.T) {
	c, _, _ := testCtl(t, probes{control: func() (time.Duration, uint32, uint32, bool) { return 0, 0, 0, false }, kill: func() bool { return false }})
	c.deps = deps{}
	contracttest.Panics(t, contract.Precondition, func() { dispatch(verbs, c, []string{"status"}) })
}
