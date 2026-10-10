package main

import (
	"bytes"
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

// The verbs run on daemon_test.go's memFS (its store lives at /state).
const memDir, trialPath, keptPath, tBoot = "/state", "/state/trial", "/state/enforce", "b1"

var tNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)

func trialBody(start, end time.Time, boot string) string {
	return "start=" + start.Format(time.RFC3339) + "\nend=" + end.Format(time.RFC3339) + "\nboot=" + boot + "\n"
}

// fake is every fact the verbs read, in the healthy shape (fresh heartbeat and record, a daemon
// following the files with rules, kill clear, state dir present, yes at the prompt); each
// refusal test flips one fact. The closures read the fields at call time.
type fake struct {
	m                        *memFS
	age                      time.Duration
	mapOK, kill, dir, answer bool
	rec                      status.Record
	recErr, bootErr          error
	asked                    string
}

func newFake(files map[string]string) *fake {
	f := &fake{m: &memFS{files: map[string]string{}}, age: 2 * time.Second, mapOK: true,
		rec: status.Record{Source: "files", Rules: 3, Written: tNow}, dir: true, answer: true}
	for name, body := range files {
		f.m.files[memDir+"/"+name] = body
	}
	return f
}

func (f *fake) run(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	control := func() (time.Duration, uint32, uint32, bool) { return f.age, 0, 0, f.mapOK }
	c, out, errw := testCtl(t, probes{control: control, kill: func() bool { return f.kill }})
	c.deps = deps{
		store:      func(dir string) trial.Store { st := f.m.store(); st.Dir = dir; return st },
		dirExists:  func(string) bool { return f.dir },
		readStatus: func(string) (status.Record, error) { return f.rec, f.recErr },
		bootID:     func() (string, error) { return tBoot, f.bootErr },
		now:        func() time.Time { return tNow },
		confirm:    func(q string) bool { f.asked = q; return f.answer },
	}
	code := dispatch(verbs, c, append([]string{args[0], "-state-dir", memDir}, args[1:]...)) // flags before the duration
	return code, out.String(), errw.String()
}

func (f *fake) has(name string) bool { _, ok := f.m.files[memDir+"/"+name]; return ok }

var liveTrialFile = trialBody(tNow.Add(-5*time.Minute), tNow.Add(5*time.Minute), tBoot)

func TestTrialRefusalsExitOneAndWriteNothing(t *testing.T) {
	notExist := &fs.PathError{Op: "open", Path: "/run/snitch/status", Err: fs.ErrNotExist}
	cases := []struct {
		name, want string
		set        func(*fake)
	}{
		{"kill set", "kill switch is set", func(f *fake) { f.kill = true }},
		{"no control map", "not running", func(f *fake) { f.mapOK = false }},
		{"stale heartbeat", "not running", func(f *fake) { f.age = 16 * time.Second }},
		{"no status file", "does not follow trial files", func(f *fake) { f.recErr = notExist }},
		{"malformed status", "status: bad line", func(f *fake) { f.recErr = errors.New("status: bad line") }},
		{"stale status record", "not following the files (status record is 16s old)", func(f *fake) { f.rec.Written = tNow.Add(-16 * time.Second) }},
		{"source flag", "runs with -mode", func(f *fake) { f.rec.Source = "flag" }},
		{"learning", "learning never denies", func(f *fake) { f.rec.Learning = true }},
		{"kept", "already kept", func(f *fake) { f.m.files[keptPath] = "kept=2026-10-10T11:00:00Z\n" }},
		{"running trial", "(5m0s left): snitchd trial -extend", func(f *fake) { f.m.files[trialPath] = liveTrialFile }},
		{"declined", "declined", func(f *fake) { f.rec.Rules = 0; f.answer = false }},
		{"no state dir", "state directory /state does not exist", func(f *fake) { f.dir = false }},
		{"boot id", "boot id: gone", func(f *fake) { f.bootErr = errors.New("boot id: gone") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(nil)
			tc.set(f)
			before := f.m.files[trialPath]
			code, out, errw := f.run(t, "trial", "2m")
			if code != 1 || !strings.Contains(errw, tc.want) || out != "" {
				t.Fatalf("exit %d out %q err %q, want 1, nothing, %q", code, out, errw, tc.want)
			}
			if f.m.files[trialPath] != before {
				t.Fatalf("a refusal changed the trial file: %v", f.m.files)
			}
		})
	}
}

func TestTrialUsageErrorsExitTwo(t *testing.T) {
	cases := []struct {
		name, want string
		args       []string
	}{
		{"not a duration", "Go syntax", []string{"trial", "ten"}},
		{"below the bound", "between 1m0s and 1h0m0s", []string{"trial", "30s"}},
		{"above the bound", "between 1m0s and 1h0m0s", []string{"trial", "61m"}},
		{"two durations", "one duration", []string{"trial", "2m", "3m"}},
		{"unknown flag", "flag provided but not defined", []string{"trial", "-bogus"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(nil)
			if code, _, errw := f.run(t, tc.args...); code != 2 || !strings.Contains(errw, tc.want) {
				t.Fatalf("exit %d err %q, want 2 and %q", code, errw, tc.want)
			}
			if f.has("trial") {
				t.Fatal("a usage error wrote the trial file")
			}
		})
	}
	f := newFake(nil)
	if code, _, errw := f.run(t, "trial", "-h"); code != 0 || !strings.Contains(errw, "10m") || !strings.Contains(errw, "-extend") {
		t.Fatalf("-h: exit %d usage %q", code, errw)
	}
}

func TestTrialStartsAndPrintsTheWayOut(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		args  []string
		rules int
		d     time.Duration
		asked bool
	}{
		{"default", nil, nil, 3, 10 * time.Minute, false},
		{"90s", nil, []string{"90s"}, 3, 90 * time.Second, false},
		{"zero rules confirmed", nil, nil, 0, 10 * time.Minute, true},
		{"zero rules -y", nil, []string{"-y", "2m"}, 0, 2 * time.Minute, false},
		{"foreign boot trial counts as none", map[string]string{"trial": trialBody(tNow.Add(-5*time.Minute), tNow.Add(5*time.Minute), "b0")}, nil, 3, 10 * time.Minute, false},
		{"expired trial counts as none", map[string]string{"trial": trialBody(tNow.Add(-20*time.Minute), tNow.Add(-10*time.Minute), tBoot)}, nil, 3, 10 * time.Minute, false},
		{"clock-jump cap: start older than MaxTrial counts as none", map[string]string{"trial": trialBody(tNow.Add(-61*time.Minute), tNow.Add(5*time.Minute), tBoot)}, nil, 3, 10 * time.Minute, false},
		{"extend without a trial starts one", nil, []string{"-extend", "3m"}, 3, 3 * time.Minute, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(tc.files)
			f.rec.Rules = tc.rules
			code, out, errw := f.run(t, append([]string{"trial"}, tc.args...)...)
			end := tNow.Add(tc.d)
			if code != 0 || errw != "" {
				t.Fatalf("exit %d err %q", code, errw)
			}
			if got := f.m.files[trialPath]; got != trialBody(tNow, end, tBoot) {
				t.Fatalf("trial file %q", got)
			}
			for _, want := range []string{"enforce until " + end.Local().Format(time.RFC3339), "end early: snitchd end", trialPath} {
				if !strings.Contains(out, want) {
					t.Errorf("output %q lacks %q", out, want)
				}
			}
			if (f.asked != "") != tc.asked || (tc.asked && !strings.Contains(f.asked, "outside the local network")) {
				t.Fatalf("prompt %q, asked wanted %v", f.asked, tc.asked)
			}
		})
	}
}

func TestTrialExtendMovesTheDeadlineWithinTheBound(t *testing.T) {
	cases := []struct {
		name string
		d    string
		code int
	}{{"20m", "20m", 0}, {"60m is the bound", "60m", 0}, {"61m is over it", "61m", 2}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(map[string]string{"trial": liveTrialFile})
			code, out, _ := f.run(t, "trial", "-extend", tc.d)
			if code != tc.code {
				t.Fatalf("exit %d, want %d", code, tc.code)
			}
			if tc.code != 0 {
				if f.m.files[trialPath] != liveTrialFile {
					t.Fatal("a refused extend changed the trial file")
				}
				return
			}
			d, _ := time.ParseDuration(tc.d)
			if got := f.m.files[trialPath]; got != trialBody(tNow, tNow.Add(d), tBoot) {
				t.Fatalf("trial file %q: start must move to now with the deadline", got)
			}
			if !strings.Contains(out, "trial extended") {
				t.Fatalf("output %q", out)
			}
		})
	}
}

func TestKeepOnlyDuringATrialAndPrintsTheRmCommand(t *testing.T) {
	cases := []struct {
		name, want  string
		files       map[string]string
		code        int
		kept, noDir bool
	}{
		{"no trial", "enforce can only be kept during a trial", nil, 1, false, false},
		{"foreign boot", "enforce can only be kept during a trial", map[string]string{"trial": trialBody(tNow.Add(-time.Minute), tNow.Add(time.Minute), "b0")}, 1, false, false},
		{"expired", "enforce can only be kept during a trial", map[string]string{"trial": trialBody(tNow.Add(-2*time.Minute), tNow.Add(-time.Minute), tBoot)}, 1, false, false},
		{"running", "rm " + keptPath, map[string]string{"trial": liveTrialFile}, 0, true, false},
		{"already kept", "already kept", map[string]string{"enforce": "kept=2026-10-10T11:00:00Z\n"}, 0, true, false},
		{"no state dir", "state directory /state does not exist", map[string]string{"trial": liveTrialFile}, 1, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(tc.files)
			f.dir = !tc.noDir
			code, out, errw := f.run(t, "keep")
			if code != tc.code || !strings.Contains(out+errw, tc.want) {
				t.Fatalf("exit %d out %q err %q, want %d and %q", code, out, errw, tc.code, tc.want)
			}
			if f.has("enforce") != tc.kept || (tc.kept && f.has("trial")) {
				t.Fatalf("files %v, want kept %v and no trial once kept", f.m.files, tc.kept)
			}
			if tc.code == 0 && (!strings.Contains(out, "snitchd unkeep") || !strings.Contains(out, "fail-open.sh")) {
				t.Fatalf("output %q lacks the ways back", out)
			}
		})
	}
}

func TestUnkeepAndEndRemoveFilesAndReportMonitor(t *testing.T) {
	kept, trialF := "kept=2026-10-10T11:00:00Z\n", liveTrialFile
	cases := []struct {
		name, want          string
		files               map[string]string
		args                []string
		wantTrial, wantKept bool
	}{
		{"unkeep nothing", "nothing was kept", nil, []string{"unkeep"}, false, false},
		{"unkeep kept", "enforce unkept", map[string]string{"enforce": kept}, []string{"unkeep"}, false, false},
		{"unkeep malformed", "enforce unkept", map[string]string{"enforce": "junk"}, []string{"unkeep"}, false, false},
		{"end nothing", "already monitor: no trial, nothing kept", nil, []string{"end"}, false, false},
		{"end trial", "trial ended", map[string]string{"trial": trialF}, []string{"end"}, false, false},
		{"end kept", "enforce unkept", map[string]string{"enforce": kept}, []string{"end"}, false, false},
		{"end both", "trial ended", map[string]string{"trial": trialF, "enforce": kept}, []string{"end"}, false, false},
		{"end malformed trial", "trial ended", map[string]string{"trial": "junk"}, []string{"end"}, false, false},
		{"at boot nothing", "already monitor", nil, []string{"end", "-at-boot"}, false, false},
		{"at boot trial", "trial ended at boot", map[string]string{"trial": trialF}, []string{"end", "-at-boot"}, false, false},
		{"at boot keeps kept", "trial ended at boot", map[string]string{"trial": trialF, "enforce": kept}, []string{"end", "-at-boot"}, false, true},
		{"at boot kept only", "no trial", map[string]string{"enforce": kept}, []string{"end", "-at-boot"}, false, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(tc.files)
			f.mapOK, f.kill = false, true // neither verb needs the daemon, and the kill switch is only ever read
			code, out, errw := f.run(t, tc.args...)
			if code != 0 || errw != "" || !strings.Contains(out, tc.want) {
				t.Fatalf("exit %d out %q err %q, want 0 and %q", code, out, errw, tc.want)
			}
			if f.has("trial") != tc.wantTrial || f.has("enforce") != tc.wantKept {
				t.Fatalf("files %v, want trial %v kept %v", f.m.files, tc.wantTrial, tc.wantKept)
			}
		})
	}
}

func TestAskYNReadsOneLine(t *testing.T) {
	for in, want := range map[string]bool{"y\n": true, "YES\n": true, "n\n": false, "": false, "yes please\n": false} {
		out := &bytes.Buffer{}
		if got := askYN(strings.NewReader(in), out)("Start? [y/N]"); got != want || !strings.Contains(out.String(), "Start? [y/N]") {
			t.Errorf("%q: %v (printed %q), want %v", in, got, out.String(), want)
		}
	}
}

func TestRunCtlDepsAreReal(t *testing.T) {
	c := newCtl(&bytes.Buffer{}, &bytes.Buffer{}, realProbes())
	d := c.deps
	if d.store == nil || d.dirExists == nil || d.readStatus == nil || d.bootID == nil || d.now == nil || d.confirm == nil {
		t.Fatalf("a delegate is nil: %+v", d)
	}
	if dir := t.TempDir(); !d.dirExists(dir) || d.dirExists(dir+"/none") || d.store(dir).Dir != dir {
		t.Fatal("dirExists or store do not look at the real file system")
	}
}

func TestContractVerbsNeedACompleteCtl(t *testing.T) {
	for _, name := range []string{"trial", "keep", "unkeep", "end"} {
		c, _, _ := testCtl(t, probes{control: func() (time.Duration, uint32, uint32, bool) { return 0, 0, 0, false }, kill: func() bool { return false }})
		c.deps = deps{}
		contracttest.Panics(t, contract.Precondition, func() { dispatch(verbs, c, []string{name}) })
	}
}
