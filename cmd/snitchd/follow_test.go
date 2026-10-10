package main

import (
	"context"
	"errors"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/rules"
	"github.com/norandom/snitch/internal/status"
	"github.com/norandom/snitch/internal/trial"
)

// followFixture is a follower over the memory store with a fake clock, applying through a real
// daemon's setMode so the log lines are the ones the journal gets.
type followFixture struct {
	d    *daemon
	m    *memFS
	f    *follower
	logs []string
	now  time.Time
}

func newFollowFixture(learn bool) *followFixture {
	x := &followFixture{m: &memFS{files: map[string]string{}}, now: t0}
	x.d = &daemon{log: func(s string) { x.logs = append(x.logs, s) }}
	x.f = &follower{store: x.m.store(), boot: "this-boot", learn: learn,
		now: func() time.Time { return x.now }, apply: x.d.setMode, log: x.d.log}
	return x
}

// ticks runs n ticks a second apart.
func (x *followFixture) ticks(t *testing.T, n int) {
	t.Helper()
	for range n {
		if err := x.f.tick(context.Background()); err != nil {
			t.Fatal(err)
		}
		x.now = x.now.Add(time.Second)
	}
}

var t0 = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC) // the fixture's first tick

// startTrial writes a trial file from t0 for the given minutes on the given boot.
func (x *followFixture) startTrial(minutes int, boot string) {
	end := t0.Add(time.Duration(minutes) * time.Minute).Format(time.RFC3339)
	x.m.files["/state/trial"] = "start=" + t0.Format(time.RFC3339) + "\nend=" + end + "\nboot=" + boot + "\n"
}

func (x *followFixture) files() []string { return slices.Sorted(maps.Keys(x.m.files)) }

const (
	keptLine   = "mode: enforce (enforce kept)"
	untilLine  = "mode: enforce (trial until 2026-10-10T12:05:00Z)" // 5 min after the fixture's now
	badTrial   = "/state/trial: line \"garbage\" is not key=value"
	badKept    = "/state/enforce: line \"nonsense\" is not key=value"
	keptMarker = "kept=2026-10-09T10:00:00Z\n"
)

// transition: files before two ticks, a change, two more ticks; then the log lines, the mode
// and the files left.
type transition struct {
	name   string
	setup  func(x *followFixture)
	change func(x *followFixture)
	logs   []string
	mode   uint32
	left   []string
}

func transitions() []transition {
	none := func(*followFixture) {}
	trial5 := func(x *followFixture) { x.startTrial(5, "this-boot") }
	kept := func(x *followFixture) { x.m.files["/state/enforce"] = keptMarker }
	rm := func(path string) func(*followFixture) { return func(x *followFixture) { delete(x.m.files, path) } }
	return []transition{
		{"trial start: one line, repeats silent", none, trial5,
			[]string{"mode: monitor (no trial)", untilLine}, 1, []string{"/state/trial"}},
		{"deadline: one line, trial cleared, then silent", trial5, func(x *followFixture) { x.now = x.now.Add(5 * time.Minute) },
			[]string{untilLine, "mode: monitor (trial ended at its deadline)"}, 0, nil},
		{"file removed by hand: ended by the operator", trial5, rm("/state/trial"),
			[]string{untilLine, "mode: monitor (trial ended by the operator: file removed)"}, 0, nil},
		{"kept: enforce; file removed: unkept", kept, rm("/state/enforce"),
			[]string{keptLine, "mode: monitor (enforce unkept: file removed)"}, 0, nil},
		{"keep during a trial: the kept line", trial5, func(x *followFixture) { kept(x); delete(x.m.files, "/state/trial") },
			[]string{untilLine, keptLine}, 1, []string{"/state/enforce"}},
		{"malformed trial: cleared and logged, then silent", func(x *followFixture) { x.m.files["/state/trial"] = "garbage" }, none,
			[]string{"mode: monitor (trial file unreadable: " + badTrial + ", removed)"}, 0, nil},
		// a problem the reason does not carry gets its own line (Req 3.5)
		{"broken kept file next to a live trial: removed and logged", func(x *followFixture) { trial5(x); x.m.files["/state/enforce"] = "nonsense\n" }, none,
			[]string{untilLine, "file removed: " + badKept}, 1, []string{"/state/trial"}},
		// the same kept enforce once its broken trial file is gone is not a new decision; a
		// foreign-boot file appearing in monitor is (the file goes), the empty directory after it is not
		{"kept with a broken trial, then a foreign-boot trial", func(x *followFixture) { kept(x); x.m.files["/state/trial"] = "garbage" },
			func(x *followFixture) {
				delete(x.m.files, "/state/enforce")
				x.f.decide(x.now)
				x.startTrial(5, "other-boot")
			},
			[]string{"mode: enforce (enforce kept; trial file unreadable: " + badTrial + ", removed)",
				"mode: monitor (enforce unkept: file removed)", "mode: monitor (trial ended at boot)"}, 0, nil},
	}
}

func TestFollowTransitionsLogOnce(t *testing.T) {
	for _, c := range transitions() {
		t.Run(c.name, func(t *testing.T) {
			x := newFollowFixture(false)
			c.setup(x)
			x.ticks(t, 2)
			c.change(x)
			x.ticks(t, 2)
			if !slices.Equal(x.logs, c.logs) {
				t.Fatalf("want logs %q, got %q", c.logs, x.logs)
			}
			if x.d.mode.Load() != c.mode || !slices.Equal(x.files(), c.left) {
				t.Fatalf("want mode %d with files %q, got mode %d, files %q", c.mode, c.left, x.d.mode.Load(), x.files())
			}
		})
	}
}

// Learning is passed on every tick: whatever the files hold, the mode stays monitor and no file
// is removed, a malformed one included.
func TestFollowLearningIgnoresTheFilesOnEveryTick(t *testing.T) {
	cases := map[string]map[string]string{
		"kept":                     {"/state/enforce": keptMarker},
		"malformed kept":           {"/state/enforce": "nonsense\n"},
		"trial and malformed kept": {"/state/enforce": "nonsense\n", "/state/trial": "start=2026-10-10T12:00:00Z\nend=2026-10-10T12:05:00Z\nboot=this-boot\n"},
	}
	for name, files := range cases {
		t.Run(name, func(t *testing.T) {
			x := newFollowFixture(true)
			maps.Copy(x.m.files, files)
			want := x.files()
			x.ticks(t, 3)
			if !slices.Equal(x.logs, []string{"mode: monitor (learning: trial/kept files ignored)"}) {
				t.Fatalf("want one learning line, got %q", x.logs)
			}
			if x.d.mode.Load() != 0 || !slices.Equal(x.files(), want) {
				t.Fatalf("want monitor with files %q untouched, got mode %d, files %q", want, x.d.mode.Load(), x.files())
			}
		})
	}
}

func TestFollowRemoveFailureIsLoggedAndRetried(t *testing.T) {
	x := newFollowFixture(false)
	x.f.store.FS.Remove = func(string) error { return errors.New("EROFS") }
	x.startTrial(5, "other-boot")
	x.ticks(t, 2)
	want := []string{"mode: monitor (trial ended at boot)", "remove /state/trial: EROFS", "remove /state/trial: EROFS"}
	if !slices.Equal(x.logs, want) || x.d.mode.Load() != 0 {
		t.Fatalf("want %q in monitor, got %q, mode %d", want, x.logs, x.d.mode.Load())
	}
}

func TestFollowJobEndsWithTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := newFollowFixture(false).f.job()(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("want Canceled, got %v", err)
	}
}

func TestFollowContracts(t *testing.T) {
	x := newFollowFixture(false)
	contracttest.Panics(t, contract.Precondition, func() { _ = (&follower{}).tick(context.Background()) })
	x.f.boot = ""
	contracttest.Panics(t, contract.Precondition, func() { _ = x.f.tick(context.Background()) })
}

// statusFixture: a writer over a two-program snapshot (one resolved), the memory store, a fake
// clock, and a recording write delegate.
type statusFixture struct {
	m      *memFS
	w      *statusWriter
	logs   []string
	writes []status.Record
	now    time.Time
	err    error
}

func newStatusFixture() *statusFixture {
	key := rules.ExeKey{Ino: 7, Dev: 1}
	snap := &snapshot{
		res: &rules.Resolved{File: &rules.File{Programs: []rules.Program{{Name: "a", ID: 1}, {Name: "b", ID: 2}},
			Rules: make([]rules.Rule, 3)}, Programs: map[rules.ExeKey]uint32{key: 1}},
		ent: rules.Entries{Programs: map[rules.ExeKey]uint32{key: 1}},
	}
	x := &statusFixture{m: &memFS{files: map[string]string{}}, now: time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)}
	x.w = &statusWriter{path: "/run/status", rulesFile: "/etc/rules.toml", source: sourceFiles, learn: true, pid: 42,
		store: x.m.store(), mode: func() trial.Mode { return trial.Enforce }, snap: func() *snapshot { return snap },
		now: func() time.Time { return x.now }, log: func(s string) { x.logs = append(x.logs, s) },
		write: func(path string, r status.Record) error { x.writes = append(x.writes, r); return x.err }}
	return x
}

func (x *statusFixture) tick(t *testing.T) {
	t.Helper()
	if err := x.w.tick(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestStatusWriterRecordFromSnapshotModeAndStore(t *testing.T) {
	x := newStatusFixture()
	x.m.files["/state/trial"] = "start=2026-10-10T11:55:00Z\nend=2026-10-10T12:05:00Z\nboot=this-boot\n"
	x.m.files["/state/enforce"] = keptMarker
	want := status.Record{PID: 42, Mode: "enforce", Source: "files", Learning: true, Trial: "2026-10-10T12:05:00Z", Kept: true,
		RulesFile: "/etc/rules.toml", Programs: 2, Resolved: 1, Executables: 1, Rules: 3, Written: x.now}
	if got := x.w.record(); got != want {
		t.Fatalf("want %+v, got %+v", want, got)
	}
}

func TestStatusWriterRecordWithoutASnapshotOrFiles(t *testing.T) {
	x := newStatusFixture()
	x.w.snap = func() *snapshot { return nil }
	x.w.mode = func() trial.Mode { return trial.Monitor }
	got := x.w.record()
	if got.Mode != "monitor" || got.Trial != "" || got.Kept || got.Programs+got.Resolved+got.Executables+got.Rules != 0 {
		t.Fatalf("want a monitor record with zero numbers and no files, got %+v", got)
	}
}

func TestStatusWriterTickWritesEveryTickAndLogsAFailureOncePerStreak(t *testing.T) {
	x := newStatusFixture()
	x.tick(t)
	x.err = errors.New("EACCES")
	x.tick(t)
	x.tick(t)
	x.err = nil
	x.tick(t)
	x.err = errors.New("EACCES")
	x.tick(t)
	if len(x.writes) != 5 || x.writes[0].PID != 42 {
		t.Fatalf("want 5 writes of the record, got %d: %+v", len(x.writes), x.writes)
	}
	if want := []string{"status /run/status: EACCES", "status /run/status: EACCES"}; !slices.Equal(x.logs, want) {
		t.Fatalf("want the failure logged once per streak %q, got %q", want, x.logs)
	}
}

func TestStatusWriterWritesTheRealFileInANewDirectory(t *testing.T) {
	x := newStatusFixture()
	x.w.path = filepath.Join(t.TempDir(), "run", "status")
	x.w.write = status.Write
	x.tick(t)
	r, err := status.Read(x.w.path)
	if err != nil {
		t.Fatal(err)
	}
	if r.Mode != "enforce" || r.Source != "files" || !r.Written.Equal(x.now) || r.Programs != 2 {
		t.Fatalf("want the record back from the file, got %+v", r)
	}
}

func TestStatusWriterContracts(t *testing.T) {
	x := newStatusFixture()
	contracttest.Panics(t, contract.Precondition, func() { _ = (&statusWriter{}).tick(context.Background()) })
	x.w.path = ""
	contracttest.Panics(t, contract.Precondition, func() { _ = x.w.tick(context.Background()) })
}

// The job list: the follow and status jobs exist only when the files decide the mode.
func TestJobListHasTheFollowJobsOnlyWithSourceFiles(t *testing.T) {
	quiet := func(string) {}
	flag := &daemon{cfg: config{source: sourceFlag, mode: modeMonitor}, log: quiet}
	if err := flag.startMode(); err != nil {
		t.Fatal(err)
	}
	if n := len(flag.modeJobs()); n != 0 {
		t.Fatalf("source flag: want no follow or status job, got %d", n)
	}
	m := &memFS{files: map[string]string{}}
	files := &daemon{cfg: config{source: sourceFiles, status: "/run/status"}, log: quiet}
	files.decideOnce(m.store(), "this-boot", time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC))
	if n := len(files.modeJobs()); n != 2 {
		t.Fatalf("source files: want the follow and status jobs, got %d", n)
	}
	if got, want := len(files.jobList()), len(flag.jobList())+2; got != want {
		t.Fatalf("want the job list to grow by the two jobs, got %d vs %d", got, len(flag.jobList()))
	}
	if files.follow.now == nil || !strings.HasPrefix(files.follow.store.TrialPath(), "/state") {
		t.Fatal("decideOnce must leave a follower on the real clock over the given store")
	}
}
