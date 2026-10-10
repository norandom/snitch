package trial

import (
	"errors"
	"io/fs"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// memFS is the two files in a map, keyed by full path, so the store never touches a disk.
type memFS struct {
	files map[string][]byte
	fail  error // when set, every write and remove returns it
}

func newMemFS() *memFS { return &memFS{files: map[string][]byte{}} }

func (m *memFS) fs() FS {
	return FS{ReadFile: m.read, WriteFile: m.write, Remove: m.remove}
}

func (m *memFS) read(path string) ([]byte, error) {
	b, ok := m.files[path]
	if !ok {
		return nil, &fs.PathError{Op: "open", Path: path, Err: fs.ErrNotExist}
	}
	return b, nil
}

func (m *memFS) write(path string, data []byte) error {
	if m.fail != nil {
		return m.fail
	}
	m.files[path] = data
	return nil
}

func (m *memFS) remove(path string) error {
	if m.fail != nil {
		return m.fail
	}
	if _, ok := m.files[path]; !ok {
		return &fs.PathError{Op: "remove", Path: path, Err: fs.ErrNotExist}
	}
	delete(m.files, path)
	return nil
}

const memDir = "/mem"

// memStore is a store over an empty memory FS, with the FS for raw checks.
func memStore() (Store, *memFS) {
	m := newMemFS()
	return Store{Dir: memDir, FS: m.fs()}, m
}

// mem fills a memory FS from file name to content, the way an operator would write them.
func mem(files map[string]string) *memFS {
	m := newMemFS()
	for name, body := range files {
		m.files[filepath.Join(memDir, name)] = []byte(body)
	}
	return m
}

var (
	tKept     = t0.Add(5 * time.Minute)
	trialBody = "start=2026-10-10T12:00:00Z\nend=2026-10-10T12:10:00Z\nboot=b1\n"
	keptBody  = "kept=2026-10-10T12:05:00Z\n"
)

// TestStoreRoundTrip: each operation sequence leaves exactly the files of the design's
// formats, and Read gives them back as the State Decide takes.
func TestStoreRoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		steps []func(Store) error
		files map[string]string // what is on disk afterwards, by file name
		want  State
	}{
		{"start writes the trial file", []func(Store) error{start},
			map[string]string{"trial": trialBody}, State{Trial: own}},
		{"keep writes the kept marker and removes the trial", []func(Store) error{start, keep},
			map[string]string{"enforce": keptBody}, State{Kept: true}},
		{"keep without a trial still writes the marker", []func(Store) error{keep},
			map[string]string{"enforce": keptBody}, State{Kept: true}},
		{"clear trial", []func(Store) error{start, Store.ClearTrial},
			map[string]string{}, State{}},
		{"clear kept", []func(Store) error{keep, Store.ClearKept},
			map[string]string{}, State{}},
		{"start again replaces the deadline", []func(Store) error{startFar, start},
			map[string]string{"trial": trialBody}, State{Trial: own}},
	}
	for _, c := range cases {
		s, m := memStore()
		for i, step := range c.steps {
			if err := step(s); err != nil {
				t.Fatalf("%s: step %d: %v", c.name, i, err)
			}
		}
		if got := m.named(); !reflect.DeepEqual(got, c.files) {
			t.Errorf("%s: files %q, want %q", c.name, got, c.files)
		}
		if got := s.Read(); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: Read() = %+v, want %+v", c.name, got, c.want)
		}
	}
}

func start(s Store) error { return s.StartTrial(*own) }
func startFar(s Store) error {
	return s.StartTrial(Deadline{Start: t0, End: t0.Add(MaxTrial), Boot: "b1"})
}
func keep(s Store) error { return s.Keep(tKept) }

// named is the FS content keyed by file name, for comparing against the expected formats.
func (m *memFS) named() map[string]string {
	out := map[string]string{}
	for path, b := range m.files {
		out[filepath.Base(path)] = string(b)
	}
	return out
}

// TestStoreReadProblems: a malformed file is reported as a Problem naming the file, never
// as a trial or a kept enforce, so the daemon stays in monitor and can clear it.
func TestStoreReadProblems(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		want  string // the one problem must contain this; the file's path always
	}{
		{"trial: missing key", map[string]string{"trial": "start=2026-10-10T12:00:00Z\nboot=b1\n"}, "end"},
		{"trial: unparsable time", map[string]string{"trial": "start=yesterday\nend=2026-10-10T12:10:00Z\nboot=b1\n"}, "start"},
		{"trial: empty boot", map[string]string{"trial": "start=2026-10-10T12:00:00Z\nend=2026-10-10T12:10:00Z\nboot=\n"}, "boot"},
		{"trial: end not after start", map[string]string{"trial": "start=2026-10-10T12:10:00Z\nend=2026-10-10T12:10:00Z\nboot=b1\n"}, "end"},
		{"trial: not key=value", map[string]string{"trial": "garbage\n"}, "garbage"},
		{"trial: unknown key", map[string]string{"trial": trialBody + "extra=1\n"}, "extra"},
		{"trial: duplicate key", map[string]string{"trial": trialBody + "boot=b2\n"}, "boot"},
		{"trial: empty file", map[string]string{"trial": ""}, "start"},
		{"enforce: missing key", map[string]string{"enforce": "x=1\n"}, "kept"},
		{"enforce: unparsable time", map[string]string{"enforce": "kept=soon\n"}, "kept"},
	}
	for _, c := range cases {
		s := Store{Dir: memDir, FS: mem(c.files).fs()}
		got := s.Read()
		if got.Trial != nil || got.Kept || len(got.Problems) != 1 {
			t.Errorf("%s: Read() = %+v, want one problem and nothing else", c.name, got)
			continue
		}
		name := strings.SplitN(c.name, ":", 2)[0]
		if p := got.Problems[0]; !strings.Contains(p, filepath.Join(memDir, name)) || !strings.Contains(p, c.want) {
			t.Errorf("%s: problem %q names neither the file nor %q", c.name, p, c.want)
		}
	}
}

func TestStoreReadReportsAnUnreadableFileAsAProblem(t *testing.T) {
	// a read error other than "missing" (permissions, a directory in the way) is not an absent
	// file: it is reported, so the daemon logs it instead of silently running in monitor
	s, _ := memStore()
	s.FS.ReadFile = func(string) ([]byte, error) { return nil, errors.New("permission denied") }
	got := s.Read()
	if got.Trial != nil || got.Kept || len(got.Problems) != 2 {
		t.Fatalf("Read() = %+v, want two problems (one per file)", got)
	}
}

func TestStoreClearsAbsentFiles(t *testing.T) {
	s, _ := memStore()
	if err := errors.Join(s.ClearTrial(), s.ClearKept()); err != nil {
		t.Fatalf("clearing absent files: %v", err)
	}
}

func TestStoreReportsFSErrors(t *testing.T) {
	boom := errors.New("disk full")
	cases := []struct {
		name string
		op   func(Store) error
	}{
		{"start", start}, {"keep", keep}, {"clear trial", Store.ClearTrial}, {"clear kept", Store.ClearKept},
	}
	for _, c := range cases {
		s, m := memStore()
		m.files[filepath.Join(memDir, TrialFile)] = []byte(trialBody)
		m.files[filepath.Join(memDir, KeptFile)] = []byte(keptBody)
		m.fail = boom
		if err := c.op(s); !errors.Is(err, boom) {
			t.Errorf("%s: err = %v, want %v", c.name, err, boom)
		}
	}
}

// TestStoreOSWriteReplacesTheFile: the OS store creates its directory (0700) and writes root
// 0600 files by rename, so a reader never sees a partial file (a new inode every write).
func TestStoreOSWriteReplacesTheFile(t *testing.T) {
	s := OSStore(filepath.Join(t.TempDir(), "snitch"))
	path := filepath.Join(s.Dir, TrialFile)
	stat := func(p string) syscall.Stat_t {
		var st syscall.Stat_t
		if err := syscall.Stat(p, &st); err != nil {
			t.Fatal(err)
		}
		return st
	}
	if err := s.StartTrial(*own); err != nil {
		t.Fatal(err)
	}
	first := stat(path)
	if err := s.StartTrial(*own); err != nil {
		t.Fatal(err)
	}
	if stat(path).Ino == first.Ino {
		t.Fatal("the trial file was rewritten in place, not replaced by rename")
	}
	if dir, file := stat(s.Dir).Mode&0o777, first.Mode&0o777; dir != 0o700 || file != 0o600 {
		t.Fatalf("modes dir %o file %o, want 700 and 600", dir, file)
	}
	if got := s.Read(); !reflect.DeepEqual(got, State{Trial: own}) {
		t.Fatalf("Read() through the OS = %+v, want the trial back", got)
	}
}

func TestStoreOSReadsAMissingDirectoryAsAbsent(t *testing.T) {
	s := OSStore(filepath.Join(t.TempDir(), "never-created"))
	if got := s.Read(); !reflect.DeepEqual(got, State{}) {
		t.Fatalf("Read() = %+v, want nothing", got)
	}
}

// TestStoreContracts: a deadline the daemon could not follow is a bug in the caller.
func TestStoreContracts(t *testing.T) {
	cases := []struct {
		name string
		d    Deadline
	}{
		{"end before start", Deadline{Start: tEnd, End: t0, Boot: "b1"}},
		{"end equals start", Deadline{Start: t0, End: t0, Boot: "b1"}},
		{"longer than the maximum", Deadline{Start: t0, End: t0.Add(MaxTrial + time.Second), Boot: "b1"}},
		{"empty boot", Deadline{Start: t0, End: tEnd}},
	}
	for _, c := range cases {
		s, _ := memStore()
		v := contracttest.Panics(t, contract.Precondition, func() { _ = s.StartTrial(c.d) })
		if !strings.HasPrefix(v.Msg, "start trial: ") {
			t.Errorf("%s: violation %q does not name StartTrial", c.name, v.Msg)
		}
	}
	for _, s := range []Store{{Dir: memDir}, {FS: newMemFS().fs()}} {
		contracttest.Panics(t, contract.Precondition, func() { s.Read() })
	}
}
