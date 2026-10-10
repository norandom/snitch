package trial

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/contract"
)

// The two files under Store.Dir. Their names are part of the operator's recovery
// ("rm /var/lib/snitch/enforce"), so they never change.
const (
	TrialFile = "trial"   // start=<RFC3339>\nend=<RFC3339>\nboot=<uuid>\n
	KeptFile  = "enforce" // kept=<RFC3339>\n
)

// FS is the file access a Store goes through: the os package in the daemon (OSStore), a map
// in tests. A missing file is an error for which errors.Is(err, fs.ErrNotExist) holds.
type FS struct {
	ReadFile  func(path string) ([]byte, error)
	WriteFile func(path string, data []byte) error // atomic: a reader sees the old file or the new, never a part
	Remove    func(path string) error
}

// Store is the trial and kept-enforce files in one directory.
type Store struct {
	Dir string
	FS  FS
}

// OSStore is a Store on the real file system. Its WriteFile creates Dir (0700) when it is
// missing, so a hand-started daemon or the CLI works without systemd's StateDirectory; Read
// needs no directory (a missing one reads as no files).
func OSStore(dir string) Store {
	return Store{Dir: dir, FS: FS{ReadFile: os.ReadFile, WriteFile: writeAtomic, Remove: os.Remove}}
}

// writeAtomic: a 0600 temp file in the same directory, then rename over the target. The
// directory is created first (0700, like the design's /var/lib/snitch).
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*") // 0600 by CreateTemp
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// TrialPath and KeptPath are the full paths, for log lines and the CLI's "rm" hint.
func (s Store) TrialPath() string { return filepath.Join(s.Dir, TrialFile) }
func (s Store) KeptPath() string  { return filepath.Join(s.Dir, KeptFile) }

func (s Store) require() {
	contract.Require(s.Dir != "", "store: empty directory")
	contract.Require(s.FS.ReadFile != nil && s.FS.WriteFile != nil && s.FS.Remove != nil, "store: incomplete FS")
}

// Read reports what the two files hold. A missing file is absent; an unreadable or malformed
// one is a Problem (its path and what is wrong) and counts as absent, so the daemon can log
// it and clear it instead of enforcing on a file it cannot trust.
func (s Store) Read() State {
	s.require()
	var st State
	if kv, ok := s.load(s.TrialPath(), &st.Problems); ok {
		st.Trial = parseTrial(s.TrialPath(), kv, &st.Problems)
	}
	if kv, ok := s.load(s.KeptPath(), &st.Problems); ok {
		st.Kept = parseKept(s.KeptPath(), kv, &st.Problems)
	}
	return st
}

// load reads and splits one file; ok is false when it is absent or reported as a problem.
func (s Store) load(path string, problems *[]string) (map[string]string, bool) {
	b, err := s.FS.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false
	}
	if err == nil {
		var kv map[string]string
		if kv, err = parseKV(b); err == nil {
			return kv, true
		}
	}
	*problems = append(*problems, path+": "+err.Error())
	return nil, false
}

// parseKV splits "key=value" lines (blank lines skipped, so a hand-written file with a
// stray newline still reads); a line without "=" or a key given twice is an error.
func parseKV(b []byte) (map[string]string, error) {
	kv := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !ok {
			return nil, fmt.Errorf("line %q is not key=value", line)
		}
		if _, dup := kv[key]; dup {
			return nil, fmt.Errorf("key %q given twice", key)
		}
		kv[key] = value
	}
	return kv, nil
}

// parseTrial turns the trial file's keys into a Deadline, or records why it cannot.
func parseTrial(path string, kv map[string]string, problems *[]string) *Deadline {
	d, err := deadlineOf(kv)
	if err != nil {
		*problems = append(*problems, path+": "+err.Error())
		return nil
	}
	return &d
}

func deadlineOf(kv map[string]string) (Deadline, error) {
	var d Deadline
	var err error
	if err = onlyKeys(kv, "start", "end", "boot"); err != nil {
		return d, err
	}
	if d.Start, err = timeOf(kv, "start"); err != nil {
		return d, err
	}
	if d.End, err = timeOf(kv, "end"); err != nil {
		return d, err
	}
	if d.Boot = kv["boot"]; d.Boot == "" {
		return d, errors.New("boot is empty")
	}
	if !d.End.After(d.Start) {
		return d, errors.New("end is not after start")
	}
	return d, nil
}

// parseKept accepts the kept marker only when it is well formed: a marker nobody could have
// written through Keep is reported, not trusted.
func parseKept(path string, kv map[string]string, problems *[]string) bool {
	err := onlyKeys(kv, "kept")
	if err == nil {
		_, err = timeOf(kv, "kept")
	}
	if err != nil {
		*problems = append(*problems, path+": "+err.Error())
		return false
	}
	return true
}

// onlyKeys checks that kv holds exactly the wanted keys.
func onlyKeys(kv map[string]string, want ...string) error {
	for _, k := range want {
		if _, ok := kv[k]; !ok {
			return fmt.Errorf("missing key %q", k)
		}
	}
	for k := range kv {
		if !slices.Contains(want, k) {
			return fmt.Errorf("unknown key %q", k)
		}
	}
	return nil
}

func timeOf(kv map[string]string, key string) (time.Time, error) {
	t, err := time.Parse(time.RFC3339, kv[key])
	if err != nil {
		return time.Time{}, fmt.Errorf("%s: %v", key, err)
	}
	return t, nil
}

// StartTrial writes the trial file (replacing a running trial's deadline: that is how
// "-extend" works). Times are written in UTC to the second. Requires a deadline the daemon
// can follow: End after Start, no longer than MaxTrial, and the boot id it is bound to.
// Whether a kept enforce or a running trial allows a start is the caller's check (Req 2.5, 5.6).
func (s Store) StartTrial(d Deadline) error {
	s.require()
	contract.Require(d.End.After(d.Start), "start trial: end is not after start")
	contract.Require(d.End.Sub(d.Start) <= MaxTrial, "start trial: longer than MaxTrial")
	contract.Require(d.Boot != "", "start trial: empty boot id")
	body := "start=" + stamp(d.Start) + "\nend=" + stamp(d.End) + "\nboot=" + d.Boot + "\n"
	return s.FS.WriteFile(s.TrialPath(), []byte(body))
}

// Keep records enforce as kept at now, then removes the trial file. The marker goes first:
// an interruption between the two leaves kept + trial, which Decide reads as kept.
func (s Store) Keep(now time.Time) error {
	s.require()
	if err := s.FS.WriteFile(s.KeptPath(), []byte("kept="+stamp(now)+"\n")); err != nil {
		return err
	}
	return s.ClearTrial()
}

// ClearTrial removes the trial file; an absent file is not an error.
func (s Store) ClearTrial() error { s.require(); return s.remove(s.TrialPath()) }

// ClearKept removes the kept marker; an absent file is not an error.
func (s Store) ClearKept() error { s.require(); return s.remove(s.KeptPath()) }

func (s Store) remove(path string) error {
	err := s.FS.Remove(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

func stamp(t time.Time) string { return t.UTC().Format(time.RFC3339) }
