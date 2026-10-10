package status

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

var (
	tWritten = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)
	full     = Record{
		PID: 4242, Mode: "enforce", Source: "files", Learning: false,
		Trial: "2026-10-10T12:10:00Z", Kept: true, RulesFile: "/etc/snitch/rules.toml",
		Programs: 3, Resolved: 2, Executables: 5, Rules: 7, Written: tWritten,
	}
	fullBody = "pid=4242\n" +
		"mode=enforce\n" +
		"source=files\n" +
		"learning=false\n" +
		"trial=2026-10-10T12:10:00Z\n" +
		"kept=true\n" +
		"rules_file=/etc/snitch/rules.toml\n" +
		"programs=3\n" +
		"resolved=2\n" +
		"executables=5\n" +
		"rules=7\n" +
		"written=2026-10-10T12:00:00Z\n"
)

// statusPath is a file in a directory that does not exist yet: a hand-started daemon has no
// /run/snitch, so Write must create it.
func statusPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "run", "status")
}

// TestWriteReadRoundTrip: what Write puts on disk is the design's key=value format, and Read
// gives the same record back (Written in UTC to the second, the precision the file carries).
func TestWriteReadRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		rec  Record
		body string // "" when only the round trip is checked
	}{
		{"every field set", full, fullBody},
		{"monitor without a trial", Record{PID: 1, Mode: "monitor", Source: "flag", Learning: true,
			RulesFile: "/tmp/r.toml", Written: tWritten}, ""},
		{"written in another zone reads back in UTC", Record{PID: 1, Mode: "monitor", Source: "flag",
			Written: tWritten.In(time.FixedZone("x", 3600))}, ""},
		{"a path with = in it survives the first-= split", Record{PID: 1, Mode: "monitor", Source: "files",
			RulesFile: "/etc/a=b/rules=x.toml", Written: tWritten}, ""},
	}
	for _, c := range cases {
		path := statusPath(t)
		if err := Write(path, c.rec); err != nil {
			t.Fatalf("%s: Write: %v", c.name, err)
		}
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		if c.body != "" && string(b) != c.body {
			t.Errorf("%s: file is\n%s\nwant\n%s", c.name, b, c.body)
		}
		got, err := Read(path)
		if err != nil {
			t.Fatalf("%s: Read: %v", c.name, err)
		}
		want := c.rec
		want.Written = want.Written.UTC()
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s: Read() = %+v, want %+v", c.name, got, want)
		}
	}
}

// TestWriteCreatesThePrivateDirectory: the tmpfs directory is created 0700 when missing and
// nothing but the status file is left behind (no temp file after the rename).
func TestWriteCreatesThePrivateDirectory(t *testing.T) {
	path := statusPath(t)
	for i := 0; i < 2; i++ { // the second write replaces the first
		if err := Write(path, full); err != nil {
			t.Fatalf("Write %d: %v", i, err)
		}
	}
	info, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Errorf("directory mode %o, want 700", perm)
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if want := []string{"status"}; !reflect.DeepEqual(names, want) {
		t.Errorf("directory holds %q, want %q", names, want)
	}
}

// TestReadMissingFile: the CLI turns this one error into "daemon not running".
func TestReadMissingFile(t *testing.T) {
	path := statusPath(t)
	_, err := Read(path)
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Read(missing) = %v, want an fs.ErrNotExist", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("error %q does not name %s", err, path)
	}
}

// TestReadMalformed: a file the daemon could not have written is an error naming the file
// and what is wrong, never a half-filled record.
func TestReadMalformed(t *testing.T) {
	cases := []struct {
		name, body, want string
	}{
		{"not key=value", "garbage\n", "garbage"},
		{"missing key", strings.Replace(fullBody, "rules=7\n", "", 1), "rules"},
		{"unknown key", fullBody + "extra=1\n", "extra"},
		{"duplicate key", fullBody + "pid=1\n", "pid"},
		{"pid not a number", strings.Replace(fullBody, "pid=4242", "pid=many", 1), "pid"},
		{"kept not a bool", strings.Replace(fullBody, "kept=true", "kept=yes", 1), "kept"},
		{"written not a time", strings.Replace(fullBody, "written=2026-10-10T12:00:00Z", "written=now", 1), "written"},
		{"trial not a time", strings.Replace(fullBody, "trial=2026-10-10T12:10:00Z", "trial=soon", 1), "trial"},
		{"empty file", "", "pid"},
	}
	for _, c := range cases {
		path := filepath.Join(t.TempDir(), "status")
		if err := os.WriteFile(path, []byte(c.body), 0o600); err != nil {
			t.Fatal(err)
		}
		got, err := Read(path)
		if err == nil {
			t.Errorf("%s: Read() = %+v, want an error", c.name, got)
			continue
		}
		if msg := err.Error(); !strings.Contains(msg, path) || !strings.Contains(msg, c.want) {
			t.Errorf("%s: error %q names neither the file nor %q", c.name, msg, c.want)
		}
		if !reflect.DeepEqual(got, Record{}) {
			t.Errorf("%s: Read() = %+v with an error, want a zero record", c.name, got)
		}
	}
}

func TestWriteReportsTheOSError(t *testing.T) {
	// a file where the directory should be: MkdirAll fails and the error reaches the caller
	dir := t.TempDir()
	blocker := filepath.Join(dir, "run")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Write(filepath.Join(blocker, "status"), full); err == nil {
		t.Fatal("Write under a file succeeded, want an error")
	}
}

// Contracts: an empty path and a value with a newline are programming errors (the line
// format could not carry the record back), not operator errors.
func TestWriteContracts(t *testing.T) {
	cases := []struct {
		name string
		path string
		rec  Record
	}{
		{"empty path", "", full},
		{"newline in rules file", "/mem/status", Record{RulesFile: "a\nb"}},
		{"newline in mode", "/mem/status", Record{Mode: "monitor\nenforce"}},
	}
	for _, c := range cases {
		v := contracttest.Panics(t, contract.Precondition, func() { _ = Write(c.path, c.rec) })
		if !strings.HasPrefix(v.Msg, "status:") {
			t.Errorf("%s: violation %q does not start with the package name", c.name, v.Msg)
		}
	}
}

func TestReadRequiresAPath(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { _, _ = Read("") })
}
