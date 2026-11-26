// logfile_test.go tests safe opening, permission narrowing, symlink/owner/type refusals,
// sanitised tail reading, and local-time appending for internal/logfile.
package logfile

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/norandom/snitch/internal/clean"
)

func TestOpenCreatesPrivateDirAndFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "state")
	path := filepath.Join(dir, "snitch.log")

	log, tail, err := Open(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer log.Close()

	if len(tail) != 0 {
		t.Fatalf("tail = %v, want empty", tail)
	}
	if got := mustLstatPerm(t, dir); got != 0o700 {
		t.Errorf("dir perm = %04o, want 0700", got)
	}
	if got := mustLstatPerm(t, path); got != 0o600 {
		t.Errorf("file perm = %04o, want 0600", got)
	}
}

func TestOpenPreservesExistingDirModeAndNarrows0644File(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(dir, 0o755)
	path := filepath.Join(dir, "snitch.log")
	if err := os.WriteFile(path, []byte("existing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(path, 0o644)

	log, tail, err := Open(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer log.Close()

	if got := mustLstatPerm(t, dir); got != 0o755 {
		t.Errorf("existing dir perm = %04o, want 0755 preserved", got)
	}
	if got := mustLstatPerm(t, path); got != 0o600 {
		t.Errorf("file perm = %04o, want 0600 narrowed", got)
	}
	if len(tail) != 1 || string(tail[0]) != "existing" {
		t.Errorf("tail = %v, want [existing]", tail)
	}
}

func TestOpenRefusesSymlinkFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "victim")
	if err := os.WriteFile(target, []byte("keep\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "snitch.log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if log, _, err := Open(link, uint32(os.Getuid())); err == nil {
		_ = log.Close()
		t.Fatal("Open succeeded on symlink file, want error")
	}
	if got, err := os.ReadFile(target); err != nil || string(got) != "keep\n" {
		t.Errorf("symlink target modified: got %q, err=%v", got, err)
	}
}

func TestOpenRefusesSymlinkDir(t *testing.T) {
	base := t.TempDir()
	realDir := filepath.Join(base, "real")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	linkDir := filepath.Join(base, "linkdir")
	if err := os.Symlink(realDir, linkDir); err != nil {
		t.Fatal(err)
	}
	if log, _, err := Open(filepath.Join(linkDir, "snitch.log"), uint32(os.Getuid())); err == nil {
		_ = log.Close()
		t.Fatal("Open succeeded through symlink dir, want error")
	}
}

func TestOpenRefusesForeignOwnerInjected(t *testing.T) {
	uid := uint32(os.Getuid())
	other := uid + 1

	for _, onCall := range []int{1, 2} {
		path := filepath.Join(t.TempDir(), "snitch.log")
		calls := 0
		ops := defaultOps()
		ops.fstat = func(fd int, st *unix.Stat_t) error {
			if err := unix.Fstat(fd, st); err != nil {
				return err
			}
			calls++
			if calls == onCall {
				st.Uid = other
			}
			return nil
		}
		if log, _, err := openWith(path, uid, ops); err == nil {
			_ = log.Close()
			t.Fatalf("call %d: openWith succeeded for foreign owner, want error", onCall)
		}
	}
}

func TestOpenRefusesNonRegularFileAndFchmodError(t *testing.T) {
	uid := uint32(os.Getuid())
	fifo := filepath.Join(t.TempDir(), "snitch.log")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if log, _, err := Open(fifo, uid); err == nil {
		_ = log.Close()
		t.Fatal("Open succeeded on FIFO, want error")
	}

	path := filepath.Join(t.TempDir(), "snitch.log")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	_ = os.Chmod(path, 0o644)
	wantErr := errors.New("chmod denied")
	ops := defaultOps()
	ops.fchmod = func(int, uint32) error { return wantErr }
	if log, _, err := openWith(path, uid, ops); !errors.Is(err, wantErr) {
		if log != nil {
			_ = log.Close()
		}
		t.Fatalf("openWith err = %v, want %v", err, wantErr)
	}
}

func TestOpenTailLastFiveLinesAndSanitisesEscapes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snitch.log")
	content := strings.Join([]string{
		"2026-11-26 10:00:01  old1",
		"2026-11-26 10:00:02  old2",
		"2026-11-26 10:00:03  \x1b[31mred\x1b[0m",
		"2026-11-26 10:00:04  osc\x1b]8;;https://evil\x07link\x1b]8;;\x07",
		"2026-11-26 10:00:05  bidi\u202ereverse",
		"2026-11-26 10:00:06  bad\xffutf8\r",
		"2026-11-26 10:00:07  last\x00byte",
	}, "\n") + "\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	log, tail, err := Open(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer log.Close()

	want := []string{
		"2026-11-26 10:00:03  ·[31mred·[0m",
		"2026-11-26 10:00:04  osc·]8;;https://evil·link·]8;;·",
		"2026-11-26 10:00:05  bidi·reverse",
		"2026-11-26 10:00:06  bad·utf8",
		"2026-11-26 10:00:07  last·byte",
	}
	if got := safeStrings(tail); !slices.Equal(got, want) {
		t.Fatalf("tail = %#v, want %#v", got, want)
	}
}

func TestOpenTailOnLargeFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snitch.log")
	var b strings.Builder
	for i := range 2500 {
		b.WriteString(strings.Repeat("x", 100))
		b.WriteByte(' ')
		b.WriteByte('0' + byte(i%10))
		b.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	log, tail, err := Open(path, uint32(os.Getuid()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer log.Close()

	if len(tail) != 5 {
		t.Fatalf("len(tail) = %d, want 5", len(tail))
	}
	for i, suffix := range []string{"5", "6", "7", "8", "9"} {
		if !strings.HasSuffix(string(tail[i]), " "+suffix) {
			t.Errorf("tail[%d] = %q, want suffix %q", i, tail[i], suffix)
		}
	}
}

func TestAppendLocalTimestampAndRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "snitch.log")
	uid := uint32(os.Getuid())
	log, _, err := Open(path, uid)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t1 := time.Date(2026, 11, 26, 14, 5, 9, 0, time.UTC)
	t2 := time.Date(2026, 11, 26, 14, 5, 10, 0, time.Local)
	if err := log.Append(clean.Text("BLOCKED /usr/bin/curl"), t1); err != nil {
		t.Fatalf("Append 1: %v", err)
	}
	if err := log.Append(clean.Text("denied curl > 1.2.3.4:443"), t2); err != nil {
		t.Fatalf("Append 2: %v", err)
	}
	_ = log.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	want1 := t1.Local().Format(timeLayout) + "  BLOCKED /usr/bin/curl"
	want2 := t2.Local().Format(timeLayout) + "  denied curl > 1.2.3.4:443"
	if string(raw) != want1+"\n"+want2+"\n" {
		t.Fatalf("file = %q, want %q", raw, want1+"\n"+want2+"\n")
	}
	log2, tail, err := Open(path, uid)
	if err != nil {
		t.Fatalf("re-Open: %v", err)
	}
	defer log2.Close()
	if got := safeStrings(tail); !slices.Equal(got, []string{want1, want2}) {
		t.Fatalf("re-Open tail = %#v", got)
	}
}

func TestInvalidPathsAndClosedLogReturnErrorsWithoutPanic(t *testing.T) {
	uid := uint32(os.Getuid())
	for _, bad := range []string{"", "/", ".", "..", filepath.Join(t.TempDir(), "dir") + "/"} {
		if log, _, err := Open(bad, uid); err == nil {
			_ = log.Close()
			t.Errorf("Open(%q) succeeded, want error", bad)
		}
	}
	var nilLog *Log
	if err := nilLog.Append(clean.Const("x"), time.Now()); err == nil {
		t.Error("nil Log.Append succeeded, want error")
	}
	if err := nilLog.Close(); err != nil {
		t.Errorf("nil Log.Close = %v, want nil", err)
	}
	log, _, err := Open(filepath.Join(t.TempDir(), "snitch.log"), uid)
	if err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Fatal(err)
	}
	if err := log.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
	if err := log.Append(clean.Const("after close"), time.Now()); err == nil {
		t.Error("Append after Close succeeded, want error")
	}
}

func mustLstatPerm(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatalf("Lstat(%s): %v", path, err)
	}
	return info.Mode().Perm()
}

func safeStrings(in []clean.Safe) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = string(s)
	}
	return out
}
