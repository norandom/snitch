package rules

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// withMountinfo swaps the mountinfo source for one test.
func withMountinfo(t *testing.T, open func() (io.ReadCloser, error)) {
	t.Helper()
	prev := openMountinfo
	openMountinfo = open
	fallbackWarned = sync.Once{} // the warning is once per process; each test wants its own
	t.Cleanup(func() { openMountinfo = prev; fallbackWarned = sync.Once{} })
}

func statDev(t *testing.T, path string) uint32 {
	t.Helper()
	_, _, stDev, err := statx(path)
	if err != nil {
		t.Fatal(err)
	}
	return devFromStat(stDev)
}

func TestDevFallbackWhenMountinfoHasNoRow(t *testing.T) {
	withMountinfo(t, func() (io.ReadCloser, error) {
		return io.NopCloser(strings.NewReader("1 1 0:1 / /nowhere rw - x x rw\n")), nil
	})
	var warnings []string
	identity := identityFunc(func(m string) { warnings = append(warnings, m) })
	a, errA := identity("testdata/valid.toml")
	b, errB := identity("testdata/mountinfo")
	if errA != nil || errB != nil || a.Dev != statDev(t, "testdata/valid.toml") || b.Dev != a.Dev {
		t.Fatalf("want the stat device for both files, got %+v %v / %+v %v", a, errA, b, errB)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "no row") {
		t.Fatalf("want exactly one warning naming the cause, got %q", warnings)
	}
}

func TestDevFallbackWhenMountinfoIsUnreadable(t *testing.T) {
	withMountinfo(t, func() (io.ReadCloser, error) { return nil, errors.New("open /proc/self/mountinfo: permission denied") })
	warned := 0
	identity := identityFunc(func(string) { warned++ })
	k, err := identity("testdata/valid.toml")
	if err != nil || k.Dev != statDev(t, "testdata/valid.toml") || warned != 1 {
		t.Fatalf("want the stat device with one warning, got %+v %v warned=%d", k, err, warned)
	}
	if _, err := devOf("testdata/valid.toml"); err == nil {
		t.Fatal("devOf must not fall back silently; it reports the error")
	}
}

func TestDevFallbackWarningNamesAMalformedRow(t *testing.T) {
	_, mnt, _, err := statx("testdata/valid.toml")
	if err != nil {
		t.Fatal(err)
	}
	row := strconv.FormatUint(mnt, 10) + " 1 eight:one / / rw - x x rw\n"
	withMountinfo(t, func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(row)), nil })
	var msg string
	identity := identityFunc(func(m string) { msg = m })
	if _, err := identity("testdata/valid.toml"); err != nil || !strings.Contains(msg, "bad device") {
		t.Fatalf("want a fallback whose warning names the malformed row, got %v, %q", err, msg)
	}
}

func TestStatxRejectsNonRegularFiles(t *testing.T) {
	if _, _, _, err := statx("testdata"); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("want 'not a regular file', got %v", err)
	}
}
