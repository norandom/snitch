package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/norandom/snitch/internal/client/clienttest"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
)

const (
	enterAltScreen = "\x1b[?1049h"
	leaveAltScreen = "\x1b[?1049l"
)

type rootDirInfo struct{ os.FileInfo }

func (rootDirInfo) Sys() any { return &syscall.Stat_t{Uid: 0} }

func openTestPTY(t *testing.T) (master, slave *os.File) {
	t.Helper()
	mfd, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) || errors.Is(err, unix.ENXIO) || errors.Is(err, unix.EACCES) {
			t.Skipf("no usable /dev/ptmx: %v", err)
		}
		t.Fatalf("open /dev/ptmx: %v", err)
	}
	master = os.NewFile(uintptr(mfd), "ptmx")
	if err := unix.IoctlSetPointerInt(mfd, unix.TIOCSPTLCK, 0); err != nil {
		_ = master.Close()
		t.Fatalf("unlockpt: %v", err)
	}
	num, err := unix.IoctlGetInt(mfd, unix.TIOCGPTN)
	if err != nil {
		_ = master.Close()
		t.Fatalf("ptsname: %v", err)
	}
	sfd, err := unix.Open(fmt.Sprintf("/dev/pts/%d", num), unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		_ = master.Close()
		t.Fatalf("open pts: %v", err)
	}
	slave = os.NewFile(uintptr(sfd), "pts")
	_ = unix.IoctlSetWinsize(sfd, unix.TIOCSWINSZ, &unix.Winsize{Row: 24, Col: 100})
	t.Cleanup(func() { _ = slave.Close(); _ = master.Close() })
	return master, slave
}

func pumpPTY(master *os.File) *memLog {
	out := &memLog{}
	go func() {
		var buf [4096]byte
		for {
			n, err := master.Read(buf[:])
			if n > 0 {
				_, _ = out.Write(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()
	return out
}

func waitPTYText(t *testing.T, out *memLog, want string) {
	t.Helper()
	waitFor(t, "pty output "+want, 5*time.Second, func() bool { return strings.Contains(out.String(), want) })
}

func startPTYFixture(t *testing.T) (string, string, *os.File, *os.File, *memLog) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	if err := s.Do("event curl /usr/bin/curl 1.1.1.1 443 tcp allow-monitor"); err != nil {
		t.Fatal(err)
	}
	master, slave := openTestPTY(t)
	return home, s.Path(), master, slave, pumpPTY(master)
}

func TestTuiNotATerminalExitsOne(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, args := range [][]string{nil, {"egress"}} {
		if code, out, errOut := run(args...); code != exitFail || out != "" || strings.Count(errOut, "\n") != 1 {
			t.Fatalf("%v: want exit 1, no stdout, 1 line; got %d %q %q", args, code, out, errOut)
		}
	}
	_, slave := openTestPTY(t)
	var outBuf, errBuf bytes.Buffer
	if code := runOverview(nil, slave, &outBuf, &errBuf); code != exitFail || strings.Count(errBuf.String(), "\n") != 1 {
		t.Fatalf("pipe stdout: want exit 1 and 1 line, got %d %q", code, errBuf.String())
	}
	errBuf.Reset()
	if code := runOverview(nil, bytes.NewBuffer(nil), slave, &errBuf); code != exitFail || strings.Count(errBuf.String(), "\n") != 1 {
		t.Fatalf("pipe stdin: want exit 1 and 1 line, got %d %q", code, errBuf.String())
	}
}

func TestTuiBadSinceExitsTwoNamingWindows(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, args := range [][]string{{"--since", "5m"}, {"--since=5m"}, {"-since", "bogus"}, {"egress", "--since", "5m"}} {
		code, out, errOut := run(args...)
		if code != exitUsage || out != "" {
			t.Fatalf("%v: want exit 2 and no stdout, got %d %q %q", args, code, out, errOut)
		}
		for _, w := range []string{"15m", "30m", "1h", "24h", "7d"} {
			if !strings.Contains(errOut, w) {
				t.Fatalf("%v: stderr %q missing window %q", args, errOut, w)
			}
		}
	}
}

func TestTuiBadConfigAndUsageExitsTwo(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cfgDir := filepath.Join(home, ".config", "snitch")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgDir, "config.toml"), []byte("trial = \"10s\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, out, errOut := run(); code != exitUsage || out != "" || !strings.Contains(errOut, "config.toml") {
		t.Fatalf("bad config: want exit 2 naming config.toml, got %d %q %q", code, out, errOut)
	}
	t.Setenv("HOME", t.TempDir())
	for _, args := range [][]string{{"-api"}, {"--since"}, {"-api", "/x", "-bogus"}, {"egress", "-bogus"}, {"egress", "extra"}} {
		if code, out, errOut := run(args...); code != exitUsage || out != "" || !strings.Contains(errOut, "usage: snitch") {
			t.Fatalf("%v: want exit 2 and usage, got %d %q %q", args, code, out, errOut)
		}
	}
}

func TestTuiLooseDirThreeConditions(t *testing.T) {
	if os.Getuid() != 0 {
		nonRoot := t.TempDir()
		_ = os.Chmod(nonRoot, 0o755)
		if !looseDir(os.Lstat)(filepath.Join(nonRoot, "prog")) {
			t.Fatal("non-root dir should be loose")
		}
		locked := t.TempDir()
		sub := filepath.Join(locked, "sub")
		_ = os.MkdirAll(sub, 0o755)
		_ = os.Chmod(locked, 0o000)
		defer func() { _ = os.Chmod(locked, 0o700) }()
		if !looseDir(os.Lstat)(filepath.Join(sub, "prog")) {
			t.Fatal("unreadable dir should be loose")
		}
	}
	rootStat := func(p string) (os.FileInfo, error) {
		fi, err := os.Lstat(p)
		if err != nil {
			return nil, err
		}
		return rootDirInfo{fi}, nil
	}
	for _, tc := range []struct {
		mode os.FileMode
		want bool
	}{{0o755, false}, {0o775, true}, {0o757, true}} {
		dir := t.TempDir()
		_ = os.Chmod(dir, tc.mode)
		if got := looseDir(rootStat)(filepath.Join(dir, "prog")); got != tc.want {
			t.Fatalf("mode %04o: got %v, want %v", tc.mode, got, tc.want)
		}
	}
	if !looseDir(os.Lstat)(filepath.Join(t.TempDir(), "missing", "prog")) {
		t.Fatal("missing dir should be loose")
	}
}

func TestTuiPeerCreds(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	c, err := dialUnix(context.Background(), s.Path())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	if uid, ok := peerCreds(c); !ok || uid != uint32(os.Getuid()) {
		t.Fatalf("peerCreds = (%d, %v), want (%d, true)", uid, ok, os.Getuid())
	}
	p1, p2 := net.Pipe()
	defer func() { _ = p1.Close(); _ = p2.Close() }()
	if uid, ok := peerCreds(p1); ok || uid != 0 {
		t.Fatalf("non-unix peerCreds = (%d, %v), want (0, false)", uid, ok)
	}
}

func TestTuiAndEgressPTYStandInExitsZeroOnQuit(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func([]string, io.Reader, io.Writer, io.Writer) int
		want string
	}{{"overview", runOverview, "curl"}, {"egress", runEgress, "EGRESS"}} {
		t.Run(tc.name, func(t *testing.T) {
			home, sock, master, slave, out := startPTYFixture(t)
			var errBuf memLog
			done := make(chan int, 1)
			go func() { done <- tc.call([]string{"-api", sock}, slave, slave, &errBuf) }()
			waitPTYText(t, out, tc.want)
			_, _ = io.WriteString(master, "q")
			if code := <-done; code != 0 || errBuf.String() != "" {
				t.Fatalf("exit=%d stderr=%q", code, errBuf.String())
			}
			if got := out.String(); !strings.Contains(got, enterAltScreen) || !strings.Contains(got, leaveAltScreen) {
				t.Fatal("missing alt-screen enter/leave")
			}
			checkCreatedOnlyLog(t, home)
		})
	}
}

func checkCreatedOnlyLog(t *testing.T, home string) {
	t.Helper()
	var files []string
	err := filepath.WalkDir(home, func(p string, d os.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			files = append(files, p)
		}
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	wantLog := filepath.Join(home, ".local", "state", "snitch", "snitch.log")
	if len(files) != 1 || files[0] != wantLog {
		t.Fatalf("created files = %v, want only [%s]", files, wantLog)
	}
}

func TestTuiLogRefusalBecomesPaneLine(t *testing.T) {
	home, sock, master, slave, out := startPTYFixture(t)
	logDir := filepath.Join(home, ".local", "state", "snitch")
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/nonexistent", filepath.Join(logDir, "snitch.log")); err != nil {
		t.Fatal(err)
	}
	var errBuf memLog
	done := make(chan int, 1)
	go func() { done <- runOverview([]string{"-api", sock}, slave, slave, &errBuf) }()
	waitPTYText(t, out, "logfile:")
	_, _ = io.WriteString(master, "q")
	if code := <-done; code != 0 {
		t.Fatalf("exit = %d, stderr=%q", code, errBuf.String())
	}
}

func TestTuiSignalExitsZeroAndContractRestoresTerminal(t *testing.T) {
	_, sock, _, slave, out := startPTYFixture(t)
	var errBuf memLog
	sigGuard := make(chan os.Signal, 1)
	signal.Notify(sigGuard, syscall.SIGTERM)
	defer signal.Stop(sigGuard)
	done := make(chan int, 1)
	go func() { done <- runOverview([]string{"-api", sock}, slave, slave, &errBuf) }()
	waitPTYText(t, out, "curl")
	time.Sleep(20 * time.Millisecond)
	_ = syscall.Kill(os.Getpid(), syscall.SIGTERM)
	if code := <-done; code != 0 || !strings.Contains(out.String(), leaveAltScreen) {
		t.Fatalf("signal exit=%d stderr=%q altLeave=%v", code, errBuf.String(), strings.Contains(out.String(), leaveAltScreen))
	}

	_, sock2, _, slave2, out2 := startPTYFixture(t)
	var errBuf2 memLog
	ready := make(chan struct{})
	boom := func(context.Context) error { <-ready; contract.Require(false, "boom-in-job"); return nil }
	go func() { waitPTYText(t, out2, "curl"); close(ready) }()
	code := runTUIWithJobs([]string{"-api", sock2}, false, slave2, slave2, &errBuf2, []jobs.Job{boom})
	if code != exitViolation || !strings.Contains(errBuf2.String(), "boom-in-job") {
		t.Fatalf("violation exit=%d stderr=%q", code, errBuf2.String())
	}
	waitPTYText(t, out2, leaveAltScreen)
}
