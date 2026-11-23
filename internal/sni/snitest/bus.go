// Package snitest starts a private D-Bus session bus for one test, so the session-bus
// adapter (internal/sni) is tested against a real bus daemon without touching the
// developer's desktop session.
//
// Fail-safe implications: none on the host. The bus is a child dbus-daemon with its own
// configuration: it listens in a fresh temporary directory, activates no services (so a test
// never starts the desktop's real notification server or tray watcher) and is killed when the
// test ends. The package imports godbus only, never internal/sni: the adapter's tests import
// this package, not the other way round.
package snitest

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"
)

// Daemon is the program a private bus runs.
const Daemon = "dbus-daemon"

// startLimit bounds how long the daemon may take to print its address.
const startLimit = 5 * time.Second

// config is a session bus with no service directories: nothing is ever auto-started on it,
// and every connection may own any name and talk to any other, as on a desktop session.
const config = `<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:dir=%s</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
`

// Installed reports whether dbus-daemon is on PATH, and says why not when it is not.
func Installed() (bool, string) {
	if _, err := exec.LookPath(Daemon); err != nil {
		return false, Daemon + " is not installed: " + err.Error()
	}
	return true, ""
}

// SkipUnlessInstalled skips the test when there is no dbus-daemon to start.
func SkipUnlessInstalled(t testing.TB) {
	t.Helper()
	if ok, why := Installed(); !ok {
		t.Skip(why)
	}
}

// Start runs a private session bus for the test and returns its address. The bus is
// stopped by t.Cleanup. The test is skipped when dbus-daemon is not installed.
func Start(t testing.TB) string {
	t.Helper()
	SkipUnlessInstalled(t)
	dir := socketDir(t)
	conf := filepath.Join(dir, "bus.conf")
	if err := os.WriteFile(conf, []byte(fmt.Sprintf(config, dir)), 0o600); err != nil {
		t.Fatalf("snitest: write config: %v", err)
	}
	cmd := exec.Command(Daemon, "--config-file="+conf, "--nofork", "--print-address")
	// The daemon dies with the test binary even when t.Cleanup never runs (a -timeout panic).
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("snitest: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("snitest: start %s: %v", Daemon, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return readAddress(t, out)
}

// socketDir makes a short-lived directory for the socket and the config. It is not
// t.TempDir: a unix socket path must stay under 108 bytes, and test names make those long.
func socketDir(t testing.TB) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "snitest-")
	if err != nil {
		t.Fatalf("snitest: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

// readAddress waits for the first line dbus-daemon prints: the bus address.
func readAddress(t testing.TB, out io.Reader) string {
	t.Helper()
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(out).ReadString('\n')
		line <- strings.TrimSpace(s)
	}()
	select {
	case addr := <-line:
		if addr == "" {
			t.Fatalf("snitest: %s printed no address", Daemon)
		}
		return addr
	case <-time.After(startLimit):
		t.Fatalf("snitest: %s printed no address within %v", Daemon, startLimit)
		return ""
	}
}

// Conn returns a raw connection to the bus at addr, authenticated and registered (Hello),
// closed by t.Cleanup. Tests use it to play the other side: an owner of a name, a watcher,
// a notification server.
func Conn(t testing.TB, addr string) *dbus.Conn {
	t.Helper()
	conn, err := dbus.Connect(addr)
	if err != nil {
		t.Fatalf("snitest: connect %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}
