// tray_test.go: the tray verb's integration (design "Testing Strategy > cmd/snitch wiring")
// against the stand-in daemon and the fake bus services: the flags, one whole wiring in
// this process, and the exits with the tray as its own process. Every test owns its private
// dbus-daemon and stand-in, loads no kernel program, never touches the real session bus,
// and runs unparallel (the bus env is process-wide).
package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/ask"
	"github.com/norandom/snitch/internal/client/clienttest"
	"github.com/norandom/snitch/internal/sni/snitest"
	"github.com/norandom/snitch/internal/tray"
)

// world is a test's whole outside: a stand-in daemon granting this user, and the fake
// session — a private bus, the fake watcher and notifications — in the env sni.Open reads.
func world(t *testing.T) (*clienttest.StandIn, *snitest.Watcher, *snitest.Notifications, string) {
	t.Helper()
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	addr := snitest.Start(t)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)
	return s, snitest.StartWatcher(t, addr), snitest.StartNotifications(t, addr, "actions", "body", "body-markup"), addr
}

// rootInfo makes any stat'ed file look root-owned: no test can chown.
type rootInfo struct{ os.FileInfo }

func (rootInfo) Sys() any          { return &syscall.Stat_t{Uid: 0} }
func (rootInfo) Mode() os.FileMode { return 0o644 }

type memLog struct { // the wiring's stderr for a test, readable while it writes
	mu sync.Mutex
	b  bytes.Buffer
}

func (m *memLog) Write(p []byte) (int, error) { m.mu.Lock(); defer m.mu.Unlock(); return m.b.Write(p) }
func (m *memLog) String() string              { m.mu.Lock(); defer m.mu.Unlock(); return m.b.String() }

// asConfig is the wiring as a writer: a temporary operator file naming this user.
func asConfig(t *testing.T, apiPath string, scope ask.Scope, log *memLog) trayConfig {
	t.Helper()
	me, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Fatalf("this test's user: %v", err)
	}
	f := filepath.Join(t.TempDir(), "operator")
	if err := os.WriteFile(f, []byte(me.Username), 0o600); err != nil {
		t.Fatalf("the operator file: %v", err)
	}
	return trayConfig{apiPath: apiPath, operatorFile: f, ask: scope, stderr: log,
		dial: dialUnix, read: os.ReadFile, stat: func(p string) (os.FileInfo, error) {
			fi, err := os.Stat(p)
			if err != nil {
				return nil, err
			}
			return rootInfo{fi}, nil
		}}
}

// wired runs one tray wiring, waits for its item, and answers its name, stderr, exit code.
func wired(t *testing.T, apiPath string, scope ask.Scope, w *snitest.Watcher) (string, *memLog, <-chan int) {
	t.Helper()
	log, code := &memLog{}, make(chan int, 1)
	go func() { code <- startTray(asConfig(t, apiPath, scope, log)) }()
	item := fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", os.Getpid())
	waitFor(t, "the item registers", 8*time.Second, func() bool { return slices.Contains(w.Items(), item) })
	return item, log, code
}

// waitFor polls what until it holds within the limit.
func waitFor(t *testing.T, what string, limit time.Duration, holds func() bool) {
	t.Helper()
	for end := time.Now().Add(limit); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
		if holds() {
			return
		}
	}
	t.Fatalf("%s did not happen within %v", what, limit)
}

// script runs one of the stand-in's scripting lines, the language of tools/fakedaemon.
func script(t *testing.T, s *clienttest.StandIn, line string) {
	t.Helper()
	if err := s.Do(line); err != nil {
		t.Fatalf("stand-in script %q: %v", line, err)
	}
}

// wantUnownedName wants the private bus's owner probe to answer that the name was released.
func wantUnownedName(t *testing.T, conn *dbus.Conn, item string) {
	t.Helper()
	if conn.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, item).Err == nil {
		t.Fatalf("the item name %s is still owned", item)
	}
}

// statusIs polls the item's Status: NeedsAttention while the daemon is gone (2.3).
func statusIs(conn *dbus.Conn, item, want string) func() bool {
	return func() bool {
		v, err := conn.Object(item, "/StatusNotifierItem").GetProperty("org.kde.StatusNotifierItem.Status")
		return err == nil && v.Value() == want
	}
}

// buildTray compiles the binary outside the repo; the test's own dir IS the package.
func buildTray(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "snitch")
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building the tray binary: %v (%s)", err, out)
	}
	return bin
}

// trayProc starts the built tray; the absent operator file keeps its role guess a reader.
func trayProc(t *testing.T, bin, apiPath string, stderr *bytes.Buffer, flags ...string) *exec.Cmd {
	t.Helper()
	args := append([]string{"tray", "-api", apiPath, "-operator-file",
		filepath.Join(t.TempDir(), "no-operator")}, flags...)
	cmd := exec.Command(bin, args...)
	cmd.Env = append(os.Environ(), "DBUS_SESSION_BUS_ADDRESS="+os.Getenv("DBUS_SESSION_BUS_ADDRESS"))
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start the tray binary: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return cmd
}

// TestTrayQuestionToRule proves the done-when's flow (1.1, 1.4, 6.2, 8.2, 5.11): the item
// registers, a scripted deny-default raises the question, the invoked allow writes the
// by-name rule.add, the pre-connect connection asks nothing, Quit ends the wiring.
func TestTrayQuestionToRule(t *testing.T) {
	stand, w, notes, addr := world(t)
	// a different connection: only a fresh decision is reported, a repeat is not
	script(t, stand, "event curl /usr/bin/curl 93.184.216.34 80 tcp deny-default")
	item, log, code := wired(t, stand.Path(), ask.All, w)
	time.Sleep(300 * time.Millisecond) // the event is unreplayed: no note can ever follow it
	if n := len(notes.Calls()); n != 0 {
		t.Fatalf("the connection before the tray subscribed asked: %d notes", n)
	}
	script(t, stand, "event curl /usr/bin/curl 93.184.216.34=example.com 443 tcp deny-default")
	waitFor(t, "the question", 8*time.Second, func() bool { return len(notes.Calls()) > 0 })
	waitFor(t, "the rule.add at the daemon", 8*time.Second, func() bool {
		notes.Invoked(1, "allow") // a press the loop has settled is ignored (6.11)
		return len(stand.Edits()) > 0
	})
	if r := stand.Edits()[0]; r.Type != "rule.add" || r.Program != "curl" || r.To != "example.com" ||
		r.Proto != "tcp" || r.Port != 443 || r.Verdict != "allow" ||
		!strings.HasPrefix(r.Note, "snitch tray ") { // the rule the answer stands for (6.2, 6.6)
		t.Fatalf("the stand-in recorded %+v, want curl to example.com tcp port 443 allow", r)
	}
	wantTrayOver(t, addr, item, log, code,
		"starting: version", "daemon: up", "role writer", "registered with the system tray as",
		"rule.add sent:", "rule.add accepted")
}

// wantTrayOver ends the wired tray by the menu's Quit row: exit 0, name released, Monitoring lines.
func wantTrayOver(t *testing.T, addr, item string, log *memLog, code <-chan int, lines ...string) {
	t.Helper()
	conn := snitest.Conn(t, addr)
	waitFor(t, "the menu's Quit row", 8*time.Second, func() bool {
		return conn.Object(item, "/StatusNotifierItem/menu").Call("com.canonical.dbusmenu.Event", 0,
			int32(tray.RowQuit), "clicked", dbus.MakeVariant(""), uint32(0)).Err == nil
	})
	select {
	case c := <-code:
		if c != 0 {
			t.Fatalf("the tray exited %d, want 0", c)
		}
	case <-time.After(10 * time.Second):
		t.Fatalf("the tray's run did not end")
	}
	wantUnownedName(t, conn, item)
	for _, line := range lines {
		if !strings.Contains(log.String(), line) {
			t.Fatalf("the tray's stderr lacks %q: %s", line, log)
		}
	}
}

// TestTrayScriptedDaemon proves -ask and the daemon's restart on one wiring (4.5, 2.3, 5.9):
// an allowed connection asks nothing in the enforce scope; stopped the item turns to
// attention, served again it turns back, by its own retry.
func TestTrayScriptedDaemon(t *testing.T) {
	stand, w, notes, addr := world(t)
	item, log, code := wired(t, stand.Path(), ask.Enforce, w)
	conn := snitest.Conn(t, addr)
	script(t, stand, "event curl /usr/bin/curl 93.184.216.34=example.com 443 tcp deny-default")
	waitFor(t, "monitor shown", 8*time.Second, statusIs(conn, item, "Active"))
	waitFor(t, "the denied question", 8*time.Second, func() bool { return len(notes.Calls()) == 1 })
	script(t, stand, "event wget /usr/bin/wget 140.82.121.4 443 tcp allow-monitor")
	time.Sleep(500 * time.Millisecond)
	if n := len(notes.Calls()); n != 1 {
		t.Fatalf("the allowed connection asked in the enforce scope: %d notes", n)
	}
	stand.Stop()
	waitFor(t, "the daemon gone turns to attention", 8*time.Second, statusIs(conn, item, "NeedsAttention"))
	if err := stand.Serve(); err != nil {
		t.Fatalf("the stand-in serves again: %v", err)
	}
	waitFor(t, "the daemon back turns to active", 10*time.Second, statusIs(conn, item, "Active"))
	wantTrayOver(t, addr, item, log, code)
}

// TestExitWithSignalsAndASecondInstance runs the tray as its own process for the design's
// exits (1.2, 1.4, 8.4, 6.9): a second start exits 1 naming the running one's pid and adds
// no item; SIGTERM ends it as Quit does — note closed, name released, exit 0, no answers.
func TestExitWithSignalsAndASecondInstance(t *testing.T) {
	stand, w, notes, addr := world(t)
	bin := buildTray(t)
	var stderr bytes.Buffer
	first := trayProc(t, bin, stand.Path(), new(bytes.Buffer))
	item := fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", first.Process.Pid)
	waitFor(t, "the first item registers", 8*time.Second, func() bool { return slices.Contains(w.Items(), item) })
	second := trayProc(t, bin, stand.Path(), &stderr)
	_ = second.Wait() // a non-zero exit is expected; the code is the assertion
	if code := second.ProcessState.ExitCode(); code != exitFail {
		t.Fatalf("the second tray exited %d, want 1", code)
	}
	if out := stderr.String(); !strings.Contains(out, fmt.Sprintf("already running (pid %d)", first.Process.Pid)) {
		t.Fatalf("the second tray's line does not name the running one: %q", out)
	}
	if i := fmt.Sprintf("org.kde.StatusNotifierItem-%d-1", second.Process.Pid); slices.Contains(w.Items(), i) {
		t.Fatalf("a second item registered: %v", w.Items())
	}
	script(t, stand, "event curl /usr/bin/curl 93.184.216.34=example.com 443 tcp deny-default")
	waitFor(t, "the question", 8*time.Second, func() bool { return len(notes.Calls()) > 0 })
	if q := notes.Calls()[0]; len(q.Actions) != 0 {
		t.Fatalf("a reader's question offers answers: %+v", q)
	}
	if err := first.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM the tray: %v", err)
	}
	_ = first.Wait() // the exit code is the assertion; a killed wait is the failure
	if code := first.ProcessState.ExitCode(); code != 0 {
		t.Fatalf("the signalled tray exited %d, want 0", code)
	}
	if !slices.Contains(notes.Closes(), uint32(1)) {
		t.Fatalf("the open question's note was not closed: closes %v", notes.Closes())
	}
	wantUnownedName(t, snitest.Conn(t, addr), item)
}

// TestFlagsParse is the flag surface: the three flags with their values and defaults, and
// any other word — a wrong value, an unknown flag, a bare trailing word — a usage error
// that exits 2 with the tray's own usage line.
func TestFlagsParse(t *testing.T) {
	want := func(args []string, apiPath string, scope ask.Scope, opFile string) {
		cfg, err := parseTray(args, io.Discard)
		if err != nil || cfg.apiPath != apiPath || cfg.ask != scope || cfg.operatorFile != opFile {
			t.Fatalf("parseTray(%q) = %+v, %v", args, cfg, err)
		}
	}
	want([]string{"-api", "/x/sock", "-ask", "enforce", "-operator-file", "/y/operator"},
		"/x/sock", ask.Enforce, "/y/operator")
	want(nil, defaultAPI, ask.All, defaultOperator)
	for _, args := range [][]string{{"-bogus"}, {"-ask", "sometimes"}, {"-ask"},
		{"-api"}, {"trailing"}, {""}} {
		code, stdout, errOut := run(append([]string{"tray"}, args...)...)
		if code != exitUsage || stdout != "" || !strings.Contains(errOut, trayUsage) {
			t.Fatalf("%q is a usage error: got %d, %q, %q", args, code, stdout, errOut)
		}
	}
}

// TestFlagsRoleAtStart is the role guess at start through the injected file access (the
// 2.2 note): the operator file naming this user makes a writer; an unreadable one guesses
// reader and says why once on stderr — the daemon may still grant writer (6.9).
func TestFlagsRoleAtStart(t *testing.T) {
	log := &memLog{}
	cfg := asConfig(t, "", ask.All, log)
	if r := roleAtStart(cfg); r != api.Writer || log.String() != "" {
		t.Fatalf("the named operator file: role %v, stderr %s", r, log)
	}
	cfg.operatorFile = filepath.Join(t.TempDir(), "unreadable")
	if r := roleAtStart(cfg); r != api.Reader || strings.Count(log.String(), "\n") != 1 ||
		!strings.Contains(log.String(), "operator file") {
		t.Fatalf("the unreadable operator file: role %v, stderr %s", r, log)
	}
}
