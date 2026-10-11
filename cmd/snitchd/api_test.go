package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/trial"
)

// fakeInfo is a stat result with the owner and mode a test wants (a test cannot own a file as root).
type fakeInfo struct {
	mode os.FileMode
	uid  uint32
}

func (f fakeInfo) Name() string       { return "operator" }
func (f fakeInfo) Size() int64        { return 3 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

func users(name string) (uint32, error) {
	if name == "mc" {
		return 1000, nil
	}
	return 0, errors.New("user: unknown user " + name)
}

// Design "Facts and state hooks": the operator file counts only when root owns it and neither
// group nor others can write it; every other case is no operator and (except a missing file)
// one log line. The 0666 case is the mutation guard: a loose file must never promote a user.
func TestOperatorFileCases(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator")
	cases := []struct {
		name    string
		content string
		info    os.FileInfo
		statErr error
		want    uint32
		log     string // "" = no line
	}{
		{"missing", "", nil, fs.ErrNotExist, 0, ""},
		{"valid", "mc\n", fakeInfo{0o644, 0}, nil, 1000, ""},
		{"bad name", "nobody-here\n", fakeInfo{0o644, 0}, nil, 0, "nobody-here"},
		{"wrong owner", "mc\n", fakeInfo{0o644, 1000}, nil, 0, "not owned by root"},
		{"world writable", "mc\n", fakeInfo{0o666, 0}, nil, 0, "0666"},
		{"group writable", "mc\n", fakeInfo{0o664, 0}, nil, 0, "0664"},
		{"stat error", "mc\n", nil, errors.New("permission denied"), 0, "permission denied"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(c.content), 0o600); err != nil {
				t.Fatal(err)
			}
			var logs []string
			stat := func(string) (os.FileInfo, error) { return c.info, c.statErr }
			got := operatorUID(path, users, stat, func(m string) { logs = append(logs, m) })
			if got != c.want {
				t.Fatalf("uid %d, want %d (logs %q)", got, c.want, logs)
			}
			if c.log == "" && len(logs) != 0 {
				t.Fatalf("unexpected log %q", logs)
			}
			if c.log != "" && (len(logs) != 1 || !strings.Contains(logs[0], c.log)) {
				t.Fatalf("want one log line with %q, got %q", c.log, logs)
			}
		})
	}
}

// The real stat on a file this user owns: ignored, as the sudoers rule would be.
func TestOperatorRealStatRejectsAUserOwnedFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the file here")
	}
	path := filepath.Join(t.TempDir(), "operator")
	if err := os.WriteFile(path, []byte("mc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var logs []string
	if got := operatorUID(path, users, os.Stat, func(m string) { logs = append(logs, m) }); got != 0 || len(logs) != 1 {
		t.Fatalf("uid %d, logs %q", got, logs)
	}
}

func TestOperatorAndListenerContracts(t *testing.T) {
	log := func(string) {}
	contracttest.Panics(t, contract.Precondition, func() { operatorUID("", users, os.Stat, log) })
	contracttest.Panics(t, contract.Precondition, func() { operatorUID("/x", nil, os.Stat, log) })
	contracttest.Panics(t, contract.Precondition, func() { listenAPI("", log) })
	contracttest.Panics(t, contract.Precondition, func() { (&daemon{}).facts() })
	contracttest.Panics(t, contract.Precondition, func() { (&daemon{}).installAPI(apiState{}) })
}

// newAPIDaemon is a daemon in memory with the API installed (no listener): the facts' sources.
func newAPIDaemon(t *testing.T, src modeSource, logs *[]string) *daemon {
	t.Helper()
	d := &daemon{cfg: config{rules: "/etc/snitch/rules.toml", overlay: "/etc/snitch/rules.d/local.toml", source: src, learn: true},
		log: func(m string) { *logs = append(*logs, m) }}
	d.st.publish(notedSnap(t))
	d.counting = true
	d.installAPI(apiState{kill: func() bool { return true },
		rulesErr: func() (time.Time, error) { return time.Time{}, nil }, started: t0})
	return d
}

// Req 1.9: no -api, no job and no line; an unwritable directory is one line and no job.
func TestApiJobsOffOrSoftFailure(t *testing.T) {
	var logs []string
	d := &daemon{log: func(m string) { logs = append(logs, m) }}
	r := &reloader{st: &d.st}
	if js := d.apiJobs(r); js != nil || len(logs) != 0 {
		t.Fatalf("no -api: jobs %d logs %q", len(js), logs)
	}
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	parent := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(parent, 0o500); err != nil {
		t.Fatal(err)
	}
	d.cfg.api = filepath.Join(parent, "run", "api.sock")
	if js := d.apiJobs(r); js != nil || len(logs) != 1 || !strings.HasPrefix(logs[0], "api off: ") {
		t.Fatalf("locked dir: jobs %d logs %q", len(js), logs)
	}
}

// Req 1.1, 1.2: directory 0755, a stale socket replaced, the socket 0666, gone on close.
func TestApiListenerShape(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run")
	path := filepath.Join(dir, "api.sock")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil { // a stale socket from a crash
		t.Fatal(err)
	}
	l, ok := listenAPI(path, func(m string) { t.Fatal(m) })
	if !ok {
		t.Fatal("listen failed")
	}
	if st, err := os.Stat(dir); err != nil || st.Mode().Perm() != 0o755 {
		t.Fatalf("dir %v %v", st.Mode(), err)
	}
	if st, err := os.Stat(path); err != nil || st.Mode().Perm() != 0o666 || st.Mode()&os.ModeSocket == 0 {
		t.Fatalf("socket %v %v", st.Mode(), err)
	}
	l.Close()
	if _, err := os.Stat(path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("socket after close: %v", err)
	}
}

// The hooks themselves: setMode and publish call their delegates (nil-safe, see the other tests).
func TestApiHooksFire(t *testing.T) {
	var calls []string
	d := &daemon{log: func(string) {}, onMode: func(m trial.Mode, reason string) { calls = append(calls, modeName(m)+" "+reason) }}
	d.setMode(trial.Enforce, "trial until noon")
	d.st.onPublish = func() { calls = append(calls, "publish") }
	d.st.publish(notedSnap(t))
	if want := []string{"enforce trial until noon", "publish"}; !slices.Equal(calls, want) {
		t.Fatalf("calls %q, want %q", calls, want)
	}
}

// apiClient talks JSON lines to the fixture's socket with a deadline per read.
type apiClient struct {
	t    *testing.T
	conn net.Conn
	r    *api.LineReader
}

func (c *apiClient) send(line string) {
	if _, err := c.conn.Write([]byte(line + "\n")); err != nil {
		c.t.Fatal(err)
	}
}

// expect reads one line and checks the given fields; the whole line comes back for the rest.
func (c *apiClient) expect(want map[string]any) map[string]any {
	c.t.Helper()
	got := c.read()
	for k, v := range want {
		if got[k] != v {
			c.t.Fatalf("%s = %v, want %v in %v", k, got[k], v, got)
		}
	}
	return got
}

func (c *apiClient) read() map[string]any {
	c.t.Helper()
	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.r.ReadLine()
	if err != nil {
		c.t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		c.t.Fatalf("%v: %s", err, line)
	}
	return m
}

// Req 1.1, 2.1, 4.1, 4.5, 4.6: the wiring end to end over a socket as this user (a reader):
// status carries the facts, a subscriber gets the state events of setMode and publish and the
// events the pump emits, and the socket is gone once the job ends.
func TestApiWiringOverTheSocket(t *testing.T) {
	var logs []string
	d := newAPIDaemon(t, sourceFlag, &logs)
	c, stop := serveAPI(t, d)
	defer stop()
	c.send(`{"type":"status","id":1}`)
	st, _ := c.expect(map[string]any{"type": "reply", "ok": true})["status"].(map[string]any)
	for k, v := range map[string]any{"running": true, "version": "dev", "clients": 1.0, "counting": true} {
		if st[k] != v {
			t.Fatalf("status %s = %v, want %v", k, st[k], v)
		}
	}
	c.send(`{"type":"subscribe","id":2}`)
	c.expect(map[string]any{"ok": true})
	d.setMode(trial.Enforce, "trial until noon")
	c.expect(map[string]any{"type": "state", "mode": "enforce", "reason": "trial until noon", "rulesChanged": false})
	d.st.publish(notedSnap(t))
	c.expect(map[string]any{"type": "state", "mode": "enforce", "reason": "rules reloaded", "rulesChanged": true})
	d.emit(api.Event{Time: evNow, Program: "curl", Addr: "9.9.9.9", Port: 443, Protocol: "tcp", Verdict: "allow-monitor"})
	c.expect(map[string]any{"type": "event", "program": "curl", "verdict": "allow-monitor"})
	c.send(`{"type":"trial","id":3,"duration":"2m"}`) // this user is a reader: refused, the stub never runs
	if e, _ := c.expect(map[string]any{"type": "error", "id": 3.0})["error"].(string); !strings.Contains(e, "operator") {
		t.Fatalf("trial as a reader: %q", e)
	}
}

// serveAPI listens in a temp dir, runs the server's job and dials it as this user; stop ends
// the job and checks the socket is gone with it (Req 1.2).
func serveAPI(t *testing.T, d *daemon) (*apiClient, func()) {
	t.Helper()
	d.cfg.api = filepath.Join(t.TempDir(), "run", "api.sock")
	l, ok := listenAPI(d.cfg.api, func(m string) { t.Error(m) })
	if !ok {
		t.FailNow()
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- d.api.server.Job(l)(ctx) }()
	conn, err := net.Dial("unix", d.cfg.api)
	if err != nil {
		t.Fatal(err)
	}
	return &apiClient{t: t, conn: conn, r: api.NewLineReader(conn)}, func() {
		conn.Close()
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("job ended with %v", err)
		}
		if _, err := os.Stat(d.cfg.api); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("socket after the job: %v", err)
		}
	}
}
