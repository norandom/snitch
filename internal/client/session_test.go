package client

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/client/clienttest"
)

// subscribeLine is the literal subscribe request of a session's first line (design "client").
const subscribeLine = `{"type":"subscribe","id":1,"events":true,"local":false,"summary":false}`

func TestSessionUpThenFactsThenEvents(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{})
	h := start(t, fast(s.Path()))
	want[Up](h)
	if f := want[Facts](h); f.Status.Version != "fake" || f.Status.Mode != "monitor" {
		t.Fatalf("facts: %#v", f)
	}
	s.Emit(api.Event{Program: "curl", Path: "/usr/bin/curl", Pid: 7, Comm: "curl",
		Addr: "9.9.9.9", Port: 443, Protocol: "tcp", Verdict: "deny-default", Hook: "connect"})
	if e := want[EventLine](h); e.Event.Program != "curl" || e.Event.Verdict != "deny-default" {
		t.Fatalf("event: %#v", e)
	}
}

func TestSessionOneStatusPerStateLine(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{})
	h := start(t, fast(s.Path()))
	want[Up](h)
	want[Facts](h)
	s.SetKill(true) // no state line: no status, the poll is an hour away
	h.quiet(200 * time.Millisecond)
	s.SetMode("enforce")
	if st := want[StateLine](h); st.State.Mode != "enforce" {
		t.Fatalf("state: %#v", st)
	}
	if f := want[Facts](h); f.Status.Mode != "enforce" || !f.Status.Kill {
		t.Fatalf("facts after the state line: %#v", f)
	}
	h.quiet(200 * time.Millisecond)
	s.StartTrial(time.Hour)
	want[StateLine](h)
	if f := want[Facts](h); f.Status.Trial == "" {
		t.Fatalf("facts after the trial: %#v", f)
	}
	h.quiet(200 * time.Millisecond)
}

func TestSessionPollsTheStatus(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{})
	cfg := fast(s.Path())
	cfg.Poll = 100 * time.Millisecond
	h := start(t, cfg)
	want[Up](h)
	want[Facts](h)
	s.SetLearning(true) // no state line: only the poll shows it
	for {
		if f := want[Facts](h); f.Status.Learning {
			return
		}
	}
}

// rawServer is a scripted listener for what the real server cannot be made to do.
type rawServer struct {
	t     *testing.T
	path  string
	conns chan *rawConn
}

type rawConn struct {
	t *testing.T
	net.Conn
	r *bufio.Reader
}

// request is a line the client sent, with its exact text.
type request struct {
	api.Request
	text string
}

func listen(t *testing.T) *rawServer {
	t.Helper()
	path := filepath.Join(t.TempDir(), "raw.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	rs := &rawServer{t: t, path: path, conns: make(chan *rawConn, 16)}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
			rs.conns <- &rawConn{t: t, Conn: c, r: bufio.NewReader(c)}
		}
	}()
	return rs
}

func (rs *rawServer) accept() *rawConn {
	rs.t.Helper()
	select {
	case c := <-rs.conns:
		return c
	case <-time.After(wait):
		rs.t.Fatal("no connection")
		return nil
	}
}

// read is the client's next line within d; ok is false when none came.
func (c *rawConn) read(d time.Duration) (request, bool) {
	c.t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(d))
	b, err := c.r.ReadBytes('\n')
	if err != nil {
		return request{}, false
	}
	var r request
	if err := json.Unmarshal(b, &r.Request); err != nil {
		c.t.Fatalf("the client sent %q: %v", b, err)
	}
	if r.Type == "snapshot" {
		c.t.Fatal("the client requested a snapshot")
	}
	r.text = string(b[:len(b)-1])
	return r, true
}

func (c *rawConn) must() request {
	c.t.Helper()
	r, ok := c.read(wait)
	if !ok {
		c.t.Fatal("the client sent nothing")
	}
	return r
}

func (c *rawConn) send(format string, args ...any) {
	c.t.Helper()
	if _, err := fmt.Fprintf(c, format+"\n", args...); err != nil {
		c.t.Fatal(err)
	}
}

func (c *rawConn) status(id int) {
	c.send(`{"type":"reply","id":%d,"ok":true,"status":{"running":true,"version":"raw","mode":"monitor"}}`, id)
}

// handshake checks the session's first two lines and answers them.
func (c *rawConn) handshake() {
	c.t.Helper()
	if sub := c.must(); sub.text != subscribeLine {
		c.t.Fatalf("first line %q, want %q", sub.text, subscribeLine)
	}
	st := c.must()
	if st.Type != "status" {
		c.t.Fatalf("second line: %q", st.text)
	}
	c.send(`{"type":"reply","id":1,"ok":true}`)
	c.status(st.Id)
}

func TestSessionNotAnsweringWhenTheDaemonStaysSilent(t *testing.T) {
	rs := listen(t)
	h := start(t, fast(rs.path))
	rs.accept() // accepted, never answered
	at := time.Now()
	if d := want[Down](h); d.Reason != NotAnswering {
		t.Fatalf("down: %#v", d)
	}
	if took := time.Since(at); took < 250*time.Millisecond {
		t.Fatalf("not answering after %v, the wait is 300 ms", took)
	}
	rs.accept() // the retry: silent again, and no second Down for the same loss
	h.quiet(500 * time.Millisecond)
}

func TestDroppedLineAsksForOneStatus(t *testing.T) {
	rs := listen(t)
	cfg := fast(rs.path)
	cfg.Gap = 200 * time.Millisecond
	h := start(t, cfg)
	c := rs.accept()
	c.handshake()
	answered := time.Now()
	want[Up](h)
	want[Facts](h)
	c.send(`{"type":"dropped","id":0,"count":17}`)
	c.send(`{"type":"dropped","id":0,"count":3}`)
	st := c.must()
	if st.Type != "status" || time.Since(answered) < 180*time.Millisecond {
		t.Fatalf("%q %v after the last status; the gap is 200 ms", st.text, time.Since(answered))
	}
	c.status(st.Id)
	want[Facts](h)
	if r, ok := c.read(500 * time.Millisecond); ok {
		t.Fatalf("a second request after the dropped lines: %q", r.text)
	}
}

func TestGarbageLineIgnoredAndLoggedOncePerSession(t *testing.T) {
	rs := listen(t)
	h := start(t, fast(rs.path))
	for session := 1; session <= 2; session++ {
		c := rs.accept()
		c.handshake()
		want[Up](h)
		want[Facts](h)
		c.send(`this is not json`)
		c.send(`{"type":"surprise","id":0}`)
		c.send(`{"type":"event","id":0,"time":"not a time"}`)
		c.send(`{"type":"state","id":0,"mode":"enforce","trial":"","kept":false,"rulesChanged":false,"reason":"r"}`)
		if st := want[StateLine](h); st.State.Mode != "enforce" {
			t.Fatalf("state: %#v", st)
		}
		if n := h.logged("ignored"); n != session {
			t.Fatalf("session %d: %d log lines about ignored lines, want %d", session, n, session)
		}
		_ = c.Close()
		if d := want[Down](h); d.Reason != NotRunning {
			t.Fatalf("down: %#v", d)
		}
	}
}

func TestAnswerTimesOutAndTheSessionStays(t *testing.T) {
	rs := listen(t)
	h := start(t, fast(rs.path))
	c := rs.accept()
	c.handshake()
	want[Up](h)
	want[Facts](h)
	h.c.Send(5, ruleAdd())
	if r := c.must(); r.Type != "rule.add" || r.To != "9.9.9.9/32" || r.Note != "tray test" {
		t.Fatalf("request: %q", r.text)
	}
	sent := time.Now()
	if a := want[Answered](h); a.Token != 5 || a.Err != NoAnswer || a.Role {
		t.Fatalf("answer: %#v", a)
	}
	if took := time.Since(sent); took < 250*time.Millisecond {
		t.Fatalf("no answer after only %v", took)
	}
	c.send(`{"type":"state","id":0,"mode":"monitor","trial":"","kept":false,"rulesChanged":true,"reason":"rules reloaded"}`)
	want[StateLine](h) // still up: no Down came first
}

func TestAnswerPendingAtALossIsAnswered(t *testing.T) {
	rs := listen(t)
	h := start(t, fast(rs.path))
	c := rs.accept()
	c.handshake()
	want[Up](h)
	want[Facts](h)
	h.c.Send(6, ruleAdd())
	c.must()
	_ = c.Close()
	a, d := h.next(), h.next()
	if a != (Answered{Token: 6, Err: NoAnswer}) || d != (Down{Reason: NotRunning}) {
		t.Fatalf("after the loss: %#v, %#v", a, d)
	}
}
