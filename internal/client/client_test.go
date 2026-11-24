package client

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/client/clienttest"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// wait bounds every expectation; the durations below are short so the tests stay fast.
const wait = 3 * time.Second

func unixDial(ctx context.Context, path string) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "unix", path)
}

// fast is a Config with short periods: Poll is long unless a test needs polling, so counted
// status replies come only from state and dropped lines.
func fast(path string) Config {
	return Config{Path: path, Dial: unixDial, Sink: func(Msg) {}, Log: func(string) {},
		Now: time.Now, Poll: time.Hour, Gap: 20 * time.Millisecond,
		AnswerWait: 300 * time.Millisecond, BackoffMin: 20 * time.Millisecond,
		BackoffMax: 200 * time.Millisecond}
}

// harness runs one client's job for a test and collects its messages and log lines.
type harness struct {
	t    *testing.T
	c    *Client
	msgs chan Msg
	mu   sync.Mutex
	logs []string
}

func start(t *testing.T, cfg Config) *harness {
	t.Helper()
	h := &harness{t: t, msgs: make(chan Msg, 4096)}
	cfg.Sink = func(m Msg) { h.msgs <- m }
	cfg.Log = func(s string) { h.mu.Lock(); h.logs = append(h.logs, s); h.mu.Unlock() }
	h.c = New(cfg)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- h.c.Job()(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; !errors.Is(err, context.Canceled) {
			t.Errorf("job ended with %v, want context.Canceled", err)
		}
	})
	return h
}

func (h *harness) next() Msg {
	h.t.Helper()
	select {
	case m := <-h.msgs:
		return m
	case <-time.After(wait):
		h.t.Fatalf("no message within %v", wait)
		return nil
	}
}

// quiet asserts that no message arrives for d.
func (h *harness) quiet(d time.Duration) {
	h.t.Helper()
	select {
	case m := <-h.msgs:
		h.t.Fatalf("want no message, got %#v", m)
	case <-time.After(d):
	}
}

// logged counts the log lines containing s.
func (h *harness) logged(s string) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	n := 0
	for _, l := range h.logs {
		if strings.Contains(l, s) {
			n++
		}
	}
	return n
}

// want takes the next message and fails unless it is a T.
func want[T Msg](h *harness) T {
	h.t.Helper()
	m := h.next()
	v, ok := m.(T)
	if !ok {
		var zero T
		h.t.Fatalf("want %T, got %#v", zero, m)
	}
	return v
}

func ruleAdd() api.Request {
	return api.Request{Type: "rule.add", Program: "curl", To: "9.9.9.9/32", Proto: "tcp",
		Port: 443, Verdict: "deny", Note: "tray test"}
}

// Answers against the stand-in: the daemon's sentence, its error, its operator refusal.
func TestAnswerRuleAddAsTheOperator(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	h := start(t, fast(s.Path()))
	want[Up](h)
	want[Facts](h)
	h.c.Send(7, ruleAdd())
	a := want[Answered](h)
	if a.Token != 7 || a.Err != "" || a.Role || a.Text != clienttest.Sentence(ruleAdd()) {
		t.Fatalf("answer: %#v", a)
	}
	if e := s.Edits(); len(e) != 1 || e[0].To != "9.9.9.9/32" {
		t.Fatalf("edits: %#v", e)
	}
}

func TestAnswerRuleAddRefusedByTheDaemon(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	h := start(t, fast(s.Path()))
	want[Up](h)
	want[Facts](h)
	s.Refuse(true)
	h.c.Send(8, ruleAdd())
	a := want[Answered](h)
	if a.Token != 8 || a.Err != "rule.add: refused by the stand-in" || a.Role || a.Text != "" {
		t.Fatalf("refused answer: %#v", a)
	}
}

func TestAnswerWriteAsAReaderCarriesTheRoleMark(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always the operator")
	}
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid()) + 1})
	h := start(t, fast(s.Path()))
	want[Up](h)
	want[Facts](h)
	h.c.Send(3, ruleAdd())
	a := want[Answered](h)
	if a.Token != 3 || !a.Role || a.Err != "rule.add: write requires the operator" || a.Text != "" {
		t.Fatalf("answer: %#v", a)
	}
	if len(s.Edits()) != 0 {
		t.Fatalf("a reader's edit was recorded: %#v", s.Edits())
	}
}

func TestAnswerWithoutASession(t *testing.T) {
	cfg := fast("/nonexistent/api.sock")
	h := start(t, cfg)
	if d := want[Down](h); d.Reason != NotRunning {
		t.Fatalf("down: %#v", d)
	}
	h.c.Send(11, ruleAdd())
	if a := want[Answered](h); a.Token != 11 || a.Err != noSession || a.Role {
		t.Fatalf("answer: %#v", a)
	}
	h.quiet(300 * time.Millisecond) // failed redials send no second Down
}

// dials records the time of every dial attempt.
type dials struct {
	mu sync.Mutex
	at []time.Time
}

func (d *dials) dial(ctx context.Context, path string) (net.Conn, error) {
	d.mu.Lock()
	d.at = append(d.at, time.Now())
	d.mu.Unlock()
	return unixDial(ctx, path)
}

// gaps are the intervals between the dials in [from, to].
func (d *dials) gaps(from, to time.Time) []time.Duration {
	d.mu.Lock()
	defer d.mu.Unlock()
	var g []time.Duration
	for i := 1; i < len(d.at); i++ {
		if d.at[i-1].After(from) && d.at[i].Before(to) {
			g = append(g, d.at[i].Sub(d.at[i-1]))
		}
	}
	return g
}

func TestReconnectAcrossAStopWithinTheBackoffBounds(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{})
	cfg, d := fast(s.Path()), &dials{}
	cfg.Dial = d.dial
	h := start(t, cfg)
	want[Up](h)
	want[Facts](h)
	s.Stop()
	stopped := time.Now()
	if dn := want[Down](h); dn.Reason != NotRunning {
		t.Fatalf("down: %#v", dn)
	}
	h.quiet(700 * time.Millisecond) // the backoff climbs to its maximum; one Down only
	if err := s.Serve(); err != nil {
		t.Fatal(err)
	}
	served := time.Now()
	want[Up](h)
	if late := time.Since(served); late > cfg.BackoffMax+150*time.Millisecond {
		t.Fatalf("up %v after the daemon came back, backoff max %v", late, cfg.BackoffMax)
	}
	want[Facts](h)
	checkGaps(t, d.gaps(stopped, served), cfg)
}

// checkGaps: every retry waits at least the minimum and at most the maximum, and the waits
// grow to the maximum.
func checkGaps(t *testing.T, g []time.Duration, cfg Config) {
	t.Helper()
	const slack = 60 * time.Millisecond
	if len(g) < 4 {
		t.Fatalf("too few retries: %v", g)
	}
	longest := time.Duration(0)
	for _, x := range g {
		if x < cfg.BackoffMin-5*time.Millisecond || x > cfg.BackoffMax+slack {
			t.Fatalf("retry gap %v outside [%v, %v]: %v", x, cfg.BackoffMin, cfg.BackoffMax, g)
		}
		longest = max(longest, x)
	}
	if longest < cfg.BackoffMax-5*time.Millisecond {
		t.Fatalf("the backoff never reached its maximum: %v", g)
	}
}

func TestReconnectAfterARestartResetsTheBackoff(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{})
	cfg := fast(s.Path())
	h := start(t, cfg)
	want[Up](h)
	want[Facts](h)
	for range 5 { // without the reset the waits would grow 20, 40, 80, 160 ms
		if err := s.Restart(); err != nil {
			t.Fatal(err)
		}
		down := time.Now()
		if dn := want[Down](h); dn.Reason != NotRunning {
			t.Fatalf("down: %#v", dn)
		}
		if up := want[Up](h); time.Since(down) > cfg.BackoffMax-50*time.Millisecond {
			t.Fatalf("%#v %v after the loss: the backoff was not reset", up, time.Since(down))
		}
		want[Facts](h)
	}
}

// Every delegate and duration is required.
func TestContractNewRequiresEveryDelegateAndDuration(t *testing.T) {
	cases := map[string]func(*Config){
		"path": func(c *Config) { c.Path = "" }, "dial": func(c *Config) { c.Dial = nil },
		"sink": func(c *Config) { c.Sink = nil }, "log": func(c *Config) { c.Log = nil },
		"now": func(c *Config) { c.Now = nil }, "poll": func(c *Config) { c.Poll = 0 },
		"gap": func(c *Config) { c.Gap = 0 }, "wait": func(c *Config) { c.AnswerWait = -1 },
		"min": func(c *Config) { c.BackoffMin = 0 },
		"max": func(c *Config) { c.BackoffMax = c.BackoffMin - 1 },
	}
	for name, edit := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := fast("/run/snitch/api.sock")
			edit(&cfg)
			contracttest.Panics(t, contract.Precondition, func() { New(cfg) })
		})
	}
}

// The session owns the subscription and never asks for a snapshot; a request without a type
// has no answer to wait for.
func TestContractSendTakesOnlyRequestsWithOneAnswer(t *testing.T) {
	c := New(fast("/run/snitch/api.sock"))
	for _, typ := range []string{"", "snapshot", "subscribe", "unsubscribe"} {
		contracttest.Panics(t, contract.Precondition, func() { c.Send(1, api.Request{Type: typ}) })
	}
}
