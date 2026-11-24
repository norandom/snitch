// client.go: the client's configuration, Send, and the reconnect job. One session at a time
// (session.go) owns the connection; between sessions the job waits with a backoff and answers
// the requests handed in meanwhile with "the daemon is not running".
//
// Fail-safe implications: a lost daemon is reported once per loss as Down and retried no more
// often than BackoffMin; nothing is retried on the caller's behalf, so a write handed to Send
// is sent at most once.
package client

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
)

// Config is the client's delegates and periods; New requires all of them.
type Config struct {
	Path       string                                                   // /run/snitch/api.sock
	Dial       func(ctx context.Context, path string) (net.Conn, error) // a unix dialer
	Sink       func(Msg)                                                // the loop's inbox; may block
	Log        func(string)                                             // one line each, to stderr
	Now        func() time.Time                                         // the clock for deadlines
	Poll       time.Duration                                            // 5 s: status every Poll
	Gap        time.Duration                                            // 2 s: least time between two status requests
	AnswerWait time.Duration                                            // 10 s: a request unanswered after it has no answer
	BackoffMin time.Duration                                            // 1 s: the first wait before a retry
	BackoffMax time.Duration                                            // 30 s: the longest wait
}

// call is one request handed in by Send with the caller's token.
type call struct {
	token uint64
	req   api.Request
}

// Client is one connection to the daemon, kept alive by its Job. The queue is the only state
// shared with callers; everything about the connection belongs to the job's goroutine.
type Client struct {
	cfg   Config
	mu    sync.Mutex
	queue []call
	kick  chan struct{} // wakes the job when the queue grows
}

// New checks the configuration; a missing delegate or a non-positive period is a bug.
func New(cfg Config) *Client {
	contract.Require(cfg.Path != "", "client: a socket path is required")
	contract.Require(cfg.Dial != nil && cfg.Sink != nil && cfg.Log != nil && cfg.Now != nil,
		"client: Dial, Sink, Log and Now are required")
	contract.Require(cfg.Poll > 0 && cfg.Gap > 0 && cfg.AnswerWait > 0,
		"client: Poll, Gap and AnswerWait must be positive")
	contract.Require(cfg.BackoffMin > 0 && cfg.BackoffMax >= cfg.BackoffMin,
		"client: the backoff needs 0 < BackoffMin <= BackoffMax")
	return &Client{cfg: cfg, kick: make(chan struct{}, 1)}
}

// Send queues one request for the current session; it never blocks, so the loop that owns
// Sink may call it. Exactly one Answered with the same token follows while the job runs: the
// reply's text, the daemon's error, or a local reason when there is no session or no answer.
// The wire id is the client's; snapshot and the subscription verbs are not requests a caller
// may make (the session owns the subscription and never asks for a snapshot).
func (c *Client) Send(token uint64, req api.Request) {
	contract.Require(req.Type != "" && req.Type != "snapshot" && req.Type != "subscribe" &&
		req.Type != "unsubscribe", "client: Send takes a request with one answer, not "+req.Type)
	c.mu.Lock()
	c.queue = append(c.queue, call{token: token, req: req})
	c.mu.Unlock()
	select {
	case c.kick <- struct{}{}:
	default: // a wake-up is already pending
	}
}

// take empties the queue.
func (c *Client) take() []call {
	c.mu.Lock()
	defer c.mu.Unlock()
	q := c.queue
	c.queue = nil
	return q
}

// Job runs sessions until ctx ends, with a backoff between them.
func (c *Client) Job() jobs.Job {
	return func(ctx context.Context) error {
		r := &retry{c: c, wait: c.cfg.BackoffMin}
		for ctx.Err() == nil {
			reason, wasUp := c.session(ctx)
			if ctx.Err() != nil {
				break
			}
			r.lost(reason, wasUp)
			r.pause(ctx)
		}
		return ctx.Err()
	}
}

// retry is the job's state between sessions: the next wait and the last Down sent.
type retry struct {
	c    *Client
	wait time.Duration
	down string // the reason of the Down already sent for this loss, "" after an Up
}

// lost sends Down once per loss: after a session that was up, or when the reason changed
// (a daemon gone, then back but silent, is news for the tooltip). A session that was up
// resets the backoff.
func (r *retry) lost(reason string, wasUp bool) {
	if wasUp {
		r.wait, r.down = r.c.cfg.BackoffMin, ""
	}
	if reason == r.down {
		return
	}
	r.down = reason
	r.c.cfg.Log("daemon: down, " + reason)
	r.c.cfg.Sink(Down{Reason: reason})
}

// pause waits the backoff, answering requests handed in meanwhile, then doubles the wait up
// to the maximum.
func (r *retry) pause(ctx context.Context) {
	t := time.NewTimer(r.wait)
	defer t.Stop()
	r.wait = min(2*r.wait, r.c.cfg.BackoffMax)
	for {
		for _, k := range r.c.take() {
			r.c.cfg.Sink(failed(k.token, noSession))
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			return
		case <-r.c.kick:
		}
	}
}
