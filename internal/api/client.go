// client.go: one connected client's outbound side. Send never blocks: the queue holds Backlog
// marshalled messages, anything beyond is dropped and counted; the writer goroutine reports
// the count as a Dropped line before the next message it gets through and resets it. A write
// slower than the deadline closes the client. Fail-safe: a stuck client costs the daemon one
// queue, never a wait on the event pump or the heartbeat.
package api

import (
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/norandom/snitch/internal/contract"
)

// Client is the outbound queue of one connection; the server owns the inbound side.
type Client struct {
	Role Role

	conn     net.Conn
	deadline time.Duration
	q        chan []byte
	pending  atomic.Int64 // drops not yet reported
	drops    atomic.Int64 // drops over the connection's life (status)
	closing  chan struct{}
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex // guards closed and err
	closed   bool
	err      error
}

// NewClient starts the writer goroutine for conn. deadline bounds each write (WriteDeadline
// in the daemon; tests pass a short one).
func NewClient(conn net.Conn, role Role, deadline time.Duration) *Client {
	contract.Require(conn != nil, "client: nil connection")
	contract.Require(deadline > 0, "client: write deadline must be positive")
	c := &Client{Role: role, conn: conn, deadline: deadline, q: make(chan []byte, Backlog),
		closing: make(chan struct{}), done: make(chan struct{})}
	go c.writeLoop()
	return c
}

// Send queues a marshalled message without blocking. It reports false when the message was
// dropped (queue full or client closed); the drop is counted either way.
func (c *Client) Send(b []byte) bool {
	select {
	case <-c.closing: // checked first: select would otherwise pick a free slot at random
	default:
		select {
		case c.q <- b:
			return true
		default:
		}
	}
	c.pending.Add(1)
	c.drops.Add(1)
	return false
}

// Drops is the number of messages dropped since the client connected.
func (c *Client) Drops() int64 { return c.drops.Load() }

// Done is closed once the writer goroutine has stopped and the connection is closed.
func (c *Client) Done() <-chan struct{} { return c.done }

// Err is the write error that closed the client, nil after Close or while running.
func (c *Client) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.err
}

// Close stops the writer and closes the connection; safe to call more than once.
func (c *Client) Close() {
	c.once.Do(func() {
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		close(c.closing)
		_ = c.conn.Close()
	})
}

func (c *Client) writeLoop() {
	defer close(c.done)
	for {
		select {
		case <-c.closing:
			return
		case b := <-c.q:
			if err := c.write(b); err != nil {
				c.fail(err)
				return
			}
		}
	}
}

// write sends the pending drop report, if any, then the message, each under the deadline.
func (c *Client) write(b []byte) error {
	if n := c.pending.Swap(0); n > 0 {
		if err := c.writeOne(Encode(Dropped{Type: "dropped", Count: int(n)})); err != nil {
			return err
		}
	}
	return c.writeOne(b)
}

func (c *Client) writeOne(b []byte) error {
	if err := c.conn.SetWriteDeadline(time.Now().Add(c.deadline)); err != nil {
		return err
	}
	_, err := c.conn.Write(b)
	return err
}

// fail records a write error unless Close already ran (a write cut by our own close is not
// a failure), then closes.
func (c *Client) fail(err error) {
	c.mu.Lock()
	if !c.closed {
		c.err = err
	}
	c.mu.Unlock()
	c.Close()
}
