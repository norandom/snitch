// Package verbs implements the non-interactive CLI subcommands (status and default)
// and the status-bar line formatter.
//
// oneshot.go provides Ask, a bounded one-shot request/reply exchange over the daemon's
// unix socket that checks peer credentials before writing anything.
//
// Fail-safe implications: none on kernel egress. Ask enforces the caller's deadline on
// both dialing and socket I/O so status checks never hang, and refuses to write through
// a socket not owned by root (requirement 13.8).
package verbs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
)

// Dial opens a connection to the daemon's unix socket under ctx.
type Dial func(context.Context) (net.Conn, error)

// Peer reports the socket peer's uid when known (ok true).
type Peer func(net.Conn) (uid uint32, ok bool)

type daemonError struct {
	msg string
}

func (e daemonError) Error() string {
	if e.msg == "" {
		return "daemon returned error"
	}
	return e.msg
}

// Ask dials the daemon, verifies that any known peer belongs to root, sends reqs with
// sequential wire ids, and reads as many replies before ctx ends.
func Ask(ctx context.Context, dial Dial, peer Peer, reqs ...api.Request) ([]api.Reply, error) {
	contract.Require(ctx != nil && dial != nil, "verbs.Ask: context and dialer are required")
	if len(reqs) == 0 {
		return nil, nil
	}
	conn, err := dialWithContext(ctx, dial)
	if err != nil {
		return nil, askErr(ctx, err)
	}
	var closeOnce sync.Once
	closeConn := func() { closeOnce.Do(func() { _ = conn.Close() }) }
	defer closeConn()

	if err := checkRootPeer(conn, peer); err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}
	done := make(chan struct{})
	defer close(done)
	go watchContext(ctx, done, closeConn)

	return exchange(ctx, conn, closeConn, reqs)
}

func checkRootPeer(conn net.Conn, peer Peer) error {
	if peer == nil {
		return nil
	}
	if uid, ok := peer(conn); ok && uid != 0 {
		return fmt.Errorf("socket belongs to uid %d, not root", uid)
	}
	return nil
}

func watchContext(ctx context.Context, done <-chan struct{}, closeConn func()) {
	select {
	case <-ctx.Done():
		closeConn()
	case <-done:
	}
}

func dialWithContext(ctx context.Context, dial Dial) (net.Conn, error) {
	type result struct {
		conn net.Conn
		err  error
	}
	var mu sync.Mutex
	abandoned := false
	ch := make(chan result, 1)
	go func() {
		c, err := dial(ctx)
		mu.Lock()
		if abandoned {
			mu.Unlock()
			if c != nil {
				_ = c.Close()
			}
			return
		}
		mu.Unlock()
		ch <- result{c, err}
	}()
	select {
	case res := <-ch:
		return res.conn, res.err
	case <-ctx.Done():
		mu.Lock()
		abandoned = true
		mu.Unlock()
		select {
		case res := <-ch:
			if res.conn != nil {
				_ = res.conn.Close()
			}
		default:
		}
		return nil, ctx.Err()
	}
}

func exchange(ctx context.Context, conn net.Conn, closeConn func(), reqs []api.Request) ([]api.Reply, error) {
	var wg sync.WaitGroup
	var werr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := writeRequests(conn, reqs); err != nil {
			werr = err
			closeConn()
		}
	}()
	replies, rerr := readReplies(conn, len(reqs))
	closeConn()
	wg.Wait()

	if err := pickExchangeErr(ctx, rerr, werr); err != nil {
		return nil, err
	}
	return replies, nil
}

func pickExchangeErr(ctx context.Context, rerr, werr error) error {
	var derr daemonError
	if errors.As(rerr, &derr) {
		return rerr
	}
	if rerr != nil || werr != nil {
		if ctx.Err() != nil {
			return askErr(ctx, ctx.Err())
		}
		if werr != nil {
			return askErr(ctx, werr)
		}
		return askErr(ctx, rerr)
	}
	return nil
}

func writeRequests(conn net.Conn, reqs []api.Request) error {
	for i, req := range reqs {
		req.Id = i + 1
		if _, err := conn.Write(api.Encode(req)); err != nil {
			return err
		}
	}
	return nil
}

func readReplies(conn net.Conn, want int) ([]api.Reply, error) {
	lr := api.NewReplyReader(conn)
	out := make([]api.Reply, want)
	seen := make([]bool, want)
	for left := want; left > 0; {
		line, err := lr.ReadLine()
		if err != nil {
			if errors.Is(err, api.ErrLineTooLong) {
				continue
			}
			return nil, err
		}
		done, err := handleReplyLine(line, out, seen)
		if err != nil {
			return nil, err
		}
		if done {
			left--
		}
	}
	return out, nil
}

func handleReplyLine(line []byte, out []api.Reply, seen []bool) (bool, error) {
	var env struct {
		Type string `json:"type"`
		Id   int    `json:"id"`
	}
	if err := json.Unmarshal(line, &env); err != nil {
		return false, fmt.Errorf("bad daemon line: %w", err)
	}
	switch env.Type {
	case "error":
		var e api.Error
		if err := json.Unmarshal(line, &e); err != nil {
			return false, fmt.Errorf("bad daemon error: %w", err)
		}
		return false, daemonError{msg: e.Error}
	case "reply":
		var rep api.Reply
		if err := json.Unmarshal(line, &rep); err != nil {
			return false, fmt.Errorf("bad daemon reply: %w", err)
		}
		if rep.Id >= 1 && rep.Id <= len(out) && !seen[rep.Id-1] {
			out[rep.Id-1] = rep
			seen[rep.Id-1] = true
			return true, nil
		}
	}
	return false, nil
}

func askErr(ctx context.Context, err error) error {
	if errors.Is(ctx.Err(), context.DeadlineExceeded) || errors.Is(err, os.ErrDeadlineExceeded) {
		if errors.Is(err, context.DeadlineExceeded) {
			return fmt.Errorf("daemon does not answer: %w", err)
		}
		if ctx.Err() != nil {
			return fmt.Errorf("daemon does not answer: %w", ctx.Err())
		}
		return fmt.Errorf("daemon does not answer: %w", context.DeadlineExceeded)
	}
	if ctx.Err() != nil {
		return ctx.Err()
	}
	return err
}
