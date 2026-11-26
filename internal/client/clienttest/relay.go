package clienttest

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"golang.org/x/sys/unix"
)

const defaultSummaryEvery = 100 * time.Millisecond

type chanListener struct {
	addr net.Addr
	ch   chan net.Conn
	done chan struct{}
	once sync.Once
}

func newChanListener(addr net.Addr) *chanListener {
	return &chanListener{addr: addr, ch: make(chan net.Conn), done: make(chan struct{})}
}

func (l *chanListener) Accept() (net.Conn, error) {
	select {
	case c := <-l.ch:
		return c, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *chanListener) Close() error {
	l.once.Do(func() { close(l.done) })
	return nil
}

func (l *chanListener) Addr() net.Addr { return l.addr }

type relayConn struct {
	client     net.Conn
	server     net.Conn
	wmu        sync.Mutex
	subscribed atomic.Bool
	summary    atomic.Bool
}

func (s *StandIn) addConn(rc *relayConn) {
	s.cmu.Lock()
	s.conns[rc] = struct{}{}
	s.cmu.Unlock()
}

func (s *StandIn) delConn(rc *relayConn) {
	s.cmu.Lock()
	delete(s.conns, rc)
	s.cmu.Unlock()
}

func (s *StandIn) closeConns() {
	s.cmu.Lock()
	for rc := range s.conns {
		_ = rc.client.Close()
		_ = rc.server.Close()
	}
	s.cmu.Unlock()
}

func (s *StandIn) acceptRelay(ctx context.Context, l net.Listener, srvL *chanListener) {
	defer s.rwg.Done()
	go func() {
		<-ctx.Done()
		_ = l.Close()
		_ = srvL.Close()
	}()
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		s.bridgeConn(ctx, c, srvL)
	}
}

func (s *StandIn) bridgeConn(ctx context.Context, clientConn net.Conn, srvL *chanListener) {
	serverEnd, relayEnd, err := unixSocketPair()
	if err != nil {
		_ = clientConn.Close()
		return
	}
	select {
	case srvL.ch <- serverEnd:
	case <-ctx.Done():
		_ = clientConn.Close()
		_ = serverEnd.Close()
		_ = relayEnd.Close()
		return
	}
	rc := &relayConn{client: clientConn, server: relayEnd}
	s.addConn(rc)
	s.rwg.Add(2)
	go s.pumpClient(rc)
	go s.pumpServer(rc)
}

func unixSocketPair() (a, b net.Conn, err error) {
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM, 0)
	if err != nil {
		return nil, nil, err
	}
	f0 := os.NewFile(uintptr(fds[0]), "relay-a")
	f1 := os.NewFile(uintptr(fds[1]), "relay-b")
	defer func() {
		_ = f0.Close()
		_ = f1.Close()
	}()
	a, err = net.FileConn(f0)
	if err != nil {
		return nil, nil, err
	}
	b, err = net.FileConn(f1)
	if err != nil {
		_ = a.Close()
		return nil, nil, err
	}
	return a, b, nil
}

func (s *StandIn) pumpClient(rc *relayConn) {
	defer s.rwg.Done()
	r := bufio.NewReader(rc.client)
	for {
		b, err := r.ReadBytes('\n')
		if len(b) > 0 {
			rc.trackSubs(bytes.TrimSuffix(bytes.TrimSuffix(b, []byte("\n")), []byte("\r")))
			if _, werr := rc.server.Write(b); werr != nil {
				_ = rc.server.Close()
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				if uc, ok := rc.server.(*net.UnixConn); ok {
					_ = uc.CloseWrite()
					return
				}
			}
			_ = rc.server.Close()
			return
		}
	}
}

func (rc *relayConn) trackSubs(line []byte) {
	req, perr := api.Parse(line)
	if perr != nil {
		return
	}
	switch req.Type {
	case "subscribe":
		rc.subscribed.Store(req.Events || req.Local || req.Summary)
		rc.summary.Store(req.Summary)
	case "unsubscribe":
		rc.subscribed.Store(false)
		rc.summary.Store(false)
	}
}

func (s *StandIn) pumpServer(rc *relayConn) {
	defer s.rwg.Done()
	defer func() {
		_ = rc.client.Close()
		_ = rc.server.Close()
		s.delConn(rc)
	}()
	r := bufio.NewReader(rc.server)
	for {
		b, err := r.ReadBytes('\n')
		if len(b) > 0 {
			if !rc.writeLine(b) {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (rc *relayConn) writeLine(b []byte) bool {
	rc.wmu.Lock()
	defer rc.wmu.Unlock()
	_, err := rc.client.Write(b)
	return err == nil
}

func (s *StandIn) summaryLoop(ctx context.Context) {
	defer s.rwg.Done()
	t := time.NewTicker(s.o.SummaryEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.FlushSummary()
		}
	}
}

// FlushSummary runs one summary pass: refreshes snapshot caches and emits a summary line to
// summary subscribers if any entries changed since the last pass.
func (s *StandIn) FlushSummary() {
	s.smu.Lock()
	now := s.o.Now()
	since := s.lastSummary
	entries := s.table.Changed(since)
	s.lastSummary = now
	s.smu.Unlock()
	if len(entries) == 0 {
		return
	}
	b := api.Encode(api.Summary{Type: "summary", Since: since.UTC().Format(time.RFC3339), Entries: entries})
	s.sendTo(b, func(rc *relayConn) bool { return rc.summary.Load() })
}

// Drop sends a dropped line with count to every subscribed client and adds count to the
// reported status drops.
func (s *StandIn) Drop(count int) {
	contract.Require(count > 0, "clienttest: drop count must be positive")
	s.dropped.Add(int64(count))
	b := api.Encode(api.Dropped{Type: "dropped", Count: count})
	s.sendTo(b, func(rc *relayConn) bool { return rc.subscribed.Load() })
}

func (s *StandIn) sendTo(b []byte, want func(*relayConn) bool) {
	s.cmu.Lock()
	var targets []*relayConn
	for rc := range s.conns {
		if want(rc) {
			targets = append(targets, rc)
		}
	}
	s.cmu.Unlock()
	for _, rc := range targets {
		_ = rc.writeLine(b)
	}
}
