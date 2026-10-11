package api

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// fillQueue emits fresh events to a subscriber that never reads until one is dropped: the
// socket buffer and the writer absorb a few hundred before the queue of Backlog fills.
func fillQueue(t *testing.T, f *fixture) {
	t.Helper()
	for i := 0; i < 4*Backlog; i++ {
		f.s.Emit(f.event(fmt.Sprintf("8.%d.%d.1", i/256, i%256), "allow-rule"))
		if f.s.Dropped() > 0 {
			return
		}
	}
	t.Fatal("the queue never filled")
}

// Design "Contracts", Req 1.6, 6.3: with a subscriber's queue full (it never reads) Emit
// still returns in under a millisecond, and the drops are counted.
func TestEmitNeverBlocks(t *testing.T) {
	f := newFixture(t)
	f.listen(nil)
	p := f.dial()
	p.subscribe("")
	fillQueue(t, f)
	var worst time.Duration
	for i := 0; i < 20; i++ {
		start := time.Now()
		f.s.Emit(f.event(fmt.Sprintf("9.9.9.%d", i), "allow-rule"))
		worst = max(worst, time.Since(start))
	}
	if worst >= time.Millisecond {
		t.Fatalf("Emit took %v with a full queue", worst)
	}
	if f.s.Clients() != 1 {
		t.Fatalf("clients: %d", f.s.Clients())
	}
}

// Design "Contracts": a client hammering snapshot never parks the pump: Observe (through
// Emit) stays under 1 ms at p99 over 1000 calls.
func TestObserveUnderSnapshotStorm(t *testing.T) {
	f := newFixture(t)
	f.listen(nil)
	for i := 0; i < 50; i++ {
		f.s.Emit(f.event(fmt.Sprintf("7.7.7.%d", i), "allow-rule"))
	}
	_ = f.s.tick(nil)
	conn, err := net.Dial("unix", f.path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var stop atomic.Bool
	done := make(chan struct{})
	go func() {
		defer close(done)
		r := bufio.NewReader(conn)
		for !stop.Load() {
			if _, err := conn.Write([]byte(`{"type":"snapshot","id":1,"window":"7d"}` + "\n")); err != nil {
				return
			}
			if _, err := r.ReadString('\n'); err != nil {
				return
			}
		}
	}()
	var p99, worst time.Duration
	for attempt := 0; attempt < 3; attempt++ { // a loaded box preempts; contention never clears
		p99, worst = observeP99(f, attempt)
		if p99 < time.Millisecond {
			break
		}
	}
	stop.Store(true)
	<-done
	if p99 >= time.Millisecond {
		t.Fatalf("Observe p99 %v under the snapshot storm (max %v)", p99, worst)
	}
}

// observeP99 times 1000 fresh Emits (Observe is their cost without subscribers) and returns
// the 99th percentile and the worst.
func observeP99(f *fixture, attempt int) (p99, worst time.Duration) {
	var took []time.Duration
	for i := 0; i < 1000; i++ {
		start := time.Now()
		f.s.Emit(f.event(fmt.Sprintf("6.%d.%d.%d", attempt, i/256, i%256), "allow-rule"))
		took = append(took, time.Since(start))
	}
	slices.Sort(took)
	return took[990], took[999]
}

// flaky fails the next n accepts with a transient error, then accepts normally.
type flaky struct {
	net.Listener
	fails atomic.Int32
}

func (l *flaky) Accept() (net.Conn, error) {
	if l.fails.Add(-1) >= 0 {
		return nil, errors.New("accept: too many open files")
	}
	return l.Listener.Accept()
}

// Design "Contracts": an accept error other than the close is logged once per streak and
// retried after 100 ms; the job keeps serving.
func TestAcceptErrorDoesNotEndJob(t *testing.T) {
	f := newFixture(t)
	fl := &flaky{}
	fl.fails.Store(3)
	f.listen(func(l net.Listener) net.Listener { fl.Listener = l; return fl })
	start := time.Now()
	p := f.dial()
	statusOk(t, p)
	if since := time.Since(start); since < 250*time.Millisecond {
		t.Fatalf("served after %v: the retry did not wait", since)
	}
	var logged int
	for _, l := range f.lines(&f.log) {
		if strings.Contains(l, "too many open files") {
			logged++
		}
	}
	if logged != 1 {
		t.Fatalf("want the error streak logged once, got %d: %v", logged, f.lines(&f.log))
	}
}

// Design "Server": the 65th connection gets one error line and is closed; when a client
// leaves, its drops are kept in the total and its slot is free again (Req 1.5).
func TestServerMaxClientsRefused(t *testing.T) {
	f := newFixture(t)
	f.listen(nil)
	peers := make([]*peer, 0, MaxClients)
	for i := 0; i < MaxClients; i++ {
		p := f.dial()
		statusOk(t, p)
		peers = append(peers, p)
	}
	extra := f.dial()
	if e := extra.errorOf(extra.line()); e.Id != 0 || !strings.Contains(e.Error, "too many clients") {
		t.Fatalf("65th: %+v", e)
	}
	extra.eof()
	if f.s.Clients() != MaxClients {
		t.Fatalf("clients: %d", f.s.Clients())
	}
	_ = peers[0].Close()
	for f.s.Clients() == MaxClients {
		time.Sleep(time.Millisecond)
	}
	statusOk(t, f.dial())
	if f.s.Clients() != MaxClients {
		t.Fatalf("clients after a leave and a join: %d", f.s.Clients())
	}
}

// A client's drops survive its leaving in the server's total.
func TestServerDroppedOutlivesTheClient(t *testing.T) {
	f := newFixture(t)
	f.listen(nil)
	p := f.dial()
	p.subscribe("")
	fillQueue(t, f)
	before := f.s.Dropped()
	_ = p.Close()
	for f.s.Clients() != 0 {
		time.Sleep(time.Millisecond)
	}
	if f.s.Dropped() != before {
		t.Fatalf("dropped %d after the leave, want %d", f.s.Dropped(), before)
	}
}
