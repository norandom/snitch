// session.go: one connection to the daemon, from dial to loss. The session goroutine owns the
// connection's state (next id, the subscribe and status in flight, the callers' requests by
// id with their deadlines) and is the only writer; one reader goroutine turns the socket into
// lines. A single timer wakes the session for polls, the status gap and every deadline, so a
// blocking Sink delays answers but never strands a timer or the reader.
//
// Fail-safe implications: the session only reads the daemon's state and sends what Send was
// given. A daemon that accepts and stays silent ends the session as "not answering" instead
// of leaving the tray showing stale facts.
package client

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/norandom/snitch/internal/api"
)

// subscribe is written literally: api.Request cannot marshal a false option, and the
// daemon's default for summary is true.
const subscribe = `{"type":"subscribe","id":%d,"events":true,"local":false,"summary":%t}` + "\n"

// line is what the reader hands over: a line, or the error that ended (or, for an over-long
// line, interrupted) the stream.
type line struct {
	b   []byte
	err error
}

// pending is a caller's request on the wire.
type pending struct {
	token uint64
	due   time.Time
}

type session struct {
	cfg       Config
	c         *Client
	conn      net.Conn
	lines     chan line
	done      chan struct{}
	wg        sync.WaitGroup
	id        int             // the last wire id used
	up        bool            // the subscription was answered
	sub       int             // the subscribe's id until it is answered, then 0
	status    int             // the status request in flight, 0 when none
	due       time.Time       // when an unanswered subscribe or status means not answering
	sentAt    time.Time       // when the last status was sent
	poll      time.Time       // when the next poll is due
	want      bool            // a status is wanted (poll, state line, dropped)
	calls     map[int]pending // the callers' requests by wire id
	noisy     bool            // the first line not understood was logged
	peerUID   uint32
	peerKnown bool
}

// session dials and runs one session; it reports why it ended and whether it was up.
func (c *Client) session(ctx context.Context) (reason string, up bool) {
	dctx, cancel := context.WithTimeout(ctx, c.cfg.AnswerWait)
	conn, err := c.cfg.Dial(dctx, c.cfg.Path)
	cancel()
	if err != nil {
		return NotRunning, false
	}
	var peerUID uint32
	var peerKnown bool
	if c.cfg.Peer != nil {
		peerUID, peerKnown = c.cfg.Peer(conn)
	}
	s := &session{cfg: c.cfg, c: c, conn: conn, lines: make(chan line),
		done: make(chan struct{}), calls: map[int]pending{},
		peerUID: peerUID, peerKnown: peerKnown}
	s.wg.Go(s.read)
	reason = s.run(ctx)
	s.close(ctx)
	return reason, s.up
}

// read hands lines over until the stream ends or the session does.
func (s *session) read() {
	r := api.NewReplyReader(s.conn)
	for {
		b, err := r.ReadLine()
		select {
		case s.lines <- line{b: b, err: err}:
		case <-s.done:
			return
		}
		if err != nil && !errors.Is(err, api.ErrLineTooLong) {
			return
		}
	}
}

// close ends the reader and answers the callers' requests still on the wire: whether the
// daemon acted on them is unknown. At shutdown nobody is listening, so nothing is sent.
func (s *session) close(ctx context.Context) {
	close(s.done)
	_ = s.conn.Close()
	s.wg.Wait()
	if ctx.Err() != nil {
		return
	}
	for _, id := range slices.Sorted(maps.Keys(s.calls)) {
		s.cfg.Sink(failed(s.calls[id].token, NoAnswer))
	}
}

// run subscribes, asks for the first status and follows the connection until it is lost.
func (s *session) run(ctx context.Context) string {
	now := s.cfg.Now()
	s.id, s.sub, s.poll = 1, 1, now.Add(s.cfg.Poll)
	if s.write([]byte(fmt.Sprintf(subscribe, s.id, s.cfg.Table))) != nil || s.ask(now) != nil {
		return NotRunning
	}
	wake := time.NewTimer(0) // the first tick sends what was handed in during the dial
	defer wake.Stop()
	for {
		reason := ""
		select {
		case <-ctx.Done():
			return ""
		case l := <-s.lines:
			reason = s.line(l)
		case <-s.c.kick:
		case <-wake.C:
		}
		if reason == "" {
			reason = s.tick(s.cfg.Now())
		}
		if reason != "" {
			return reason
		}
		wake.Reset(s.next().Sub(s.cfg.Now()))
	}
}

// tick applies the clock: deadlines, the poll, requests handed in, a wanted status.
func (s *session) tick(now time.Time) string {
	if (s.sub != 0 || s.status != 0) && !now.Before(s.due) {
		return NotAnswering
	}
	s.expire(now)
	if !now.Before(s.poll) {
		s.want, s.poll = true, now.Add(s.cfg.Poll)
	}
	if s.flush(now) != nil {
		return NotRunning
	}
	if s.want && s.status == 0 && now.Sub(s.sentAt) >= s.cfg.Gap && s.ask(now) != nil {
		return NotRunning
	}
	return ""
}

// expire answers the callers' requests past their wait; the session stays.
func (s *session) expire(now time.Time) {
	for _, id := range slices.Sorted(maps.Keys(s.calls)) {
		if p := s.calls[id]; !now.Before(p.due) {
			delete(s.calls, id)
			s.cfg.Sink(failed(p.token, NoAnswer))
		}
	}
}

// next is the earliest moment tick has something to do.
func (s *session) next() time.Time {
	t := s.poll
	if s.sub != 0 || s.status != 0 {
		t = earlier(t, s.due)
	}
	if s.want && s.status == 0 {
		t = earlier(t, s.sentAt.Add(s.cfg.Gap))
	}
	for _, p := range s.calls {
		t = earlier(t, p.due)
	}
	return t
}

func earlier(a, b time.Time) time.Time {
	if b.Before(a) {
		return b
	}
	return a
}

// ask sends a status request; at most one is in flight.
func (s *session) ask(now time.Time) error {
	s.id++
	s.status, s.sentAt, s.due, s.want = s.id, now, now.Add(s.cfg.AnswerWait), false
	return s.write(api.Encode(api.Request{Type: "status", Id: s.id}))
}

// flush puts the requests handed in on the wire. Each is registered before the writes, so a
// failed write still leaves every one of them to be answered when the session closes.
func (s *session) flush(now time.Time) error {
	q := s.c.take()
	ids := make([]int, len(q))
	for i, k := range q {
		s.id++
		ids[i], s.calls[s.id] = s.id, pending{token: k.token, due: now.Add(s.cfg.AnswerWait)}
	}
	for i, k := range q {
		k.req.Id = ids[i]
		if err := s.write(api.Encode(k.req)); err != nil {
			return err
		}
	}
	return nil
}

// write sends one line; a daemon that does not take it within the wait is as good as gone.
func (s *session) write(b []byte) error {
	_ = s.conn.SetWriteDeadline(time.Now().Add(s.cfg.AnswerWait)) // the OS clock: a socket deadline is real time, not the injected one
	_, err := s.conn.Write(b)
	return err
}

// line handles what the reader handed over; a read error ends the session.
func (s *session) line(l line) string {
	if errors.Is(l.err, api.ErrLineTooLong) {
		s.ignored(l.err.Error())
		return ""
	}
	if l.err != nil {
		return NotRunning
	}
	return s.handle(l.b)
}

// ignored logs the first line per session that was not understood (4.8).
func (s *session) ignored(why string) {
	if s.noisy {
		return
	}
	s.noisy = true
	s.cfg.Log("daemon: ignored a line it could not understand (" + why +
		"); further ones in this session are dropped silently")
}
