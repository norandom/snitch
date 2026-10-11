package api

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"
)

func msg(i int) []byte { return Encode(Reply{Type: "reply", Id: i, Ok: true}) }

// fill sends Backlog+1+extra messages to a client nobody reads and returns the counts.
func fill(c *Client, extra int) (sent, dropped int) {
	for i := 1; i <= Backlog+1+extra; i++ {
		if c.Send(msg(i)) {
			sent++
		} else {
			dropped++
		}
	}
	return sent, dropped
}

// readUntil scans lines until n replies were seen or the deadline cuts the pipe; lost
// messages fail fast instead of hanging the test.
func readUntil(t *testing.T, conn net.Conn, n int) []string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	sc := bufio.NewScanner(conn)
	var lines []string
	for replies := 0; replies < n && sc.Scan(); {
		lines = append(lines, sc.Text())
		if !strings.Contains(sc.Text(), `"dropped"`) {
			replies++
		}
	}
	return lines
}

// splitReports separates the dropped reports from the replies, checking each report's
// shape and place: id 0, a positive count, followed by a reply (never adjacent, never last).
func splitReports(t *testing.T, lines []string) (replies []string, reported int) {
	t.Helper()
	for i, line := range lines {
		if !strings.Contains(line, `"dropped"`) {
			replies = append(replies, line)
			continue
		}
		var d Dropped
		if err := json.Unmarshal([]byte(line), &d); err != nil || d.Type != "dropped" || d.Id != 0 || d.Count <= 0 {
			t.Fatalf("line %d %q is not a dropped report: %+v %v", i, line, d, err)
		}
		if i+1 >= len(lines) || strings.Contains(lines[i+1], `"dropped"`) {
			t.Fatalf("line %d: a dropped report must precede a reply", i)
		}
		reported += d.Count
	}
	return replies, reported
}

// repliesInOrder asserts lines are replies with strictly increasing ids, the first being 1.
func repliesInOrder(t *testing.T, lines []string) {
	t.Helper()
	last := 0
	for i, line := range lines {
		var r Reply
		if err := json.Unmarshal([]byte(line), &r); err != nil || r.Type != "reply" || r.Id <= last {
			t.Fatalf("line %d %q out of order after id %d: %v", i, line, last, err)
		}
		last = r.Id
	}
	if len(lines) > 0 && lines[0] != strings.TrimSpace(string(msg(1))) {
		t.Fatalf("first delivered message %q is not msg(1)", lines[0])
	}
}

// Req 1.6: a client that does not read loses messages past the backlog; each batch of drops
// is reported once, as a dropped line before the next message that gets through, and the
// counter resets. The writer runs concurrently with fill, so one or two reports are legal;
// their counts sum to the drops.
func TestClientDropsAndReports(t *testing.T) {
	ours, theirs := net.Pipe()
	c := NewClient(ours, Reader, WriteDeadline)
	defer c.Close()
	const extra = 5
	sent, dropped := fill(c, extra)
	// One message may sit in the writer goroutine's hands, the queue holds Backlog.
	if dropped < extra || dropped > extra+1 {
		t.Fatalf("dropped %d, want %d or %d", dropped, extra, extra+1)
	}
	if c.Drops() != int64(dropped) {
		t.Fatalf("Drops() %d != %d", c.Drops(), dropped)
	}
	replies, reported := splitReports(t, readUntil(t, theirs, sent))
	if len(replies) != sent {
		t.Fatalf("got %d replies, want %d", len(replies), sent)
	}
	if reported != dropped || int64(reported) != c.Drops() {
		t.Fatalf("reports sum to %d, want %d dropped sends (Drops() %d)", reported, dropped, c.Drops())
	}
	repliesInOrder(t, replies)
}

// Req 1.6: a stuck reader is closed after the write deadline; nothing else waits for it.
func TestClientDeadlineClosesStuckReader(t *testing.T) {
	ours, theirs := net.Pipe()
	c := NewClient(ours, Reader, 20*time.Millisecond)
	if !c.Send(msg(1)) {
		t.Fatal("first send must queue")
	}
	select {
	case <-c.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("client not closed by the deadline")
	}
	if err := c.Err(); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("want a deadline error, got %v", err)
	}
	if c.Send(msg(2)) {
		t.Fatal("send after close must report a drop")
	}
	if _, err := theirs.Read(make([]byte, 1)); err != io.EOF {
		t.Fatalf("peer still open after the close: %v", err)
	}
}

func TestClientCloseIsClean(t *testing.T) {
	ours, theirs := net.Pipe()
	c := NewClient(ours, Writer, WriteDeadline)
	if c.Role != Writer {
		t.Fatalf("role lost: %s", c.Role)
	}
	go func() { _, _ = io.Copy(io.Discard, theirs) }()
	if !c.Send(msg(1)) {
		t.Fatal("send")
	}
	c.Close()
	c.Close() // idempotent
	select {
	case <-c.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("writer goroutine did not stop")
	}
	if c.Err() != nil {
		t.Fatalf("a clean close has no error, got %v", c.Err())
	}
}
