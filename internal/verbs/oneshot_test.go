package verbs

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/client/clienttest"
)

func unixDialer(path string) Dial {
	return func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", path)
	}
}

func TestAskRoundTripStandIn(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	replies, err := Ask(ctx, unixDialer(s.Path()), nil,
		api.Request{Type: "status"},
		api.Request{Type: "snapshot", Window: "1h"},
	)
	if err != nil {
		t.Fatalf("Ask failed: %v", err)
	}
	if len(replies) != 2 {
		t.Fatalf("got %d replies, want 2", len(replies))
	}
	if !replies[0].Ok || replies[0].Status == nil || replies[0].Status.Mode != "monitor" {
		t.Fatalf("unexpected status reply: %#v", replies[0])
	}
	if !replies[1].Ok || replies[1].Window != "1h" {
		t.Fatalf("unexpected snapshot reply: %#v", replies[1])
	}
}

func TestAskDialNeverAnswersEndsWithinDeadline(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	dial := func(context.Context) (net.Conn, error) {
		<-block
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Ask(ctx, dial, nil, api.Request{Type: "status"})
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("took %v, expected <= 500ms", elapsed)
	}
}

func TestAskSilentPeerEndsWithinDeadline(t *testing.T) {
	server, clientConn := net.Pipe()
	defer func() { _ = server.Close() }()
	go func() {
		buf := make([]byte, 512)
		for {
			if _, err := server.Read(buf); err != nil {
				return
			}
		}
	}()
	dial := func(context.Context) (net.Conn, error) { return clientConn, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := Ask(ctx, dial, nil, api.Request{Type: "status"})
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want context.DeadlineExceeded", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("took %v, expected <= 500ms", elapsed)
	}
}

func TestAskDialError(t *testing.T) {
	wantErr := errors.New("connect: connection refused")
	dial := func(context.Context) (net.Conn, error) { return nil, wantErr }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := Ask(ctx, dial, nil, api.Request{Type: "status"})
	if !errors.Is(err, wantErr) {
		t.Fatalf("err = %v, want %v", err, wantErr)
	}
}

func TestAskNonRootPeerRefusedBeforeWriting(t *testing.T) {
	server, clientConn := net.Pipe()
	defer func() { _ = server.Close() }()
	wrote := make(chan int, 1)
	go func() {
		buf := make([]byte, 64)
		n, _ := server.Read(buf)
		wrote <- n
	}()
	dial := func(context.Context) (net.Conn, error) { return clientConn, nil }
	peer := func(net.Conn) (uint32, bool) { return 1000, true }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := Ask(ctx, dial, peer, api.Request{Type: "trial", Duration: "10m"})
	if err == nil || !strings.Contains(err.Error(), "root") {
		t.Fatalf("err = %v, want non-root reason", err)
	}
	if n := <-wrote; n != 0 {
		t.Fatalf("wrote %d bytes to non-root socket, want 0", n)
	}
}

func TestAskRootAndUnknownPeerAllowed(t *testing.T) {
	for _, tc := range []struct {
		name string
		peer Peer
	}{
		{"root", func(net.Conn) (uint32, bool) { return 0, true }},
		{"unknown", func(net.Conn) (uint32, bool) { return 0, false }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			replies, err := Ask(ctx, unixDialer(s.Path()), tc.peer, api.Request{Type: "status"})
			if err != nil || len(replies) != 1 || replies[0].Status == nil {
				t.Fatalf("replies=%#v err=%v", replies, err)
			}
		})
	}
}

func TestAskDaemonErrorPreserved(t *testing.T) {
	const q = "No rules are loaded: every connection outside the local network will be denied for 10m0s. Start the trial? [y/N]"
	server, clientConn := net.Pipe()
	defer func() { _ = server.Close() }()
	go func() {
		_, _ = api.NewLineReader(server).ReadLine()
		_, _ = server.Write(api.Encode(api.Error{Type: "error", Id: 1, Error: q}))
	}()
	dial := func(context.Context) (net.Conn, error) { return clientConn, nil }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := Ask(ctx, dial, nil, api.Request{Type: "trial", Duration: "10m"})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != q {
		t.Fatalf("err.Error() = %q, want %q", err.Error(), q)
	}
	if !client.IsQuestion(err.Error()) {
		t.Fatalf("client.IsQuestion(%q) = false", err.Error())
	}
}

func TestAskSkipsUnsolicitedLines(t *testing.T) {
	server, clientConn := net.Pipe()
	defer func() { _ = server.Close() }()
	go func() {
		_, _ = api.NewLineReader(server).ReadLine()
		_, _ = server.Write(api.Encode(api.State{Type: "state", Mode: "monitor"}))
		_, _ = server.Write(api.Encode(api.Reply{Type: "reply", Id: 1, Ok: true, Text: "ok"}))
	}()
	dial := func(context.Context) (net.Conn, error) { return clientConn, nil }
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	replies, err := Ask(ctx, dial, nil, api.Request{Type: "end"})
	if err != nil || len(replies) != 1 || replies[0].Text != "ok" {
		t.Fatalf("replies=%#v err=%v", replies, err)
	}
}

func TestAskContextCanceled(t *testing.T) {
	server, clientConn := net.Pipe()
	defer func() { _ = server.Close() }()
	go func() {
		_, _ = api.NewLineReader(server).ReadLine()
	}()
	dial := func(context.Context) (net.Conn, error) { return clientConn, nil }
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(40*time.Millisecond, cancel)
	_, err := Ask(ctx, dial, nil, api.Request{Type: "status"})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
}

// A snapshot of a busy table is one reply line far over the request limit; Ask must read it
// (chandali 2026-11-28: 738 entries, a 237 KB line, and `snitch status` said "down").
func TestAskReadsReplyOverRequestLimit(t *testing.T) {
	server, clientConn := net.Pipe()
	defer func() { _ = server.Close() }()
	entries := make([]api.Entry, 2000)
	for i := range entries {
		entries[i] = api.Entry{Program: "unknown", Path: "/usr/sbin/" + strings.Repeat("p", 200),
			Addr: "159.69.58.118", Port: 36057, Protocol: "udp"}
	}
	big := api.Encode(api.Reply{Type: "reply", Id: 1, Ok: true, Window: "1h", Entries: entries})
	if len(big) <= api.LineLimit {
		t.Fatalf("fixture line %d bytes, want over %d", len(big), api.LineLimit)
	}
	go func() {
		_, _ = api.NewLineReader(server).ReadLine()
		_, _ = server.Write(big)
	}()
	dial := func(context.Context) (net.Conn, error) { return clientConn, nil }
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	replies, err := Ask(ctx, dial, nil, api.Request{Type: "snapshot", Window: "1h"})
	if err != nil || len(replies) != 1 || len(replies[0].Entries) != len(entries) {
		t.Fatalf("err=%v replies=%d", err, len(replies))
	}
}
