package term

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"github.com/charmbracelet/x/ansi"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/conf"
	"github.com/norandom/snitch/internal/tui"
)

type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func newTestModel() tui.Model {
	return tui.New(tui.Options{
		Conf:   conf.Default(),
		Loc:    time.UTC,
		Socket: clean.Const("/run/snitch/snitch.sock"),
	})
}

func waitForOutput(t *testing.T, buf *syncBuffer, substr string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(buf.String(), substr) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %q in output (%d bytes): %q", substr, len(buf.String()), buf.String())
}

func TestRunQuitEndsWithNilAndLeavesAltScreen(t *testing.T) {
	var out syncBuffer
	err := Run(Config{
		Model:  newTestModel(),
		Input:  bytes.NewBufferString("q"),
		Output: &out,
		Now:    func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})(context.Background())
	if err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}
	s := out.String()
	if !strings.Contains(s, ansi.SetModeAltScreenSaveCursor) {
		t.Fatalf("output never entered alt screen")
	}
	if !strings.Contains(s, ansi.ResetModeAltScreenSaveCursor) {
		t.Fatalf("output never left alt screen")
	}
	leaveIdx := strings.LastIndex(s, ansi.ResetModeAltScreenSaveCursor)
	enterIdx := strings.LastIndex(s, ansi.SetModeAltScreenSaveCursor)
	if leaveIdx < enterIdx {
		t.Fatalf("leave alt screen (%d) before enter (%d)", leaveIdx, enterIdx)
	}
	if strings.Contains(s, ansi.RequestBackgroundColor) {
		t.Fatalf("output queried terminal background color")
	}
}

func TestRunViewPropertiesAndNoRawOrBackgroundQuery(t *testing.T) {
	pm := newProgramModel(context.Background(), Config{
		Model: newTestModel(),
		Now:   func() time.Time { return time.Unix(1700000000, 0).UTC() },
	})
	v := pm.View()
	if !v.AltScreen {
		t.Fatalf("View.AltScreen = false, want true")
	}
	if v.MouseMode != tea.MouseModeNone {
		t.Fatalf("View.MouseMode = %v, want MouseModeNone", v.MouseMode)
	}
	if v.Cursor != nil {
		t.Fatalf("View.Cursor = %#v, want nil", v.Cursor)
	}
	if v.WindowTitle != "snitch" {
		t.Fatalf("View.WindowTitle = %q, want %q", v.WindowTitle, "snitch")
	}
}

func startPipedRun(ctx context.Context, cfg Config) (*syncBuffer, *io.PipeWriter, <-chan error) {
	var out syncBuffer
	pr, pw := io.Pipe()
	cfg.Input = pr
	cfg.Output = &out
	done := make(chan error, 1)
	go func() { done <- Run(cfg)(ctx) }()
	return &out, pw, done
}

func TestRunPasteNeverReachesActionKey(t *testing.T) {
	in := make(chan any, 8)
	now := time.Unix(1700000000, 0).UTC()
	in <- client.Up{PeerKnown: true, PeerUID: 0}
	in <- client.Facts{Status: api.Status{Running: true, Mode: "monitor"}}
	in <- client.SummaryLine{Entries: []api.Entry{{
		Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1",
		Port: 443, Protocol: "tcp", BytesSent: 512, LastSeen: now.Format(time.RFC3339),
	}}}
	var mu sync.Mutex
	var reqs []api.Request
	out, pw, done := startPipedRun(context.Background(), Config{
		Model: newTestModel(),
		In:    in,
		Now:   func() time.Time { return now },
		Send: func(_ uint64, r api.Request) {
			mu.Lock()
			reqs = append(reqs, r)
			mu.Unlock()
		},
	})
	waitForOutput(t, out, "curl")
	_, _ = io.WriteString(pw, ansi.BracketedPasteStart+"x TxKy"+ansi.BracketedPasteEnd)
	time.Sleep(80 * time.Millisecond)
	_, _ = io.WriteString(pw, "q")
	_ = pw.Close()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, r := range reqs {
		if r.Type == "rule.add" || r.Type == "trial" || r.Type == "keep" {
			t.Fatalf("pasted text triggered action request: %+v", r)
		}
	}
}

func TestRunCancelledContextRestoresTerminal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	var out syncBuffer
	done := make(chan error, 1)
	go func() {
		done <- Run(Config{
			Model:  newTestModel(),
			Output: &out,
			Now:    func() time.Time { return time.Unix(1700000000, 0).UTC() },
		})(ctx)
	}()
	waitForOutput(t, &out, ansi.SetModeAltScreenSaveCursor)
	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Run err = %v, want context.Canceled", err)
	}
	s := out.String()
	if !strings.Contains(s, ansi.ResetModeAltScreenSaveCursor) {
		t.Fatalf("cancelled run did not leave alt screen")
	}
	if !strings.Contains(s, ansi.SetModeTextCursorEnable) {
		t.Fatalf("cancelled run did not restore cursor")
	}
}

func TestRunInboxBatchAndEffects(t *testing.T) {
	in := make(chan any, 8)
	now := time.Unix(1700000000, 0).UTC()
	in <- client.Up{PeerKnown: true, PeerUID: 0}
	in <- client.Facts{Status: api.Status{Running: true, Mode: "enforce"}}
	in <- client.SummaryLine{Entries: []api.Entry{{
		Program: "wget", Path: "/tmp/wget", Addr: "9.9.9.9",
		Port: 443, Protocol: "tcp", BytesSent: 1024, LastSeen: now.Format(time.RFC3339),
	}}}
	in <- client.EventLine{Event: api.Event{Program: "wget", Path: "/tmp/wget", Addr: "9.9.9.9", Port: 443, Verdict: "deny-rule"}}

	var mu sync.Mutex
	var logCalls, inspectCalls int
	var sent []api.Request
	out, pw, done := startPipedRun(context.Background(), Config{
		Model: newTestModel(), In: in, Now: func() time.Time { return now },
		Send:  func(_ uint64, r api.Request) { mu.Lock(); sent = append(sent, r); mu.Unlock() },
		Log:   func(clean.Safe) error { mu.Lock(); logCalls++; mu.Unlock(); return errors.New("read-only") },
		Loose: func(path string) bool { mu.Lock(); inspectCalls++; mu.Unlock(); return path == "/tmp/wget" },
	})
	waitForOutput(t, out, "[writable dir]")
	waitForOutput(t, out, "log write failed")
	in <- client.EventLine{Event: api.Event{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Port: 443, Verdict: "deny-rule"}}
	waitForOutput(t, out, "denied curl")
	close(in)
	_, _ = io.WriteString(pw, "q")
	_ = pw.Close()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(sent) < 3 || logCalls != 1 || inspectCalls != 1 {
		t.Fatalf("sent=%d logCalls=%d inspectCalls=%d, want >=3, 1, 1", len(sent), logCalls, inspectCalls)
	}
}

func TestRunHonoursNoColor(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	in := make(chan any, 2)
	now := time.Unix(1700000000, 0).UTC()
	in <- client.SummaryLine{Entries: []api.Entry{{
		Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1",
		Port: 443, Protocol: "tcp", BytesSent: 1024, LastSeen: now.Format(time.RFC3339),
	}}}
	out, pw, done := startPipedRun(context.Background(), Config{
		Model: newTestModel(),
		In:    in,
		Now:   func() time.Time { return now },
	})
	waitForOutput(t, out, "curl")
	_, _ = io.WriteString(pw, "e")
	waitForOutput(t, out, "EGRESS")
	_, _ = io.WriteString(pw, "q")
	_ = pw.Close()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v, want nil", err)
	}
	if strings.Contains(out.String(), "\x1b[38;") {
		t.Fatalf("NO_COLOR output contained RGB/256 foreground SGR sequence")
	}
}
