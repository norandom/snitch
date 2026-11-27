package term

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
)

type termDaemonVec struct {
	Name         string `json:"name"`
	Value        string `json:"value"`
	NameOnly     bool   `json:"name_only"`
	WantSubstr   string `json:"want_substr"`
	ForbidSubstr string `json:"forbid_substr"`
}

type termHostileCorpus struct {
	DaemonStrings  []termDaemonVec `json:"daemon_strings"`
	Pastes         []string        `json:"pastes"`
	BurstSequences []string        `json:"burst_sequences"`
}

func loadTermHostileCorpus(t *testing.T) termHostileCorpus {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "hostile_corpus.json"))
	if err != nil {
		t.Fatalf("read term hostile corpus: %v", err)
	}
	var c termHostileCorpus
	if err := json.Unmarshal(b, &c); err != nil {
		t.Fatalf("unmarshal term hostile corpus: %v", err)
	}
	if len(c.DaemonStrings) == 0 || len(c.Pastes) == 0 || len(c.BurstSequences) == 0 {
		t.Fatalf("term hostile corpus missing required sections")
	}
	return c
}

func isTermForbiddenRune(r rune) bool {
	if r == '\x07' || r == '\x7f' || (r >= 0x80 && r <= 0x9f) {
		return true
	}
	switch r {
	case 0x061c, 0x200b, 0x200c, 0x200d, 0x200e, 0x200f,
		0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
		0x2060, 0x2066, 0x2067, 0x2068, 0x2069, 0xfeff:
		return true
	}
	return false
}

func assertTermOutputClean(t *testing.T, out string, vec termDaemonVec) {
	t.Helper()
	if !utf8.ValidString(out) {
		t.Fatalf("%s: terminal output contains invalid UTF-8", vec.Name)
	}
	stripped := strings.ReplaceAll(out, "\x1b]2;snitch\a", "")
	stripped = strings.ReplaceAll(stripped, "\x1b]2;\a", "")
	for _, seq := range []string{"\x1b[31m", "\x1b[99;99H", "\x1b]8;;"} {
		if strings.Contains(stripped, seq) {
			t.Fatalf("%s: terminal output leaked raw sequence %q", vec.Name, seq)
		}
	}
	for _, r := range stripped {
		if isTermForbiddenRune(r) {
			t.Fatalf("%s: terminal output leaked forbidden rune U+%04X", vec.Name, r)
		}
	}
	if vec.ForbidSubstr != "" && strings.Contains(stripped, vec.ForbidSubstr) {
		t.Fatalf("%s: terminal output leaked forbidden substring %q", vec.Name, vec.ForbidSubstr)
	}
	if vec.WantSubstr != "" && !strings.Contains(stripped, vec.WantSubstr) {
		t.Fatalf("%s: terminal output missing %q in:\n%s", vec.Name, vec.WantSubstr, out)
	}
}

func assertLogLinesSafe(t *testing.T, lines []clean.Safe) {
	t.Helper()
	for _, line := range lines {
		s := string(line)
		if !utf8.ValidString(s) {
			t.Fatalf("log line invalid UTF-8: %q", s)
		}
		for _, r := range s {
			if r < 0x20 || isTermForbiddenRune(r) {
				t.Fatalf("log line leaked replaced rune U+%04X: %q", r, s)
			}
		}
	}
}

func assertNoActionRequests(t *testing.T, what string, reqs []api.Request) {
	t.Helper()
	for _, r := range reqs {
		switch r.Type {
		case "rule.add", "rule.remove", "trial", "keep", "end", "unkeep":
			t.Fatalf("%s triggered forbidden request: %+v", what, r)
		}
	}
}

func TestHostileTermDaemonCorpusAndLog(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	corpus := loadTermHostileCorpus(t)
	now := time.Unix(1700000000, 0).UTC()
	for _, vec := range corpus.DaemonStrings {
		t.Run(vec.Name, func(t *testing.T) {
			runHostileTermVec(t, vec, now)
		})
	}
}

func runHostileTermVec(t *testing.T, vec termDaemonVec, now time.Time) {
	t.Helper()
	in := make(chan any, 16)
	var mu sync.Mutex
	var logLines []clean.Safe
	field := vec.Value
	if vec.NameOnly {
		field = "curl"
	}
	in <- client.Up{PeerKnown: true, PeerUID: 0}
	in <- client.Facts{Status: api.Status{Running: true, Mode: "monitor", Counting: true}}
	out, pw, done := startPipedRun(context.Background(), Config{
		Model: newTestModel(), In: in, Now: func() time.Time { return now },
		Log:  func(line clean.Safe) error { mu.Lock(); logLines = append(logLines, line); mu.Unlock(); return nil },
		Send: func(tok uint64, r api.Request) { replyHostile(in, tok, r, field, vec.Value, now) },
	})
	in <- client.EventLine{Event: api.Event{Program: field, Path: "/opt/" + field, Addr: "9.9.9.9", Name: vec.Value, Port: 443, Protocol: "tcp", Verdict: "deny-rule", Rule: &api.RuleRef{Id: 1, Note: field}}}
	in <- client.StateLine{State: api.State{Mode: "enforce", Reason: field}}
	waitForOutput(t, out, "9.9.9.9")
	in <- client.Down{Reason: field}
	waitForOutput(t, out, "STALE")
	_, _ = io.WriteString(pw, "q")
	_ = pw.Close()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v", err)
	}
	mu.Lock()
	gotLogs := slices.Clone(logLines)
	mu.Unlock()
	if len(gotLogs) < 2 {
		t.Fatalf("expected >= 2 log lines, got %d", len(gotLogs))
	}
	assertLogLinesSafe(t, gotLogs)
	assertTermOutputClean(t, out.String(), vec)
}

func replyHostile(in chan<- any, tok uint64, r api.Request, field, name string, now time.Time) {
	switch r.Type {
	case "snapshot":
		in <- client.Answered{Token: tok, Reply: &api.Reply{Ok: true, Window: r.Window, Entries: []api.Entry{{
			Program: field, Path: "/opt/" + field, Addr: "9.9.9.9", Name: name, Port: 443, Protocol: "tcp", DenyCount: 1, BytesSent: 1024, LastSeen: now.Format(time.RFC3339), Verdict: "deny-rule",
		}}}}
	case "rules":
		in <- client.Answered{Token: tok, Reply: &api.Reply{Ok: true, Rules: []api.RuleView{{Id: 1, Program: field, To: "9.9.9.9/32", Protocol: "tcp", Port: 443, Verdict: "deny", Note: field, Source: field}}}}
	case "programs":
		in <- client.Answered{Token: tok, Reply: &api.Reply{Ok: true, Programs: []api.ProgramView{{Name: field, Paths: []string{"/opt/" + field}, Resolved: true}}}}
	}
}

func TestHostileTermPasteBurstTypeahead(t *testing.T) {
	corpus := loadTermHostileCorpus(t)
	in := make(chan any, 8)
	base := time.Unix(1700000000, 0).UTC()
	var clock atomic.Int64
	clock.Store(base.UnixNano())
	in <- client.Up{PeerKnown: true, PeerUID: 0}
	in <- client.Facts{Status: api.Status{Running: true, Mode: "monitor"}}
	in <- client.SummaryLine{Entries: []api.Entry{{
		Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Port: 443, Protocol: "tcp", BytesSent: 512, LastSeen: base.Format(time.RFC3339),
	}}}
	var mu sync.Mutex
	var reqs []api.Request
	out, pw, done := startPipedRun(context.Background(), Config{
		Model: newTestModel(),
		In:    in,
		Now:   func() time.Time { return time.Unix(0, clock.Load()).UTC() },
		Send:  func(_ uint64, r api.Request) { mu.Lock(); reqs = append(reqs, r); mu.Unlock() },
	})
	drivePasteBurstTypeahead(t, out, pw, &clock, base, corpus)
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v", err)
	}
	mu.Lock()
	got := slices.Clone(reqs)
	mu.Unlock()
	assertNoActionRequests(t, "paste/typeahead/burst", got)
}

func drivePasteBurstTypeahead(t *testing.T, out *syncBuffer, pw *io.PipeWriter, clock *atomic.Int64, base time.Time, corpus termHostileCorpus) {
	t.Helper()
	waitForOutput(t, out, "curl")
	for _, p := range corpus.Pastes {
		_, _ = io.WriteString(pw, ansi.BracketedPasteStart+p+ansi.BracketedPasteEnd)
		time.Sleep(40 * time.Millisecond)
	}
	_, _ = io.WriteString(pw, "T")
	waitForOutput(t, out, "Start enforce trial")
	clock.Store(base.Add(200 * time.Millisecond).UnixNano())
	_, _ = io.WriteString(pw, "y")
	time.Sleep(40 * time.Millisecond)
	clock.Store(base.Add(900 * time.Millisecond).UnixNano())
	_, _ = io.WriteString(pw, "n")
	waitForOutput(t, out, "trial cancelled")
	clock.Store(base.Add(2 * time.Second).UnixNano())
	for _, seq := range corpus.BurstSequences {
		_, _ = io.WriteString(pw, seq)
		time.Sleep(40 * time.Millisecond)
	}
	clock.Store(base.Add(3 * time.Second).UnixNano())
	_, _ = io.WriteString(pw, "q")
	_ = pw.Close()
}

func TestHostileTermNonRootSocket(t *testing.T) {
	in := make(chan any, 8)
	base := time.Unix(1700000000, 0).UTC()
	var clock atomic.Int64
	clock.Store(base.UnixNano())
	in <- client.Up{PeerKnown: true, PeerUID: 1000}
	in <- client.Facts{Status: api.Status{Running: true, Mode: "monitor"}}
	in <- client.SummaryLine{Entries: []api.Entry{{
		Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Port: 443, Protocol: "tcp", BytesSent: 512, LastSeen: base.Format(time.RFC3339),
	}}}
	var mu sync.Mutex
	var reqs []api.Request
	out, pw, done := startPipedRun(context.Background(), Config{
		Model: newTestModel(),
		In:    in,
		Now:   func() time.Time { return time.Unix(0, clock.Load()).UTC() },
		Send:  func(_ uint64, r api.Request) { mu.Lock(); reqs = append(reqs, r); mu.Unlock() },
	})
	waitForOutput(t, out, "FOREIGN (")
	for i, k := range []string{"x", " ", "T", "K", "E", "U", "y"} {
		clock.Store(base.Add(time.Duration(i+1) * time.Second).UnixNano())
		_, _ = io.WriteString(pw, k)
		time.Sleep(25 * time.Millisecond)
	}
	waitForOutput(t, out, "not the system daemon: writes are off")
	clock.Store(base.Add(10 * time.Second).UnixNano())
	_, _ = io.WriteString(pw, "q")
	_ = pw.Close()
	if err := <-done; err != nil {
		t.Fatalf("Run returned %v", err)
	}
	mu.Lock()
	got := slices.Clone(reqs)
	mu.Unlock()
	assertNoActionRequests(t, "non-root socket", got)
}
