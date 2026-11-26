package tui

import (
	"context"
	"errors"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/client/clienttest"
	"github.com/norandom/snitch/internal/conf"
	"github.com/norandom/snitch/internal/table"
)

type intHarness struct {
	t      *testing.T
	s      *clienttest.StandIn
	c      *client.Client
	inbox  chan client.Msg
	cancel context.CancelFunc
	done   chan error
	m      Model
	now    time.Time
	sends  []Send
	snaps  int
}

func newIntHarness(t *testing.T, op uint32, wantEntries int, initCmds ...string) *intHarness {
	t.Helper()
	s := clienttest.Start(t, clienttest.Options{Operator: op, ReloadAfter: 20 * time.Millisecond, SummaryEvery: time.Hour})
	ctx, cancel := context.WithCancel(context.Background())
	inbox := make(chan client.Msg, 256)
	dial := func(dctx context.Context, p string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(dctx, "unix", p)
	}
	sink := func(m client.Msg) {
		select {
		case inbox <- m:
		case <-ctx.Done():
		}
	}
	c := client.New(client.Config{
		Path: s.Path(), Table: true, Now: time.Now, Log: func(string) {}, Dial: dial, Sink: sink,
		Peer: func(net.Conn) (uint32, bool) { return 0, true }, Poll: time.Hour,
		Gap: 10 * time.Millisecond, AnswerWait: 500 * time.Millisecond, BackoffMin: 20 * time.Millisecond, BackoffMax: 100 * time.Millisecond,
	})
	h := &intHarness{t: t, s: s, c: c, inbox: inbox, cancel: cancel, done: make(chan error, 1),
		m: New(Options{Conf: conf.Default(), Loc: time.UTC, Socket: clean.Text(s.Path())}), now: time.Now()}
	h.do(initCmds...)
	go func() { h.done <- c.Job()(ctx) }()
	t.Cleanup(h.stopClient)
	h.pumpUntil("initial snapshot", func(m Model) bool {
		return m.up && !m.stale && m.status != nil && m.store.Len() >= wantEntries && len(m.pending) == 0
	})
	h.tick(rebuildEvery)
	return h
}

func (h *intHarness) stopClient() {
	if h.cancel == nil {
		return
	}
	h.cancel()
	if err := <-h.done; !errors.Is(err, context.Canceled) {
		h.t.Errorf("client job ended with %v", err)
	}
	h.cancel = nil
}

func (h *intHarness) apply(msg any) {
	if a, ok := msg.(client.Answered); ok && a.Reply != nil && a.Reply.Window != "" {
		h.snaps++
	}
	var fx []Effect
	h.m, fx = Update(h.m, msg, h.now)
	for _, eff := range fx {
		if snd, ok := eff.(Send); ok {
			h.sends = append(h.sends, snd)
			h.c.Send(snd.Token, snd.Req)
		}
	}
}

func (h *intHarness) pumpUntil(desc string, cond func(Model) bool) {
	h.t.Helper()
	deadline := time.After(3 * time.Second)
	for !cond(h.m) {
		select {
		case msg := <-h.inbox:
			h.apply(msg)
		case <-deadline:
			h.t.Fatalf("timeout waiting for %s (up=%v stale=%v pending=%d notice=%q)", desc, h.m.up, h.m.stale, len(h.m.pending), h.m.notice)
		}
	}
}

func (h *intHarness) tick(d time.Duration) { h.now = h.now.Add(d); h.apply(Tick{}) }
func (h *intHarness) key(name string) {
	h.now = h.now.Add(100 * time.Millisecond)
	h.apply(Key{Name: name, At: h.now})
}

func (h *intHarness) openAndSelect(titles ...string) {
	h.t.Helper()
	for i, title := range titles {
		h.m = selectRow(h.t, h.m, title, i < len(titles)-1, h.now)
	}
}

func (h *intHarness) row(title string) table.Row {
	h.t.Helper()
	for _, r := range h.m.rows {
		if string(r.Title) == title {
			return r
		}
	}
	h.t.Fatalf("row %q not found in %v", title, rowTitles(h.m.rows))
	return table.Row{}
}

func (h *intHarness) do(cmds ...string) {
	h.t.Helper()
	for _, cmd := range cmds {
		if err := h.s.Do(cmd); err != nil {
			h.t.Fatalf("Do(%q): %v", cmd, err)
		}
	}
}

type editSpec [5]any

func assertEdits(t *testing.T, got []api.Request, want []editSpec) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("edits len=%d want %d: %#v", len(got), len(want), got)
	}
	for i, w := range want {
		g := got[i]
		if [5]any{g.Type, g.Program, g.To, g.Proto, g.Port} != w {
			t.Fatalf("edit[%d] = %+v, want %v", i, g, w)
		}
	}
}

func (h *intHarness) toggleAndCheck(key string, wantRules int, wantBlocked bool, check ...string) {
	h.t.Helper()
	h.key(key)
	h.pumpUntil("rules reload", func(m Model) bool {
		return len(m.rules.Views) == wantRules && len(m.pending) == 0 && len(m.batches) == 0
	})
	h.tick(rebuildEvery)
	for _, title := range check {
		if h.row(title).Blocked != wantBlocked {
			h.t.Fatalf("%s blocked=%v want %v", title, h.row(title).Blocked, wantBlocked)
		}
	}
}

func TestIntegrationStartSummaryAndCursor(t *testing.T) {
	h := newIntHarness(t, uint32(os.Getuid()), 2,
		"event curl /usr/bin/curl 1.1.1.1 443 tcp allow-rule",
		"event dig /usr/bin/dig 8.8.8.8 53 udp allow-monitor", "summary")
	h.openAndSelect("dig")
	wantCursor := h.m.cursor
	h.do("event curl /usr/bin/curl 1.1.1.1 443 tcp allow-rule", "summary")
	h.pumpUntil("summary dirty", func(m Model) bool { return m.dirty })
	h.tick(rebuildEvery)
	if h.m.cursor != wantCursor || h.row("curl").Allow != 2 {
		t.Fatalf("cursor=%q want %q, curl.Allow=%d want 2", h.m.cursor, wantCursor, h.row("curl").Allow)
	}
	assertContainsAll(t, flattenScreen(Render(h.m, h.now)), "curl", "dig", "2/0")
}

func TestIntegrationBlockAndUnblockAllLevels(t *testing.T) {
	h := newIntHarness(t, uint32(os.Getuid()), 2,
		"event curl /usr/bin/curl 9.9.9.9=dns.example.org 443 tcp allow-monitor",
		"event curl /usr/bin/curl 8.8.4.4=dns.example.org 443 tcp allow-monitor", "summary")
	base := len(h.m.rules.Views)
	h.openAndSelect("curl", "dns.example.org", "9.9.9.9:443 tcp")
	h.toggleAndCheck("x", base+1, true, "9.9.9.9:443 tcp")
	h.toggleAndCheck("space", base, false, "9.9.9.9:443 tcp")
	h.openAndSelect("dns.example.org")
	h.toggleAndCheck("x", base+2, true, "dns.example.org", "8.8.4.4:443 tcp", "9.9.9.9:443 tcp")
	h.toggleAndCheck("x", base, false, "dns.example.org")
	h.openAndSelect("curl")
	h.toggleAndCheck("x", base+2, true, "curl")
	assertContainsAll(t, string(h.m.notice), "local network stays reachable")
	h.toggleAndCheck("x", base, false, "curl")
	assertEdits(t, h.s.Edits(), []editSpec{
		{"rule.add", "curl", "9.9.9.9/32", "tcp", 443}, {"rule.remove", "curl", "9.9.9.9/32", "tcp", 443},
		{"rule.add", "curl", "8.8.4.4/32", "tcp", 443}, {"rule.add", "curl", "9.9.9.9/32", "tcp", 443},
		{"rule.remove", "curl", "8.8.4.4/32", "tcp", 443}, {"rule.remove", "curl", "9.9.9.9/32", "tcp", 443},
		{"rule.add", "curl", "0.0.0.0/0", "", 0}, {"rule.add", "curl", "::/0", "", 0},
		{"rule.remove", "curl", "0.0.0.0/0", "", 0}, {"rule.remove", "curl", "::/0", "", 0},
	})
}

func TestIntegrationUndeclaredProgramBlockedByPath(t *testing.T) {
	h := newIntHarness(t, uint32(os.Getuid()), 1, "event unknown /opt/bin/customtool 9.9.9.9 53 udp allow-monitor", "summary")
	base := len(h.m.rules.Views)
	h.openAndSelect("/opt/bin/customtool")
	h.toggleAndCheck("x", base+2, true, "/opt/bin/customtool")
	if edits := h.s.Edits(); len(edits) != 2 || edits[0].Path != "/opt/bin/customtool" || edits[0].Program != "" {
		t.Fatalf("path edits = %#v", edits)
	}
	h.do("event customtool /opt/bin/customtool 1.0.0.1 443 tcp allow-monitor", "summary")
	h.pumpUntil("ad-hoc name summary", func(m Model) bool { return m.dirty })
	h.tick(rebuildEvery)
	if !h.row("/opt/bin/customtool").Blocked || !h.row("customtool").Blocked {
		t.Fatalf("both forms must show blocked: path=%v name=%v", h.row("/opt/bin/customtool").Blocked, h.row("customtool").Blocked)
	}
}

func TestIntegrationReaderRefusal(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always the operator")
	}
	h := newIntHarness(t, uint32(os.Getuid())+1, 1, "event curl /usr/bin/curl 9.9.9.9 443 tcp allow-monitor", "summary")
	h.openAndSelect("curl")
	h.key("x")
	h.pumpUntil("reader refusal", func(m Model) bool { return m.notice != "" && len(m.pending) == 0 && len(m.batches) == 0 })
	if len(h.s.Edits()) != 0 {
		t.Fatalf("reader edit recorded: %#v", h.s.Edits())
	}
	assertContainsAll(t, flattenScreen(Render(h.m, h.now)), "rule.add: write requires the operator")
}

func TestIntegrationRestartStaleAndReload(t *testing.T) {
	h := newIntHarness(t, uint32(os.Getuid()), 1, "event curl /usr/bin/curl 1.1.1.1 443 tcp allow-rule", "summary")
	prevSnaps := h.snaps
	h.s.Stop()
	h.pumpUntil("stale mark", func(m Model) bool { return !m.up && m.stale })
	assertContainsAll(t, flattenScreen(Render(h.m, h.now)), "STALE", "curl")
	for _, k := range []string{"x", "T", "K", "E", "U"} {
		h.key(k)
		if string(h.m.notice) != "the daemon is not reachable" {
			t.Fatalf("%s down notice = %q", k, h.m.notice)
		}
	}
	h.do("event dig /usr/bin/dig 8.8.8.8 53 udp allow-monitor", "summary")
	if err := h.s.Serve(); err != nil {
		t.Fatal(err)
	}
	h.pumpUntil("reload after restart", func(m Model) bool {
		return m.up && !m.stale && h.snaps > prevSnaps && m.store.Len() >= 2 && len(m.pending) == 0
	})
	h.tick(rebuildEvery)
	scr := flattenScreen(Render(h.m, h.now))
	if strings.Contains(scr, "STALE") {
		t.Fatalf("STALE persisted after reload:\n%s", scr)
	}
	assertContainsAll(t, scr, "curl", "dig")
}

func TestIntegrationDroppedLineResnapshot(t *testing.T) {
	h := newIntHarness(t, uint32(os.Getuid()), 1, "event curl /usr/bin/curl 1.1.1.1 443 tcp allow-rule", "summary")
	prevSnaps, prevSends := h.snaps, len(h.sends)
	h.do("drop 4")
	h.pumpUntil("resnapshot after drop", func(m Model) bool {
		return h.snaps > prevSnaps && m.status != nil && m.status.Dropped >= 4 && len(m.pending) == 0
	})
	mustSend(t, h.sends[prevSends:], "snapshot")
}

func TestIntegrationKilledMidBatch(t *testing.T) {
	h := newIntHarness(t, uint32(os.Getuid()), 3,
		"event curl /usr/bin/curl 1.1.1.1=multi.example.org 443 tcp allow-monitor",
		"event curl /usr/bin/curl 8.8.4.4=multi.example.org 443 tcp allow-monitor",
		"event curl /usr/bin/curl 9.9.9.9=multi.example.org 443 tcp allow-monitor", "summary")
	h.s.StartTrial(10 * time.Minute)
	h.pumpUntil("trial mode", func(m Model) bool { return m.status != nil && m.status.Mode == "enforce" })
	h.openAndSelect("curl", "multi.example.org")
	h.now = h.now.Add(100 * time.Millisecond)
	var fx []Effect
	h.m, fx = Update(h.m, Key{Name: "x", At: h.now}, h.now)
	sends := sendsOf(fx)
	if len(sends) != 3 {
		t.Fatalf("want 3 batch sends, got %d", len(sends))
	}
	h.c.Send(sends[0].Token, sends[0].Req)
	h.pumpUntil("first batch answer", func(m Model) bool { b, ok := m.batches[sends[0].Token]; return ok && b.done == 1 })
	wantFacts, wantEdits := h.s.Facts(), len(h.s.Edits())
	h.stopClient()
	for _, rest := range sends[1:] {
		h.c.Send(rest.Token, rest.Req)
	}
	time.Sleep(40 * time.Millisecond)
	got := h.s.Facts()
	if got.Mode != wantFacts.Mode || got.Trial != wantFacts.Trial || got.Kept != wantFacts.Kept ||
		got.Rules.Rules != wantFacts.Rules.Rules || len(h.s.Edits()) != wantEdits {
		t.Fatalf("stand-in mutated after client kill: got=%+v want=%+v edits=%d/%d", got, wantFacts, len(h.s.Edits()), wantEdits)
	}
}
