package tui

import (
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

func TestUnknownMessagePanicsByContract(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	m := New(Options{})
	for _, bad := range []any{nil, "bad", 42, struct{}{}} {
		contracttest.Panics(t, contract.Precondition, func() {
			_, _ = Update(m, bad, now)
		})
	}
}

func TestGuardsOrderAndActionKeys(t *testing.T) {
	t0 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	actionKeys := []string{"x", "space", "T", "K", "E", "U", "y"}
	for _, key := range actionKeys {
		t.Run(key, func(t *testing.T) {
			checkGuardsForKey(t, key, t0)
		})
	}
}

func checkGuardsForKey(t *testing.T, key string, t0 time.Time) {
	t.Helper()
	base := func() Model {
		m := New(Options{})
		if key == "y" {
			m.confirm = &confirmState{openedAt: t0.Add(-time.Second)}
		}
		return m
	}
	checkGuardDrops(t, key, t0, base)
	checkGuardNotices(t, key, t0, base)
}

func checkGuardDrops(t *testing.T, key string, t0 time.Time, base func() Model) {
	t.Helper()
	m1 := base()
	m1.foreign, m1.up = true, false
	g1, fx1 := Update(m1, Key{Name: key, Repeat: true, At: t0}, t0)
	if g1.notice != "" || len(fx1) != 0 {
		t.Fatalf("guard 1 (repeat) leaked: notice=%q fx=%#v", g1.notice, fx1)
	}

	m2 := base()
	m2.foreign, m2.up = true, false
	m2.lastKeyAt = t0
	g2, fx2 := Update(m2, Key{Name: key, At: t0.Add(10 * time.Millisecond)}, t0.Add(10*time.Millisecond))
	if g2.notice != "" || len(fx2) != 0 {
		t.Fatalf("guard 2 (10ms burst) leaked: notice=%q fx=%#v", g2.notice, fx2)
	}

	m3 := New(Options{})
	m3.foreign, m3.up = true, false
	m3.confirm = &confirmState{openedAt: t0}
	g3, fx3 := Update(m3, Key{Name: key, At: t0.Add(500 * time.Millisecond)}, t0.Add(500*time.Millisecond))
	if g3.notice != "" || len(fx3) != 0 || g3.confirm == nil {
		t.Fatalf("guard 3 (<0.6s confirm) leaked: notice=%q fx=%#v confirm=%v", g3.notice, fx3, g3.confirm)
	}
}

func checkGuardNotices(t *testing.T, key string, t0 time.Time, base func() Model) {
	t.Helper()
	m4 := base()
	m4.foreign, m4.up = true, false
	g4, fx4 := Update(m4, Key{Name: key, At: t0}, t0)
	if g4.notice != clean.Const("not the system daemon: writes are off") || len(fx4) != 0 {
		t.Fatalf("guard 4 (foreign) notice=%q fx=%#v", g4.notice, fx4)
	}

	m5 := base()
	m5.foreign, m5.up = false, false
	g5, fx5 := Update(m5, Key{Name: key, At: t0}, t0)
	if g5.notice != clean.Const("the daemon is not reachable") || len(fx5) != 0 {
		t.Fatalf("guard 5 (down) notice=%q fx=%#v", g5.notice, fx5)
	}

	m6 := base()
	m6.up = true
	m6.lastKeyAt = t0
	if key == "y" {
		m6.confirm = &confirmState{openedAt: t0.Add(-600 * time.Millisecond)}
	}
	g6, _ := Update(m6, Key{Name: key, At: t0.Add(50 * time.Millisecond)}, t0.Add(50*time.Millisecond))
	if g6.notice == clean.Const("not the system daemon: writes are off") ||
		g6.notice == clean.Const("the daemon is not reachable") {
		t.Fatalf("unexpected guard notice when all guards pass: %q", g6.notice)
	}
}

func TestGuardsMovementNotBlockedByRepeatOrBurst(t *testing.T) {
	t0 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	m := New(Options{})
	m.lastKeyAt = t0
	m.foreign = true
	next, fx := Update(m, Key{Name: "down", Repeat: true, At: t0.Add(10 * time.Millisecond)}, t0.Add(10*time.Millisecond))
	if len(fx) != 0 || next.notice != "" {
		t.Fatalf("movement key triggered guard notice/effect: notice=%q fx=%#v", next.notice, fx)
	}
}

func TestInboundMessagesDispatched(t *testing.T) {
	now := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	msgs := []any{
		client.Up{PeerUID: 0, PeerKnown: true},
		client.Down{Reason: client.NotRunning},
		client.Facts{Status: api.Status{Running: true, Mode: "monitor"}},
		client.StateLine{State: api.State{Mode: "enforce"}},
		client.EventLine{Event: api.Event{Program: "curl", Verdict: "allow-rule"}},
		client.SummaryLine{Entries: []api.Entry{{Program: "curl", Addr: "1.1.1.1"}}},
		client.Dropped{Count: 3},
		client.Answered{Token: 1, Text: "ok"},
		Resize{W: 120, H: 40},
		Tick{},
		LogFailed{Err: clean.Const("read-only")},
		Inspected{Path: "/usr/bin/curl", Loose: false},
	}
	m := New(Options{})
	for _, msg := range msgs {
		m, _ = Update(m, msg, now)
	}
	if m.size.W != 120 || m.size.H != 40 {
		t.Fatalf("size = %+v, want 120x40", m.size)
	}
}
