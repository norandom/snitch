package tui

import (
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/conf"
	"github.com/norandom/snitch/internal/table"
)

func feedTime() time.Time {
	return time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
}

func sendsOf(fx []Effect) []Send {
	var out []Send
	for _, e := range fx {
		if s, ok := e.(Send); ok {
			out = append(out, s)
		}
	}
	return out
}

func mustSend(t *testing.T, sends []Send, typ string) Send {
	t.Helper()
	for _, s := range sends {
		if s.Req.Type == typ {
			return s
		}
	}
	t.Fatalf("missing %q send in %#v", typ, sends)
	return Send{}
}

func upModel(t *testing.T, t0 time.Time, opts Options) (Model, Send, Send, Send) {
	t.Helper()
	m, fx := Update(New(opts), client.Up{PeerUID: 0, PeerKnown: true}, t0)
	sends := sendsOf(fx)
	if !m.up || m.foreign || len(sends) != 3 {
		t.Fatalf("Up: up=%v foreign=%v sends=%#v", m.up, m.foreign, sends)
	}
	r := mustSend(t, sends, "rules")
	p := mustSend(t, sends, "programs")
	s := mustSend(t, sends, "snapshot")
	if r.Token == 0 || r.Token == p.Token || r.Token == s.Token || p.Token == s.Token {
		t.Fatalf("Up tokens not unique non-zero: %#v", sends)
	}
	return m, r, p, s
}

func TestFeedStartAndReplies(t *testing.T) {
	t0 := feedTime()
	m, rulesReq, progsReq, snapReq := upModel(t, t0, Options{Conf: conf.Config{Since: "15m"}})
	if snapReq.Req.Window != "15m" {
		t.Fatalf("snapshot window = %q, want 15m", snapReq.Req.Window)
	}
	m, _ = Update(m, client.Facts{Status: api.Status{
		Running: true, Mode: "monitor",
		Rules: api.RulesSummary{Overlay: "/etc/snitch/rules.d/local.toml"},
	}}, t0)
	m, _ = Update(m, client.Answered{Token: rulesReq.Token, Reply: &api.Reply{
		Ok:    true,
		Rules: []api.RuleView{{Id: 1, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "deny"}},
	}}, t0)
	m, _ = Update(m, client.Answered{Token: progsReq.Token, Reply: &api.Reply{
		Ok:       true,
		Programs: []api.ProgramView{{Name: "curl", Paths: []string{"/usr/bin/curl"}, Resolved: true, Executables: 1}},
	}}, t0)
	m, _ = Update(m, client.Answered{Token: snapReq.Token, Reply: &api.Reply{
		Ok:      true,
		Window:  "15m",
		Entries: []api.Entry{{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Port: 443, Protocol: "tcp", BytesSent: 100}},
	}}, t0)
	if len(m.rules.Views) != 1 || len(m.rules.Programs) != 1 || m.rules.Overlay != "/etc/snitch/rules.d/local.toml" {
		t.Fatalf("rules not populated: %+v", m.rules)
	}
	if m.store.Len() != 1 || !m.dirty || len(m.pending) != 0 {
		t.Fatalf("snapshot state: len=%d dirty=%v pending=%d", m.store.Len(), m.dirty, len(m.pending))
	}
}

func TestFeedSummaryUpdatesStore(t *testing.T) {
	t0 := feedTime()
	m, _, _, _ := upModel(t, t0, Options{})
	m.dirty = false
	m, _ = Update(m, client.SummaryLine{}, t0.Add(time.Second))
	if m.dirty {
		t.Fatalf("empty summary marked dirty")
	}
	e1 := api.Entry{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Port: 443, Protocol: "tcp", BytesSent: 500}
	e2 := api.Entry{Program: "dig", Path: "/usr/bin/dig", Addr: "8.8.8.8", Port: 53, Protocol: "udp", BytesSent: 64}
	m, _ = Update(m, client.SummaryLine{Entries: []api.Entry{e1, e2}}, t0.Add(2*time.Second))
	if !m.dirty || m.store.Len() != 2 {
		t.Fatalf("summary failed: dirty=%v len=%d", m.dirty, m.store.Len())
	}
	if got, ok := m.store.Get(table.KeyOf(e1)); !ok || got.BytesSent != 500 {
		t.Fatalf("store entry = %+v, ok=%v, want BytesSent=500", got, ok)
	}
}

func TestFeedRulesChangeAndState(t *testing.T) {
	t0 := feedTime()
	m, _, _, _ := upModel(t, t0, Options{})
	m, _ = Update(m, client.Facts{Status: api.Status{Running: true, Mode: "monitor"}}, t0)

	m, fx := Update(m, client.StateLine{State: api.State{
		Mode: "monitor", RulesChanged: true, Reason: "rules reloaded",
	}}, t0.Add(time.Second))
	sends := sendsOf(fx)
	if len(sends) != 2 {
		t.Fatalf("rulesChanged sends = %#v, want 2", sends)
	}
	mustSend(t, sends, "rules")
	mustSend(t, sends, "programs")

	m, fx2 := Update(m, client.StateLine{State: api.State{
		Mode: "enforce", Trial: "2026-11-26T12:10:00Z", Reason: "trial until 2026-11-26T12:10:00Z",
	}}, t0.Add(2*time.Second))
	if len(sendsOf(fx2)) != 0 || m.state.Mode != "enforce" || m.status.Mode != "enforce" || m.status.Trial != "2026-11-26T12:10:00Z" {
		t.Fatalf("state sync failed: fx=%#v state=%+v status=%+v", fx2, m.state, m.status)
	}
}

func TestFeedDropAndPeriodicSnapshot(t *testing.T) {
	t0 := feedTime()
	m, _, _, _ := upModel(t, t0, Options{})
	tDrop := t0.Add(5 * time.Second)
	m, fx := Update(m, client.Dropped{Count: 4}, tDrop)
	s := mustSend(t, sendsOf(fx), "snapshot")
	if s.Req.Window != "1h" {
		t.Fatalf("dropped window = %q, want 1h", s.Req.Window)
	}
	m, fxBefore := Update(m, Tick{}, tDrop.Add(29*time.Second))
	if len(sendsOf(fxBefore)) != 0 {
		t.Fatalf("tick at 29s sent unexpected requests: %#v", fxBefore)
	}
	m, fxAt := Update(m, Tick{}, tDrop.Add(30*time.Second))
	snapAt := mustSend(t, sendsOf(fxAt), "snapshot")

	m.window = "15m"
	m, _ = Update(m, client.Answered{
		Token: snapAt.Token,
		Reply: &api.Reply{Ok: true, Window: "1h", Entries: []api.Entry{{Program: "curl", Addr: "9.9.9.9", Port: 443, Protocol: "tcp"}}},
	}, tDrop.Add(31*time.Second))
	if m.store.Len() != 0 {
		t.Fatalf("stale-window snapshot polluted store: len=%d", m.store.Len())
	}
}

func TestFeedLossKeepsTableAndBlocksTick(t *testing.T) {
	t0 := feedTime()
	m, _, _, snapReq := upModel(t, t0, Options{})
	oldEntry := api.Entry{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Port: 443, Protocol: "tcp", BytesSent: 100}
	m, _ = Update(m, client.Answered{
		Token: snapReq.Token,
		Reply: &api.Reply{Ok: true, Window: "1h", Entries: []api.Entry{oldEntry}},
	}, t0)
	m, _ = Update(m, client.Down{Reason: client.NotRunning + "\x1b[31m"}, t0.Add(5*time.Second))
	if m.up || !m.stale || m.store.Len() != 1 {
		t.Fatalf("after Down: up=%v stale=%v len=%d", m.up, m.stale, m.store.Len())
	}
	if m.downReason != clean.Const("not running·[31m") {
		t.Fatalf("downReason = %q, want sanitized reason", m.downReason)
	}
	if _, fx := Update(m, client.Dropped{Count: 1}, t0.Add(6*time.Second)); len(sendsOf(fx)) != 0 {
		t.Fatalf("dropped while down sent snapshot: %#v", fx)
	}
	if _, fx := Update(m, Tick{}, t0.Add(40*time.Second)); len(sendsOf(fx)) != 0 {
		t.Fatalf("tick while down sent requests: %#v", fx)
	}
}

func TestFeedReturnReloadsAndClearsStale(t *testing.T) {
	t0 := feedTime()
	m, _, _, _ := upModel(t, t0, Options{})
	m, _ = Update(m, client.Down{Reason: client.NotAnswering}, t0.Add(5*time.Second))
	m, fxUp := Update(m, client.Up{PeerUID: 0, PeerKnown: true}, t0.Add(10*time.Second))
	snap2 := mustSend(t, sendsOf(fxUp), "snapshot")
	if !m.up || !m.stale || m.downReason != "" {
		t.Fatalf("return Up before snapshot: up=%v stale=%v reason=%q", m.up, m.stale, m.downReason)
	}
	m, _ = Update(m, client.Answered{Token: snap2.Token, Err: client.NoAnswer}, t0.Add(11*time.Second))
	if !m.stale {
		t.Fatalf("failed snapshot cleared stale")
	}
	m, fxR := Update(m, client.Dropped{Count: 1}, t0.Add(12*time.Second))
	snap3 := mustSend(t, sendsOf(fxR), "snapshot")
	newEntry := api.Entry{Program: "dig", Path: "/usr/bin/dig", Addr: "8.8.8.8", Port: 53, Protocol: "udp", BytesSent: 200}
	m, _ = Update(m, client.Answered{
		Token: snap3.Token,
		Reply: &api.Reply{Ok: true, Window: "1h", Entries: []api.Entry{newEntry}},
	}, t0.Add(13*time.Second))
	if m.stale || m.store.Len() != 1 {
		t.Fatalf("after return snapshot: stale=%v len=%d", m.stale, m.store.Len())
	}
}

func TestFeedForeignSocket(t *testing.T) {
	t0 := feedTime()
	m, _ := Update(New(Options{}), client.Up{PeerUID: 1000, PeerKnown: true}, t0)
	if !m.foreign || !m.up {
		t.Fatalf("foreign Up: foreign=%v up=%v, want true true", m.foreign, m.up)
	}
	m, fx := Update(m, Key{Name: "x", At: t0.Add(time.Second)}, t0.Add(time.Second))
	if len(sendsOf(fx)) != 0 || m.notice != clean.Const("not the system daemon: writes are off") {
		t.Fatalf("foreign write guard: fx=%#v notice=%q", fx, m.notice)
	}
	m, _ = Update(m, client.Up{PeerUID: 0, PeerKnown: true}, t0.Add(2*time.Second))
	if m.foreign {
		t.Fatalf("root Up did not clear foreign")
	}
	m, _ = Update(m, client.Up{PeerUID: 0, PeerKnown: false}, t0.Add(3*time.Second))
	if m.foreign {
		t.Fatalf("unknown peer marked foreign")
	}
}

func TestFeedTokensUnknownAndNilReply(t *testing.T) {
	t0 := feedTime()
	m, rulesReq, progsReq, snapReq := upModel(t, t0, Options{})
	m, _ = Update(m, client.Answered{
		Token: 999999,
		Reply: &api.Reply{Ok: true, Entries: []api.Entry{{Program: "curl", Addr: "1.1.1.1"}}},
	}, t0)
	if m.store.Len() != 0 || len(m.pending) != 3 {
		t.Fatalf("unknown token mutated state: len=%d pending=%d", m.store.Len(), len(m.pending))
	}
	m, _ = Update(m, client.Answered{Token: rulesReq.Token, Err: client.NoAnswer}, t0)
	m, _ = Update(m, client.Answered{Token: progsReq.Token, Err: client.NoAnswer}, t0)
	m, _ = Update(m, client.Answered{Token: snapReq.Token, Err: client.NoAnswer}, t0)
	if len(m.pending) != 0 {
		t.Fatalf("failed replies left pending tokens: %#v", m.pending)
	}
}

func TestFeedKillSwitchAndImmutability(t *testing.T) {
	t0 := feedTime()
	m0, _, _, _ := upModel(t, t0, Options{})
	snap := m0
	m1, _ := Update(m0, client.EventLine{Event: api.Event{Verdict: "allow-kill"}}, t0.Add(time.Second))
	m2, _ := Update(m1, client.Facts{Status: api.Status{Running: true, Mode: "monitor", Kill: false}}, t0.Add(2*time.Second))
	m3, _ := Update(m2, client.Facts{Status: api.Status{Running: true, Mode: "enforce", Kill: true}}, t0.Add(3*time.Second))
	if !m1.killEvent || m2.killEvent || !m3.killEvent || !m3.status.Kill {
		t.Fatalf("kill tracking failed: m1=%v m2=%v m3=%v/%v", m1.killEvent, m2.killEvent, m3.killEvent, m3.status.Kill)
	}
	if len(snap.pending) != 3 || snap.killEvent || snap.status != nil {
		t.Fatalf("prior Model value mutated: %+v", snap)
	}
}

func TestFeedStaleHeartbeatExpiry(t *testing.T) {
	t0 := feedTime()
	m, _, _, _ := upModel(t, t0, Options{})
	m, _ = Update(m, client.EventLine{Event: api.Event{Verdict: "allow-stale"}}, t0)
	if !m.staleHeartbeat(t0.Add(14*time.Second)) || m.staleHeartbeat(t0.Add(15*time.Second)) {
		t.Fatalf("staleHeartbeat window mismatch")
	}
	m14, _ := Update(m, Tick{}, t0.Add(14*time.Second))
	m15, _ := Update(m14, Tick{}, t0.Add(15*time.Second))
	if m14.staleBeatAt.IsZero() || !m15.staleBeatAt.IsZero() {
		t.Fatalf("staleBeatAt expiry: m14=%v m15=%v", m14.staleBeatAt, m15.staleBeatAt)
	}
}
