// feed.go handles the daemon's connection lifecycle, subscription stream, reply dispatch,
// and periodic snapshot/heartbeat timers for the pure TUI state machine.
//
// Fail-safe implications: none on kernel egress. Pure state transitions over daemon
// messages; socket ownership is tracked as foreign when the peer UID is non-zero, and
// loss keeps the last table marked stale without sending writes.
package tui

import (
	"maps"
	"slices"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
)

const (
	resnapshotEvery = 30 * time.Second
	staleBeatWindow = 15 * time.Second
)

func onUp(m Model, u client.Up, now time.Time) (Model, []Effect) {
	m.up = true
	m.downReason = ""
	m.foreign = u.PeerKnown && u.PeerUID != 0
	var fx []Effect
	var e Effect
	m, e = sendReq(m, purpose{kind: purposeRules}, api.Request{Type: "rules"})
	fx = append(fx, e)
	m, e = sendReq(m, purpose{kind: purposePrograms}, api.Request{Type: "programs"})
	fx = append(fx, e)
	m, e = requestSnapshot(m, now)
	fx = append(fx, e)
	return m, fx
}

func onDown(m Model, d client.Down, _ time.Time) (Model, []Effect) {
	m.up = false
	m.stale = true
	m.downReason = clean.Text(d.Reason)
	return m, nil
}

func onFacts(m Model, f client.Facts, _ time.Time) (Model, []Effect) {
	st := f.Status
	m.status = &st
	m.killEvent = st.Kill
	if m.rules.Overlay != st.Rules.Overlay {
		m.rules.Overlay = st.Rules.Overlay
		m.dirty = true
	}
	if m.state != nil {
		s := *m.state
		s.Mode, s.Trial, s.Kept = st.Mode, st.Trial, st.Kept
		m.state = &s
	}
	return m, nil
}

func onStateLine(m Model, sl client.StateLine, _ time.Time) (Model, []Effect) {
	s := sl.State
	m.state = &s
	if m.status != nil {
		st := *m.status
		st.Mode, st.Trial, st.Kept = s.Mode, s.Trial, s.Kept
		m.status = &st
	}
	if !s.RulesChanged {
		return m, nil
	}
	var fx []Effect
	var e Effect
	m, e = sendReq(m, purpose{kind: purposeRules}, api.Request{Type: "rules"})
	fx = append(fx, e)
	m, e = sendReq(m, purpose{kind: purposePrograms}, api.Request{Type: "programs"})
	fx = append(fx, e)
	return m, fx
}

func onEventLine(m Model, ev client.EventLine, now time.Time) (Model, []Effect) {
	switch ev.Event.Verdict {
	case "allow-stale":
		m.staleBeatAt = now
	case "allow-kill":
		m.killEvent = true
	}
	return m, nil
}

func onSummaryLine(m Model, sl client.SummaryLine, _ time.Time) (Model, []Effect) {
	if len(sl.Entries) == 0 {
		return m, nil
	}
	m.store = m.store.Upsert(sl.Entries)
	m.dirty = true
	return m, nil
}

func onDropped(m Model, _ client.Dropped, now time.Time) (Model, []Effect) {
	if !m.up {
		return m, nil
	}
	m, e := requestSnapshot(m, now)
	return m, []Effect{e}
}

func onAnswered(m Model, a client.Answered, now time.Time) (Model, []Effect) {
	p, ok := m.pending[a.Token]
	if !ok {
		return m, nil
	}
	m = dropPending(m, a.Token)
	switch p.kind {
	case purposeRules, purposePrograms, purposeSnapshot:
		return applyTableReply(m, p, a), nil
	case purposeBatch:
		return onBatchAnswer(m, p, a, now)
	}
	return m, nil
}

func applyTableReply(m Model, p purpose, a client.Answered) Model {
	if a.Reply == nil || a.Err != "" {
		return m
	}
	switch p.kind {
	case purposeRules:
		m.rules.Views = slices.Clone(a.Reply.Rules)
		m.dirty = true
	case purposePrograms:
		m.rules.Programs = slices.Clone(a.Reply.Programs)
		m.dirty = true
	case purposeSnapshot:
		if p.window == m.window {
			m.store = m.store.Replace(a.Reply.Entries)
			m.dirty = true
			m.stale = false
		}
	}
	return m
}

func onTick(m Model, now time.Time) (Model, []Effect) {
	if !m.staleBeatAt.IsZero() && now.Sub(m.staleBeatAt) >= staleBeatWindow {
		m.staleBeatAt = time.Time{}
	}
	m = rerankIfDue(m, now)
	m = rebuildIfDue(m, now)
	if !m.up {
		return m, nil
	}
	if m.snapAt.IsZero() {
		m.snapAt = now
		return m, nil
	}
	if now.Sub(m.snapAt) >= resnapshotEvery {
		m, e := requestSnapshot(m, now)
		return m, []Effect{e}
	}
	return m, nil
}

func (m Model) staleHeartbeat(now time.Time) bool {
	if m.staleBeatAt.IsZero() {
		return false
	}
	d := now.Sub(m.staleBeatAt)
	return d >= 0 && d < staleBeatWindow
}

func requestSnapshot(m Model, now time.Time) (Model, Effect) {
	m.snapAt = now
	return sendReq(m, purpose{kind: purposeSnapshot, window: m.window}, api.Request{
		Type:   "snapshot",
		Window: m.window,
	})
}

func sendReq(m Model, p purpose, req api.Request) (Model, Effect) {
	m.nextToken++
	token := m.nextToken
	next := maps.Clone(m.pending)
	if next == nil {
		next = make(map[uint64]purpose, 1)
	}
	next[token] = p
	m.pending = next
	return m, Send{Token: token, Req: req}
}

func dropPending(m Model, token uint64) Model {
	next := maps.Clone(m.pending)
	delete(next, token)
	m.pending = next
	return m
}
