// trial.go handles the trial verbs (T, K, E, U), the two-stage confirmation state
// machine with its 0.6 s gate and y-only acceptance, the daemon's own no-rules question,
// and verbatim outcome/refusal notices.
//
// Fail-safe implications: none on kernel egress. The TUI never writes trial or enforce
// files itself and leaves deadlines and boot reverts to the daemon; trial and keep are
// never sent without an explicit confirmation keypress after 0.6 s, and Extend is never set.
package tui

import (
	"fmt"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/conf"
)

func onTrial(m Model, k Key, now time.Time) (Model, []Effect) {
	at := keyTime(k, now)
	d := m.trialDuration()
	end := at.Add(d).In(m.location()).Format("15:04")
	m.notice = ""
	m.confirm = &confirmState{
		kind:     confirmTrial,
		openedAt: at,
		prompt: clean.Text(fmt.Sprintf(
			"Start enforce trial for %v (until %s)? Connections no rule allows are denied until then. [y/N]",
			d, end,
		)),
	}
	return m, nil
}

func onKeep(m Model, k Key, now time.Time) (Model, []Effect) {
	at := keyTime(k, now)
	m.notice = ""
	m.confirm = &confirmState{
		kind:     confirmKeep,
		openedAt: at,
		prompt:   clean.Const("Keep enforce? Enforce then stays beyond the deadline and across reboots. [y/N]"),
	}
	return m, nil
}

func onEnd(m Model, _ Key, _ time.Time) (Model, []Effect) {
	m.notice = ""
	m, eff := sendReq(m, purpose{kind: purposeEnd}, api.Request{Type: "end"})
	return m, []Effect{eff}
}

func onUnkeep(m Model, _ Key, _ time.Time) (Model, []Effect) {
	m.notice = ""
	m, eff := sendReq(m, purpose{kind: purposeUnkeep}, api.Request{Type: "unkeep"})
	return m, []Effect{eff}
}

func onConfirmYes(m Model, _ Key, _ time.Time) (Model, []Effect) {
	if m.confirm == nil {
		return m, nil
	}
	kind := m.confirm.kind
	m.confirm = nil
	m.notice = ""
	var p purpose
	var req api.Request
	switch kind {
	case confirmTrial:
		p = purpose{kind: purposeTrial}
		req = api.Request{Type: "trial", Duration: m.trialDuration().String()}
	case confirmTrialForce:
		p = purpose{kind: purposeTrial}
		req = api.Request{Type: "trial", Duration: m.trialDuration().String(), Yes: true}
	case confirmKeep:
		p = purpose{kind: purposeKeep}
		req = api.Request{Type: "keep"}
	default:
		return m, nil
	}
	m, eff := sendReq(m, p, req)
	return m, []Effect{eff}
}

func onConfirmCancel(m Model, _ Key, _ time.Time) (Model, []Effect) {
	if m.confirm == nil {
		return m, nil
	}
	kind := m.confirm.kind
	m.confirm = nil
	if kind == confirmKeep {
		m.notice = clean.Const("keep cancelled")
	} else {
		m.notice = clean.Const("trial cancelled")
	}
	return m, nil
}

func onTrialAnswer(m Model, p purpose, a client.Answered, now time.Time) Model {
	if p.kind == purposeTrial && a.Question {
		q := a.Err
		if q == "" {
			q = replyText(a)
		}
		m.notice = ""
		m.confirm = &confirmState{
			kind:     confirmTrialForce,
			openedAt: now,
			prompt:   clean.Text(q),
		}
		return m
	}
	if a.Err != "" {
		m.notice = clean.Text(a.Err)
		return m
	}
	m.notice = clean.Text(replyText(a))
	return m
}

func (m Model) trialDuration() time.Duration {
	if m.conf.Trial > 0 {
		return m.conf.Trial
	}
	return conf.Default().Trial
}

func (m Model) location() *time.Location {
	if m.loc != nil {
		return m.loc
	}
	return time.Local
}
