// block.go handles x/space block and unblock actions, protected-program arming and
// disarming, batch request bookkeeping, daemon reply/refusal notices, and BLOCKED /
// UNBLOCKED log entries.
//
// Fail-safe implications: none on kernel egress. Local-network addresses are refused by
// table.MakePlan before any request is queued; protected programs require a second x/space
// directly after the warning notice; one keypress never sends more than its own plan.
package tui

import (
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"time"

	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/table"
)

const logTimeLayout = "2006-01-02 15:04:05"

func onBlock(m Model, _ Key, now time.Time) (Model, []Effect) {
	row, ok := m.currentRow()
	if !ok {
		m.armed = ""
		return m, nil
	}
	plan := table.MakePlan(row, m.store, m.rules, now)
	if plan.Refusal != "" {
		m.armed = ""
		m.notice = plan.Refusal
		return m, nil
	}
	if !plan.Unblock {
		if prog, prot := protectedTarget(row, plan, m.conf.Protect); prot && m.armed != row.ID {
			m.armed = row.ID
			m.notice = clean.Join(clean.Text(prog), clean.Const(" is protected: press x again to block it"))
			return m, nil
		}
	}
	m.armed = ""
	return sendPlan(m, row, plan)
}

func sendPlan(m Model, row table.Row, plan table.Plan) (Model, []Effect) {
	contract.Require(len(plan.Requests) > 0, "tui.sendPlan: empty request plan")
	batchID := m.nextToken + 1
	verb := clean.Const("BLOCKED ")
	if plan.Unblock {
		verb = clean.Const("UNBLOCKED ")
	}
	logLine := clean.Join(verb, rowBreadcrumb(m.rows, row))

	next := maps.Clone(m.batches)
	if next == nil {
		next = make(map[uint64]batch, 1)
	}
	next[batchID] = batch{
		total:    len(plan.Requests),
		unblock:  plan.Unblock,
		logLines: []clean.Safe{logLine},
		note:     plan.Note,
	}
	m.batches = next
	m.notice = ""

	fx := make([]Effect, 0, len(plan.Requests))
	for _, req := range plan.Requests {
		var eff Effect
		m, eff = sendReq(m, purpose{kind: purposeBatch, batchID: batchID}, req)
		fx = append(fx, eff)
	}
	return m, fx
}

func onBatchAnswer(m Model, p purpose, a client.Answered, now time.Time) (Model, []Effect) {
	b, ok := m.batches[p.batchID]
	if !ok {
		return m, nil
	}
	b.done++
	var fx []Effect
	if a.Err != "" {
		if b.firstErr == "" {
			b.firstErr = clean.Text(a.Err)
		}
	} else {
		m, b, fx = recordBatchAccept(m, b, a, now)
	}

	next := maps.Clone(m.batches)
	if b.done < b.total {
		next[p.batchID] = b
		m.batches = next
		return m, fx
	}
	delete(next, p.batchID)
	m.batches = next
	m.notice = batchNotice(b)
	return m, fx
}

func recordBatchAccept(m Model, b batch, a client.Answered, now time.Time) (Model, batch, []Effect) {
	b.ok++
	if txt := replyText(a); txt != "" {
		b.lastText = clean.Text(txt)
	}
	if len(b.logLines) == 0 {
		return m, b, nil
	}
	var fx []Effect
	for _, line := range b.logLines {
		var eff Effect
		m, eff = recordLogLine(m, line, now)
		if eff != nil {
			fx = append(fx, eff)
		}
	}
	b.logLines = nil
	return m, b, fx
}

func batchNotice(b batch) clean.Safe {
	if b.ok == 0 {
		return b.firstErr
	}
	if b.ok == b.total {
		return allSucceededNotice(b)
	}
	verb := batchVerb(b.unblock)
	msg := clean.Join(clean.Text(fmt.Sprintf("%d of %d ", b.ok, b.total)), verb, clean.Const("; first refusal: "), b.firstErr)
	if b.note != "" {
		msg = clean.Join(msg, clean.Const("; "), b.note)
	}
	return msg
}

func allSucceededNotice(b batch) clean.Safe {
	var msg clean.Safe
	if b.total == 1 {
		msg = b.lastText
	} else {
		head := clean.Join(clean.Text(fmt.Sprintf("%d of %d ", b.ok, b.total)), batchVerb(b.unblock))
		msg = head
		if b.lastText != "" {
			msg = clean.Join(head, clean.Const(": "), b.lastText)
		}
	}
	if b.note == "" {
		return msg
	}
	if msg == "" {
		return b.note
	}
	return clean.Join(msg, clean.Const("; "), b.note)
}

func batchVerb(unblock bool) clean.Safe {
	if unblock {
		return clean.Const("unblocked")
	}
	return clean.Const("blocked")
}

func replyText(a client.Answered) string {
	if a.Text != "" {
		return a.Text
	}
	if a.Reply != nil {
		return a.Reply.Text
	}
	return ""
}

func recordLogLine(m Model, line clean.Safe, now time.Time) (Model, Effect) {
	loc := m.loc
	if loc == nil {
		loc = time.Local
	}
	ts := clean.Text(now.In(loc).Format(logTimeLayout))
	entry := clean.Join(ts, clean.Const("  "), line)
	m.log = append(slices.Clone(m.log), entry)
	if m.logBroken {
		return m, nil
	}
	return m, Append{Line: line}
}

func rowBreadcrumb(rows []table.Row, row table.Row) clean.Safe {
	parts := []clean.Safe{row.Title}
	cur := row
	for cur.Parent != "" {
		idx := rowIndex(rows, cur.Parent)
		if idx < 0 {
			break
		}
		cur = rows[idx]
		parts = append(parts, cur.Title)
	}
	slices.Reverse(parts)
	out := make([]clean.Safe, 0, len(parts)*2-1)
	for i, p := range parts {
		if i > 0 {
			out = append(out, clean.Const(" > "))
		}
		out = append(out, p)
	}
	return clean.Join(out...)
}

func protectedTarget(row table.Row, plan table.Plan, protect []string) (string, bool) {
	if len(row.Keys) == 0 || len(plan.Requests) == 0 {
		return "", false
	}
	req := plan.Requests[0]
	candidates := []string{req.Program, row.Keys[0].Who, req.Path}
	if req.Path != "" {
		candidates = append(candidates, filepath.Base(req.Path))
	}
	for _, c := range candidates {
		if c != "" && isProtectedName(c, protect) {
			return c, true
		}
	}
	return "", false
}

func isProtectedName(name string, protect []string) bool {
	if name == "hypr-rdp" || name == "sshd" {
		return true
	}
	return slices.Contains(protect, name)
}
