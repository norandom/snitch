package tui

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/conf"
)

func appendsOf(fx []Effect) []Append {
	var out []Append
	for _, e := range fx {
		if a, ok := e.(Append); ok {
			out = append(out, a)
		}
	}
	return out
}

func blockEntry(prog, path, addr, name string, last time.Time) api.Entry {
	return api.Entry{Program: prog, Path: path, Addr: addr, Name: name, Port: 443, Protocol: "tcp", LastSeen: last.Format(time.RFC3339)}
}

func blockModelWith(t *testing.T, t0 time.Time, opts Options, entries []api.Entry, rules []api.RuleView) Model {
	t.Helper()
	m, rReq, pReq, sReq := upModel(t, t0, opts)
	ov := "/etc/snitch/rules.d/local.toml"
	m, _ = Update(m, client.Facts{Status: api.Status{Running: true, Rules: api.RulesSummary{Overlay: ov}}}, t0)
	m, _ = Update(m, client.Answered{Token: rReq.Token, Reply: &api.Reply{Ok: true, Rules: rules}}, t0)
	m, _ = Update(m, client.Answered{Token: pReq.Token, Reply: &api.Reply{Ok: true}}, t0)
	m, _ = Update(m, client.Answered{Token: sReq.Token, Reply: &api.Reply{Ok: true, Window: m.window, Entries: entries}}, t0)
	m, _ = Update(m, Tick{}, t0.Add(time.Second))
	return m
}

func selectRow(t *testing.T, m Model, title string, open bool, at time.Time) Model {
	t.Helper()
	for i, r := range m.rows {
		if string(r.Title) == title {
			m = setCursorIndex(m, i, true)
			if open {
				m, _ = pressKey(m, "enter", at)
			}
			return m
		}
	}
	t.Fatalf("row %q not found in %v", title, rowTitles(m.rows))
	return m
}

func TestBlockAddressAndUnblock(t *testing.T) {
	t0 := feedTime()
	entries := []api.Entry{blockEntry("curl", "/usr/bin/curl", "1.1.1.1", "api.example.com", t0)}
	m := blockModelWith(t, t0, Options{Loc: time.UTC}, entries, nil)
	m = selectRow(t, m, "curl", true, t0.Add(2*time.Second))
	m = selectRow(t, m, "api.example.com", true, t0.Add(3*time.Second))
	m = selectRow(t, m, "1.1.1.1:443 tcp", false, t0)

	m, fx := pressKey(m, "x", t0.Add(4*time.Second))
	sends := sendsOf(fx)
	if len(sends) != 1 || sends[0].Req.Type != "rule.add" {
		t.Fatalf("x on address sends = %#v, want 1 rule.add", sends)
	}
	if sends[0].Req.To != "1.1.1.1/32" || len(appendsOf(fx)) != 0 || len(m.log) != 0 {
		t.Fatalf("unexpected pre-answer state: send=%+v fx=%#v log=%v", sends[0], fx, m.log)
	}
	replyTxt := "rule added: curl to 1.1.1.1/32 tcp port 443 deny\x1b[31m"
	m, fx = Update(m, client.Answered{Token: sends[0].Token, Text: replyTxt}, t0.Add(5*time.Second))
	wantLog := clean.Const("BLOCKED curl > api.example.com > 1.1.1.1:443 tcp")
	assertLoggedNotice(t, m, fx, clean.Text(replyTxt), wantLog)
	checkAddressUnblock(t, m, t0)
}

func assertLoggedNotice(t *testing.T, m Model, fx []Effect, notice, logLine clean.Safe) {
	t.Helper()
	if m.notice != notice {
		t.Fatalf("notice = %q, want %q", m.notice, notice)
	}
	if apps := appendsOf(fx); len(apps) != 1 || apps[0].Line != logLine {
		t.Fatalf("appends = %#v, want [%q]", apps, logLine)
	}
	if len(m.log) == 0 || !strings.HasSuffix(string(m.log[len(m.log)-1]), "  "+string(logLine)) {
		t.Fatalf("log = %v, want suffix %q", m.log, logLine)
	}
}

func checkAddressUnblock(t *testing.T, m Model, t0 time.Time) {
	t.Helper()
	m.rules.Views = []api.RuleView{{Id: 1, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "deny", Source: m.rules.Overlay}}
	m.dirty = true
	m, _ = Update(m, Tick{}, t0.Add(6*time.Second))
	m, fx := pressKey(m, "space", t0.Add(7*time.Second))
	sends := sendsOf(fx)
	if len(sends) != 1 || sends[0].Req.Type != "rule.remove" || len(appendsOf(fx)) != 0 {
		t.Fatalf("space unblock sends = %#v, fx=%#v", sends, fx)
	}
	m, fx = Update(m, client.Answered{Token: sends[0].Token, Text: "rule removed: curl to 1.1.1.1/32 tcp port 443"}, t0.Add(8*time.Second))
	want := clean.Const("UNBLOCKED curl > api.example.com > 1.1.1.1:443 tcp")
	if apps := appendsOf(fx); len(apps) != 1 || apps[0].Line != want {
		t.Fatalf("unblock append = %#v, want %q", apps, want)
	}
}

func TestBlockProgramAddsLocalNetworkNote(t *testing.T) {
	t0 := feedTime()
	entries := []api.Entry{blockEntry("curl", "/usr/bin/curl", "1.1.1.1", "a.example", t0)}
	m := blockModelWith(t, t0, Options{Loc: time.UTC}, entries, nil)
	m, fx := pressKey(m, "x", t0.Add(2*time.Second))
	sends := sendsOf(fx)
	if len(sends) != 2 || sends[0].Req.To != "0.0.0.0/0" || sends[1].Req.To != "::/0" {
		t.Fatalf("program block sends = %#v, want 2 (v4+v6)", sends)
	}
	m, fx1 := Update(m, client.Answered{Token: sends[0].Token, Text: "rule added: curl to 0.0.0.0/0 deny"}, t0.Add(3*time.Second))
	if m.notice != "" || len(appendsOf(fx1)) != 1 {
		t.Fatalf("after 1st answer: notice=%q appends=%#v", m.notice, appendsOf(fx1))
	}
	m, fx2 := Update(m, client.Answered{Token: sends[1].Token, Text: "rule added: curl to ::/0 deny"}, t0.Add(4*time.Second))
	if len(appendsOf(fx2)) != 0 || len(m.log) != 1 {
		t.Fatalf("2nd answer log mismatch: appends=%#v log=%v", appendsOf(fx2), m.log)
	}
	assertContainsAll(t, string(m.notice), "the local network stays reachable", "rule added: curl to ::/0 deny")
}

func assertContainsAll(t *testing.T, got string, subs ...string) {
	t.Helper()
	for _, s := range subs {
		if !strings.Contains(got, s) {
			t.Fatalf("%q missing %q", got, s)
		}
	}
}

func TestBlockRefusalsAndReaderVerbatim(t *testing.T) {
	t0 := feedTime()
	entries := []api.Entry{
		blockEntry("curl", "/usr/bin/curl", "127.0.0.1", "localhost", t0),
		blockEntry("curl", "/usr/bin/curl", "1.1.1.1", "a.example", t0),
	}
	m := blockModelWith(t, t0, Options{}, entries, nil)
	m = selectRow(t, m, "curl", true, t0.Add(2*time.Second))
	m = selectRow(t, m, "localhost", true, t0.Add(3*time.Second))
	m = selectRow(t, m, "127.0.0.1:443 tcp", false, t0)
	m, fx := pressKey(m, "x", t0.Add(4*time.Second))
	if len(sendsOf(fx)) != 0 || !strings.Contains(string(m.notice), "local network") {
		t.Fatalf("local address should refuse without send: notice=%q fx=%#v", m.notice, fx)
	}

	m = selectRow(t, m, "curl", false, t0)
	m, fx = pressKey(m, "x", t0.Add(5*time.Second))
	sends := sendsOf(fx)
	readerErr := "rule.add: write requires the operator\x1b[0m"
	for i, s := range sends {
		m, fx = Update(m, client.Answered{Token: s.Token, Err: readerErr, Role: true}, t0.Add(time.Duration(6+i)*time.Second))
		if len(appendsOf(fx)) != 0 || len(m.log) != 0 {
			t.Fatalf("refusal logged: fx=%#v log=%v", fx, m.log)
		}
	}
	if m.notice != clean.Text(readerErr) {
		t.Fatalf("reader refusal notice = %q, want verbatim %q", m.notice, clean.Text(readerErr))
	}
}

func TestBlockBatchOfFiveWithTwoRefusals(t *testing.T) {
	t0 := feedTime()
	entries := make([]api.Entry, 5)
	for i := range entries {
		entries[i] = blockEntry("curl", "/usr/bin/curl", fmt.Sprintf("1.1.1.%d", i+1), "cdn.example", t0)
	}
	m := selectRow(t, selectRow(t, blockModelWith(t, t0, Options{Loc: time.UTC}, entries, nil), "curl", true, t0.Add(2*time.Second)), "cdn.example", false, t0)
	m, fx := pressKey(m, "x", t0.Add(3*time.Second))
	sends := sendsOf(fx)
	if len(sends) != 5 {
		t.Fatalf("batch of 5 sent %d requests, want 5", len(sends))
	}
	answers := []client.Answered{
		{Token: sends[0].Token, Text: "ok 1"}, {Token: sends[1].Token, Err: "first refusal text\nline2"},
		{Token: sends[2].Token, Text: "ok 2"}, {Token: sends[3].Token, Err: "second refusal"},
		{Token: sends[4].Token, Text: "ok 3"},
	}
	for i, ans := range answers[:4] {
		m, _ = Update(m, ans, t0.Add(time.Duration(4+i)*time.Second))
		if m.notice != "" {
			t.Fatalf("batch reported early after %d answers: %q", i+1, m.notice)
		}
	}
	m, fxLast := Update(m, answers[4], t0.Add(8*time.Second))
	if want := clean.Const("3 of 5 blocked; first refusal: first refusal text·line2"); m.notice != want {
		t.Fatalf("batch notice = %q, want %q", m.notice, want)
	}
	assertBatchDone(t, m, fxLast, "BLOCKED curl > cdn.example")
}

func assertBatchDone(t *testing.T, m Model, fxLast []Effect, suffix string) {
	t.Helper()
	if len(appendsOf(fxLast)) != 0 || len(m.log) != 1 || !strings.HasSuffix(string(m.log[0]), "  "+suffix) {
		t.Fatalf("batch log = %v (last appends=%#v)", m.log, appendsOf(fxLast))
	}
	if len(m.batches) != 0 || len(m.pending) != 0 {
		t.Fatalf("batch leaked state: batches=%v pending=%v", m.batches, m.pending)
	}
}

func TestProtectRequiresSecondPressAndDisarms(t *testing.T) {
	t0 := feedTime()
	entries := []api.Entry{
		blockEntry("sshd", "/usr/sbin/sshd", "1.1.1.1", "peer.example", t0),
		blockEntry("custom", "/usr/bin/custom", "8.8.8.8", "dns.example", t0.Add(-time.Second)),
	}
	m := blockModelWith(t, t0, Options{Conf: conf.Config{Since: "15m", Protect: []string{"custom"}}}, entries, nil)
	m, fx := pressKey(m, "x", t0.Add(2*time.Second))
	if len(sendsOf(fx)) != 0 || m.notice != clean.Const("sshd is protected: press x again to block it") || m.armed == "" {
		t.Fatalf("1st x on sshd: armed=%q notice=%q fx=%#v", m.armed, m.notice, fx)
	}
	m, _ = pressKey(m, "z", t0.Add(3*time.Second))
	if m.armed != "" {
		t.Fatalf("unknown key did not disarm: %q", m.armed)
	}
	m, _ = pressKey(m, "x", t0.Add(4*time.Second))
	m, fxRep := Update(m, Key{Name: "x", Repeat: true, At: t0.Add(5 * time.Second)}, t0.Add(5*time.Second))
	m, fxBurst := Update(m, Key{Name: "x", At: t0.Add(5*time.Second + 10*time.Millisecond)}, t0.Add(5*time.Second+10*time.Millisecond))
	if len(sendsOf(fxRep)) != 0 || len(sendsOf(fxBurst)) != 0 {
		t.Fatalf("repeat or burst triggered protected block: rep=%#v burst=%#v", fxRep, fxBurst)
	}
	m, fx2 := pressKey(m, "space", t0.Add(6*time.Second))
	if m.armed != "" || len(sendsOf(fx2)) != 2 {
		t.Fatalf("2nd press on sshd: armed=%q sends=%#v", m.armed, sendsOf(fx2))
	}
	checkProtectMoveAndUnblock(t, m, t0)
}

func checkProtectMoveAndUnblock(t *testing.T, m Model, t0 time.Time) {
	t.Helper()
	m = selectRow(t, m, "custom", false, t0)
	m, _ = pressKey(m, "x", t0.Add(7*time.Second))
	if m.armed == "" || m.notice != clean.Const("custom is protected: press x again to block it") {
		t.Fatalf("custom protect arm failed: armed=%q notice=%q", m.armed, m.notice)
	}
	m, _ = pressKey(m, "up", t0.Add(8*time.Second))
	if m.armed != "" {
		t.Fatalf("cursor move did not disarm: %q", m.armed)
	}
	m.rules.Views = []api.RuleView{
		{Id: 1, Program: "sshd", To: "0.0.0.0/0", Verdict: "deny", Source: m.rules.Overlay},
		{Id: 2, Program: "sshd", To: "::/0", Verdict: "deny", Source: m.rules.Overlay},
	}
	m.dirty = true
	m, _ = Update(m, Tick{}, t0.Add(9*time.Second))
	m = selectRow(t, m, "sshd", false, t0)
	m, fx := pressKey(m, "x", t0.Add(10*time.Second))
	if len(sendsOf(fx)) != 2 || sendsOf(fx)[0].Req.Type != "rule.remove" || m.armed != "" {
		t.Fatalf("protected unblock required 2nd press or failed: armed=%q fx=%#v", m.armed, fx)
	}
}

func TestBlockBatchUnblockLogBrokenAndImmutability(t *testing.T) {
	t0 := feedTime()
	entries, views := make([]api.Entry, 3), make([]api.RuleView, 3)
	for i := range entries {
		addr := fmt.Sprintf("1.1.1.%d", i+1)
		entries[i] = blockEntry("curl", "/usr/bin/curl", addr, "h.example", t0)
		views[i] = api.RuleView{Id: i + 1, Program: "curl", To: addr + "/32", Protocol: "tcp", Port: 443, Verdict: "deny", Source: "/etc/snitch/rules.d/local.toml"}
	}
	m := selectRow(t, selectRow(t, blockModelWith(t, t0, Options{Loc: time.UTC}, entries, views), "curl", true, t0.Add(2*time.Second)), "h.example", false, t0)
	m, fx := pressKey(m, "x", t0.Add(3*time.Second))
	sends := sendsOf(fx)
	if len(sends) != 3 {
		t.Fatalf("unblock batch sent %d, want 3", len(sends))
	}
	m, _ = Update(m, client.Answered{Token: 999999, Text: "ignored"}, t0.Add(4*time.Second))
	m, _ = Update(m, client.Answered{Token: sends[0].Token, Text: "removed 1"}, t0.Add(4*time.Second))
	m, _ = Update(m, client.Answered{Token: sends[1].Token, Err: "in deployed file"}, t0.Add(5*time.Second))
	m, _ = Update(m, client.Answered{Token: sends[2].Token, Text: "removed 3"}, t0.Add(6*time.Second))
	if m.notice != clean.Const("2 of 3 unblocked; first refusal: in deployed file") || len(m.log) != 1 || !strings.HasSuffix(string(m.log[0]), "  UNBLOCKED curl > h.example") {
		t.Fatalf("unblock batch notice=%q log=%v", m.notice, m.log)
	}
	checkHyprRdpLogBrokenAndImmutability(t, t0)
}

func checkHyprRdpLogBrokenAndImmutability(t *testing.T, t0 time.Time) {
	t.Helper()
	entries := []api.Entry{blockEntry("hypr-rdp", "/usr/bin/hypr-rdp", "1.1.1.1", "r.example", t0)}
	m1 := selectRow(t, blockModelWith(t, t0, Options{LogBroken: true, Loc: time.UTC}, entries, nil), "hypr-rdp", true, t0.Add(2*time.Second))
	m1 = selectRow(t, m1, "r.example", false, t0)
	m2, fx := pressKey(m1, "x", t0.Add(3*time.Second))
	if len(sendsOf(fx)) != 0 || m2.notice != clean.Const("hypr-rdp is protected: press x again to block it") || m1.armed != "" {
		t.Fatalf("hypr-rdp host protect failed: armed=%q m1.armed=%q", m2.armed, m1.armed)
	}
	m3, fx2 := pressKey(m2, "x", t0.Add(4*time.Second))
	sends := sendsOf(fx2)
	m4, fx3 := Update(m3, client.Answered{Token: sends[0].Token, Text: "rule added"}, t0.Add(5*time.Second))
	if len(sends) != 1 || len(appendsOf(fx3)) != 0 || len(m4.log) != 1 || len(m3.log) != 0 {
		t.Fatalf("LogBroken/immutability failed: sends=%#v fx=%#v m4.log=%v m3.log=%v", sends, fx3, m4.log, m3.log)
	}
}
