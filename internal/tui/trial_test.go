package tui

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/conf"
)

func trialUpModel(t *testing.T, t0 time.Time, opts Options) Model {
	t.Helper()
	m, _, _, _ := upModel(t, t0, opts)
	m, _ = Update(m, client.Facts{Status: api.Status{Running: true, Mode: "monitor", Source: "files"}}, t0)
	return m
}

func mustConfirm(t *testing.T, m Model, fx []Effect, kind confirmKind) {
	t.Helper()
	if len(fx) != 0 {
		t.Fatalf("unexpected effects opening confirm: %#v", fx)
	}
	if m.confirm == nil || m.confirm.kind != kind {
		t.Fatalf("confirm = %+v, want kind %v", m.confirm, kind)
	}
}

func mustCancelConfirm(t *testing.T, m Model, key string, at time.Time) {
	t.Helper()
	next, fx := pressKey(m, key, at)
	if next.confirm != nil || len(fx) != 0 {
		t.Fatalf("cancel %q: confirm=%+v fx=%#v", key, next.confirm, fx)
	}
	if !strings.Contains(strings.ToLower(string(next.notice)), "cancel") {
		t.Fatalf("cancel %q notice = %q", key, next.notice)
	}
}

func TestTrialConfirmStateDiagram(t *testing.T) {
	t0 := feedTime()
	loc := time.FixedZone("CEST", 2*3600)
	m := trialUpModel(t, t0, Options{Conf: conf.Config{Trial: 15 * time.Minute}, Loc: loc})

	// Idle -> Asking (T)
	mAsk, fx := pressKey(m, "T", t0)
	mustConfirm(t, mAsk, fx, confirmTrial)
	assertContainsAll(t, strings.ToLower(string(mAsk.confirm.prompt)), "15m0s", "14:15", "no rule allows", "denied until then")

	checkAskingTrialEdges(t, mAsk, t0)

	// Asking -> Sent (y after 0.6s)
	mSent, fxSent := pressKey(mAsk, "y", t0.Add(600*time.Millisecond))
	req := mustSend(t, sendsOf(fxSent), "trial")
	if mSent.confirm != nil || req.Req.Duration != "15m0s" || req.Req.Yes || req.Req.Extend {
		t.Fatalf("y from Asking: confirm=%+v req=%+v", mSent.confirm, req.Req)
	}
	checkSentOutcomes(t, mSent, req.Token, t0.Add(time.Second))

	// Sent -> AskingDaemon (Question) -> AskingDaemon (<0.6s) -> Sent (Yes:true) -> Idle
	tAns := t0.Add(time.Second)
	qRaw := "No rules are loaded: every connection outside the local network will be denied for 15m0s. Start the trial? [y/N]\x1b[31m"
	mDaemon, fxQ := Update(mSent, client.Answered{Token: req.Token, Err: qRaw, Question: true}, tAns)
	mustConfirm(t, mDaemon, fxQ, confirmTrialForce)
	if mDaemon.confirm.prompt != clean.Text(qRaw) {
		t.Fatalf("daemon prompt = %q, want %q", mDaemon.confirm.prompt, clean.Text(qRaw))
	}
	checkAskingDaemonEdges(t, mDaemon, tAns)
}

func checkAskingTrialEdges(t *testing.T, mAsk Model, t0 time.Time) {
	t.Helper()
	for _, k := range []string{"y", "n", "E", "q", "T"} {
		mEarly, fxEarly := pressKey(mAsk, k, t0.Add(599*time.Millisecond))
		mustConfirm(t, mEarly, fxEarly, confirmTrial)
	}
	mustCancelConfirm(t, mAsk, "n", t0.Add(600*time.Millisecond))
}

func checkSentOutcomes(t *testing.T, mSent Model, tok uint64, at time.Time) {
	t.Helper()
	wantPending := len(mSent.pending) - 1
	okText := "enforce until 2026-11-26T14:15:00+02:00 (15m0s)\n"
	mOK, _ := Update(mSent, client.Answered{Token: tok, Text: okText}, at)
	if _, ok := mOK.pending[tok]; ok || mOK.confirm != nil || mOK.notice != clean.Text(okText) || len(mOK.pending) != wantPending {
		t.Fatalf("Sent->Idle ok failed: confirm=%v notice=%q pending=%d (want %d)", mOK.confirm, mOK.notice, len(mOK.pending), wantPending)
	}
	refusal := "the kill switch is set\x1b[0m"
	mRef, _ := Update(mSent, client.Answered{Token: tok, Err: refusal}, at)
	if _, ok := mRef.pending[tok]; ok || mRef.confirm != nil || mRef.notice != clean.Text(refusal) || len(mRef.pending) != wantPending {
		t.Fatalf("Sent->Idle refusal failed: confirm=%v notice=%q pending=%d (want %d)", mRef.confirm, mRef.notice, len(mRef.pending), wantPending)
	}
}

func checkAskingDaemonEdges(t *testing.T, mDaemon Model, tAns time.Time) {
	t.Helper()
	for _, k := range []string{"y", "n", "q"} {
		mEarly, fxEarly := pressKey(mDaemon, k, tAns.Add(599*time.Millisecond))
		mustConfirm(t, mEarly, fxEarly, confirmTrialForce)
	}
	mustCancelConfirm(t, mDaemon, "esc", tAns.Add(600*time.Millisecond))
	mSent2, fx2 := pressKey(mDaemon, "y", tAns.Add(600*time.Millisecond))
	req2 := mustSend(t, sendsOf(fx2), "trial")
	if mSent2.confirm != nil || !req2.Req.Yes || req2.Req.Extend || req2.Req.Duration != "15m0s" {
		t.Fatalf("second y failed: confirm=%+v req=%+v", mSent2.confirm, req2.Req)
	}
	mDone, _ := Update(mSent2, client.Answered{Token: req2.Token, Reply: &api.Reply{Ok: true, Text: "enforce started\x1b[32m"}}, tAns.Add(time.Second))
	if mDone.notice != clean.Text("enforce started\x1b[32m") || mDone.confirm != nil {
		t.Fatalf("second answer notice=%q confirm=%v", mDone.notice, mDone.confirm)
	}
}

func TestTrialDefaultDurationAndKeep(t *testing.T) {
	t0 := feedTime()
	m := trialUpModel(t, t0, Options{Conf: conf.Config{Since: "15m"}, Loc: time.UTC})
	mT, fxT := pressKey(m, "T", t0)
	mustConfirm(t, mT, fxT, confirmTrial)
	assertContainsAll(t, string(mT.confirm.prompt), "10m0s", "12:10")

	mK, fxK := pressKey(m, "K", t0.Add(time.Second))
	mustConfirm(t, mK, fxK, confirmKeep)
	assertContainsAll(t, strings.ToLower(string(mK.confirm.prompt)), "beyond the deadline", "across reboots")
	mustCancelConfirm(t, mK, "x", t0.Add(1600*time.Millisecond))
	mK2, fxK2 := pressKey(mK, "y", t0.Add(1600*time.Millisecond))
	reqK := mustSend(t, sendsOf(fxK2), "keep")
	mKDone, _ := Update(mK2, client.Answered{Token: reqK.Token, Err: "enforce can only be kept during a trial"}, t0.Add(2*time.Second))
	if mKDone.notice != clean.Const("enforce can only be kept during a trial") {
		t.Fatalf("keep refusal notice = %q", mKDone.notice)
	}
}

func TestTrialEndAndUnkeepImmediate(t *testing.T) {
	t0 := feedTime()
	m := trialUpModel(t, t0, Options{Loc: time.UTC})
	m.graph = true

	mE, fxE := pressKey(m, "E", t0.Add(time.Second))
	reqE := mustSend(t, sendsOf(fxE), "end")
	if mE.confirm != nil {
		t.Fatalf("E opened confirmation")
	}
	mE, _ = Update(mE, client.Answered{Token: reqE.Token, Text: "trial ended: /var/lib/snitch/trial removed"}, t0.Add(2*time.Second))
	if mE.notice != clean.Const("trial ended: /var/lib/snitch/trial removed") {
		t.Fatalf("E outcome notice = %q", mE.notice)
	}

	mU, fxU := pressKey(m, "U", t0.Add(3*time.Second))
	reqU := mustSend(t, sendsOf(fxU), "unkeep")
	if mU.confirm != nil {
		t.Fatalf("U opened confirmation")
	}
	mU, _ = Update(mU, client.Answered{Token: reqU.Token, Err: "unkeep: write requires the operator"}, t0.Add(4*time.Second))
	if mU.notice != clean.Const("unkeep: write requires the operator") {
		t.Fatalf("U refusal notice = %q", mU.notice)
	}
}

func TestTrialStateLineUpdatesHeaderMode(t *testing.T) {
	t0 := feedTime()
	m := trialUpModel(t, t0, Options{})
	m, _ = Update(m, client.StateLine{State: api.State{
		Mode: "enforce", Trial: "2026-11-26T12:10:00Z", Reason: "trial until 2026-11-26T12:10:00Z",
	}}, t0.Add(time.Second))
	if m.state == nil || m.state.Mode != "enforce" || m.status.Mode != "enforce" || m.status.Trial != "2026-11-26T12:10:00Z" {
		t.Fatalf("external trial state not reflected: state=%+v status=%+v", m.state, m.status)
	}
	m, _ = Update(m, client.StateLine{State: api.State{
		Mode: "monitor", Trial: "", Kept: false, Reason: "trial ended at its deadline",
	}}, t0.Add(2*time.Second))
	if m.state.Mode != "monitor" || m.status.Mode != "monitor" || m.status.Trial != "" {
		t.Fatalf("external revert state not reflected: state=%+v status=%+v", m.state, m.status)
	}
}

func TestConfirmSearchAndPasteIsolation(t *testing.T) {
	t0 := feedTime()
	m := trialUpModel(t, t0, Options{})
	init := ""
	m.search = &init
	for _, k := range []string{"T", "K", "E", "U", "y"} {
		next, fx := pressKey(m, k, t0.Add(time.Second))
		if len(fx) != 0 || next.confirm != nil {
			t.Fatalf("open search + %q leaked: fx=%#v confirm=%+v", k, fx, next.confirm)
		}
	}
	mT, _ := pressKey(trialUpModel(t, t0, Options{}), "T", t0)
	afterPaste, fxPaste := Update(mT, Paste{Text: "y"}, t0.Add(time.Second))
	if len(fxPaste) != 0 || afterPaste.confirm == nil || afterPaste.confirm.kind != confirmTrial {
		t.Fatalf("paste during confirm acted: fx=%#v confirm=%+v", fxPaste, afterPaste.confirm)
	}
}

func TestTrialAllKeysInEveryStateNeverBypassConfirmOrExtend(t *testing.T) {
	t0 := feedTime()
	allKeys := append(slices.Clone(designKeys), "n", "Y", "backspace", "tab", "?", "")
	base := blockModelWith(t, t0, Options{Loc: time.UTC}, []api.Entry{blockEntry("curl", "/usr/bin/curl", "1.1.1.1", "a.example", t0)}, nil)
	base, _ = Update(base, client.Facts{Status: api.Status{Running: true, Mode: "monitor", Source: "files"}}, t0)

	mAskT, _ := pressKey(base, "T", t0.Add(time.Second))
	mAskK, _ := pressKey(base, "K", t0.Add(time.Second))
	mSentT, fxSent := pressKey(mAskT, "y", t0.Add(2*time.Second))
	tok := mustSend(t, sendsOf(fxSent), "trial").Token
	mAskD, _ := Update(mSentT, client.Answered{Token: tok, Err: "No rules? [y/N]", Question: true}, t0.Add(3*time.Second))

	idleAllow := map[string]string{
		"E": "end", "U": "unkeep", "x": "rule.add", "space": "rule.add",
		"t": "snapshot", "1": "snapshot", "2": "snapshot", "4": "snapshot", "5": "snapshot",
	}
	states := []struct {
		name      string
		m         Model
		at        time.Time
		allowSend map[string]string
		confirm   bool
		early     bool
	}{
		{"Idle", base, t0.Add(time.Second), idleAllow, false, false},
		{"Sent", mSentT, t0.Add(3 * time.Second), idleAllow, false, false},
		{"AskingT_early", mAskT, t0.Add(1500 * time.Millisecond), nil, true, true},
		{"AskingT_ready", mAskT, t0.Add(2 * time.Second), map[string]string{"y": "trial"}, true, false},
		{"AskingK_early", mAskK, t0.Add(1500 * time.Millisecond), nil, true, true},
		{"AskingK_ready", mAskK, t0.Add(2 * time.Second), map[string]string{"y": "keep"}, true, false},
		{"AskingDaemon_early", mAskD, t0.Add(3500 * time.Millisecond), nil, true, true},
		{"AskingDaemon_ready", mAskD, t0.Add(4 * time.Second), map[string]string{"y": "trial"}, true, false},
	}

	for _, st := range states {
		checkStateKeyMatrix(t, st.name, st.m, st.at, allKeys, st.allowSend, st.confirm, st.early)
	}
}

func checkStateKeyMatrix(t *testing.T, state string, m Model, at time.Time, keys []string, allow map[string]string, inConfirm, early bool) {
	t.Helper()
	for _, k := range keys {
		next, fx := pressKey(m, k, at)
		assertNoForbiddenTrialSend(t, state, k, fx, allow)
		if inConfirm {
			assertConfirmKeyIsolation(t, state, k, next, fx, early)
		}
	}
}

func assertConfirmKeyIsolation(t *testing.T, state, key string, next Model, fx []Effect, early bool) {
	t.Helper()
	for _, e := range fx {
		if _, isQuit := e.(Quit); isQuit {
			t.Fatalf("%s + %q emitted Quit while confirmation open", state, key)
		}
	}
	if early {
		if next.confirm == nil || len(fx) != 0 {
			t.Fatalf("%s + %q acted inside 0.6s: confirm=%v fx=%#v", state, key, next.confirm, fx)
		}
		return
	}
	if key != "y" && next.confirm != nil {
		t.Fatalf("%s + %q did not close confirmation", state, key)
	}
}

func assertNoForbiddenTrialSend(t *testing.T, state, key string, fx []Effect, allow map[string]string) {
	t.Helper()
	for _, s := range sendsOf(fx) {
		if s.Req.Extend {
			t.Fatalf("%s + %q sent Extend=true: %+v", state, key, s.Req)
		}
		if want, ok := allow[key]; !ok || s.Req.Type != want {
			t.Fatalf("%s + %q sent unexpected %q (allow=%v)", state, key, s.Req.Type, allow)
		}
	}
}
