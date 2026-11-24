// questions_test.go: the question rules of 3.3 as message scripts with a fake time. Every
// script runs through sc.do, which records every send's request type (TestMain: only rule.add,
// 6.12, 8.1) and asserts that at most one note with actions is in flight or shown at a time.
package tray

import (
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/ask"
	"github.com/norandom/snitch/internal/client"
)

var (
	sentTypes  = map[string]int{} // the request type of every send of any script of the package
	writerCaps = Capabilities{Available: true, Actions: true}
	allowBlock = []Action{{Key: "allow", Label: "Allow"}, {Key: "block", Label: "Block"}}
)

func TestMain(m *testing.M) {
	code := m.Run()
	if _, ok := sentTypes["rule.add"]; len(sentTypes) > 1 || len(sentTypes) == 1 && !ok {
		fmt.Printf("FAIL: requests sent %v; only rule.add is allowed (6.12, 8.1)\n", sentTypes)
		code = 1
	}
	os.Exit(code)
}

// sc is a script: model, fake time, notes with actions in flight or shown, last effects.
type sc struct {
	t        *testing.T
	m        Model
	at       time.Time
	asking   map[uint64]bool
	live     map[uint32]bool
	posts    []post
	sends    []send
	retracts []retract
}

// script is a writer's or reader's tray with a notification service and the first facts.
func script(t *testing.T, writer bool, caps Capabilities) *sc {
	s := &sc{t: t, m: NewModel(Options{Loc: zone, Writer: writer}), at: now,
		asking: map[uint64]bool{}, live: map[uint32]bool{}}
	return s.do(caps).do(client.Up{}).do(client.Facts{Status: running()})
}

// do runs one message and sorts its effects; a show must come last.
func (s *sc) do(msg any) *sc {
	s.t.Helper()
	m, fx := Update(s.m, msg, s.at)
	if show, ok := fx[len(fx)-1].(show); !ok || !reflect.DeepEqual(show.View, Render(m, s.at)) {
		s.t.Fatalf("%T: last effect is not the new view", msg)
	}
	s.posts, s.sends, s.retracts = nil, nil, nil
	for _, e := range fx[:len(fx)-1] {
		switch v := e.(type) {
		case post:
			s.posts = append(s.posts, v)
		case send:
			sentTypes[v.Req.Type]++
			s.sends = append(s.sends, v)
		case retract:
			s.retracts = append(s.retracts, v)
		default:
			s.t.Fatalf("%T: unexpected effect %#v", msg, e)
		}
	}
	s.m = m
	s.track(msg)
	return s
}

// track follows the notes with actions and asserts that at most one is in flight or shown.
func (s *sc) track(msg any) {
	switch v := msg.(type) {
	case posted:
		if s.asking[v.Token] {
			delete(s.asking, v.Token)
			s.live[v.NoteID] = true
		}
	case postFailed:
		delete(s.asking, v.Token)
	case Closed:
		delete(s.live, v.NoteID)
	}
	for _, r := range s.retracts {
		delete(s.live, r.NoteID)
	}
	for _, p := range s.posts {
		if len(p.Note.Actions) > 0 {
			s.asking[p.Token] = true
		}
	}
	if n := len(s.asking) + len(s.live); n > 1 {
		s.t.Fatalf("%T: %d notes with actions at once", msg, n)
	}
}

// ev is firefox to example.org with a verdict; to is a blocked one to an address without name.
func ev(verdict string) client.EventLine {
	return client.EventLine{Event: api.Event{Type: "event", Program: "firefox", Path: "/usr/lib/firefox/firefox",
		Addr: "93.184.216.34", Name: "example.org", Port: 443, Protocol: "tcp", Verdict: verdict}}
}

func to(addr string) client.EventLine {
	e := ev("deny-default")
	e.Event.Addr, e.Event.Name = addr, ""
	return e
}

// question asserts that the last step posted the question and nothing else.
func (s *sc) question() Note {
	s.t.Helper()
	if len(s.posts) != 1 || s.posts[0].Token != s.m.askToken || s.m.askToken == 0 {
		s.t.Fatalf("want one question post, got %+v (askToken %d)", s.posts, s.m.askToken)
	}
	return s.posts[0].Note
}

// shown asks one question and has it posted as note id.
func (s *sc) shown(e client.EventLine, id uint32) Note {
	s.t.Helper()
	n := s.do(e).question()
	s.do(posted{Token: s.m.askToken, NoteID: id})
	if s.m.openNote != id || !s.m.openSince.Equal(s.at) || s.m.askToken != 0 {
		s.t.Fatalf("posted: openNote %d since %v askToken %d", s.m.openNote, s.m.openSince, s.m.askToken)
	}
	return n
}

func has(t *testing.T, text string, words ...string) {
	t.Helper()
	for _, w := range words {
		if !strings.Contains(text, w) {
			t.Errorf("%q lacks %q", text, w)
		}
	}
}

// 5.1, 6.1: a blocked connection asks with Allow and Block and names everything.
func TestQuestionBlockedWithActions(t *testing.T) {
	n := script(t, true, writerCaps).shown(ev("deny-default"), 5)
	has(t, n.Summary, "firefox", "example.org")
	has(t, n.Body, "firefox", "/usr/lib/firefox/firefox", "example.org", "93.184.216.34", "443", "tcp", "blocked")
	if !reflect.DeepEqual(n.Actions, allowBlock) || !n.Urgent || n.Timeout != questionTime {
		t.Fatalf("note %+v", n)
	}
}

// 5.2, 5.3, 5.9: allow-monitor has its own wording; rules' verdicts, the local network and
// allow-monitor in the enforce-only scope ask nothing.
func TestQuestionMonitorAndNone(t *testing.T) {
	n := script(t, true, writerCaps).do(ev("allow-monitor")).question()
	has(t, n.Body, "allowed, not yet decided")
	if n.Urgent || strings.Contains(n.Body, "blocked") {
		t.Fatalf("monitor note %+v", n)
	}
	s := script(t, true, writerCaps)
	s.m.opts.Scope = ask.Enforce
	for _, e := range []client.EventLine{ev("allow-monitor"), ev("allow-rule"), ev("deny-rule"), ev("allow-kill"), to("192.168.1.9")} {
		if s.do(e); len(s.posts) != 0 || s.m.queue.Stats().Waiting != 0 {
			t.Fatalf("%+v asked", e.Event)
		}
	}
}

// 5.5, 5.6, 7.8: one question at a time, a notice at once while it is open, and the next note
// counts the waiting and the dropped ones (none shown when none).
func TestQuestionOneAtATimeCounts(t *testing.T) {
	s := script(t, true, writerCaps)
	s.shown(to("1.1.1.1"), 5)
	if strings.Contains(script(t, true, writerCaps).do(ev("deny-default")).question().Body, "waiting") {
		t.Fatal("counts shown without waiting")
	}
	for i := range ask.MaxWaiting + 1 { // the 33rd drops the oldest waiting one
		if s.do(to(fmt.Sprintf("8.8.%d.%d", i/200, i%200+1))); len(s.posts) != 0 {
			t.Fatalf("a second question posted while one is open: %+v", s.posts)
		}
	}
	st := running()
	st.Kill = true
	if s.do(client.Facts{Status: st}); len(s.posts) != 1 || s.posts[0].Note.Actions != nil || s.m.openNote != 5 {
		t.Fatalf("notice while open: %+v", s.posts)
	}
	s.do(Pressed{NoteID: 5, Action: "allow"})
	has(t, s.question().Body, "31 more waiting, 1 dropped")
}

// A failed post settles as failed: no snooze, and the next waiting one is posted.
func TestQuestionPostFailed(t *testing.T) {
	s := script(t, true, writerCaps)
	s.do(to("1.1.1.1")).do(to("2.2.2.2"))
	s.do(postFailed{Token: s.m.askToken})
	has(t, s.question().Body, "2.2.2.2")
	if s.do(to("1.1.1.1")); s.m.queue.Stats().Waiting != 1 {
		t.Fatal("the failed question was snoozed")
	}
}

// 6.2 to 6.4, 6.11: an answer retracts, sends the rule under a fresh token and snoozes.
func TestAnswerSendsRule(t *testing.T) {
	for action, a := range map[string]ask.Answer{"allow": ask.Allow, "block": ask.Block} {
		s := script(t, true, writerCaps)
		s.shown(ev("deny-default"), 5)
		q, _ := s.m.queue.Open()
		tok := s.m.nextToken + 1
		s.do(Pressed{NoteID: 5, Action: action})
		want := send{Token: tok, Req: ask.RuleFor(q, a, s.at)}
		if !reflect.DeepEqual(s.sends, []send{want}) || !reflect.DeepEqual(s.retracts, []retract{{NoteID: 5}}) ||
			s.m.pending[tok] != q.Key || s.m.openNote != 0 {
			t.Fatalf("%s: sends %+v retracts %+v pending %v openNote %d", action, s.sends, s.retracts, s.m.pending, s.m.openNote)
		}
		if s.do(ev("deny-default")); len(s.posts) != 0 {
			t.Fatalf("%s: answered key asked again at once", action)
		}
	}
}

// 6.11: a press for another note, an unknown action or a note not yet posted writes nothing.
func TestAnswerOtherNoteIgnored(t *testing.T) {
	s := script(t, true, writerCaps).do(ev("deny-default"))
	for i, p := range []Pressed{{NoteID: 0, Action: "allow"}, {NoteID: 5, Action: "allow"}, // not posted yet
		{NoteID: 99, Action: "allow"}, {NoteID: 5, Action: "default"}, {NoteID: 5}} {
		if i == 2 {
			s.do(posted{Token: s.m.askToken, NoteID: 5})
		}
		if s.do(p); len(s.sends)+len(s.retracts) != 0 || (s.m.openNote == 5) != (i >= 2) {
			t.Fatalf("%+v wrote: %+v %+v", p, s.sends, s.retracts)
		}
	}
}

// 6.7 to 6.9: the daemon's sentence or error becomes a notice; an error lifts the snooze, the
// operator refusal makes the tray a reader; an unknown token is ignored.
func TestAnswerOutcomes(t *testing.T) {
	for _, a := range []client.Answered{{Text: "added rule 14 for firefox"}, {Err: "rule.add: bad port"},
		{Err: client.NoAnswer}, {Err: "rule.add: write requires the operator", Role: true}} {
		s := script(t, true, writerCaps)
		s.shown(ev("deny-default"), 5)
		s.do(Pressed{NoteID: 5, Action: "allow"})
		tok := s.sends[0].Token
		if s.do(client.Answered{Token: tok + 100, Text: "other"}); len(s.posts) != 0 {
			t.Fatal("an unknown token posted")
		}
		a.Token = tok
		if s.do(a); len(s.posts) != 1 || s.posts[0].Note.Actions != nil || len(s.m.pending) != 0 || s.m.writer == a.Role {
			t.Fatalf("%+v: posts %+v pending %v writer %v", a, s.posts, s.m.pending, s.m.writer)
		}
		has(t, s.posts[0].Note.Body, a.Text+a.Err)
		if s.do(ev("deny-default")); (len(s.posts) == 1) != (a.Err != "") { // asks again only after an error
			t.Fatalf("%+v: asked again %v", a, s.posts)
		}
		if a.Role && s.question().Actions != nil {
			t.Fatal("a reader's question has actions")
		}
	}
}

// 6.5, 6.9, 8.6: a reader's, an unknown program's and a buttonless service's notes have no actions
// and say why; a press on them writes nothing, even after buttons appear (Capabilities flip).
func TestReaderAndUnanswerableQuestion(t *testing.T) {
	unknown := ev("deny-default")
	unknown.Event.Program, unknown.Event.Path = ask.Unknown, ""
	writers, caps := []bool{false, true, true}, []Capabilities{writerCaps, writerCaps, {Available: true}}
	events := []client.EventLine{ev("deny-default"), unknown, ev("deny-default")}
	for i, says := range []string{"only the operator can decide", "the program cannot be identified", "Protocol: tcp"} {
		s := script(t, writers[i], caps[i])
		n := s.shown(events[i], 5)
		has(t, n.Body, says)
		if s.do(writerCaps).do(Pressed{NoteID: 5, Action: "block"}); n.Actions != nil || len(s.sends) != 0 {
			t.Fatalf("%q: %+v sends %+v", says, n, s.sends)
		}
	}
}

// 5.10, 8.6: capabilities are taken as they come; paused, or without a notification service,
// nothing asks, waits or gives notice.
func TestCapabilitiesGate(t *testing.T) {
	paused, none := script(t, true, writerCaps), script(t, true, Capabilities{})
	paused.m.paused = true
	st := running()
	st.Kill = true
	for i, s := range []*sc{paused, none} {
		if s.do(ev("deny-default")); len(s.posts) != 0 || s.m.queue.Stats().Waiting != 0 {
			t.Fatalf("%d asked: %+v", i, s.posts)
		}
	}
	if none.do(client.Facts{Status: st}); len(none.posts) != 0 || none.m.canNotify || none.m.canAct {
		t.Fatalf("notice without a service: %+v", none.posts)
	}
	if none.do(writerCaps); !none.m.canNotify || !none.m.canAct {
		t.Fatal("capabilities not taken")
	}
}
