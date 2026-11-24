// discard_test.go: the closing, timing out, discarding and pausing rules of 3.4 as message
// scripts with a fake time, through sc.do (questions_test.go), so every send of these scripts is
// counted by TestMain as well (only rule.add, 6.12, 8.1). None of these paths may send at all.
package tray

import (
	"reflect"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/client"
)

// mon is an allowed-in-monitor connection to an address without name.
func mon(addr string) client.EventLine {
	e := to(addr)
	e.Event.Verdict = "allow-monitor"
	return e
}

// quiet asserts that the last step sent nothing and retracted exactly the given note ids.
func (s *sc) quiet(what string, retracted ...uint32) {
	s.t.Helper()
	var got []uint32
	for _, r := range s.retracts {
		got = append(got, r.NoteID)
	}
	if len(s.sends) != 0 || !reflect.DeepEqual(got, retracted) {
		s.t.Fatalf("%s: sends %+v retracts %v, want retracts %v", what, s.sends, got, retracted)
	}
}

// waiting asserts the number of waiting questions.
func (s *sc) waiting(what string, n int) {
	s.t.Helper()
	if w := s.m.queue.Stats().Waiting; w != n {
		s.t.Fatalf("%s: %d waiting, want %d", what, w, n)
	}
}

// 5.7, 6.10: open for 59 s nothing happens; at 61 s the tray retracts it, writes nothing,
// snoozes it (left unanswered) and posts the next waiting one.
func TestTimeoutAfterSixtySeconds(t *testing.T) {
	s := script(t, true, writerCaps)
	s.shown(to("1.1.1.1"), 5)
	s.do(to("2.2.2.2"))
	start := s.at
	s.at = start.Add(59 * time.Second)
	if s.do(Tick{}).quiet("59 s"); s.m.openNote != 5 || len(s.posts) != 0 {
		t.Fatalf("59 s: openNote %d posts %+v", s.m.openNote, s.posts)
	}
	s.at = start.Add(61 * time.Second)
	s.do(Tick{}).quiet("61 s", 5)
	has(t, s.question().Body, "2.2.2.2")
	if s.m.openNote != 0 {
		t.Fatalf("61 s: openNote %d", s.m.openNote)
	}
	s.do(to("1.1.1.1")).waiting("timed out key offered again", 0)
}

// 5.4, 6.10: Closed for the open note settles it unanswered (snoozed), writes nothing and
// posts the next; Closed for a foreign id changes nothing.
func TestClosedOpenAndForeign(t *testing.T) {
	s := script(t, true, writerCaps)
	s.shown(to("1.1.1.1"), 5)
	s.do(to("2.2.2.2"))
	before := s.m
	if s.do(Closed{NoteID: 99}).quiet("foreign"); len(s.posts) != 0 || !reflect.DeepEqual(before, s.m) {
		t.Fatalf("foreign Closed changed the model or posted %+v", s.posts)
	}
	s.do(Closed{NoteID: 5}).quiet("closed") // the server closed it: nothing to retract
	has(t, s.question().Body, "2.2.2.2")
	if s.m.openNote != 0 {
		t.Fatalf("closed: openNote %d", s.m.openNote)
	}
	s.do(to("1.1.1.1")).waiting("closed key offered again", 0)
}

// 5.8: a rules reload flushes all three waiting questions (not snoozed), the open one stays.
func TestFlushRulesChanged(t *testing.T) {
	s := script(t, true, writerCaps)
	s.shown(to("1.1.1.1"), 5)
	s.do(to("2.2.2.2")).do(to("3.3.3.3")).do(to("4.4.4.4")).waiting("three", 3)
	s.do(client.StateLine{State: api.State{Type: "state", Mode: "monitor", RulesChanged: true, Reason: "rules reloaded"}})
	s.quiet("rules reloaded")
	if s.waiting("rules reloaded", 0); s.m.openNote != 5 || len(s.posts) != 0 {
		t.Fatalf("open one lost or posts %+v", s.posts)
	}
	s.do(to("2.2.2.2")).waiting("flushed key offered again", 1)
}

// 5.8: monitor to enforce flushes the waiting allow-monitor question, keeps the deny-default
// one, retracts the open allow-monitor question without snoozing it and posts the fitting one.
func TestFlushModeChange(t *testing.T) {
	s := script(t, true, writerCaps)
	s.shown(mon("1.1.1.1"), 5)
	s.do(mon("2.2.2.2")).do(to("3.3.3.3")).waiting("two", 2)
	s.do(client.StateLine{State: api.State{Type: "state", Mode: "enforce", Trial: deadline, Reason: "trial"}})
	s.quiet("mode change", 5)
	if len(s.posts) != 2 || s.posts[0].Note.Actions != nil || s.posts[1].Token != s.m.askToken {
		t.Fatalf("mode change: want the trial notice, then the question: %+v", s.posts)
	}
	has(t, s.posts[1].Note.Body, "3.3.3.3")
	s.waiting("mode change", 0)
	s.do(mon("1.1.1.1")).do(mon("2.2.2.2")).waiting("discarded keys offered again", 2)
}

// 5.8: a mode change first seen in facts (a reconnect) flushes the same way.
func TestFlushModeChangeInFacts(t *testing.T) {
	s := script(t, true, writerCaps)
	s.shown(mon("1.1.1.1"), 5)
	st := running()
	st.Mode, st.Trial = "enforce", deadline
	s.do(client.Facts{Status: st})
	if s.m.openNote != 0 || len(s.retracts) != 1 || s.retracts[0].NoteID != 5 {
		t.Fatalf("facts mode change: openNote %d retracts %+v", s.m.openNote, s.retracts)
	}
}

// 5.8: down retracts the open question and flushes the waiting ones, none snoozed.
func TestFlushDown(t *testing.T) {
	s := script(t, true, writerCaps)
	s.shown(to("1.1.1.1"), 5)
	s.do(to("2.2.2.2"))
	s.do(client.Down{Reason: client.NotRunning}).quiet("down", 5)
	if s.waiting("down", 0); s.m.openNote != 0 || len(s.posts) != 0 {
		t.Fatalf("down: openNote %d posts %+v", s.m.openNote, s.posts)
	}
	s.do(client.Up{}).do(client.Facts{Status: running()})
	has(t, s.do(to("1.1.1.1")).question().Body, "1.1.1.1")
}

// 8.6: the notification service going away drops the open question (nothing to retract on a
// service that is gone) and the waiting ones; none is snoozed.
func TestFlushServiceGone(t *testing.T) {
	s := script(t, true, writerCaps)
	s.shown(to("1.1.1.1"), 5)
	s.do(to("2.2.2.2"))
	if s.do(Capabilities{}).quiet("service gone"); s.m.openNote != 0 || len(s.posts) != 0 {
		t.Fatalf("service gone: openNote %d posts %+v", s.m.openNote, s.posts)
	}
	s.waiting("service gone", 0)
	s.live = map[uint32]bool{} // the service took its notes with it
	has(t, s.do(writerCaps).do(to("1.1.1.1")).question().Body, "1.1.1.1")
}

// 3.4, 5.10: a pause click checks the row, retracts the open question, flushes the waiting
// ones and ignores events; a second click unchecks it and questions ask again, unsnoozed.
func TestPauseToggle(t *testing.T) {
	s := script(t, true, writerCaps)
	s.shown(to("1.1.1.1"), 5)
	s.do(to("2.2.2.2"))
	s.do(MenuClick{Row: RowPause}).quiet("pause", 5)
	if s.waiting("pause", 0); !row(t, Render(s.m, s.at).Menu, RowPause).Checked || s.m.openNote != 0 {
		t.Fatal("pause: row not checked or question still open")
	}
	if s.do(to("3.3.3.3")).quiet("paused event"); len(s.posts) != 0 {
		t.Fatalf("paused: asked %+v", s.posts)
	}
	s.waiting("paused event", 0)
	if s.do(MenuClick{Row: RowPause}).quiet("resume"); row(t, Render(s.m, s.at).Menu, RowPause).Checked || len(s.posts) != 0 {
		t.Fatalf("resume: row checked or posts %+v", s.posts)
	}
	has(t, s.do(to("1.1.1.1")).question().Body, "1.1.1.1")
}

// 5.10: a question whose note is still being posted when the pause comes is retracted as soon
// as its id is known.
func TestPauseInFlight(t *testing.T) {
	s := script(t, true, writerCaps)
	s.do(to("1.1.1.1"))
	tok := s.m.askToken
	s.do(MenuClick{Row: RowPause}).quiet("pause in flight")
	s.do(posted{Token: tok, NoteID: 7}).quiet("posted while paused", 7)
	if s.m.openNote != 0 || s.m.askToken != 0 {
		t.Fatalf("posted while paused: openNote %d askToken %d", s.m.openNote, s.m.askToken)
	}
	if _, open := s.m.queue.Open(); open {
		t.Fatal("posted while paused: question still open")
	}
}
