// counts_test.go: the counts on a question note are read before Next (2.4 note, 5.6): when the
// last waiting question opens while some were dropped, its note still says so, because the
// queue resets Dropped as soon as nothing waits.
package tray

import (
	"fmt"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/ask"
)

func TestQuestionLastWaitingShowsDropped(t *testing.T) {
	s := script(t, true, writerCaps)
	s.shown(to("1.1.1.1"), 1)
	for i := range ask.MaxWaiting + 1 { // 32 wait, 1 dropped
		s.do(to(fmt.Sprintf("8.8.%d.%d", i/200, i%200+1)))
	}
	for id := uint32(1); id <= ask.MaxWaiting; id++ { // answer until the last waiting one opens
		s.do(Pressed{NoteID: id, Action: "allow"})
		n := s.question()
		s.do(posted{Token: s.m.askToken, NoteID: id + 1})
		if id == ask.MaxWaiting && !strings.Contains(n.Body, "0 more waiting, 1 dropped") {
			t.Fatalf("last waiting question: %q", n.Body)
		}
	}
	if st := s.m.queue.Stats(); st != (ask.Stats{}) {
		t.Fatalf("stats after the last opened: %+v", st)
	}
}
