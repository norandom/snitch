// urgency_test.go: the normal end of the spec's 0..2 urgency byte, which
// notify_test.go could no longer take (its file is at the line cap). The critical
// end (2) is asserted there on a question; the normal end (1) is pinned here on
// a notice, so a future edit cannot drift a plain state notice to silent (0) or
// to critical (2): silent would drop it behind Plasma's quiet mode, critical
// would ring for every rule that reloads.
//
// Fail-safe implications: none. The assertion reads a hint the fake notification
// server of snitest recorded on the private bus.
package sni

import (
	"testing"

	"github.com/norandom/snitch/internal/sni/snitest"
	"github.com/norandom/snitch/internal/tray"
)

// A note without the Urgent flag carries urgency 1, the spec's normal.
func TestNotifyNormalNoteCarriesUrgencyOne(t *testing.T) {
	addr := privateBus(t)
	server := snitest.StartNotifications(t, addr, "body", "body-markup", "actions")
	_, tr, in, _ := trayOn(t, addr)
	wantCapabilities(t, in, tray.Capabilities{Available: true, Actions: true})
	if _, err := tr.Post(tray.Note{Summary: "monitor", Body: "rules are loaded"}); err != nil {
		t.Fatalf("Post: %v", err)
	}
	waitUntil(t, func() bool { return len(server.Calls()) == 1 }, "the server saw no note")
	if v, _ := server.Calls()[0].Hints["urgency"].Value().(byte); v != 1 {
		t.Fatalf("urgency = %v, want 1 (normal, the spec's 0..2 scale)", v)
	}
}
