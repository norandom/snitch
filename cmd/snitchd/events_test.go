package main

import (
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/api"
)

// The event reader survives a record it cannot decode: it counts and skips it, logs the first
// one only, and handles the next valid record as usual (8.3).
func TestOnRecordSkipsAnUndecodableRecordAndContinues(t *testing.T) {
	var logs []string
	var events []api.Event
	d := &daemon{log: func(m string) { logs = append(logs, m) }}
	d.emit = func(e api.Event) { events = append(events, e) }
	d.st.publish(fakeSnap(t))
	d.onRecord(rawOf(sample(), 1))               // one byte too long
	d.onRecord(rawOf(sample(), 0)[:eventSize-1]) // one byte too short
	d.onRecord(rawOf(sample(), 0))               // valid
	if got := d.undecodable.Load(); got != 2 {
		t.Fatalf("undecodable %d, want 2", got)
	}
	if len(logs) != 1 || !strings.Contains(logs[0], "undecodable") {
		t.Fatalf("want one log line for the kind, got %q", logs)
	}
	if len(events) != 1 || events[0].Pid != 4242 {
		t.Fatalf("the valid record after the bad ones is handled: %+v", events)
	}
}
