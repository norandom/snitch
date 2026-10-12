package main

import (
	"errors"
	"os"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/trial"
)

// Req 4.1: a -mode daemon has no follower: trial none, kept false, source flag; everything else
// comes from memory.
func TestFactsOfAFlagDaemon(t *testing.T) {
	var logs []string
	d := newAPIDaemon(t, sourceFlag, &logs)
	got := d.facts()
	if got.DNS == nil || *got.DNS != (api.DNSStatus{On: false, Reason: "unavailable"}) {
		t.Fatalf("DNS: %+v", got.DNS)
	}
	got.DNS = nil
	want := api.Status{Running: true, Pid: os.Getpid(), Version: "dev", Mode: "monitor", Source: "flag", Kill: true, Learning: true,
		Rules:   api.RulesSummary{Programs: 1, Resolved: 0, Executables: 0, Rules: 1, File: "/etc/snitch/rules.toml", Overlay: "/etc/snitch/rules.d/local.toml"},
		Started: "2026-10-10T12:00:00Z", Counting: true}
	if got != want {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

// Req 4.1: the follower's store gives the deadline and kept; the reloader's error is stamped
// when it has a time. Kept follows the store exactly (a mutant reporting kept=true dies here).
func TestFactsOfAFilesDaemon(t *testing.T) {
	var logs []string
	d := newAPIDaemon(t, sourceFiles, &logs)
	m := &memFS{files: map[string]string{}}
	d.follow = &follower{store: m.store()}
	d.mode.Store(uint32(trial.Enforce))
	d.counting = false
	if got := d.facts(); got.Trial != "" || got.Kept || got.Counting || got.Source != "files" || got.Mode != "enforce" {
		t.Fatalf("empty store: %+v", got)
	}
	m.files["/state/trial"] = "start=2026-10-10T12:00:00Z\nend=2026-10-10T12:30:00Z\nboot=this-boot\n"
	m.files["/state/enforce"] = "kept=2026-10-10T12:00:00Z\n"
	rErr := errors.New("local.toml:3: bad verdict")
	d.api.rulesErr = func() (time.Time, error) { return time.Time{}, rErr }
	got := d.facts()
	if got.Trial != "2026-10-10T12:30:00Z" || !got.Kept || got.RulesError != rErr.Error() {
		t.Fatalf("trial %q kept %v rulesError %q", got.Trial, got.Kept, got.RulesError)
	}
	d.api.rulesErr = func() (time.Time, error) { return t0.Add(time.Minute), rErr }
	if got := d.facts(); got.RulesError != "2026-10-10T12:01:00Z: local.toml:3: bad verdict" {
		t.Fatalf("stamped error %q", got.RulesError)
	}
}
