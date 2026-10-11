// apiwrite_test.go: the trial verbs over the API (design "trialOps", Req 5.1): the daemon's
// side of the seam gives the CLI's texts and refusals for the same state. The reader refusal
// is the server's (api_test.go); here the delegate runs as it would for a writer.
package main

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/rules"
	"github.com/norandom/snitch/internal/trial"
)

// apiDaemonOf is a daemon whose trial facts are the fake's: the follower over its memory
// store with the fake's boot and clock (source files), or no follower (source flag: a -mode
// daemon, whose store would be the state directory), the fake's learning flag, kill switch
// and rule count (a snapshot with that many rules).
func apiDaemonOf(f *fake) *daemon {
	d := &daemon{cfg: config{learn: f.rec.Learning, stateDir: memDir}, log: func(string) {}}
	d.api.kill = func() bool { return f.kill }
	d.st.publish(&snapshot{res: &rules.Resolved{File: &rules.File{Rules: make([]rules.Rule, f.rec.Rules)}}})
	if f.rec.Source == "files" {
		d.follow = &follower{store: f.m.store(), boot: tBoot, now: func() time.Time { return tNow }}
	}
	return d
}

// requestOf turns a CLI case's words into the request the TUI sends; ok is false for a case
// the API does not offer (end -at-boot is the boot unit's alone).
func requestOf(args []string) (api.Request, bool) {
	req := api.Request{Type: args[0]}
	for _, a := range args[1:] {
		switch a {
		case "-extend":
			req.Extend = true
		case "-y":
			req.Yes = true
		case "-at-boot":
			return req, false
		default:
			req.Duration = a
		}
	}
	return req, true
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// Every case of the seam's table, driven through apiTrial on a daemon in the same state: the
// text, the error and the files left must equal the seam's (and so the CLI's). The boot id
// case is skipped: a follower knows its boot, the API cannot fail to read it.
func TestApiWriteTrialTextsMatchTheSeam(t *testing.T) {
	for _, tc := range trialOpsCases() {
		t.Run(tc.name, func(t *testing.T) {
			req, ok := requestOf(tc.args)
			seam, mine := newFake(tc.files), newFake(tc.files)
			if tc.set != nil {
				tc.set(seam)
				tc.set(mine)
			}
			if !ok || seam.bootErr != nil {
				t.Skip("not offered over the API")
			}
			want, werr := tc.call(opsOf(seam))
			got, err := apiDaemonOf(mine).apiTrial(req, 0)
			if got != want || errText(err) != errText(werr) {
				t.Fatalf("api %q / %v, seam %q / %v", got, err, want, werr)
			}
			if !reflect.DeepEqual(mine.m.files, seam.m.files) {
				t.Fatalf("files differ: api %v, seam %v", mine.m.files, seam.m.files)
			}
		})
	}
}

// A daemon started with -mode has no follower: the CLI's sentence, nothing written anywhere.
func TestApiWriteTrialRefusedWithoutAFollower(t *testing.T) {
	f := newFake(nil)
	f.rec.Source = "flag"
	d := apiDaemonOf(f)
	text, err := d.apiTrial(api.Request{Type: "trial", Duration: "2m"}, 0)
	if text != "" || errText(err) != "the daemon runs with -mode, it does not follow trial files" {
		t.Fatalf("text %q err %v", text, err)
	}
}

// Zero rules: without yes the confirm sentence is the error and nothing is written; with yes
// the trial starts (the TUI asks the operator the same question the CLI asks).
func TestApiWriteTrialZeroRulesNeedsYes(t *testing.T) {
	f := newFake(nil)
	f.rec.Rules = 0
	d := apiDaemonOf(f)
	text, err := d.apiTrial(api.Request{Type: "trial", Duration: "2m"}, 0)
	want := "No rules are loaded: every connection outside the local network will be denied for 2m0s. Start the trial? [y/N]"
	if text != "" || errText(err) != want || f.has("trial") {
		t.Fatalf("text %q err %v files %v", text, err, f.m.files)
	}
	text, err = d.apiTrial(api.Request{Type: "trial", Duration: "2m", Yes: true}, 0)
	if err != nil || !strings.HasPrefix(text, "enforce until ") || !f.has("trial") {
		t.Fatalf("yes: text %q err %v files %v", text, err, f.m.files)
	}
}

// The duration follows the CLI's rules: empty is the default, Go syntax only, the seam's bounds.
func TestApiWriteTrialDuration(t *testing.T) {
	cases := []struct{ duration, want string }{
		{"", deadlineLine(trial.DefaultTrial)},
		{"ten", `duration "ten": use Go syntax such as 10m or 90s`},
		{"30s", trial.Bounds(30 * time.Second).Error()},
	}
	for _, c := range cases {
		f := newFake(nil)
		text, err := apiDaemonOf(f).apiTrial(api.Request{Type: "trial", Duration: c.duration}, 0)
		if err != nil {
			text = err.Error()
		}
		if !strings.HasPrefix(text, c.want) {
			t.Errorf("duration %q: got %q, want %q", c.duration, text, c.want)
		}
		if (err == nil) != f.has("trial") {
			t.Errorf("duration %q: err %v, files %v", c.duration, err, f.m.files)
		}
	}
}

// Only the four verbs reach the delegate; anything else is an error, not a panic.
func TestApiWriteTrialUnknownVerb(t *testing.T) {
	if _, err := apiDaemonOf(newFake(nil)).apiTrial(api.Request{Type: "status"}, 0); err == nil || !strings.Contains(err.Error(), "status") {
		t.Fatalf("err %v", err)
	}
}

// The state event on "trial ended at its deadline" carries no deadline: the follower removes
// the spent file before it applies the mode (the event reads the store), while the journal
// keeps its order (follow_test.go pins it).
func TestStateEventAfterTheDeadlineCarriesNoTrial(t *testing.T) {
	x := newFollowFixture(false)
	x.d.follow = x.f
	var events []api.State
	x.d.onMode = func(m trial.Mode, reason string) { events = append(events, x.d.stateEvent(m, reason, false)) }
	x.startTrial(5, "this-boot")
	x.ticks(t, 2)
	x.now = x.now.Add(5 * time.Minute)
	x.ticks(t, 2)
	if len(events) != 2 || events[0].Mode != "enforce" || events[0].Trial != "2026-10-10T12:05:00Z" {
		t.Fatalf("events %+v", events)
	}
	if e := events[1]; e.Mode != "monitor" || e.Trial != "" || e.Reason != "trial ended at its deadline" {
		t.Fatalf("the spent deadline went on the wire: %+v", e)
	}
	if _, left := x.m.files["/state/trial"]; left {
		t.Fatal("the spent trial file must be gone")
	}
}
