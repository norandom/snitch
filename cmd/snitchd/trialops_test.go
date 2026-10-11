// trialops_test.go: the seam's texts equal the CLI's for every refusal and success (design
// "trialOps", Req 5.1 of daemon-api). Every case runs twice on identical state: once through the
// CLI (ctl_verbs_test.go's fake), once through the seam; the CLI's output must be the seam's
// text plus the verb prefix or a newline, and both must leave the same files. The fragments in
// `want` are the ones ctl_verbs_test.go asserts (copied: they are literals inside its tables),
// so a check dropped from the seam fails here even though the CLI delegates to the seam.
package main

import (
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/trial"
)

// opsOf builds the seam the way the CLI does, from the fake's facts.
func opsOf(f *fake) trialOps {
	return trialOps{
		store:     f.m.store(),
		now:       func() time.Time { return tNow },
		boot:      func() (string, error) { return tBoot, f.bootErr },
		learning:  f.rec.Learning,
		kill:      func() bool { return f.kill },
		following: f.rec.Source == "files",
		rules:     func() int { return f.rec.Rules },
	}
}

// opsCase is one verb on one state, driven through the CLI and the seam.
type opsCase struct {
	name, want string
	files      map[string]string
	set        func(*fake)
	args       []string // the CLI's words after the verb
	call       func(trialOps) (string, error)
	code       int // the CLI's exit code; the seam's error must be nil for 0 and usageErr for 2
}

// The states the cases start from (newFake copies them) and the seam calls they make.
var (
	keptFiles = map[string]string{"enforce": "kept=2026-10-10T11:00:00Z\n"}
	liveFiles = map[string]string{"trial": liveTrialFile}
	bothFiles = map[string]string{"trial": liveTrialFile, "enforce": "kept=2026-10-10T11:00:00Z\n"}
)

func opsStart(d time.Duration, extend, yes bool) func(trialOps) (string, error) {
	return func(o trialOps) (string, error) { return o.start(d, extend, yes) }
}

func opsEnd(atBoot bool) func(trialOps) (string, error) {
	return func(o trialOps) (string, error) { return o.end(atBoot) }
}

// deadlineLine is the success line's head; the verb prints the deadline in local time, as the CLI
// test expects.
func deadlineLine(d time.Duration) string {
	return fmt.Sprintf("enforce until %s (%v)", tNow.Add(d).Local().Format(time.RFC3339), d)
}

func trialOpsCases() []opsCase {
	return []opsCase{
		{"trial kill set", "kill switch is set", nil, func(f *fake) { f.kill = true }, []string{"trial", "2m"}, opsStart(2*time.Minute, false, false), 1},
		{"trial not following", "runs with -mode", nil, func(f *fake) { f.rec.Source = "flag" }, []string{"trial", "2m"}, opsStart(2*time.Minute, false, false), 1},
		{"trial learning", "learning never denies", nil, func(f *fake) { f.rec.Learning = true }, []string{"trial", "2m"}, opsStart(2*time.Minute, false, false), 1},
		{"trial kept", "already kept", keptFiles, nil, []string{"trial", "2m"}, opsStart(2*time.Minute, false, false), 1},
		{"trial running", "(5m0s left): snitchd trial -extend", liveFiles, nil, []string{"trial", "2m"}, opsStart(2*time.Minute, false, false), 1},
		{"trial boot id", "boot id: gone", nil, func(f *fake) { f.bootErr = errors.New("boot id: gone") }, []string{"trial", "2m"}, opsStart(2*time.Minute, false, false), 1},
		{"trial below the bound", "between 1m0s and 1h0m0s", nil, nil, []string{"trial", "30s"}, opsStart(30*time.Second, false, false), 2},
		{"trial above the bound", "between 1m0s and 1h0m0s", nil, nil, []string{"trial", "61m"}, opsStart(61*time.Minute, false, false), 2},
		{"trial extend over the bound", "between 1m0s and 1h0m0s", liveFiles, nil, []string{"trial", "-extend", "61m"}, opsStart(61*time.Minute, true, false), 2},
		{"trial default", deadlineLine(10*time.Minute) + "; end early: snitchd end\ntrial file: " + trialPath, nil, nil, []string{"trial"}, opsStart(10*time.Minute, false, false), 0},
		{"trial 90s", deadlineLine(90 * time.Second), nil, nil, []string{"trial", "90s"}, opsStart(90*time.Second, false, false), 0},
		{"trial zero rules -y", deadlineLine(2 * time.Minute), nil, func(f *fake) { f.rec.Rules = 0 }, []string{"trial", "-y", "2m"}, opsStart(2*time.Minute, false, true), 0},
		{"trial extend", "trial extended: " + deadlineLine(20*time.Minute), liveFiles, nil, []string{"trial", "-extend", "20m"}, opsStart(20*time.Minute, true, false), 0},
		{"trial extend without a trial", deadlineLine(3 * time.Minute), nil, nil, []string{"trial", "-extend", "3m"}, opsStart(3*time.Minute, true, false), 0},
		{"keep no trial", "enforce can only be kept during a trial", nil, nil, []string{"keep"}, trialOps.keep, 1},
		{"keep expired", "enforce can only be kept during a trial", map[string]string{"trial": trialBody(tNow.Add(-2*time.Minute), tNow.Add(-time.Minute), tBoot)}, nil, []string{"keep"}, trialOps.keep, 1},
		{"keep running", "enforce kept: " + keptPath + "\nthe way back: rm " + keptPath, liveFiles, nil, []string{"keep"}, trialOps.keep, 0},
		{"keep already kept", "enforce is already kept: " + keptPath + "\nthe way back: rm " + keptPath, keptFiles, nil, []string{"keep"}, trialOps.keep, 0},
		{"unkeep nothing", "nothing was kept", nil, nil, []string{"unkeep"}, trialOps.unkeep, 0},
		{"unkeep kept", "enforce unkept: " + keptPath + " removed (monitor within 5 s)", keptFiles, nil, []string{"unkeep"}, trialOps.unkeep, 0},
		{"unkeep malformed", "enforce unkept", map[string]string{"enforce": "junk"}, nil, []string{"unkeep"}, trialOps.unkeep, 0},
		{"end nothing", "already monitor: no trial, nothing kept", nil, nil, []string{"end"}, opsEnd(false), 0},
		{"end trial", "trial ended: " + trialPath + " removed (monitor within 5 s)", liveFiles, nil, []string{"end"}, opsEnd(false), 0},
		{"end kept", "enforce unkept: " + keptPath + " removed (monitor within 5 s)", keptFiles, nil, []string{"end"}, opsEnd(false), 0},
		{"end both", "trial ended: " + trialPath + " removed; enforce unkept: " + keptPath + " removed (monitor within 5 s)", bothFiles, nil, []string{"end"}, opsEnd(false), 0},
		{"end malformed trial", "trial ended", map[string]string{"trial": "junk"}, nil, []string{"end"}, opsEnd(false), 0},
		{"end at boot nothing", "already monitor", nil, nil, []string{"end", "-at-boot"}, opsEnd(true), 0},
		{"end at boot trial", "trial ended at boot: " + trialPath + " removed", liveFiles, nil, []string{"end", "-at-boot"}, opsEnd(true), 0},
		{"end at boot keeps kept", "trial ended at boot: " + trialPath + " removed; enforce stays kept: " + keptPath, bothFiles, nil, []string{"end", "-at-boot"}, opsEnd(true), 0},
		{"end at boot kept only", "no trial to end at boot; enforce stays kept: " + keptPath, keptFiles, nil, []string{"end", "-at-boot"}, opsEnd(true), 0},
	}
}

func TestTrialOpsTextsMatchCLI(t *testing.T) {
	for _, tc := range trialOpsCases() {
		t.Run(tc.name, func(t *testing.T) {
			cli, seam := newFake(tc.files), newFake(tc.files)
			if tc.set != nil {
				tc.set(cli)
				tc.set(seam)
			}
			code, out, errw := cli.run(t, tc.args...)
			text, err := tc.call(opsOf(seam))
			if code != tc.code {
				t.Fatalf("CLI exit %d out %q err %q, want %d", code, out, errw, tc.code)
			}
			var u usageErr
			if (err != nil) != (tc.code != 0) || errors.As(err, &u) != (tc.code == 2) {
				t.Fatalf("seam text %q err %v, want an error for exit %d (a usageErr for 2)", text, err, tc.code)
			}
			if err != nil {
				text = err.Error()
			}
			if !strings.Contains(text, tc.want) {
				t.Fatalf("text %q lacks %q", text, tc.want)
			}
			sameOutput(t, tc, text, err, out, errw)
			if !reflect.DeepEqual(cli.m.files, seam.m.files) {
				t.Fatalf("files differ: CLI %v, seam %v", cli.m.files, seam.m.files)
			}
		})
	}
}

// sameOutput: the CLI printed the seam's text byte for byte, on the stream its outcome takes.
func sameOutput(t *testing.T, tc opsCase, text string, err error, out, errw string) {
	t.Helper()
	if err != nil {
		if want := "snitchd " + tc.args[0] + ": " + text + "\n"; errw != want || out != "" {
			t.Fatalf("CLI err %q out %q, want %q", errw, out, want)
		}
	} else if out != text+"\n" || errw != "" {
		t.Fatalf("CLI out %q err %q, want the seam's %q", out, errw, text)
	}
}

// The zero-rules gate, seam side: without yes the question comes back as a needsYes error and
// nothing is written; with yes the same seam starts the trial.
func TestTrialOpsZeroRulesNeedsYes(t *testing.T) {
	seam := newFake(nil)
	seam.rec.Rules = 0
	text, err := opsOf(seam).start(2*time.Minute, false, false)
	var q needsYes
	if !errors.As(err, &q) || text != "" || seam.has("trial") {
		t.Fatalf("text %q err %v files %v, want a needsYes error and no trial file", text, err, seam.m.files)
	}
	if want := "No rules are loaded: every connection outside the local network will be denied for 2m0s. Start the trial? [y/N]"; err.Error() != want {
		t.Fatalf("question %q, want %q", err.Error(), want)
	}
	text, err = opsOf(seam).start(2*time.Minute, false, true)
	if err != nil || !strings.HasPrefix(text, "enforce until ") || !seam.has("trial") {
		t.Fatalf("yes: text %q err %v files %v", text, err, seam.m.files)
	}
}

// The zero-rules gate, CLI side: the CLI asks the seam's question word for word and, declined,
// prints its own "declined" without writing.
func TestTrialCLIAsksTheSeamsQuestion(t *testing.T) {
	cli, seam := newFake(nil), newFake(nil)
	cli.rec.Rules, seam.rec.Rules, cli.answer = 0, 0, false
	code, out, errw := cli.run(t, "trial", "2m")
	_, err := opsOf(seam).start(2*time.Minute, false, false)
	if cli.asked != err.Error() {
		t.Fatalf("CLI asked %q, the seam's question is %q", cli.asked, err.Error())
	}
	if code != 1 || errw != "snitchd trial: declined\n" || out != "" || cli.has("trial") {
		t.Fatalf("declined: exit %d out %q err %q files %v", code, out, errw, cli.m.files)
	}
}

func TestContractTrialOpsNeedsAStoreDir(t *testing.T) {
	f := newFake(nil)
	for name, call := range map[string]func(trialOps) (string, error){
		"start":  func(o trialOps) (string, error) { return o.start(2*time.Minute, false, true) },
		"keep":   trialOps.keep,
		"unkeep": trialOps.unkeep,
		"end":    func(o trialOps) (string, error) { return o.end(false) },
	} {
		o := opsOf(f)
		o.store.Dir = ""
		got := contracttest.Panics(t, contract.Precondition, func() { _, _ = call(o) })
		if got.Msg != "trialOps: empty store directory" {
			t.Errorf("%s: violation %q", name, got.Msg)
		}
	}
	o := opsOf(f)
	o.rules = nil
	if got := contracttest.Panics(t, contract.Precondition, func() { _, _ = o.start(2*time.Minute, false, true) }); got.Msg != "trialOps: incomplete delegates" {
		t.Errorf("nil rules: violation %q", got.Msg)
	}
}

// trial.Bounds is the seam's bound, so the API inherits the CLI's 1 to 60 minutes.
func TestTrialOpsBoundsAreTrialBounds(t *testing.T) {
	for _, d := range []time.Duration{trial.MinTrial - time.Second, trial.MaxTrial + time.Second} {
		f := newFake(nil)
		_, err := opsOf(f).start(d, false, true)
		var u usageErr
		if !errors.As(err, &u) || err.Error() != trial.Bounds(d).Error() || f.has("trial") {
			t.Errorf("%v: err %v files %v", d, err, f.m.files)
		}
	}
}
