package main

import (
	"bytes"
	"errors"
	"flag"
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"

	snitchbpf "github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// testCtl is a command line run as root with fake probes and captured output.
func testCtl(t *testing.T, p probes) (*ctl, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	out, errw := &bytes.Buffer{}, &bytes.Buffer{}
	c := newCtl(out, errw, p)
	c.euid = func() int { return 0 }
	return c, out, errw
}

func TestVerbTableNamesTheSixVerbs(t *testing.T) {
	want := []string{"trial", "keep", "unkeep", "end", "status", "check"}
	for _, name := range want {
		if !isVerb(name) {
			t.Errorf("%q is not a verb", name)
		}
	}
	if len(verbs) != len(want) {
		t.Fatalf("verb table has %d entries, want %d", len(verbs), len(want))
	}
	for _, name := range []string{"foo", "-h", "", "Status", "-mode"} {
		if isVerb(name) {
			t.Errorf("%q must not be a verb", name)
		}
	}
}

func TestVerbDispatchRunsTheHandlerWithTheSharedFlags(t *testing.T) {
	cases := []struct {
		name          string
		args          []string
		wantDir, want string
	}{
		{"defaults", []string{"stub"}, defaultStateDir, defaultStatus},
		{"flags", []string{"stub", "-state-dir", "/tmp/sd", "-status", "/tmp/st"}, "/tmp/sd", "/tmp/st"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got *ctl
			table := []verb{{"stub", func(c *ctl, args []string) int {
				if err := c.parse(args, nil); err != nil {
					t.Fatal(err)
				}
				got = c
				return 7
			}, true}}
			c, _, _ := testCtl(t, probes{})
			if code := dispatch(table, c, tc.args); code != 7 {
				t.Fatalf("exit %d, want the handler's 7", code)
			}
			if got == nil || got.name != "stub" || got.stateDir != tc.wantDir || got.status != tc.want {
				t.Fatalf("handler saw %+v, want stub with state-dir %q status %q", got, tc.wantDir, tc.want)
			}
		})
	}
}

func TestVerbParseRefusesUnknownFlagsAndHelpIsNotAnError(t *testing.T) {
	c, _, errw := testCtl(t, probes{})
	c.name = "stub"
	if err := c.parse([]string{"-bogus"}, nil); err == nil || !strings.Contains(errw.String(), "state-dir") ||
		!strings.Contains(errw.String(), "snitchd stub") {
		t.Fatalf("unknown flag: err %v, usage %q", err, errw.String())
	}
	c, _, _ = testCtl(t, probes{})
	if err := c.parse([]string{"-h"}, nil); !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("-h: got %v, want flag.ErrHelp", err)
	}
}

func TestVerbUnknownWordExitsTwoNamingTheVerbs(t *testing.T) {
	c, _, errw := testCtl(t, probes{})
	if code := dispatch(verbs, c, []string{"foo"}); code != 2 {
		t.Fatalf("exit %d, want 2", code)
	}
	for _, name := range []string{"foo", "trial", "keep", "unkeep", "end", "status", "check"} {
		if !strings.Contains(errw.String(), name) {
			t.Errorf("usage %q does not name %q", errw.String(), name)
		}
	}
}

// TestVerbNeedsRoot: dispatch refuses a non-root caller only for the verbs that need root
// (spec deploy-service, design "check verb": the table's root flag).
func TestVerbNeedsRoot(t *testing.T) {
	cases := []struct {
		name     string
		root     bool
		wantCode int
		wantRun  bool
	}{
		{"root verb refuses", true, 2, false},
		{"rootless verb runs", false, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			called := false
			table := []verb{{"stub", func(*ctl, []string) int { called = true; return 0 }, tc.root}}
			c, _, errw := testCtl(t, probes{})
			c.euid = func() int { return 1000 }
			if code := dispatch(table, c, []string{"stub"}); code != tc.wantCode || called != tc.wantRun {
				t.Fatalf("exit %d called %v, want %d and called %v", code, called, tc.wantCode, tc.wantRun)
			}
			if got := strings.Contains(errw.String(), "run as root"); got != !tc.wantRun {
				t.Fatalf("stderr %q: 'run as root' present %v, want %v", errw.String(), got, !tc.wantRun)
			}
		})
	}
}

// TestVerbDispatchRootGateOnTheRealTable: check is the only verb that runs without root; every
// other verb of the real table still refuses with exit 2 and never reaches its handler.
func TestVerbDispatchRootGateOnTheRealTable(t *testing.T) {
	valid := writeRules(t, "[[program]]\nname = \"ghost\"\npaths = [\"/nonexistent/ghost\"]\n")
	rootless := 0
	for _, v := range verbs {
		c, out, errw := testCtl(t, probes{})
		c.euid = func() int { return 1000 }
		if !v.root {
			rootless++
			if v.name != "check" {
				t.Errorf("%q runs without root; only check may", v.name)
			}
			if code := dispatch(verbs, c, []string{v.name, "-rules", valid}); code != 0 || !strings.Contains(out.String(), "rules:") {
				t.Errorf("%s as uid 1000: exit %d stdout %q stderr %q, want 0 and the summary", v.name, code, out.String(), errw.String())
			}
			continue
		}
		if code := dispatch(verbs, c, []string{v.name}); code != 2 || !strings.Contains(errw.String(), "run as root") {
			t.Errorf("%s as uid 1000: exit %d stderr %q, want 2 and 'run as root'", v.name, code, errw.String())
		}
	}
	if rootless != 1 {
		t.Fatalf("%d rootless verbs, want exactly one (check)", rootless)
	}
}

func TestVerbRunCtlHasTheRealProbesAndUid(t *testing.T) {
	c := newCtl(os.Stdout, os.Stderr, realProbes())
	if c.probes.control == nil || c.probes.kill == nil || c.euid == nil {
		t.Fatalf("a delegate is nil: %+v", c)
	}
	if c.euid() != os.Geteuid() {
		t.Fatalf("euid %d, want %d", c.euid(), os.Geteuid())
	}
}

func TestContractDispatchNeedsAVerb(t *testing.T) {
	c, _, _ := testCtl(t, probes{})
	contracttest.Panics(t, contract.Precondition, func() { dispatch(verbs, c, nil) })
}

func TestContractPinnedReadersNeedTheirDelegates(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { controlFrom(nil, monotonicNow) })
	contracttest.Panics(t, contract.Precondition, func() { controlFrom(fakeLookup(nil), nil) })
	contracttest.Panics(t, contract.Precondition, func() { killFrom(nil) })
}

// fakeLookup answers pinned-map reads from a table; a missing name is an absent pin.
func fakeLookup(maps map[string]any) lookupFn {
	return func(name string, key uint32, out any) error {
		v, ok := maps[name]
		if !ok || key != 0 {
			return fs.ErrNotExist
		}
		switch o := out.(type) {
		case *snitchbpf.SnitchControlState:
			*o = v.(snitchbpf.SnitchControlState)
		case *uint32:
			*o = v.(uint32)
		}
		return nil
	}
}

func TestPinnedAbsentMapsReadNotRunningKillClear(t *testing.T) {
	lookup := fakeLookup(nil)
	age, mode, flags, ok := controlFrom(lookup, func() time.Duration { return time.Hour })()
	if ok || age != 0 || mode != 0 || flags != 0 {
		t.Fatalf("absent control read as %v %d %d %v", age, mode, flags, ok)
	}
	if killFrom(lookup)() {
		t.Fatal("absent kill map read as set")
	}
}

func TestPinnedControlAgeIsOnTheMonotonicClock(t *testing.T) {
	beat := snitchbpf.SnitchControlState{HeartbeatNs: uint64(90 * time.Second), Mode: 1, Flags: 1}
	lookup := fakeLookup(map[string]any{"control": beat})
	age, mode, flags, ok := controlFrom(lookup, func() time.Duration { return 100 * time.Second })()
	if !ok || age != 10*time.Second || mode != 1 || flags != 1 {
		t.Fatalf("got %v %d %d %v, want 10s 1 1 true", age, mode, flags, ok)
	}
}

func TestPinnedKillReadsKeyZero(t *testing.T) {
	cases := []struct {
		name string
		v    uint32
		want bool
	}{{"clear", 0, false}, {"set", 1, true}, {"any nonzero", 7, true}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := killFrom(fakeLookup(map[string]any{"kill": tc.v}))(); got != tc.want {
				t.Fatalf("kill %d read as %v", tc.v, got)
			}
		})
	}
}

func TestPinnedRealMapsReadAsRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	if _, err := os.Stat(pinDir + "/control"); err != nil {
		t.Skip("no pinned control map:", err)
	}
	age, mode, flags, ok := controlState()
	if !ok {
		t.Fatal("control map present but not readable")
	}
	t.Logf("heartbeat age %v mode %d flags %d kill %v", age, mode, flags, killSet())
	if age < 15*time.Second {
		t.Fatalf("heartbeat age %v: a daemon is running, this test expects a stale heartbeat", age)
	}
	if killSet() {
		t.Fatal("kill switch set: the test expects it clear")
	}
}
