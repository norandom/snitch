// hook_refusal_test.go: verifies trial and keep refusal when the kernel hook is inactive,
// acceptance when active or unknown, and end/unkeep working in all states without probing.
package main

import (
	"bytes"
	"io/fs"
	"reflect"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/lsm"
	"github.com/norandom/snitch/internal/status"
	"github.com/norandom/snitch/internal/trial"
)

type hookRefusalCase struct {
	name string
	hook lsm.Hook
	read func(string) ([]byte, error)
}

func inactiveRefusalCases() []hookRefusalCase {
	rel, cfgYes := []byte("7.3.4\n"), []byte("CONFIG_BPF_LSM=y\n")
	cfgNo := []byte("# CONFIG_BPF_LSM is not set\n")
	return []hookRefusalCase{
		{"unsupported", lsm.Hook{State: lsm.Inactive, Unsupported: true}, fakeHookRead(map[string][]byte{
			lsm.ListPath: []byte("apparmor\n"), "/proc/sys/kernel/osrelease": rel, "/boot/config-7.3.4": cfgNo,
		}, nil)},
		{"pending", lsm.Hook{State: lsm.Inactive, Pending: true, CanTell: true}, fakeHookRead(map[string][]byte{
			lsm.ListPath: []byte("apparmor\n"), "/proc/sys/kernel/osrelease": rel,
			"/boot/config-7.3.4": cfgYes, "/boot/grub/grub.cfg": []byte("\tlinux /vmlinuz lsm=apparmor,bpf\n"),
		}, nil)},
		{"not configured", lsm.Hook{State: lsm.Inactive, CanTell: true}, fakeHookRead(map[string][]byte{
			lsm.ListPath: []byte("apparmor\n"), "/proc/sys/kernel/osrelease": rel,
			"/boot/config-7.3.4": cfgYes, "/boot/grub/grub.cfg": []byte("\tlinux /vmlinuz quiet\n"),
		}, nil)},
		{"cannot tell", lsm.Hook{State: lsm.Inactive}, fakeHookRead(
			map[string][]byte{lsm.ListPath: []byte("apparmor\n"), "/proc/sys/kernel/osrelease": rel, "/boot/config-7.3.4": cfgYes},
			map[string]error{"/boot/grub/grub.cfg": fs.ErrPermission},
		)},
	}
}

func allowHookCases() []hookRefusalCase {
	return []hookRefusalCase{
		{"active", lsm.Hook{State: lsm.Active}, fakeHookRead(map[string][]byte{lsm.ListPath: []byte("apparmor,bpf\n")}, nil)},
		{"unknown", lsm.Hook{State: lsm.Unknown}, fakeHookRead(nil, map[string]error{lsm.ListPath: fs.ErrNotExist})},
	}
}

func runCLIWithHook(t *testing.T, f *fake, hook func() lsm.Hook, args ...string) (int, string, string) {
	t.Helper()
	control := func() (time.Duration, uint32, uint32, bool) { return f.age, 0, 0, f.mapOK }
	c, out, errw := testCtl(t, probes{control: control, kill: func() bool { return f.kill }})
	c.deps = deps{
		store:      func(dir string) trial.Store { st := f.m.store(); st.Dir = dir; return st },
		dirExists:  func(string) bool { return f.dir },
		readStatus: func(string) (status.Record, error) { return f.rec, f.recErr },
		bootID:     func() (string, error) { return tBoot, f.bootErr },
		now:        func() time.Time { return tNow },
		confirm:    func(q string) bool { f.asked = q; return f.answer },
		hook:       hook,
	}
	code := dispatch(verbs, c, append([]string{args[0], "-state-dir", memDir}, args[1:]...))
	return code, out.String(), errw.String()
}

func copyFiles(m map[string]string) map[string]string {
	out := make(map[string]string, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func assertRefused(t *testing.T, label, text, want string, err error, f *fake, before map[string]string) {
	t.Helper()
	if err == nil || err.Error() != want || text != "" {
		t.Fatalf("%s: text %q err %v, want %q", label, text, err, want)
	}
	if !reflect.DeepEqual(f.m.files, before) {
		t.Fatalf("%s modified store: %v -> %v", label, before, f.m.files)
	}
}

func TestHookRefusalInactiveBlocksTrialAndKeep(t *testing.T) {
	for _, tc := range inactiveRefusalCases() {
		t.Run(tc.name, func(t *testing.T) {
			want := "refused: " + tc.hook.Sentence()
			assertInactiveRefusesVerb(t, tc, nil, want, "trial",
				func(o trialOps) (string, error) { return o.start(2*time.Minute, false, true) },
				api.Request{Type: "trial", Duration: "2m"}, "trial", "2m")
			assertInactiveRefusesVerb(t, tc, liveFiles, want, "keep",
				trialOps.keep, api.Request{Type: "keep"}, "keep")
		})
	}
}

func assertInactiveRefusesVerb(t *testing.T, tc hookRefusalCase, initial map[string]string, want, verb string,
	seamCall func(trialOps) (string, error), req api.Request, cliArgs ...string) {
	t.Helper()
	fSeam, fAPI, fCLI := newFake(initial), newFake(initial), newFake(initial)
	before := copyFiles(fSeam.m.files)

	o := opsOf(fSeam)
	o.hook = func() lsm.Hook { return lsm.Probe(tc.read) }
	text, err := seamCall(o)
	assertRefused(t, "seam "+verb, text, want, err, fSeam, before)

	d := apiDaemonOf(fAPI)
	d.hook = hookCache{read: tc.read, clock: func() time.Time { return tNow }}
	text, err = d.apiTrial(req, 0)
	assertRefused(t, "api "+verb, text, want, err, fAPI, before)

	code, out, errw := runCLIWithHook(t, fCLI, func() lsm.Hook { return lsm.Probe(tc.read) }, cliArgs...)
	if code != 1 || out != "" || errw != "snitchd "+verb+": "+want+"\n" {
		t.Fatalf("cli %s: exit %d out %q err %q, want 1 and %q", verb, code, out, errw, want)
	}
	if !reflect.DeepEqual(fCLI.m.files, before) {
		t.Fatalf("cli %s modified store: %v -> %v", verb, before, fCLI.m.files)
	}
}

func TestHookRefusalCheckedBeforeOtherChecksAndWrites(t *testing.T) {
	h := lsm.Hook{State: lsm.Inactive, Unsupported: true}
	want := "refused: " + h.Sentence()
	f := newFake(nil)
	f.kill, f.rec.Source, f.rec.Learning, f.rec.Rules, f.answer = true, "flag", true, 0, false
	o := opsOf(f)
	o.hook = func() lsm.Hook { return h }

	if _, err := o.start(10*time.Second, false, false); err == nil || err.Error() != want {
		t.Fatalf("start with invalid duration/kill/learning: err %v, want %q", err, want)
	}
	if _, err := o.keep(); err == nil || err.Error() != want {
		t.Fatalf("keep without trial: err %v, want %q", err, want)
	}
	if len(f.m.files) != 0 {
		t.Fatalf("store modified: %v", f.m.files)
	}
}

func TestHookAllowActiveAndUnknownTrialAndKeep(t *testing.T) {
	for _, tc := range allowHookCases() {
		t.Run(tc.name, func(t *testing.T) {
			assertAllowTrialAndKeep(t, tc)
		})
	}
}

func mustHaveKey(t *testing.T, label string, f *fake, key string, err error) {
	t.Helper()
	if err != nil || !f.has(key) {
		t.Fatalf("%s: err %v files %v", label, err, f.m.files)
	}
}

func assertAllowTrialAndKeep(t *testing.T, tc hookRefusalCase) {
	t.Helper()
	fSeam, fAPI, fCLI := newFake(nil), newFake(nil), newFake(nil)
	o := opsOf(fSeam)
	o.hook = func() lsm.Hook { return lsm.Probe(tc.read) }
	_, err := o.start(2*time.Minute, false, true)
	mustHaveKey(t, "seam start", fSeam, "trial", err)
	_, err = o.keep()
	mustHaveKey(t, "seam keep", fSeam, "enforce", err)

	d := apiDaemonOf(fAPI)
	d.hook = hookCache{read: tc.read, clock: func() time.Time { return tNow }}
	_, err = d.apiTrial(api.Request{Type: "trial", Duration: "2m"}, 0)
	mustHaveKey(t, "api start", fAPI, "trial", err)
	_, err = d.apiTrial(api.Request{Type: "keep"}, 0)
	mustHaveKey(t, "api keep", fAPI, "enforce", err)

	hookFn := func() lsm.Hook { return lsm.Probe(tc.read) }
	assertCLIOK(t, fCLI, hookFn, "trial", "trial", "2m")
	assertCLIOK(t, fCLI, hookFn, "enforce", "keep")
}

func assertCLIOK(t *testing.T, f *fake, hook func() lsm.Hook, key string, args ...string) {
	t.Helper()
	if code, _, errw := runCLIWithHook(t, f, hook, args...); code != 0 || !f.has(key) {
		t.Fatalf("cli %v: exit %d err %q files %v", args, code, errw, f.m.files)
	}
}

func TestHookEndAndUnkeepWorkAndNeverProbe(t *testing.T) {
	states := append(allowHookCases(), inactiveRefusalCases()[:2]...)
	for _, tc := range states {
		t.Run(tc.name, func(t *testing.T) {
			assertEndUnkeepNeverProbe(t, tc)
		})
	}
}

func assertEndUnkeepNeverProbe(t *testing.T, tc hookRefusalCase) {
	t.Helper()
	var calls int
	spy := func() lsm.Hook { calls++; return tc.hook }
	readSpy := func(string) ([]byte, error) { calls++; return nil, bytes.ErrTooLarge }
	for _, verb := range []string{"unkeep", "end"} {
		wantTrial := verb == "unkeep"
		f := newFake(bothFiles)
		o := opsOf(f)
		o.hook = spy
		_, err := callEndOrUnkeep(o, verb)
		assertCleared(t, "seam "+verb, f, 0, "", err, wantTrial)

		fCLI := newFake(bothFiles)
		code, _, errw := runCLIWithHook(t, fCLI, spy, verb)
		assertCleared(t, "cli "+verb, fCLI, code, errw, nil, wantTrial)

		fAPI := newFake(bothFiles)
		d := apiDaemonOf(fAPI)
		d.hook = hookCache{read: readSpy}
		_, err = d.apiTrial(api.Request{Type: verb}, 0)
		assertCleared(t, "api "+verb, fAPI, 0, "", err, wantTrial)
	}
	if calls != 0 {
		t.Fatalf("end/unkeep probed hook %d times, want 0", calls)
	}
}

func callEndOrUnkeep(o trialOps, verb string) (string, error) {
	if verb == "unkeep" {
		return o.unkeep()
	}
	return o.end(false)
}

func assertCleared(t *testing.T, label string, f *fake, code int, errw string, err error, wantTrial bool) {
	t.Helper()
	if code != 0 || errw != "" || err != nil || f.has("enforce") || f.has("trial") != wantTrial {
		t.Fatalf("%s: code=%d errw=%q err=%v files=%v (wantTrial=%v)", label, code, errw, err, f.m.files, wantTrial)
	}
}
