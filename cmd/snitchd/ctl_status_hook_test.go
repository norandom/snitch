package main

import (
	"io/fs"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/lsm"
	"github.com/norandom/snitch/internal/status"
	"github.com/norandom/snitch/internal/trial"
)

type statusHookCase struct {
	name string
	read func(string) ([]byte, error)
	want string
}

func statusHookCases() []statusHookCase {
	rel, cfgYes, cfgNo := []byte("7.3.4\n"), []byte("CONFIG_BPF_LSM=y\n"), []byte("# CONFIG_BPF_LSM is not set\n")
	base := func(grub []byte, errs map[string]error) func(string) ([]byte, error) {
		m := map[string][]byte{lsm.ListPath: []byte("apparmor\n"), "/proc/sys/kernel/osrelease": rel, "/boot/config-7.3.4": cfgYes}
		if grub != nil {
			m["/boot/grub/grub.cfg"] = grub
		}
		return fakeHookRead(m, errs)
	}
	return []statusHookCase{
		{"active", fakeHookRead(map[string][]byte{lsm.ListPath: []byte("apparmor,bpf\n")}, nil), "kernel hook active"},
		{"inactive pending", base([]byte("\tlinux /vmlinuz lsm=apparmor,bpf\n"), nil),
			"kernel hook inactive: reboot to activate it; until then connections are neither seen nor blocked"},
		{"inactive not configured", base([]byte("\tlinux /vmlinuz quiet\n"), nil),
			"kernel hook inactive: bpf is not in the kernel's LSM list and the next boot is not configured for it; connections are neither seen nor blocked"},
		{"inactive unsupported", fakeHookRead(map[string][]byte{lsm.ListPath: []byte("apparmor\n"), "/proc/sys/kernel/osrelease": rel, "/boot/config-7.3.4": cfgNo}, nil),
			"kernel hook unavailable: this kernel is built without BPF LSM support, so no reboot can activate it; connections are neither seen nor blocked"},
		{"inactive cannot tell", base(nil, map[string]error{"/boot/grub/grub.cfg": fs.ErrPermission}),
			"kernel hook inactive: connections are neither seen nor blocked; run as root to see whether a reboot is pending"},
		{"unknown", fakeHookRead(nil, map[string]error{lsm.ListPath: fs.ErrNotExist}),
			"kernel hook not checked: the kernel's LSM list could not be read"},
	}
}

func runStatusWithHook(t *testing.T, f *fake, hook func() lsm.Hook, args ...string) (int, string, string) {
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
	code := dispatch(verbs, c, append([]string{"status", "-state-dir", memDir}, args...))
	return code, out.String(), errw.String()
}

func assertHookAfterKill(t *testing.T, out, wantSentence string) {
	t.Helper()
	wantLine := "hook:      " + wantSentence
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	killIdx, hookCount := -1, 0
	for i, l := range lines {
		if strings.HasPrefix(l, "kill:") {
			killIdx = i
		}
		if strings.HasPrefix(l, "hook:") {
			hookCount++
		}
	}
	if hookCount != 1 {
		t.Fatalf("got %d hook: lines, want 1 in:\n%s", hookCount, out)
	}
	if killIdx < 0 || killIdx+1 >= len(lines) {
		t.Fatalf("missing kill: or following line in:\n%s", out)
	}
	if lines[killIdx+1] != wantLine {
		t.Fatalf("line after kill: is %q, want %q\nfull output:\n%s", lines[killIdx+1], wantLine, out)
	}
}

func TestStatusHookLineAcrossAllStates(t *testing.T) {
	for _, tc := range statusHookCases() {
		t.Run(tc.name, func(t *testing.T) {
			hookFn := func() lsm.Hook { return lsm.Probe(tc.read) }

			fRun := newFake(nil)
			fRun.rec = fullRecord
			code, out, errw := runStatusWithHook(t, fRun, hookFn)
			if code != 0 || errw != "" {
				t.Fatalf("running: exit %d err %q, want 0 and empty", code, errw)
			}
			assertHookAfterKill(t, out, tc.want)

			fDown := newFake(nil)
			fDown.mapOK = false
			fDown.recErr = &fs.PathError{Op: "open", Path: "/run/snitch/status", Err: fs.ErrNotExist}
			code, out, errw = runStatusWithHook(t, fDown, hookFn)
			if code != 1 || errw != "" {
				t.Fatalf("down: exit %d err %q, want 1 and empty", code, errw)
			}
			assertHookAfterKill(t, out, tc.want)

			fKept := newFake(map[string]string{"enforce": "kept=2026-10-10T11:00:00Z\n"})
			fKept.rec = fullRecord
			fKept.rec.Mode = "enforce"
			code, out, errw = runStatusWithHook(t, fKept, hookFn)
			if code != 0 || errw != "" {
				t.Fatalf("kept enforce: exit %d err %q, want 0 and empty", code, errw)
			}
			assertHookAfterKill(t, out, tc.want)
		})
	}
}

func TestStatusHookUsageListsHookAfterKill(t *testing.T) {
	f := newFake(nil)
	code, out, errw := f.run(t, "status", "-h")
	if code != 0 || out != "" {
		t.Fatalf("-h: exit %d out %q", code, out)
	}
	if !strings.Contains(errw, "kill: hook: learning:") {
		t.Fatalf("usage %q does not list hook: after kill:", errw)
	}
}

func TestStatusHookProbesOnce(t *testing.T) {
	calls := 0
	f := newFake(nil)
	f.rec = fullRecord
	code, out, errw := runStatusWithHook(t, f, func() lsm.Hook {
		calls++
		return lsm.Hook{State: lsm.Inactive, Pending: true, CanTell: true}
	})
	if code != 0 || errw != "" || calls != 1 {
		t.Fatalf("exit %d err %q calls %d, want 0, empty, 1 (out:\n%s)", code, errw, calls, out)
	}
}
