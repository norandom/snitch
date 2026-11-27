package main

import (
	"bytes"
	"errors"
	"io/fs"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/lsm"
	"github.com/norandom/snitch/internal/trial"
)

func fakeHookRead(files map[string][]byte, errs map[string]error) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		if err, ok := errs[path]; ok {
			return nil, err
		}
		if b, ok := files[path]; ok {
			return b, nil
		}
		return nil, fs.ErrNotExist
	}
}

type hookFactCase struct {
	name string
	read func(string) ([]byte, error)
	want api.HookStatus
}

func hookFactCases() []hookFactCase {
	cfgYes, cfgNo := []byte("CONFIG_BPF_LSM=y\n"), []byte("# CONFIG_BPF_LSM is not set\n")
	rel, grubYes, grubNo := []byte("7.3.4-2-t2\n"), []byte("\tlinux\t/vmlinuz lsm=apparmor,bpf\n"), []byte("\tlinux\t/vmlinuz quiet\n")
	return []hookFactCase{
		{"active", fakeHookRead(map[string][]byte{lsm.ListPath: []byte("lockdown,apparmor,bpf\n")}, nil),
			api.HookStatus{State: api.HookActive, Reason: (lsm.Hook{State: lsm.Active}).Sentence()}},
		{"inactive pending", fakeHookRead(map[string][]byte{
			lsm.ListPath: []byte("lockdown,apparmor\n"), "/proc/sys/kernel/osrelease": rel,
			"/boot/config-7.3.4-2-t2": cfgYes, "/boot/grub/grub.cfg": grubYes,
		}, nil), api.HookStatus{State: api.HookInactive, Pending: true, Reason: (lsm.Hook{State: lsm.Inactive, Pending: true, CanTell: true}).Sentence()}},
		{"inactive not configured", fakeHookRead(map[string][]byte{
			lsm.ListPath: []byte("lockdown,apparmor\n"), "/proc/sys/kernel/osrelease": rel,
			"/boot/config-7.3.4-2-t2": cfgYes, "/boot/grub/grub.cfg": grubNo,
		}, nil), api.HookStatus{State: api.HookInactive, Reason: (lsm.Hook{State: lsm.Inactive, CanTell: true}).Sentence()}},
		{"inactive unsupported", fakeHookRead(map[string][]byte{
			lsm.ListPath: []byte("lockdown,apparmor\n"), "/proc/sys/kernel/osrelease": rel,
			"/boot/config-7.3.4-2-t2": cfgNo,
		}, nil), api.HookStatus{State: api.HookInactive, Unsupported: true, Reason: (lsm.Hook{State: lsm.Inactive, Unsupported: true}).Sentence()}},
		{"inactive cannot tell", fakeHookRead(
			map[string][]byte{lsm.ListPath: []byte("lockdown,apparmor\n"), "/proc/sys/kernel/osrelease": rel, "/boot/config-7.3.4-2-t2": cfgYes},
			map[string]error{"/boot/grub/grub.cfg": fs.ErrPermission},
		), api.HookStatus{State: api.HookInactive, Reason: (lsm.Hook{State: lsm.Inactive}).Sentence()}},
		{"unknown", fakeHookRead(nil, map[string]error{lsm.ListPath: errors.New("open /sys/kernel/security/lsm: no such file or directory")}),
			api.HookStatus{State: api.HookUnknown, Reason: (lsm.Hook{State: lsm.Unknown}).Sentence()}},
	}
}

func TestHookFactsAllStates(t *testing.T) {
	for _, tc := range hookFactCases() {
		t.Run(tc.name, func(t *testing.T) {
			var logs []string
			d := newAPIDaemon(t, sourceFlag, &logs)
			d.hook = hookCache{read: tc.read, clock: func() time.Time { return t0 }}
			got := d.facts().Hook
			if got == nil || *got != tc.want {
				t.Fatalf("got %+v, want %+v", got, tc.want)
			}
		})
	}
}

func TestHookStatusGuardsInactiveOnlyFlags(t *testing.T) {
	for _, st := range []lsm.State{lsm.Active, lsm.Unknown} {
		got := hookStatus(lsm.Hook{State: st, Pending: true, Unsupported: true})
		if got.Pending || got.Unsupported {
			t.Fatalf("state %s leaked flags: %+v", st, got)
		}
	}
}

func TestHookStartLogsSentenceWithoutOSErrorText(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { (&hookCache{}).start(nil) })
	rel, cfgYes := []byte("7.3.4-2-t2\n"), []byte("CONFIG_BPF_LSM=y\n")
	cases := []struct {
		name string
		read func(string) ([]byte, error)
		want string
	}{
		{"active", fakeHookRead(map[string][]byte{lsm.ListPath: []byte("apparmor,bpf\n")}, nil), (lsm.Hook{State: lsm.Active}).Sentence()},
		{"inactive cannot tell with os error", fakeHookRead(
			map[string][]byte{lsm.ListPath: []byte("apparmor\n"), "/proc/sys/kernel/osrelease": rel, "/boot/config-7.3.4-2-t2": cfgYes},
			map[string]error{"/boot/grub/grub.cfg": errors.New("permission denied: /boot/grub/grub.cfg")},
		), (lsm.Hook{State: lsm.Inactive}).Sentence()},
		{"unknown with os error", fakeHookRead(nil, map[string]error{lsm.ListPath: errors.New("no such file or directory")}),
			(lsm.Hook{State: lsm.Unknown}).Sentence()},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs []string
			c := hookCache{read: tc.read, clock: func() time.Time { return t0 }}
			c.start(func(m string) { logs = append(logs, m) })
			if !slices.Equal(logs, []string{tc.want}) {
				t.Fatalf("logs %q, want %q", logs, []string{tc.want})
			}
			if strings.Contains(logs[0], "no such file") || strings.Contains(logs[0], "permission denied") {
				t.Fatalf("log leaked OS error: %q", logs[0])
			}
		})
	}
}

func ttlHookReader(reads *atomic.Int32, pending *bool) func(string) ([]byte, error) {
	return func(path string) ([]byte, error) {
		switch path {
		case lsm.ListPath:
			reads.Add(1)
			return []byte("apparmor\n"), nil
		case "/proc/sys/kernel/osrelease":
			return []byte("7.3.4\n"), nil
		case "/boot/config-7.3.4":
			return []byte("CONFIG_BPF_LSM=y\n"), nil
		case "/boot/grub/grub.cfg":
			if *pending {
				return []byte("\tlinux /vmlinuz lsm=apparmor,bpf\n"), nil
			}
			return []byte("\tlinux /vmlinuz quiet\n"), nil
		}
		return nil, fs.ErrNotExist
	}
}

func TestHookCacheTTLAndReprobe(t *testing.T) {
	if hookTTL != 30*time.Second {
		t.Fatalf("hookTTL = %v, want 30s", hookTTL)
	}
	now := t0
	var reads atomic.Int32
	pending := false
	c := hookCache{read: ttlHookReader(&reads, &pending), clock: func() time.Time { return now }}
	c.start(func(string) {})
	if reads.Load() != 1 {
		t.Fatalf("start reads = %d, want 1", reads.Load())
	}
	pending = true
	now = t0.Add(29 * time.Second)
	if h := c.now(); h.Pending || reads.Load() != 1 {
		t.Fatalf("within TTL: got %+v, reads=%d", h, reads.Load())
	}
	now = t0.Add(31 * time.Second)
	if h := c.now(); !h.Pending || reads.Load() != 2 {
		t.Fatalf("past TTL: got %+v, reads=%d", h, reads.Load())
	}
}

func TestHookCacheZeroAndConcurrent(t *testing.T) {
	var mu sync.Mutex
	now := t0
	var reads atomic.Int32
	c := hookCache{
		read: func(path string) ([]byte, error) {
			if path == lsm.ListPath {
				reads.Add(1)
				return []byte("apparmor,bpf\n"), nil
			}
			return nil, fs.ErrNotExist
		},
		clock: func() time.Time {
			mu.Lock()
			defer mu.Unlock()
			return now
		},
	}

	if h := c.now(); h.State != lsm.Active || reads.Load() != 1 {
		t.Fatalf("zero cache first now: %+v reads=%d", h, reads.Load())
	}
	var wg sync.WaitGroup
	for i := range 16 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%4 == 0 {
				mu.Lock()
				now = now.Add(15 * time.Second)
				mu.Unlock()
			}
			if h := c.now(); h.State != lsm.Active {
				t.Errorf("concurrent now: %+v", h)
			}
		}(i)
	}
	wg.Wait()
}

type preserveCase struct {
	name      string
	file      func(trial.Store) string
	raw       []byte
	read      func(string) ([]byte, error)
	kill      bool
	wantState string
}

func TestHookInactiveAndUnknownPreserveModeKillAndStore(t *testing.T) {
	trialRaw := []byte("start=2026-10-10T11:55:00Z\nend=2026-10-10T12:30:00Z\nboot=this-boot\n")
	keptRaw := []byte("kept=2026-10-09T10:00:00Z\n")
	cases := []preserveCase{
		{"inactive keeps open trial", trial.Store.TrialPath, trialRaw,
			fakeHookRead(map[string][]byte{lsm.ListPath: []byte("apparmor\n")}, nil), false, api.HookInactive},
		{"inactive keeps kept enforce", trial.Store.KeptPath, keptRaw,
			fakeHookRead(map[string][]byte{lsm.ListPath: []byte("apparmor\n")}, nil), true, api.HookInactive},
		{"unknown keeps kept enforce and kill", trial.Store.KeptPath, keptRaw,
			fakeHookRead(nil, map[string]error{lsm.ListPath: fs.ErrNotExist}), true, api.HookUnknown},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertHookPreservesState(t, tc)
		})
	}
}

func assertHookPreservesState(t *testing.T, tc preserveCase) {
	t.Helper()
	store := trial.OSStore(t.TempDir())
	path := tc.file(store)
	if err := os.WriteFile(path, tc.raw, 0o600); err != nil {
		t.Fatal(err)
	}
	var logs []string
	d := newAPIDaemon(t, sourceFiles, &logs)
	d.cfg.learn = false
	d.api.kill = func() bool { return tc.kill }
	d.decideOnce(store, "this-boot", t0)
	modeBefore := d.mode.Load()
	d.hook = hookCache{read: tc.read, clock: func() time.Time { return t0 }}
	d.hook.start(d.log)
	st := d.facts()
	if d.mode.Load() != modeBefore || st.Mode != modeEnforce || st.Kill != tc.kill {
		t.Fatalf("mode/kill altered: mode=%d->%d st=%+v", modeBefore, d.mode.Load(), st)
	}
	if st.Hook == nil || st.Hook.State != tc.wantState {
		t.Fatalf("hook = %+v, want %s", st.Hook, tc.wantState)
	}
	if got, err := os.ReadFile(path); err != nil || !bytes.Equal(got, tc.raw) {
		t.Fatalf("store file changed: %q (%v)", got, err)
	}
}
