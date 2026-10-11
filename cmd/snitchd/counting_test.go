package main

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/cilium/ebpf/link"

	"github.com/norandom/snitch/internal/api"
	snitchbpf "github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

const fakeMounts = `sysfs /sys sysfs rw,nosuid 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,memory 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0
bpf /sys/fs/bpf bpf rw,nosuid 0 0
`

func TestCountingRootIsTheCgroup2MountNotV1(t *testing.T) {
	root, ok := cgroupRoot(strings.NewReader(fakeMounts))
	if !ok || root != "/sys/fs/cgroup" {
		t.Fatalf("got %q %v", root, ok)
	}
	v1only := strings.ReplaceAll(fakeMounts, "cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0\n", "")
	if root, ok := cgroupRoot(strings.NewReader(v1only)); ok || root != "" {
		t.Fatalf("a v1 cgroup mount is not a root: %q %v", root, ok)
	}
	if _, ok := cgroupRoot(strings.NewReader("broken line\n")); ok {
		t.Fatal("a short line is skipped, not a root")
	}
}

type fakeMountsReader struct{ s string }

func (f fakeMountsReader) open() (io.ReadCloser, error) {
	if f.s == "" {
		return nil, errors.New("open /proc/mounts: EACCES")
	}
	return io.NopCloser(strings.NewReader(f.s)), nil
}

// Counting never decides and never stops the daemon: every failure is one log line starting
// with "byte counting off: " and a false, the success path hands the link back (Req 3.3).
func TestAttachCountingLogsOffOnEveryFailure(t *testing.T) {
	noAttach := func(string) (link.Link, error) { t.Fatal("attach must not run without a root"); return nil, nil }
	cases := []struct {
		name   string
		mounts string
		attach func(string) (link.Link, error)
		want   string
	}{
		{"mounts unreadable", "", noAttach, "byte counting off: open /proc/mounts: EACCES"},
		{"no cgroup2", "bpf /sys/fs/bpf bpf rw 0 0\n", noAttach, "byte counting off: no cgroup2 mount in /proc/mounts"},
		{"attach refused", fakeMounts, func(string) (link.Link, error) { return nil, errors.New("link: EPERM") }, "byte counting off: link: EPERM"},
	}
	for _, c := range cases {
		var logs []string
		l, ok := attachCountingWith(fakeMountsReader{c.mounts}.open, c.attach, func(m string) { logs = append(logs, m) })
		if ok || l != nil || len(logs) != 1 || logs[0] != c.want {
			t.Fatalf("%s: ok %v link %v logs %q", c.name, ok, l, logs)
		}
	}
}

func TestAttachCountingAttachesAtTheCgroup2Root(t *testing.T) {
	var got string
	attach := func(root string) (link.Link, error) { got = root; return nil, nil }
	_, ok := attachCountingWith(fakeMountsReader{fakeMounts}.open, attach, func(m string) { t.Fatalf("unexpected log %q", m) })
	if !ok || got != "/sys/fs/cgroup" {
		t.Fatalf("ok %v root %q", ok, got)
	}
}

// The sweep (Req 3.2, 3.4): every 2 s the bytes map is read and the delta per cookie since the
// last sweep goes to the table; a lower value means the kernel LRU recreated the entry, so the
// delta is the current value, never a wrapped subtraction.

type fakeBytes struct {
	rows map[uint64]uint64
	err  error
}

func (f *fakeBytes) each(fn func(uint64, snitchbpf.SnitchByteCount)) error {
	if f.err != nil {
		return f.err
	}
	for c, b := range f.rows {
		fn(c, snitchbpf.SnitchByteCount{Bytes: b, Pkts: 1, LastNs: 1})
	}
	return nil
}

type sweepRig struct {
	s      *sweeper
	bytes  *fakeBytes
	clock  time.Time
	adds   map[uint64]uint64
	addN   int
	prunes int
	logs   []string
}

func newSweepRig(t *testing.T) *sweepRig {
	t.Helper()
	r := &sweepRig{bytes: &fakeBytes{rows: map[uint64]uint64{}}, clock: time.Unix(1_700_000_000, 0), adds: map[uint64]uint64{}}
	r.s = newSweeper(r.bytes,
		func(cookie, delta uint64, at time.Time) {
			if at != r.clock {
				t.Fatalf("add at %v, sweep at %v", at, r.clock)
			}
			r.adds[cookie] += delta
			r.addN++
		},
		func(at time.Time) { r.prunes++ },
		func() time.Time { return r.clock },
		func(m string) { r.logs = append(r.logs, m) })
	return r
}

func (r *sweepRig) tick(t *testing.T, advance time.Duration) {
	t.Helper()
	r.clock = r.clock.Add(advance)
	if err := r.s.tick(context.Background()); err != nil {
		t.Fatalf("tick: %v", err)
	}
}

func TestSweepDeltasPerCookie(t *testing.T) {
	r := newSweepRig(t)
	r.bytes.rows[7] = 100
	r.tick(t, 0)
	if r.adds[7] != 100 || r.addN != 1 {
		t.Fatalf("first sight is the full value: %v (%d adds)", r.adds, r.addN)
	}
	r.bytes.rows[7] = 160
	r.tick(t, 2*time.Second)
	if r.adds[7] != 160 || r.addN != 2 {
		t.Fatalf("growth adds the delta: %v (%d adds)", r.adds, r.addN)
	}
	r.tick(t, 2*time.Second)
	if r.adds[7] != 160 || r.addN != 2 {
		t.Fatalf("an unchanged value adds nothing: %v (%d adds)", r.adds, r.addN)
	}
	r.bytes.rows[7] = 40 // below the last value: the LRU evicted and recreated the entry
	r.tick(t, 2*time.Second)
	if r.adds[7] != 200 || r.addN != 3 {
		t.Fatalf("a lower value is a recreated entry, delta is the current value: %v (%d adds)", r.adds, r.addN)
	}
	if r.prunes != 4 {
		t.Fatalf("prune runs once per tick: %d after 4 ticks", r.prunes)
	}
}

func TestSweepForgetsCookiesIdleTenMinutes(t *testing.T) {
	r := newSweepRig(t)
	r.bytes.rows[9] = 100
	r.tick(t, 0)
	delete(r.bytes.rows, 9)
	r.tick(t, 9*time.Minute)
	if _, kept := r.s.last[9]; !kept {
		t.Fatal("a cookie unseen for 9 minutes is still remembered")
	}
	r.tick(t, 2*time.Minute)
	if _, kept := r.s.last[9]; kept {
		t.Fatal("a cookie unseen for 11 minutes is forgotten")
	}
	r.bytes.rows[9] = 100 // same value as before: a remembered cookie would add nothing
	r.tick(t, 2*time.Second)
	if r.adds[9] != 200 {
		t.Fatalf("after forgetting, a reappearance is a first sight: %v", r.adds)
	}
}

func TestSweepReadErrorLoggedOncePerStreakAndContinues(t *testing.T) {
	r := newSweepRig(t)
	r.bytes.err = errors.New("lookup: EINTR")
	r.tick(t, 0)
	r.tick(t, 2*time.Second)
	if len(r.logs) != 1 || r.logs[0] != "byte sweep: lookup: EINTR" || r.prunes != 2 {
		t.Fatalf("one line per streak, prune still runs: %q prunes %d", r.logs, r.prunes)
	}
	r.bytes.err = nil
	r.bytes.rows[1] = 5
	r.tick(t, 2*time.Second)
	if r.adds[1] != 5 {
		t.Fatalf("the sweep continues after a failed read: %v", r.adds)
	}
	r.bytes.err = errors.New("lookup: EINTR")
	r.tick(t, 2*time.Second)
	if len(r.logs) != 2 {
		t.Fatalf("a new streak logs again: %q", r.logs)
	}
}

func TestContractSweeperRequiresDelegates(t *testing.T) {
	read, add, prune := &fakeBytes{}, func(uint64, uint64, time.Time) {}, func(time.Time) {}
	now, log := time.Now, func(string) {}
	contracttest.Panics(t, contract.Precondition, func() { newSweeper(nil, add, prune, now, log) })
	contracttest.Panics(t, contract.Precondition, func() { newSweeper(read, nil, prune, now, log) })
	contracttest.Panics(t, contract.Precondition, func() { newSweeper(read, add, nil, now, log) })
	contracttest.Panics(t, contract.Precondition, func() { newSweeper(read, add, prune, nil, log) })
	contracttest.Panics(t, contract.Precondition, func() { newSweeper(read, add, prune, now, nil) })
}

func TestSweepJobsOnlyWithCountingAndATable(t *testing.T) {
	if js := (&daemon{}).sweepJobs(); js != nil {
		t.Fatalf("counting off: %d jobs", len(js))
	}
	if js := (&daemon{counting: true}).sweepJobs(); js != nil {
		t.Fatalf("no table (no -api): %d jobs", len(js))
	}
	off := &daemon{counting: false, log: func(string) {}, api: apiState{table: api.NewTable(time.Now)}}
	if js := off.sweepJobs(); js != nil {
		t.Fatalf("counting off with a table: %d jobs, want none (the fail-safe gate)", len(js))
	}
	d := &daemon{counting: true, log: func(string) {}, api: apiState{table: api.NewTable(time.Now)}}
	if js := d.sweepJobs(); len(js) != 1 {
		t.Fatalf("counting with the API: %d jobs", len(js))
	}
}
