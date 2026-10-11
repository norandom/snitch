package main

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/cilium/ebpf/link"
)

const fakeMounts = `sysfs /sys sysfs rw,nosuid 0 0
cgroup /sys/fs/cgroup/memory cgroup rw,memory 0 0
cgroup2 /sys/fs/cgroup cgroup2 rw,nosuid,nodev,noexec,relatime,nsdelegate 0 0
bpf /sys/fs/bpf bpf rw,nosuid 0 0
`

func TestCgroupRootIsTheCgroup2MountNotV1(t *testing.T) {
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
