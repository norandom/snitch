//go:build root

// The socket test enters an isolated cgroup and restores the process on cleanup.
package dns

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func testCgroup(t *testing.T) string {
	t.Helper()
	mounts, err := os.ReadFile("/proc/mounts")
	mustProg(t, err)
	root := ""
	for _, line := range strings.Split(string(mounts), "\n") {
		f := strings.Fields(line)
		if len(f) >= 3 && f[2] == "cgroup2" {
			root = f[1]
			break
		}
	}
	if root == "" {
		t.Fatal("no cgroup2 mount")
	}
	original := originalCgroup(t, root)
	path := filepath.Join(root, fmt.Sprintf("snitch-dnsprogtest-%d", os.Getpid()))
	mustProg(t, os.Mkdir(path, 0755))
	t.Cleanup(func() { mustProg(t, os.Remove(path)) })
	t.Cleanup(func() { moveTestProcess(t, original) })
	moveTestProcess(t, path)
	return path
}

func originalCgroup(t *testing.T, root string) string {
	t.Helper()
	data, err := os.ReadFile("/proc/self/cgroup")
	mustProg(t, err)
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "0::") {
			return filepath.Join(root, strings.TrimPrefix(line, "0::"))
		}
	}
	t.Fatal("no unified process cgroup")
	return ""
}

func moveTestProcess(t *testing.T, path string) {
	t.Helper()
	mustProg(t, os.WriteFile(filepath.Join(path, "cgroup.procs"), []byte(fmt.Sprint(os.Getpid())), 0644))
}

func attachTestDNS(t *testing.T, c *ebpf.Collection, path string) {
	t.Helper()
	for _, a := range []struct {
		name string
		kind ebpf.AttachType
	}{{"dns_query", ebpf.AttachCGroupInetEgress}, {"dns_answer", ebpf.AttachCGroupInetIngress}} {
		l, err := link.AttachCgroup(link.CgroupOptions{Path: path, Attach: a.kind, Program: c.Programs[a.name]})
		mustProg(t, err)
		t.Cleanup(func() { mustProg(t, l.Close()) })
	}
}
