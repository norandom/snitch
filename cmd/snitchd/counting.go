package main

import (
	"bufio"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	snitchbpf "github.com/norandom/snitch/internal/bpf"
)

// Byte counting: count_egress on the cgroup2 root adds each packet's length to the bytes map
// by socket cookie. It only counts and always passes; the LSM hooks decide. Any failure here
// is one log line and counting off: the decisions, the heartbeat and the events are never
// affected (Req 3.3). The link is not pinned: it dies with the daemon like the LSM links.

const mountsPath = "/proc/mounts"

// attachCounting attaches count_egress at the cgroup2 root found in /proc/mounts; false
// means counting is off and the reason was logged.
func attachCounting(objs *snitchbpf.SnitchObjects, log func(string)) (link.Link, bool) {
	mounts := func() (io.ReadCloser, error) { return os.Open(mountsPath) }
	attach := func(root string) (link.Link, error) {
		return link.AttachCgroup(link.CgroupOptions{Path: root, Attach: ebpf.AttachCGroupInetEgress, Program: objs.CountEgress})
	}
	return attachCountingWith(mounts, attach, log)
}

// attachCountingWith is attachCounting with the mounts table and the attach injected.
func attachCountingWith(mounts func() (io.ReadCloser, error), attach func(root string) (link.Link, error), log func(string)) (link.Link, bool) {
	l, err := func() (link.Link, error) {
		f, err := mounts()
		if err != nil {
			return nil, err
		}
		defer f.Close()
		root, ok := cgroupRoot(f)
		if !ok {
			return nil, errors.New("no cgroup2 mount in " + mountsPath)
		}
		return attach(root)
	}()
	if err != nil {
		log("byte counting off: " + err.Error())
		return nil, false
	}
	return l, true
}

// cgroupRoot is the mount point of the first cgroup2 filesystem in a mounts table (the third
// field is the type; a v1 "cgroup" mount does not count).
func cgroupRoot(mounts io.Reader) (string, bool) {
	sc := bufio.NewScanner(mounts)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 3 && f[2] == "cgroup2" {
			return f[1], true
		}
	}
	return "", false
}
