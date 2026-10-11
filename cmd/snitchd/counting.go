package main

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	snitchbpf "github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
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

// The sweep (Req 3.2, 3.4): every sweepEvery the bytes map is read whole and the growth per
// cookie since the last sweep goes to the table, which joins it to the connection the cookie
// belongs to or parks it as unknown. The sweep never writes the map; the kernel LRU evicts on
// its own, and an entry it recreated shows as a value below the remembered one.

const (
	sweepEvery  = 2 * time.Second  // the join period (bytes visible within 5 s, Req 3.2)
	sweepForget = 10 * time.Minute // a cookie unseen this long leaves the Go map
	sweepBatch  = 256              // entries per BPF_MAP_LOOKUP_BATCH call
)

// byteReader hands every (cookie, count) of the bytes map to fn; the map is the real one, a
// fake stands in for tests.
type byteReader interface {
	each(fn func(cookie uint64, v snitchbpf.SnitchByteCount)) error
}

// mapReader reads the bytes map in batches, one element at a time where the kernel has no
// batch lookup.
type mapReader struct{ m *ebpf.Map }

func (r mapReader) each(fn func(uint64, snitchbpf.SnitchByteCount)) error {
	err := r.batch(fn)
	if errors.Is(err, ebpf.ErrNotSupported) {
		return r.iterate(fn)
	}
	return err
}

func (r mapReader) batch(fn func(uint64, snitchbpf.SnitchByteCount)) error {
	var cursor ebpf.MapBatchCursor
	keys := make([]uint64, sweepBatch)
	vals := make([]snitchbpf.SnitchByteCount, sweepBatch)
	for {
		n, err := r.m.BatchLookup(&cursor, keys, vals, nil)
		for i := 0; i < n; i++ {
			fn(keys[i], vals[i])
		}
		if errors.Is(err, ebpf.ErrKeyNotExist) { // the end, after the partial last batch
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (r mapReader) iterate(fn func(uint64, snitchbpf.SnitchByteCount)) error {
	var (
		cookie uint64
		v      snitchbpf.SnitchByteCount
	)
	it := r.m.Iterate()
	for it.Next(&cookie, &v) {
		fn(cookie, v)
	}
	return it.Err()
}

// seen is a cookie's value at the last sweep that saw it.
type seen struct {
	bytes uint64
	at    time.Time
}

// sweeper turns the map's running totals into deltas for the table.
type sweeper struct {
	read    byteReader
	last    map[uint64]seen
	add     func(cookie, delta uint64, at time.Time)
	prune   func(time.Time)
	now     func() time.Time
	log     func(string)
	failing bool // a read error was logged; the next good read ends the streak
}

func newSweeper(read byteReader, add func(cookie, delta uint64, at time.Time), prune func(time.Time),
	now func() time.Time, log func(string)) *sweeper {
	contract.Require(read != nil && add != nil && prune != nil && now != nil && log != nil, "newSweeper: nil delegate")
	return &sweeper{read: read, last: map[uint64]seen{}, add: add, prune: prune, now: now, log: log}
}

// tick is one sweep. It never ends the job: a read error is one log line per streak and the
// table is still pruned, so the next tick tries again (Req 3.3).
func (s *sweeper) tick(context.Context) error {
	now := s.now()
	err := s.read.each(func(cookie uint64, v snitchbpf.SnitchByteCount) {
		delta := v.Bytes // a cookie first seen, or recreated by the LRU below its last value
		if prev, known := s.last[cookie]; known && v.Bytes >= prev.bytes {
			delta = v.Bytes - prev.bytes
		}
		if delta > 0 {
			s.add(cookie, delta, now)
		}
		s.last[cookie] = seen{bytes: v.Bytes, at: now}
	})
	if s.noteRead(err) {
		s.forget(now)
	}
	s.prune(now)
	return nil
}

// noteRead logs the first error of a streak and reports whether the read went through.
func (s *sweeper) noteRead(err error) bool {
	if err == nil {
		s.failing = false
		return true
	}
	if !s.failing {
		s.log("byte sweep: " + err.Error())
		s.failing = true
	}
	return false
}

// forget drops cookies no complete read has shown for sweepForget.
func (s *sweeper) forget(now time.Time) {
	for cookie, prev := range s.last {
		if now.Sub(prev.at) >= sweepForget {
			delete(s.last, cookie)
		}
	}
}

// sweepJobs is the sweep over the real map for the API's table: nothing while counting is off
// or the API is not installed (then no table wants the bytes).
func (d *daemon) sweepJobs() []jobs.Job {
	if !d.counting || d.api.table == nil {
		return nil
	}
	s := newSweeper(mapReader{d.objs.Bytes}, d.api.table.AddBytes, d.api.table.Prune, time.Now, d.log)
	return []jobs.Job{jobs.Every(sweepEvery, s.tick)}
}
