// apioperator_test.go: the operator file followed at runtime (design "Operator": re-read on
// the 2 s stamp). A change of what acceptance depends on re-reads the file and hands the uid
// to the server; an unchanged file is never re-read.
package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// expect checks the uids handed to the server and the log lines (one fragment each) so far.
func expect(t *testing.T, set []uint32, logs []string, wantSet []uint32, wantLogs ...string) {
	t.Helper()
	if !slices.Equal(set, wantSet) || len(logs) != len(wantLogs) {
		t.Fatalf("set %v logs %q, want %v and %d lines %q", set, logs, wantSet, len(wantLogs), wantLogs)
	}
	for i, want := range wantLogs {
		if !strings.Contains(logs[i], want) {
			t.Fatalf("log %d %q lacks %q", i, logs[i], want)
		}
	}
}

func TestOperatorWatchReReadsOnlyOnAStampChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator")
	if err := os.WriteFile(path, []byte("mc\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	info, statErr := os.FileInfo(fakeInfo{0o644, 0}), error(nil)
	var set []uint32
	var logs []string
	w := &operatorWatch{path: path, stat: func(string) (os.FileInfo, error) { return info, statErr }, lookup: users,
		log: func(m string) { logs = append(logs, m) }, set: func(u uint32) { set = append(set, u) }}
	w.job() // stamps the file as the startup read saw it
	tick := func() {
		t.Helper()
		if err := w.tick(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	tick()
	tick()
	expect(t, set, logs, nil) // unchanged: never re-read
	info = fakeInfo{0o666, 0} // chmod loose: re-read once, refused with one line
	tick()
	tick()
	expect(t, set, logs, []uint32{0}, "0666")
	info = fakeInfo{0o644, 0} // chmod back: the operator again
	tick()
	statErr = fs.ErrNotExist // removed: no operator, no line
	tick()
	statErr, info = nil, fakeInfo{0o644, 1000} // back, but chowned: refused
	tick()
	expect(t, set, logs, []uint32{0, 1000, 0, 0}, "0666", "not owned by root")
}

func TestOperatorWatchContracts(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { _ = (&operatorWatch{}).tick(context.Background()) })
	contracttest.Panics(t, contract.Precondition, func() { (&operatorWatch{path: "/x"}).job() })
}

// The API's job list carries the operator watch next to the server; both end with the context.
func TestApiJobsIncludeTheOperatorWatch(t *testing.T) {
	var logs []string
	d := newAPIDaemon(t, sourceFlag, &logs)
	d.cfg.api = filepath.Join(t.TempDir(), "run", "api.sock")
	js := d.apiJobs(&reloader{st: &d.st})
	want := 2 + len(d.sweepJobs()) // the server, the operator watch, and the byte sweep when counting is on
	if len(js) != want {
		t.Fatalf("want %d jobs (server, operator watch, sweep when counting), got %d (logs %q)", want, len(js), logs)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for i, j := range js {
		if err := j(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("job %d ended with %v", i, err)
		}
	}
}
