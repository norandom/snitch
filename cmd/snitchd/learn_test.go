package main

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/rules"
)

type fakeWriter struct {
	files []*rules.File
	fail  bool
}

func (w *fakeWriter) write(string, *rules.File) error {
	if w.fail {
		return errors.New("disk full")
	}
	w.files = append(w.files, nil)
	return nil
}

func curlObs(at time.Time) rules.Observation {
	return rules.Observation{Path: "/usr/bin/curl", Exe: rules.ExeKey{Ino: 1, Dev: 1}, Addr: netip.MustParseAddr("1.1.1.1"), Proto: rules.TCP, Port: 443, At: at}
}

func TestLearnerFlushWritesOnlyWhenDirty(t *testing.T) {
	w := &fakeWriter{}
	l, err := newLearner(filepath.Join(t.TempDir(), "none.toml"), w.write, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	l.flush()
	if len(w.files) != 0 {
		t.Fatal("nothing observed, nothing written")
	}
	l.observe(curlObs(time.Now()))
	l.flush()
	l.flush()
	if len(w.files) != 1 {
		t.Fatalf("one observation, one write, got %d", len(w.files))
	}
}

func TestLearnerFlushLogsAFailureAndRetriesLater(t *testing.T) {
	w := &fakeWriter{fail: true}
	var logs []string
	l, _ := newLearner(filepath.Join(t.TempDir(), "none.toml"), w.write, func(m string) { logs = append(logs, m) })
	l.observe(curlObs(time.Now()))
	if l.flush() == nil || len(logs) != 1 || !strings.Contains(logs[0], "not written") {
		t.Fatalf("want a logged failure, got %q", logs)
	}
	w.fail = false
	if l.flush() != nil || len(w.files) != 1 {
		t.Fatal("the next flush must retry the same data")
	}
}

func TestLearnerJobFlushesOnceMoreWhenTheRunEnds(t *testing.T) {
	w := &fakeWriter{}
	l, _ := newLearner(filepath.Join(t.TempDir(), "none.toml"), w.write, func(string) {})
	l.observe(curlObs(time.Now()))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := l.job()(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("the job ends with the context, got %v", err)
	}
	if len(w.files) != 1 {
		t.Fatalf("want the final flush, got %d writes", len(w.files))
	}
}

func TestLearnerSeedsFromAnExistingFileAndRefusesABrokenOne(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "learned.toml")
	set := rules.NewLearned(nil)
	set.Observe(curlObs(time.Unix(1_000_000, 0)))
	if err := rules.WriteFile(path, set.File()); err != nil {
		t.Fatal(err)
	}
	var logs []string
	l, err := newLearner(path, (&fakeWriter{}).write, func(m string) { logs = append(logs, m) })
	if err != nil || len(logs) != 1 || !strings.Contains(logs[0], "continues") {
		t.Fatalf("seeding: %v %q", err, logs)
	}
	l.observe(curlObs(time.Unix(1_000_100, 0)))
	if f := l.set.File(); f.Rules[0].Count != 2 {
		t.Fatalf("seed not continued: %+v", f.Rules[0])
	}
	os.WriteFile(path, []byte("broken = [\n"), 0o644)
	if _, err := newLearner(path, (&fakeWriter{}).write, func(string) {}); err == nil || !strings.Contains(err.Error(), "learned file") {
		t.Fatalf("an edited, invalid learned file must refuse to start, got %v", err)
	}
}

func TestSetupLearningSetsSinkAndWantPath(t *testing.T) {
	d := &daemon{cfg: config{learn: true, learned: filepath.Join(t.TempDir(), "l.toml")}, log: func(string) {}}
	if err := d.setupLearning(); err != nil || d.sink == nil || d.flags&flagWantPath == 0 || d.learn == nil {
		t.Fatalf("learning not wired: %v %+v", err, d)
	}
	off := &daemon{cfg: config{}, log: func(string) {}}
	if err := off.setupLearning(); err != nil || off.sink != nil || off.flags != 0 {
		t.Fatal("learning off: no sink, no flag")
	}
}

func TestLearnerObserveAndFlushAreSafeTogether(t *testing.T) {
	w := &fakeWriter{}
	l, _ := newLearner(filepath.Join(t.TempDir(), "none.toml"), w.write, func(string) {})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 200; i++ {
			l.observe(curlObs(time.Now()))
		}
		close(done)
	}()
	for i := 0; i < 50; i++ {
		l.flush()
	}
	<-done
	l.flush()
	if l.set.File().Rules[0].Count != 200 {
		t.Fatal("observations lost under concurrent flushes")
	}
}
