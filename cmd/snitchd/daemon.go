package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	snitchbpf "github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
	"github.com/norandom/snitch/internal/rules"
	"github.com/norandom/snitch/internal/trial"
)

const (
	pinDir          = "/sys/fs/bpf/snitch" // control + kill maps live here (kill: bpftool from a console)
	heartbeatPeriod = 2 * time.Second
	flagWantPath    = 1 // control_state.flags bit 0: the kernel fills the exe path on every event
)

var errStop = errors.New("stop requested")

// daemon is the running state: kernel objects, the current snapshot, and what the heartbeat
// writes. Built once by startup; the jobs read it. mode is written by setMode (startup, the
// follow job) and read by every heartbeat.
type daemon struct {
	cfg    config
	objs   snitchbpf.SnitchObjects
	links  []link.Link
	rd     *ringbuf.Reader
	st     state
	mode   atomic.Uint32
	flags  uint32
	log    func(string)
	sink   func(rules.Observation) // learning; nil = off
	learn  *learner
	follow *follower // source files: decides the mode from the trial and kept files; nil = flag
}

// startup: rules first (a bad file is reported before anything touches the kernel), then the
// mode (from the flag or the files: a kept enforce or an old trial is decided before the first
// heartbeat), the objects, the first heartbeat, the maps, and only then the hooks.
func startup(cfg config) (*daemon, error) {
	d := &daemon{cfg: cfg, log: func(m string) { fmt.Fprintln(os.Stderr, "snitchd:", m) }}
	snap, err := loadRules(cfg.rules, cfg.overlay, d.log)
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if snap.rulesErr != nil { // the overlay alone is bad: start on the base, report (Req 5.4)
		d.log(fmt.Sprintf("overlay not loaded, running on the rules file alone: %v", snap.rulesErr))
	}
	if err := d.setupLearning(); err != nil {
		return nil, err
	}
	if err := d.startMode(); err != nil {
		return nil, err
	}
	if err := d.loadObjects(); err != nil {
		return nil, err
	}
	if err := d.beat(); err != nil {
		return nil, fmt.Errorf("heartbeat: %w", err)
	}
	if err := apply(mapOps(d.objs.Programs), mapOps(d.objs.Rules), rules.Diff(rules.Entries{}, snap.ent)); err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	d.st.publish(snap)
	fmt.Println(summary(snap))
	if err := d.attach(); err != nil {
		return nil, err
	}
	fmt.Println(startupLine(version, modeName(trial.Mode(d.mode.Load())), cfg.source))
	return d, nil
}

// startMode sets the mode once before the first heartbeat. Source flag: the flag, and the
// files are never read (Req 3.6). Source files: the state directory is created when missing
// (a hand-started daemon has no StateDirectory), then one decision from the files, so a kept
// enforce enforces from the first beat and a trial from another boot is gone before any hook
// is attached (Req 4.2, 5.3).
func (d *daemon) startMode() error {
	if d.cfg.source == sourceFlag {
		d.setMode(flagMode(d.cfg.mode), "-mode "+d.cfg.mode)
		return nil
	}
	if err := os.MkdirAll(d.cfg.stateDir, 0o700); err != nil {
		return fmt.Errorf("state dir: %w", err)
	}
	boot, err := trial.BootID(os.ReadFile)
	if err != nil {
		return err
	}
	d.decideOnce(trial.OSStore(d.cfg.stateDir), boot, time.Now())
	return nil
}

// decideOnce builds the follower over the files on this boot and makes its first decision at
// now (what it applies and removes: see follower.decide); the follow job carries it on from
// there on the real clock, so a transition at startup is remembered for the next tick's log.
func (d *daemon) decideOnce(store trial.Store, bootID string, now time.Time) {
	d.follow = &follower{store: store, boot: bootID, now: time.Now, learn: d.cfg.learn, apply: d.setMode, log: d.log}
	d.follow.decide(now)
}

// setMode is the one place the mode changes: it stores the value the next heartbeat carries
// and logs "mode: <monitor|enforce> (<reason>)" (Req 1.4). It logs every call: the follower
// alone decides which decisions deserve a line, so a spent file is never removed silently.
func (d *daemon) setMode(m trial.Mode, reason string) {
	d.mode.Store(uint32(m))
	d.log(fmt.Sprintf("mode: %s (%s)", modeName(m), reason))
}

func modeName(m trial.Mode) string {
	if m == trial.Enforce {
		return modeEnforce
	}
	return modeMonitor
}

func flagMode(s string) trial.Mode {
	if s == modeEnforce {
		return trial.Enforce
	}
	return trial.Monitor
}

// setupLearning: seed the learned set, feed the pump's sink into it, and ask the kernel for the
// exe path on every event (unknown executables are the point of learning).
func (d *daemon) setupLearning() error {
	if !d.cfg.learn {
		return nil
	}
	l, err := newLearner(d.cfg.learned, rules.WriteFile, d.log)
	if err != nil {
		return err
	}
	d.learn, d.sink, d.flags = l, l.observe, d.flags|flagWantPath
	return nil
}

func (d *daemon) loadObjects() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		d.log("memlock: " + err.Error())
	}
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		return fmt.Errorf("pin dir: %w", err)
	}
	opts := &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}}
	if err := snitchbpf.LoadSnitchObjects(&d.objs, opts); err != nil {
		return fmt.Errorf("load: %w", err)
	}
	rd, err := ringbuf.NewReader(d.objs.Events)
	if err != nil {
		return fmt.Errorf("ringbuf: %w", err)
	}
	d.rd = rd
	return nil
}

func (d *daemon) attach() error {
	for _, p := range []*ebpf.Program{d.objs.SocketConnect, d.objs.SocketSendmsg} {
		l, err := link.AttachLSM(link.LSMOptions{Program: p})
		if err != nil {
			return fmt.Errorf("attach: %w", err)
		}
		d.links = append(d.links, l)
	}
	if l, ok := attachCounting(&d.objs, d.log); ok { // counting only; off is logged, never fatal
		d.links = append(d.links, l)
	}
	return nil
}

// beat writes the heartbeat the kernel program needs to enforce at all (stale 15 s = allow).
func (d *daemon) beat() error {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return err
	}
	c := snitchbpf.SnitchControlState{HeartbeatNs: uint64(ts.Nano()), Mode: d.mode.Load(), Flags: d.flags}
	return d.objs.Control.Put(uint32(0), &c)
}

// serve runs the jobs until the deadline, a stop signal, or a job's error ends the run.
func (d *daemon) serve() int { return runJobs(d.log, d.jobList()...) }

// jobList: the heartbeat, the deadline, the stop signals, the event pump, the reloads, and,
// when configured, the learned-file writer and the mode follower with its status writer.
func (d *daemon) jobList() []jobs.Job {
	r := &reloader{path: d.cfg.rules, overlay: d.cfg.overlay, paths: []string{d.cfg.rules, d.cfg.overlay},
		st: &d.st, programs: mapOps(d.objs.Programs), rules: mapOps(d.objs.Rules), load: loadRules, log: d.log}
	js := []jobs.Job{
		jobs.Every(heartbeatPeriod, func(context.Context) error { return d.beat() }),
		jobs.After(d.cfg.duration),
		jobs.OnSignal(func(os.Signal) error { return errStop }, os.Interrupt, syscall.SIGTERM),
		d.pump,
		r.watchFile(), r.reResolve(), r.onHUP(),
	}
	if d.learn != nil {
		js = append(js, d.learn.job())
	}
	return append(js, d.modeJobs()...)
}

// runJobs runs the jobs, each behind a contract guard, and turns the outcome into an exit
// code: 0 for the deadline or a stop signal, 70 for a contract violation (logged with its
// stack; the exit detaches the hooks, so a bug fails open), 1 for any other error.
func runJobs(log func(string), js ...jobs.Job) int {
	guarded := make([]jobs.Job, len(js))
	for i, j := range js {
		guarded[i] = guard(j)
	}
	err := jobs.Run(context.Background(), guarded...)
	var v *violation
	switch {
	case err == nil, errors.Is(err, errStop):
		return 0
	case errors.As(err, &v):
		log(fmt.Sprintf("%v\n%s", v.Violation, v.stack))
		return exitViolation
	}
	log(err.Error())
	return 1
}

// violation is a contract failure raised inside a job, carried out of its goroutine as the
// run's error (a panic there would bypass main's recover).
type violation struct {
	*contract.Violation
	stack []byte
}

func (v *violation) Error() string { return v.Violation.Error() }
func (v *violation) Unwrap() error { return v.Violation }

func guard(j jobs.Job) jobs.Job {
	return func(ctx context.Context) (err error) {
		defer func() {
			r := recover()
			if r == nil {
				return
			}
			var cv *contract.Violation
			if e, ok := r.(error); ok && errors.As(e, &cv) {
				err = &violation{Violation: cv, stack: debug.Stack()}
				return
			}
			panic(r)
		}()
		return j(ctx)
	}
}

// close detaches the hooks (links are not pinned: a gone daemon never enforces) and closes
// the objects; the pinned control and kill maps stay.
func (d *daemon) close() {
	for _, l := range d.links {
		l.Close()
	}
	if d.rd != nil {
		d.rd.Close()
	}
	d.objs.Close()
}
