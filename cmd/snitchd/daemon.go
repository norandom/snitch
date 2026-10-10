package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime/debug"
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
)

const (
	pinDir          = "/sys/fs/bpf/snitch" // control + kill maps live here (kill: bpftool from a console)
	heartbeatPeriod = 2 * time.Second
	flagWantPath    = 1 // control_state.flags bit 0: the kernel fills the exe path on every event
)

var errStop = errors.New("stop requested")

// daemon is the running state: kernel objects, the current snapshot, and what the heartbeat
// writes. Built once by startup; the jobs read it.
type daemon struct {
	cfg   config
	objs  snitchbpf.SnitchObjects
	links []link.Link
	rd    *ringbuf.Reader
	st    state
	mode  uint32
	flags uint32
	log   func(string)
}

// startup: rules first (a bad file is reported before anything touches the kernel), then the
// objects, the first heartbeat, the maps, and only then the hooks.
func startup(cfg config) (*daemon, error) {
	d := &daemon{cfg: cfg, log: func(m string) { fmt.Fprintln(os.Stderr, "snitchd:", m) }}
	if cfg.mode == modeEnforce {
		d.mode = 1
	}
	snap, err := loadRules(cfg.rules, d.log)
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
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
	fmt.Printf("snitchd: mode %s, hooks lsm/socket_connect + lsm/socket_sendmsg, maps pinned in %s\n", cfg.mode, pinDir)
	return d, nil
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
	return nil
}

// beat writes the heartbeat the kernel program needs to enforce at all (stale 15 s = allow).
func (d *daemon) beat() error {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return err
	}
	c := snitchbpf.SnitchControlState{HeartbeatNs: uint64(ts.Nano()), Mode: d.mode, Flags: d.flags}
	return d.objs.Control.Put(uint32(0), &c)
}

// serve runs the jobs until the deadline, a stop signal, or a job's error ends the run.
func (d *daemon) serve() int {
	r := &reloader{path: d.cfg.rules, st: &d.st, programs: mapOps(d.objs.Programs), rules: mapOps(d.objs.Rules), load: loadRules, log: d.log}
	return runJobs(d.log,
		jobs.Every(heartbeatPeriod, func(context.Context) error { return d.beat() }),
		jobs.After(d.cfg.duration),
		jobs.OnSignal(func(os.Signal) error { return errStop }, os.Interrupt, syscall.SIGTERM),
		d.pump,
		r.watchFile(), r.reResolve(), r.onHUP(),
	)
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
