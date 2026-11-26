// tui.go: the overview and egress verbs: flag parsing, config loading, terminal check,
// private log opening, SO_PEERCRED socket-owner and loose-directory delegates, and the
// shared jobs.Run group (client, terminal adapter, signals).
//
// Fail-safe implications: runs as the ordinary user, talks only to the daemon's unix socket,
// writes nothing on disk except ~/.local/state/snitch/snitch.log and its directory, and
// restores the terminal before reporting any contract violation (exit 70).
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/conf"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
	"github.com/norandom/snitch/internal/logfile"
	"github.com/norandom/snitch/internal/term"
	"github.com/norandom/snitch/internal/tui"
)

const tuiUsage = "usage: snitch [egress] [-api PATH] [--since WINDOW]"

var errSignal = errors.New("signal")

type tuiFlags struct {
	apiPath  string
	since    string
	hasSince bool
}

type tuiSetup struct {
	flags  tuiFlags
	cfg    conf.Config
	egress bool
	stdin  io.Reader
	stdout io.Writer
}

func runOverview(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runTUIWithJobs(args, false, stdin, stdout, stderr, nil)
}

func runEgress(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runTUIWithJobs(args, true, stdin, stdout, stderr, nil)
}

func runTUIWithJobs(args []string, egress bool, stdin io.Reader, stdout, stderr io.Writer, extra []jobs.Job) int {
	flags, err := parseTUIFlags(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprintln(stderr, tuiUsage)
		return exitUsage
	}
	cfg, err := loadTUIConfig(flags)
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "snitch: %v\n", err)
		return exitUsage
	}
	if !isTerminal(stdin) || !isTerminal(stdout) {
		_, _ = fmt.Fprintln(stderr, "snitch: stdin and stdout must be terminals")
		return exitFail
	}
	return startTUIJobs(tuiSetup{flags: flags, cfg: cfg, egress: egress, stdin: stdin, stdout: stdout}, stderr, extra)
}

func startTUIJobs(s tuiSetup, stderr io.Writer, extra []jobs.Job) int {
	log, tail, logBroken := openTUILog()
	if log != nil {
		defer func() { _ = log.Close() }()
	}
	inbox := make(chan any, inboxSize)
	stop := make(chan struct{})
	var stopOnce sync.Once
	closeStop := func() { stopOnce.Do(func() { close(stop) }) }

	c := newTUIClient(s.flags.apiPath, inbox, stop)
	termCfg := newTermConfig(s, c, inbox, tail, logBroken, log)
	group := []jobs.Job{
		catchJobPanic(c.Job(), closeStop),
		catchJobPanic(term.Run(termCfg), closeStop),
		catchJobPanic(jobs.OnSignal(func(os.Signal) error { return errSignal }, os.Interrupt, syscall.SIGTERM), closeStop),
	}
	for _, j := range extra {
		group = append(group, catchJobPanic(j, closeStop))
	}
	return tuiEnd(stderr, jobs.Run(context.Background(), group...))
}

func newTUIClient(apiPath string, inbox chan<- any, stop <-chan struct{}) *client.Client {
	return client.New(client.Config{
		Path: apiPath, Dial: dialUnix,
		Sink: func(m client.Msg) {
			select {
			case inbox <- m:
			case <-stop:
			}
		},
		Log: func(string) {}, Now: time.Now,
		Poll: pollEvery, Gap: statusGap, AnswerWait: answerWait,
		BackoffMin: backoffMin, BackoffMax: backoffMax,
		Table: true, Peer: peerCreds,
	})
}

func newTermConfig(s tuiSetup, c *client.Client, inbox <-chan any, tail []clean.Safe, logBroken bool, log *logfile.Log) term.Config {
	var logAppend func(clean.Safe) error
	if log != nil {
		logAppend = func(line clean.Safe) error { return log.Append(line, time.Now()) }
	}
	model := tui.New(tui.Options{
		Conf: s.cfg, Egress: s.egress, Socket: clean.Text(s.flags.apiPath),
		LogTail: tail, LogBroken: logBroken,
	})
	return term.Config{
		Model: model, In: inbox, Send: c.Send, Log: logAppend,
		Loose: looseDir(os.Lstat), Now: time.Now, Input: s.stdin, Output: s.stdout,
	}
}

func parseTUIFlags(args []string) (tuiFlags, error) {
	f := tuiFlags{apiPath: defaultAPI}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, val, hasEq := strings.Cut(arg, "=")
		switch name {
		case "-api", "--api":
			v, next, err := flagValue(args, i, val, hasEq, "-api wants the daemon's socket path")
			if err != nil {
				return tuiFlags{}, err
			}
			f.apiPath, i = v, next
		case "-since", "--since":
			v, next, err := flagValue(args, i, val, hasEq, "--since wants a time window")
			if err != nil {
				return tuiFlags{}, err
			}
			f.since, f.hasSince, i = v, true, next
		default:
			return tuiFlags{}, fmt.Errorf("snitch: unknown argument %q", arg)
		}
	}
	return f, nil
}

func flagValue(args []string, i int, val string, hasEq bool, msg string) (string, int, error) {
	if hasEq {
		if val == "" {
			return "", i, errors.New("snitch: " + msg)
		}
		return val, i, nil
	}
	if i+1 >= len(args) || args[i+1] == "" {
		return "", i, errors.New("snitch: " + msg)
	}
	return args[i+1], i + 1, nil
}

func loadTUIConfig(f tuiFlags) (conf.Config, error) {
	home, homeErr := os.UserHomeDir()
	cfg, err := conf.Load(func() ([]byte, error) {
		if homeErr != nil {
			return nil, homeErr
		}
		return os.ReadFile(filepath.Join(home, ".config", "snitch", "config.toml"))
	})
	if err != nil {
		return conf.Config{}, err
	}
	if f.hasSince {
		return cfg.WithSince(f.since)
	}
	return cfg, nil
}

func isTerminal(v any) bool {
	f, ok := v.(*os.File)
	if !ok || f == nil {
		return false
	}
	_, err := unix.IoctlGetTermios(int(f.Fd()), unix.TCGETS)
	return err == nil
}

func openTUILog() (*logfile.Log, []clean.Safe, bool) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, []clean.Safe{clean.Text(err.Error())}, true
	}
	path := filepath.Join(home, ".local", "state", "snitch", "snitch.log")
	log, tail, err := logfile.Open(path, uint32(os.Getuid()))
	if err != nil {
		return nil, []clean.Safe{clean.Text(err.Error())}, true
	}
	return log, tail, false
}

// peerCreds reads the connected unix socket peer's uid via SO_PEERCRED.
func peerCreds(c net.Conn) (uint32, bool) {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return 0, false
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return 0, false
	}
	var cred *unix.Ucred
	if cerr := raw.Control(func(fd uintptr) {
		cred, err = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); cerr != nil || err != nil || cred == nil {
		return 0, false
	}
	return cred.Uid, true
}

// looseDir returns a directory-inspection delegate that reports true when execPath's
// directory is not root-owned, is writable by group or others, or cannot be stat'd.
func looseDir(lstat func(string) (os.FileInfo, error)) func(string) bool {
	return func(execPath string) bool {
		if execPath == "" {
			return true
		}
		fi, err := lstat(filepath.Dir(execPath))
		if err != nil {
			return true
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		return !ok || st.Uid != 0 || fi.Mode().Perm()&0o022 != 0
	}
}

type jobPanic struct {
	val   any
	stack []byte
}

func (p jobPanic) Error() string { return fmt.Sprintf("job panic: %v", p.val) }

func catchJobPanic(j jobs.Job, closeStop func()) jobs.Job {
	return func(ctx context.Context) (err error) {
		defer closeStop()
		defer func() {
			if r := recover(); r != nil {
				err = jobPanic{val: r, stack: debug.Stack()}
			}
		}()
		return j(ctx)
	}
}

func tuiEnd(stderr io.Writer, err error) int {
	if err == nil || errors.Is(err, errSignal) {
		return 0
	}
	var jp jobPanic
	if errors.As(err, &jp) {
		var v *contract.Violation
		if e, ok := jp.val.(error); ok && errors.As(e, &v) {
			_, _ = fmt.Fprintf(stderr, "snitch: %v\n%s", v, jp.stack)
			return exitViolation
		}
		panic(jp.val)
	}
	contract.Invariant(false, "tui: the run ended in a way the design does not name: "+err.Error())
	return exitFail
}
