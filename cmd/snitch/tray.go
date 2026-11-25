// tray.go: the tray verb: its flags, its wiring and its exit codes (kde-tray design "Binary
// > cmd/snitch"). parseTray reads the command line into a trayConfig — the role guess's
// file access passed in as delegates, so a test can stand in for /etc/snitch/operator —
// and startTray runs the whole wiring under one jobs.Run: the client, the session-bus
// tray, the loop, a one second tick and the termination signals, one buffered inbox
// between them.
//
// Fail-safe implications: the daemon's decisions are untouched by any of this desktop code.
// The tray reads the daemon's API, writes only the rule.add the operator clicked, runs no
// privileged call and asks for none (8.4); hung, crashed or absent, every kernel verdict
// stays what it was without it (8.2). A contract violation ends the process like snitchd's
// (exit 70) and the kernel notices nothing.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"strconv"
	"sync"
	"syscall"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/ask"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/jobs"
	"github.com/norandom/snitch/internal/sni"
	"github.com/norandom/snitch/internal/tray"
)

// The tray's command line (the design's flags and defaults), its inbox and its periods:
// the client's poll and gap (2.1's note: the wiring sets Gap to 2 s), its answer wait and
// its backoff bounds (4.5's cadence), and the loop's one second tick.
const (
	trayUsage       = "usage: snitch tray [-api PATH] [-ask all|enforce] [-operator-file PATH]"
	defaultAPI      = "/run/snitch/api.sock"
	defaultOperator = "/etc/snitch/operator"
	inboxSize       = 256
	pollEvery       = 5 * time.Second
	statusGap       = 2 * time.Second
	answerWait      = 10 * time.Second
	backoffMin      = time.Second
	backoffMax      = 30 * time.Second
	tickEvery       = time.Second
)

// trayConfig is the tray's whole command line with the delegates the wiring runs on: the
// operator file's stat and read are delegates, so a test can play the file.
type trayConfig struct {
	apiPath, operatorFile string
	ask                   ask.Scope // -ask all | enforce (5.9)
	stderr                io.Writer // the Monitoring lines
	dial                  func(context.Context, string) (net.Conn, error)
	stat                  func(string) (os.FileInfo, error)
	read                  func(string) ([]byte, error)
}

// runTray is the tray verb: a usage error prints its line and the usage and exits 2;
// otherwise the wiring runs until it ends and answers with the exit code.
func runTray(args []string, stderr io.Writer) int {
	cfg, err := parseTray(args, stderr)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprintln(stderr, trayUsage)
		return exitUsage
	}
	return startTray(cfg)
}

// parseTray reads the tray's three flags over the defaults, in any order, each with its
// value; everything else — an unknown flag, a flag without its value, a bare word — is one
// usage line.
func parseTray(args []string, stderr io.Writer) (trayConfig, error) {
	cfg := trayConfig{apiPath: defaultAPI, operatorFile: defaultOperator, ask: ask.All, stderr: stderr,
		dial: dialUnix, stat: os.Stat, read: os.ReadFile}
	for i := 0; i < len(args); i++ {
		f, v := args[i], ""
		if i+1 < len(args) {
			v = args[i+1]
		}
		switch f {
		case "-api":
			if v == "" {
				return trayConfig{}, errors.New("snitch: -api wants the daemon's socket path")
			}
			cfg.apiPath, i = v, i+1
		case "-operator-file":
			if v == "" {
				return trayConfig{}, errors.New("snitch: -operator-file wants a path")
			}
			cfg.operatorFile, i = v, i+1
		case "-ask":
			scope, err := parseAsk(v)
			if err != nil {
				return trayConfig{}, err
			}
			cfg.ask, i = scope, i+1
		default:
			return trayConfig{}, fmt.Errorf("snitch: tray takes -api, -ask and -operator-file, not %q", f)
		}
	}
	return cfg, nil
}

// parseAsk is the -ask value: all asks about denied and allowed connections, enforce only
// about denied ones (5.9).
func parseAsk(v string) (ask.Scope, error) {
	switch v {
	case "all":
		return ask.All, nil
	case "enforce":
		return ask.Enforce, nil
	}
	return ask.All, fmt.Errorf("snitch: -ask is all or enforce, not %q", v)
}

// startTray is the tray's life: the session bus, the instance name, the composed tray and
// the wiring. Exit 1 with one line for no session bus (1.5), a tray already running (1.2)
// or a compose failure; the wiring's own ends answer from there.
func startTray(cfg trayConfig) int {
	bus, err := sni.Open()
	if err != nil {
		return trayFail(cfg, err)
	}
	defer bus.Close()
	if err := bus.Claim(); err != nil {
		return trayFail(cfg, err)
	}
	inbox := make(chan any, inboxSize)
	tr, err := bus.Tray(func(a any) { inbox <- a }, trayLog(cfg))
	if err != nil {
		return trayFail(cfg, err)
	}
	return runTrayJobs(cfg, tr, inbox)
}

// trayFail is one operator error line and exit 1 (the design's Error Categories).
func trayFail(cfg trayConfig, err error) int {
	_, _ = fmt.Fprintf(cfg.stderr, "snitch tray: %v\n", err)
	return exitFail
}

// trayLog is the adapters' log delegate: every line on stderr, the session's journal under
// autostart — the design's Monitoring, which an unattended tray is read through.
func trayLog(cfg trayConfig) func(string) {
	return func(s string) { _, _ = fmt.Fprintln(cfg.stderr, "snitch tray: "+s) }
}

// dialUnix is the -api dialer: the daemon's unix socket only, never a network address (8.5).
func dialUnix(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, "unix", path)
}

// runTrayJobs is the wiring of the design's one jobs.Run: the client of the daemon, the
// adapter's job (item and notifications), the loop, a one second tick that sends Tick, and
// the signals (SIGINT, SIGTERM) that send Stop — one buffered inbox carrying both sides'
// messages to the loop.
func runTrayJobs(cfg trayConfig, tr *sni.Tray, inbox chan any) int {
	role := roleAtStart(cfg)
	_, _ = fmt.Fprintf(cfg.stderr, "snitch tray: starting: version %s, daemon socket %s, role %s\n",
		version, cfg.apiPath, role)
	rules := &ruleLog{say: trayLog(cfg), to: inbox, sent: map[uint64]string{}}
	c := client.New(client.Config{Path: cfg.apiPath, Dial: cfg.dial, Sink: rules.answered,
		Log: trayLog(cfg), Now: time.Now, Poll: pollEvery, Gap: statusGap,
		AnswerWait: answerWait, BackoffMin: backoffMin, BackoffMax: backoffMax})
	rules.pass = c.Send
	fx := tray.Effects{Show: tr.Show, Post: tr.Post, Retract: tr.Retract, Send: rules.send, Now: time.Now}
	m := tray.NewModel(tray.Options{Scope: cfg.ask, Writer: role == api.Writer})
	err := jobs.Run(context.Background(), c.Job(), tr.Job(), tray.Run(inbox, fx, m),
		jobs.Every(tickEvery, func(context.Context) error { inbox <- tray.Tick{}; return nil }),
		jobs.OnSignal(func(os.Signal) error { inbox <- tray.Stop{}; return nil },
			os.Interrupt, syscall.SIGTERM))
	return trayEnd(cfg, tr, err)
}

// trayEnd maps the run's end to the exit code, the ends the design names: the loop's nil —
// Quit in the menu or a signal ended the tray — removes the item and exits 0 (1.4); the
// adapter's ErrBusLost exits 1 with one line (the session is over or broken); any other end
// is a wiring bug and ends the process as a contract violation (70, as in snitchd).
func trayEnd(cfg trayConfig, tr *sni.Tray, err error) int {
	switch {
	case err == nil:
		tr.Remove()
		return 0
	case errors.Is(err, sni.ErrBusLost):
		_, _ = fmt.Fprintln(cfg.stderr, "snitch tray: "+err.Error())
		return exitFail
	default:
		contract.Invariant(false, "tray: the run ended in a way the design does not name: "+err.Error())
		return exitFail
	}
}

// roleAtStart guesses the role the daemon will grant this user (client.Role, the 2.2 note):
// uid 0 writes, otherwise the operator file decides, and the operator's name comes from
// user.LookupId — never $USER. The file access goes through the delegates, and a stat or
// read that fails says so once on stderr: questions without buttons would otherwise be a
// mystery, and the daemon may still grant writer (its refusal corrects the guess, 6.9).
func roleAtStart(cfg trayConfig) api.Role {
	if os.Getuid() == 0 {
		return api.Writer
	}
	me, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		me = &user.User{Uid: strconv.Itoa(os.Getuid())}
	}
	return client.Role(uint32(os.Getuid()), me.Username,
		cfg.saidStat(), cfg.saidRead(), cfg.operatorFile)
}

// saidStat and saidRead wrap the role guess's file accesses: a failure is spoken once on
// stderr, so questions without buttons are not a mystery (the 2.2 note).
func (cfg trayConfig) saidStat() func(string) (os.FileInfo, error) {
	return func(p string) (os.FileInfo, error) {
		fi, err := cfg.stat(p)
		if err != nil {
			_, _ = fmt.Fprintf(cfg.stderr, "snitch tray: the operator file %s: %v\n", p, err)
		}
		return fi, err
	}
}

func (cfg trayConfig) saidRead() func(string) ([]byte, error) {
	return func(p string) ([]byte, error) {
		b, err := cfg.read(p)
		if err != nil {
			_, _ = fmt.Fprintf(cfg.stderr, "snitch tray: the operator file %s: %v\n", p, err)
		}
		return b, err
	}
}

// ruleLog is the Monitoring seat for rule.add (design "Monitoring"): the loop's Send effect
// passes it on the way to the daemon, and the client's Answered for its token on the way to
// the loop's inbox, so each rule.add is spoken with its outcome. Only the operator's click
// reaches it, and only rule.add ever flows through it (6.12, 8.1); after the run's context
// ends nothing is answered, and the wiring waits for no answer (2.1's note).
type ruleLog struct {
	say  func(string)
	pass func(uint64, api.Request) // the client's Send
	to   chan<- any                // the loop's inbox
	mu   sync.Mutex
	sent map[uint64]string // the rule.adds in flight as log lines
}

// send runs the loop's Send effect: one line as the request leaves.
func (r *ruleLog) send(token uint64, req api.Request) {
	who := req.Program
	if who == "" {
		who = req.Path
	}
	line := fmt.Sprintf("%s to %s %s port %d %s", who, req.To, req.Proto, req.Port, req.Verdict)
	r.mu.Lock()
	r.sent[token] = line
	r.mu.Unlock()
	r.say("rule.add sent: " + line)
	r.pass(token, req)
}

// answered runs the client's Sink: the outcome of a rule.add in flight is spoken once, and
// every message reaches the loop's inbox whatever it is.
func (r *ruleLog) answered(m client.Msg) {
	if a, ok := m.(client.Answered); ok {
		r.mu.Lock()
		line, open := r.sent[a.Token]
		delete(r.sent, a.Token)
		r.mu.Unlock()
		if open {
			if a.Err == "" {
				r.say("rule.add accepted (" + line + "): " + a.Text)
			} else {
				r.say("rule.add failed (" + line + "): " + a.Err)
			}
		}
	}
	r.to <- m
}
