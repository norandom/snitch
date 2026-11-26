// oneshot.go: the non-interactive `status` and `default` verbs (requirements 9.1-9.11, 13.8).
// `status` queries the daemon with an 800 ms deadline, ignores config.toml, prints one
// waybar JSON line, and exits 0 in every case. `default` loads config.toml, checks usage,
// and forwards trial/keep/end requests under a 5 s per-RPC deadline via verbs.Default.
//
// Fail-safe implications: runs as the ordinary user, talks only to the daemon's unix socket,
// refuses non-root sockets via SO_PEERCRED before writing, and alters no kernel state on exit.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/verbs"
)

const (
	statusTimeout  = 800 * time.Millisecond
	defaultTimeout = 5 * time.Second
	statusUsage    = "usage: snitch status [-api PATH]"
	defaultUsage   = "usage: snitch default deny|allow [--keep] [-api PATH]"
)

var oneshotPeer verbs.Peer = peerCreds

func runStatus(args []string, stdout, stderr io.Writer) int {
	return runStatusWith(args, stdout, stderr, oneshotPeer)
}

func runDefault(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	return runDefaultWith(args, stdin, stdout, stderr, oneshotPeer)
}

func runStatusWith(args []string, stdout, stderr io.Writer, peer verbs.Peer) int {
	apiPath, rest, err := extractAPIFlag(args)
	if err == nil && len(rest) > 0 {
		err = fmt.Errorf("snitch: unknown argument %q", rest[0])
	}
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprintln(stderr, statusUsage)
		return exitUsage
	}
	line := fetchStatusBar(apiPath, peer)
	b, err := json.Marshal(line)
	contract.Invariant(err == nil, "status: json marshal failed")
	_, _ = fmt.Fprintf(stdout, "%s\n", b)
	return 0
}

func fetchStatusBar(apiPath string, peer verbs.Peer) verbs.Line {
	ctx, cancel := context.WithTimeout(context.Background(), statusTimeout)
	defer cancel()
	dial := func(c context.Context) (net.Conn, error) { return dialUnix(c, apiPath) }
	replies, err := verbs.Ask(ctx, dial, peer,
		api.Request{Type: "status"},
		api.Request{Type: "snapshot", Window: "1h"},
	)
	now := time.Now()
	if err != nil {
		return verbs.Bar(nil, nil, now, err.Error())
	}
	var st *api.Status
	var down string
	if len(replies) < 1 || !replies[0].Ok || replies[0].Status == nil {
		down = "no status from daemon"
	} else {
		st = replies[0].Status
	}
	var hour []api.Entry
	if len(replies) >= 2 && replies[1].Ok {
		hour = replies[1].Entries
	}
	return verbs.Bar(st, hour, now, down)
}

func runDefaultWith(args []string, stdin io.Reader, stdout, stderr io.Writer, peer verbs.Peer) int {
	apiPath, rest, err := extractAPIFlag(args)
	if err != nil {
		_, _ = fmt.Fprintln(stderr, err)
		_, _ = fmt.Fprintln(stderr, defaultUsage)
		return exitUsage
	}
	cfg, err := loadTUIConfig(tuiFlags{})
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "snitch: %v\n", err)
		return exitUsage
	}
	ask := func(ctx context.Context, reqs ...api.Request) ([]api.Reply, error) {
		askCtx, cancel := context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
		dial := func(c context.Context) (net.Conn, error) { return dialUnix(c, apiPath) }
		return verbs.Ask(askCtx, dial, peer, reqs...)
	}
	tty := isTerminal(stdin)
	stdio := verbs.IO{
		In:    stdin,
		Out:   stdout,
		Err:   stderr,
		IsTTY: tty,
		Flush: flushTerminalInput(stdin, tty),
	}
	return verbs.Default(context.Background(), rest, cfg, ask, stdio)
}

func extractAPIFlag(args []string) (apiPath string, rest []string, err error) {
	apiPath = defaultAPI
	for i := 0; i < len(args); i++ {
		name, val, hasEq := strings.Cut(args[i], "=")
		if name == "-api" || name == "--api" {
			v, next, err := flagValue(args, i, val, hasEq, "-api wants the daemon's socket path")
			if err != nil {
				return "", nil, err
			}
			apiPath, i = v, next
			continue
		}
		rest = append(rest, args[i])
	}
	return apiPath, rest, nil
}

func flushTerminalInput(in io.Reader, tty bool) func() {
	if !tty {
		return nil
	}
	f, ok := in.(*os.File)
	if !ok || f == nil {
		return nil
	}
	return func() {
		_ = unix.IoctlSetInt(int(f.Fd()), unix.TCFLSH, unix.TCIFLUSH)
	}
}
