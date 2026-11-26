// mode.go implements `snitch default deny|allow [--keep]` (requirements 9.1-9.6, 13.1).
//
// Fail-safe implications: none on kernel egress. The command only sends trial, keep or end
// requests to the daemon over the unix socket; any daemon question about missing rules
// requires a terminal, flushes typeahead, waits 0.6 s, and continues only on an explicit y.
package verbs

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/conf"
	"github.com/norandom/snitch/internal/contract"
)

const (
	exitFail     = 1
	exitUsage    = 2
	confirmDelay = 600 * time.Millisecond
	defaultUsage = "usage: snitch default deny|allow [--keep]"
)

// Asker sends one or more requests to the daemon under ctx and returns its replies.
type Asker func(ctx context.Context, reqs ...api.Request) ([]api.Reply, error)

// IO holds the terminal streams and typeahead flush hook for Default.
type IO struct {
	In    io.Reader
	Out   io.Writer
	Err   io.Writer
	IsTTY bool
	Flush func()
}

// Default runs `snitch default deny|allow [--keep]` and returns the process exit code
// (0 on success, 1 on refusal/unreachable/declined/no-TTY, 2 on usage error).
func Default(ctx context.Context, args []string, c conf.Config, ask Asker, stdio IO) int {
	contract.Require(ctx != nil && ask != nil, "verbs.Default: context and asker are required")
	outW, errW := defaultWriters(stdio)
	word, keep, ok := parseDefaultArgs(args)
	if !ok {
		_, _ = fmt.Fprintln(errW, defaultUsage)
		return exitUsage
	}

	replies, err := ask(ctx, defaultRequest(word, keep, c, false))
	if err != nil {
		if word == "deny" && !keep && client.IsQuestion(err.Error()) {
			return confirmAndRetry(ctx, err.Error(), c, ask, stdio, outW, errW)
		}
		_, _ = fmt.Fprintln(errW, cleanText(err.Error()))
		return exitFail
	}
	return writeReply(replies, outW, errW)
}

func defaultWriters(stdio IO) (outW, errW io.Writer) {
	outW, errW = stdio.Out, stdio.Err
	if outW == nil {
		outW = io.Discard
	}
	if errW == nil {
		errW = io.Discard
	}
	return outW, errW
}

func parseDefaultArgs(args []string) (word string, keep bool, ok bool) {
	for _, a := range args {
		if a == "--keep" || a == "-keep" {
			if keep {
				return "", false, false
			}
			keep = true
			continue
		}
		if strings.HasPrefix(a, "-") || word != "" {
			return "", false, false
		}
		word = a
	}
	if word == "allow" {
		return word, false, !keep
	}
	return word, keep, word == "deny"
}

func defaultRequest(word string, keep bool, c conf.Config, yes bool) api.Request {
	if word == "allow" {
		return api.Request{Type: "end"}
	}
	if keep {
		return api.Request{Type: "keep"}
	}
	d := c.Trial
	if d <= 0 {
		d = conf.Default().Trial
	}
	return api.Request{Type: "trial", Duration: d.String(), Yes: yes}
}

func confirmAndRetry(ctx context.Context, question string, c conf.Config, ask Asker, stdio IO, outW, errW io.Writer) int {
	cleanQ := cleanText(question)
	if !stdio.IsTTY {
		_, _ = fmt.Fprintln(errW, cleanQ)
		_, _ = fmt.Fprintln(errW, "confirmation requires a terminal")
		return exitFail
	}
	_, _ = fmt.Fprint(outW, cleanQ, " ")
	if stdio.Flush != nil {
		stdio.Flush()
	}
	if err := waitConfirm(ctx, confirmDelay); err != nil {
		_, _ = fmt.Fprintln(errW, cleanText(err.Error()))
		return exitFail
	}
	if !readYes(stdio.In) {
		_, _ = fmt.Fprintln(errW, "declined")
		return exitFail
	}
	replies, err := ask(ctx, defaultRequest("deny", false, c, true))
	if err != nil {
		_, _ = fmt.Fprintln(errW, cleanText(err.Error()))
		return exitFail
	}
	return writeReply(replies, outW, errW)
}

func writeReply(replies []api.Reply, outW, errW io.Writer) int {
	if len(replies) == 0 || !replies[0].Ok {
		_, _ = fmt.Fprintln(errW, "unexpected empty reply from daemon")
		return exitFail
	}
	if replies[0].Text != "" {
		_, _ = fmt.Fprintln(outW, cleanText(replies[0].Text))
	}
	return 0
}

func waitConfirm(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func readYes(r io.Reader) bool {
	if r == nil {
		return false
	}
	line, _ := bufio.NewReader(io.LimitReader(r, 1024)).ReadString('\n')
	return strings.TrimSpace(line) == "y"
}

func cleanText(s string) string {
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = string(clean.Text(line))
	}
	return strings.Join(lines, "\n")
}
