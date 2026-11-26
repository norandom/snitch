package verbs

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client/clienttest"
	"github.com/norandom/snitch/internal/conf"
)

func standInAsker(path string) Asker {
	return func(ctx context.Context, reqs ...api.Request) ([]api.Reply, error) {
		return Ask(ctx, unixDialer(path), nil, reqs...)
	}
}

func runDefault(ctx context.Context, args []string, c conf.Config, ask Asker, stdio IO) (int, string, string) {
	var out, errBuf bytes.Buffer
	stdio.Out, stdio.Err = &out, &errBuf
	return Default(ctx, args, c, ask, stdio), out.String(), errBuf.String()
}

func mustDefaultOK(t *testing.T, ctx context.Context, args []string, c conf.Config, ask Asker, wantSub string) {
	t.Helper()
	code, out, errOut := runDefault(ctx, args, c, ask, IO{})
	if code != 0 || errOut != "" || !strings.Contains(out, wantSub) {
		t.Fatalf("%v: code=%d out=%q err=%q (want %q)", args, code, out, errOut, wantSub)
	}
}

func checkFacts(t *testing.T, s *clienttest.StandIn, mode string, hasTrial, kept bool) {
	t.Helper()
	st := s.Facts()
	if st.Mode != mode || (st.Trial != "") != hasTrial || st.Kept != kept {
		t.Fatalf("facts=%#v, want mode=%q hasTrial=%v kept=%v", st, mode, hasTrial, kept)
	}
}

func TestDefaultDenyKeepAllowAgainstStandIn(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	ask := standInAsker(s.Path())
	cfg := conf.Default()
	cfg.Trial = 15 * time.Minute
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	mustDefaultOK(t, ctx, []string{"deny"}, cfg, ask, "15m0s")
	checkFacts(t, s, "enforce", true, false)

	mustDefaultOK(t, ctx, []string{"deny", "--keep"}, cfg, ask, "enforce kept")
	checkFacts(t, s, "enforce", false, true)

	mustDefaultOK(t, ctx, []string{"allow"}, cfg, ask, "enforce unkept")
	checkFacts(t, s, "monitor", false, false)

	if code, out, errOut := runDefault(ctx, []string{"--keep", "deny"}, cfg, ask, IO{}); code != 1 || out != "" || errOut == "" {
		t.Fatalf("keep outside trial: code=%d out=%q err=%q", code, out, errOut)
	}
	mustDefaultOK(t, ctx, []string{"deny"}, cfg, ask, "15m0s")
	mustDefaultOK(t, ctx, []string{"allow"}, cfg, ask, "trial ended")
	checkFacts(t, s, "monitor", false, false)
}

func delayedPipeYes(t *testing.T) *os.File {
	t.Helper()
	pr, pw, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	t.Cleanup(func() { _ = pr.Close() })
	go func() {
		time.Sleep(650 * time.Millisecond)
		_, _ = pw.WriteString("y\n")
		_ = pw.Close()
	}()
	return pr
}

func TestDefaultQuestionAnsweredY(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid()), NoRules: true})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var mu sync.Mutex
	var flushAt time.Time
	start := time.Now()
	code, out, errOut := runDefault(ctx, []string{"deny"}, conf.Default(), standInAsker(s.Path()), IO{
		In:    delayedPipeYes(t),
		IsTTY: true,
		Flush: func() { mu.Lock(); flushAt = time.Now(); mu.Unlock() },
	})
	elapsed := time.Since(start)
	if code != 0 || errOut != "" || !strings.Contains(out, "[y/N]") || !strings.Contains(out, "enforce until") {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
	mu.Lock()
	fAt := flushAt
	mu.Unlock()
	if fAt.IsZero() || fAt.Sub(start) >= 600*time.Millisecond || elapsed < 600*time.Millisecond {
		t.Fatalf("timing: flushAt=%v elapsed=%v", fAt.Sub(start), elapsed)
	}
	if st := s.Facts(); st.Mode != "enforce" || st.Trial == "" {
		t.Fatalf("trial not started: %#v", st)
	}
}

func TestDefaultQuestionTypeaheadDiscarded(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid()), NoRules: true})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var buf bytes.Buffer
	buf.WriteString("y\n")
	code, out, errOut := runDefault(ctx, []string{"deny"}, conf.Default(), standInAsker(s.Path()), IO{
		In:    &buf,
		IsTTY: true,
		Flush: func() { buf.Reset() },
	})
	if code != 1 || !strings.Contains(out, "[y/N]") || errOut == "" {
		t.Fatalf("code=%d out=%q err=%q", code, out, errOut)
	}
	if st := s.Facts(); st.Mode != "monitor" || st.Trial != "" {
		t.Fatalf("typeahead started trial: %#v", st)
	}
}

func TestDefaultQuestionAnsweredN(t *testing.T) {
	for _, tc := range []struct{ name, input string }{
		{"n", "n\n"}, {"N", "N\n"}, {"yes", "yes\n"}, {"Y", "Y\n"}, {"empty_line", "\n"}, {"eof", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid()), NoRules: true})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			code, out, errOut := runDefault(ctx, []string{"deny"}, conf.Default(), standInAsker(s.Path()), IO{
				In: strings.NewReader(tc.input), IsTTY: true,
			})
			if code != 1 || !strings.Contains(out, "[y/N]") || errOut == "" {
				t.Fatalf("%q: code=%d out=%q err=%q", tc.input, code, out, errOut)
			}
			if st := s.Facts(); st.Mode != "monitor" || st.Trial != "" {
				t.Fatalf("%q started trial: %#v", tc.input, st)
			}
		})
	}
}

func TestDefaultQuestionWithoutTerminal(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid()), NoRules: true})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	code, out, errOut := runDefault(ctx, []string{"deny"}, conf.Default(), standInAsker(s.Path()), IO{
		In: strings.NewReader("y\n"), IsTTY: false,
	})
	if code != 1 || out != "" || !strings.Contains(errOut, "[y/N]") || time.Since(start) >= 500*time.Millisecond {
		t.Fatalf("code=%d out=%q err=%q elapsed=%v", code, out, errOut, time.Since(start))
	}
	if st := s.Facts(); st.Mode != "monitor" || st.Trial != "" {
		t.Fatalf("without TTY started trial: %#v", st)
	}
}

func TestDefaultRefusalAndUnreachable(t *testing.T) {
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	s.Refuse(true)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	for _, args := range [][]string{{"deny"}, {"deny", "--keep"}, {"allow"}} {
		code, out, errOut := runDefault(ctx, args, conf.Default(), standInAsker(s.Path()), IO{})
		if code != 1 || out != "" || !strings.Contains(errOut, "refused") {
			t.Fatalf("refused %v: code=%d out=%q err=%q", args, code, out, errOut)
		}
	}
	s.Stop()
	for _, args := range [][]string{{"deny"}, {"allow"}} {
		code, out, errOut := runDefault(ctx, args, conf.Default(), standInAsker(s.Path()), IO{})
		if code != 1 || out != "" || errOut == "" {
			t.Fatalf("unreachable %v: code=%d out=%q err=%q", args, code, out, errOut)
		}
	}
}

func TestDefaultUsageErrors(t *testing.T) {
	called := false
	ask := func(context.Context, ...api.Request) ([]api.Reply, error) {
		called = true
		return nil, errors.New("should not be called")
	}
	for _, args := range [][]string{
		nil, {}, {"status"}, {"allow", "--keep"}, {"deny", "extra"}, {"deny", "--keep", "--keep"}, {"--unknown"},
	} {
		code, out, errOut := runDefault(context.Background(), args, conf.Default(), ask, IO{})
		if code != 2 || out != "" || !strings.Contains(strings.ToLower(errOut), "usage") {
			t.Fatalf("args %v: code=%d out=%q err=%q", args, code, out, errOut)
		}
	}
	if called {
		t.Fatal("ask called on usage error")
	}
}

func TestDefaultSanitisesDaemonText(t *testing.T) {
	evil := "line1\x1b[31mred\x1b[0m\r\x7f\u202ebidi\u200b\xff\nline2\u009b"
	ctx := context.Background()

	code, out, errOut := runDefault(ctx, []string{"allow"}, conf.Default(),
		func(context.Context, ...api.Request) ([]api.Reply, error) {
			return []api.Reply{{Ok: true, Text: evil}}, nil
		}, IO{})
	if code != 0 || errOut != "" {
		t.Fatalf("reply: code=%d err=%q", code, errOut)
	}
	assertCleanLines(t, "stdout", out, 2)

	code, out, errOut = runDefault(ctx, []string{"allow"}, conf.Default(),
		func(context.Context, ...api.Request) ([]api.Reply, error) { return nil, errors.New(evil) }, IO{})
	if code != 1 || out != "" {
		t.Fatalf("err: code=%d out=%q", code, out)
	}
	assertCleanLines(t, "stderr", errOut, 2)

	askQ := func(context.Context, ...api.Request) ([]api.Reply, error) {
		return nil, errors.New("No rules \x1b[31mred\x1b[0m\u202e? [y/N]")
	}
	code, out, errOut = runDefault(ctx, []string{"deny"}, conf.Default(), askQ, IO{IsTTY: false})
	if code != 1 || out != "" {
		t.Fatalf("question no-tty: code=%d out=%q", code, out)
	}
	assertCleanLines(t, "question-stderr", errOut, 2)

	code, out, errOut = runDefault(ctx, []string{"deny"}, conf.Default(), askQ, IO{In: strings.NewReader("n\n"), IsTTY: true})
	if code != 1 || errOut == "" {
		t.Fatalf("question tty: code=%d err=%q", code, errOut)
	}
	assertCleanLines(t, "question-stdout", out, 1)
}

func TestDefaultContextCanceledDuringConfirmWait(t *testing.T) {
	ask := func(context.Context, ...api.Request) ([]api.Reply, error) {
		return nil, errors.New("No rules are loaded. Start the trial? [y/N]")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Millisecond)
	defer cancel()

	start := time.Now()
	code, _, errOut := runDefault(ctx, []string{"deny"}, conf.Default(), ask, IO{
		In: strings.NewReader("y\n"), IsTTY: true,
	})
	if code != 1 || errOut == "" || time.Since(start) >= 400*time.Millisecond {
		t.Fatalf("code=%d err=%q elapsed=%v", code, errOut, time.Since(start))
	}
}

func assertCleanLines(t *testing.T, where, raw string, wantLines int) {
	t.Helper()
	lines := strings.Split(strings.TrimSuffix(raw, "\n"), "\n")
	if len(lines) != wantLines {
		t.Fatalf("%s has %d lines (%q), want %d", where, len(lines), raw, wantLines)
	}
	for i, line := range lines {
		if !utf8.ValidString(line) || string(clean.Text(line)) != line {
			t.Fatalf("%s line %d not clean: %q", where, i, line)
		}
	}
}
