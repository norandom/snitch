package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/client/clienttest"
	"github.com/norandom/snitch/internal/verbs"
)

func asRootPeer(t *testing.T) {
	t.Helper()
	orig := oneshotPeer
	oneshotPeer = func(net.Conn) (uint32, bool) { return 0, true }
	t.Cleanup(func() { oneshotPeer = orig })
}

func decodeStatusLine(t *testing.T, out string) verbs.Line {
	t.Helper()
	if strings.Count(out, "\n") != 1 {
		t.Fatalf("status stdout must be one line, got %q", out)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatalf("invalid JSON %q: %v", out, err)
	}
	for _, k := range []string{"text", "class", "tooltip"} {
		if _, ok := raw[k]; !ok {
			t.Fatalf("JSON %q missing field %q", out, k)
		}
	}
	var line verbs.Line
	if err := json.Unmarshal([]byte(out), &line); err != nil {
		t.Fatalf("unmarshal Line %q: %v", out, err)
	}
	return line
}

func writeConfigFile(t *testing.T, home, content string) {
	t.Helper()
	dir := filepath.Join(home, ".config", "snitch")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func mustRunStatus(t *testing.T, args ...string) verbs.Line {
	t.Helper()
	code, out, errOut := run(args...)
	if code != 0 || errOut != "" {
		t.Fatalf("%v: code=%d out=%q err=%q", args, code, out, errOut)
	}
	return decodeStatusLine(t, out)
}

func assertLineHas(t *testing.T, line verbs.Line, wantClass, wantText, wantTip string) {
	t.Helper()
	if line.Class != wantClass || !strings.Contains(line.Text, wantText) || !strings.Contains(line.Tooltip, wantTip) {
		t.Fatalf("line = %#v (want class=%q text=%q tip=%q)", line, wantClass, wantText, wantTip)
	}
}

func TestStatusStandInJSONAndModes(t *testing.T) {
	asRootPeer(t)
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	if err := s.Do("event curl /usr/bin/curl 1.1.1.1 443 tcp deny-default"); err != nil {
		t.Fatal(err)
	}
	s.FlushSummary()

	line := mustRunStatus(t, "status", "-api", s.Path())
	assertLineHas(t, line, "allow", "\U000F0499 1", "denied in the last hour: 1")

	if err := s.Do("trial 10m"); err != nil {
		t.Fatal(err)
	}
	line = mustRunStatus(t, "status", "--api="+s.Path())
	assertLineHas(t, line, "deny", "\U000F0498", "enforce")
}

func listenSilentUnix(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "silent.sock")
	ln, err := net.Listen("unix", p)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		var conns []net.Conn
		for {
			c, err := ln.Accept()
			if err != nil {
				for _, c := range conns {
					_ = c.Close()
				}
				return
			}
			conns = append(conns, c)
		}
	}()
	t.Cleanup(func() { _ = ln.Close(); <-done })
	return p
}

func TestStatusDownDeadAndSilentWithinOneSecond(t *testing.T) {
	asRootPeer(t)
	cases := []struct {
		name    string
		path    string
		wantTip string
	}{
		{"dead", filepath.Join(t.TempDir(), "missing.sock"), ""},
		{"silent", listenSilentUnix(t), "does not answer"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			code, out, errOut := run("status", "-api", tc.path)
			if elapsed := time.Since(start); elapsed >= time.Second {
				t.Fatalf("status took %v, want < 1s", elapsed)
			}
			if code != 0 || errOut != "" {
				t.Fatalf("status: code=%d out=%q err=%q", code, out, errOut)
			}
			line := decodeStatusLine(t, out)
			if line.Class != "down" || !strings.Contains(line.Tooltip, tc.wantTip) {
				t.Fatalf("line = %#v (want class=down tip %q)", line, tc.wantTip)
			}
		})
	}
}

func TestStatusForeignSocketReportsDown(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; non-root peer check requires non-root uid")
	}
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	code, out, errOut := run("status", "-api", s.Path())
	if code != 0 || errOut != "" {
		t.Fatalf("foreign status: code=%d out=%q err=%q", code, out, errOut)
	}
	line := decodeStatusLine(t, out)
	if line.Class != "down" || !strings.Contains(line.Tooltip, "not root") {
		t.Fatalf("foreign status = %#v", line)
	}
}

func TestStatusIgnoresBrokenConfigAndRejectsBadFlags(t *testing.T) {
	asRootPeer(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeConfigFile(t, home, "trial = \"10s\"\n[[[invalid\n")
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})

	code, out, errOut := run("status", "-api", s.Path())
	if code != 0 || errOut != "" {
		t.Fatalf("status with broken config: code=%d out=%q err=%q", code, out, errOut)
	}
	if line := decodeStatusLine(t, out); line.Class != "allow" {
		t.Fatalf("status with broken config: line=%#v", line)
	}

	for _, args := range [][]string{{"status", "-api"}, {"status", "-bogus"}, {"status", "extra"}} {
		code, out, errOut := run(args...)
		if code != exitUsage || out != "" || !strings.Contains(errOut, "usage: snitch status") {
			t.Fatalf("%v: want exit 2, usage; got %d %q %q", args, code, out, errOut)
		}
	}
}

func mustDefaultStep(t *testing.T, s *clienttest.StandIn, args []string, wantOut, wantMode string, hasTrial, kept bool) {
	t.Helper()
	code, out, errOut := run(args...)
	if code != 0 || errOut != "" || !strings.Contains(out, wantOut) {
		t.Fatalf("%v: code=%d out=%q err=%q (want %q)", args, code, out, errOut, wantOut)
	}
	st := s.Facts()
	if st.Mode != wantMode || (st.Trial != "") != hasTrial || st.Kept != kept {
		t.Fatalf("after %v: facts=%#v", args, st)
	}
}

func TestDefaultStandInDenyKeepAllowAndConfig(t *testing.T) {
	asRootPeer(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	writeConfigFile(t, home, "trial = \"15m\"\n")
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})

	mustDefaultStep(t, s, []string{"default", "-api", s.Path(), "deny"}, "15m0s", "enforce", true, false)
	mustDefaultStep(t, s, []string{"default", "deny", "--keep", "-api", s.Path()}, "enforce kept", "enforce", false, true)
	mustDefaultStep(t, s, []string{"default", "--api=" + s.Path(), "allow"}, "monitor", "monitor", false, false)
}

func TestDefaultQuestionNonTTYAndPTYFlush(t *testing.T) {
	asRootPeer(t)
	t.Setenv("HOME", t.TempDir())
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid()), NoRules: true})

	var outBuf, errBuf bytes.Buffer
	code := runDefault([]string{"-api", s.Path(), "deny"}, bytes.NewBufferString("y\n"), &outBuf, &errBuf)
	if code != exitFail || outBuf.String() != "" || !strings.Contains(errBuf.String(), "terminal") {
		t.Fatalf("non-tty question: code=%d out=%q err=%q", code, outBuf.String(), errBuf.String())
	}
	if st := s.Facts(); st.Mode != "monitor" {
		t.Fatalf("non-tty must not enter enforce, got %#v", st)
	}

	master, slave := openTestPTY(t)
	ptyOut := pumpPTY(master)
	_, _ = io.WriteString(master, "n\n")
	time.Sleep(30 * time.Millisecond)

	errBuf.Reset()
	done := make(chan int, 1)
	go func() {
		done <- runDefault([]string{"-api", s.Path(), "deny"}, slave, slave, &errBuf)
	}()
	waitPTYText(t, ptyOut, "[y/N]")
	time.Sleep(50 * time.Millisecond)
	_, _ = io.WriteString(master, "y\n")
	if code := <-done; code != 0 || errBuf.String() != "" {
		t.Fatalf("pty confirm: code=%d err=%q out=%q", code, errBuf.String(), ptyOut.String())
	}
	if st := s.Facts(); st.Mode != "enforce" {
		t.Fatalf("pty confirm must enter enforce, got %#v", st)
	}
}

func mustRunErr(t *testing.T, wantCode int, wantErr string, args ...string) {
	t.Helper()
	code, out, errOut := run(args...)
	if code != wantCode || out != "" || !strings.Contains(errOut, wantErr) || errOut == "" {
		t.Fatalf("%v: want exit %d, %q; got %d %q %q", args, wantCode, wantErr, code, out, errOut)
	}
}

func TestDefaultUsageBrokenConfigAndRefusalExitCodes(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, args := range [][]string{
		{"default"}, {"default", "bogus"}, {"default", "allow", "--keep"},
		{"default", "-api"}, {"default", "deny", "-bogus"},
	} {
		mustRunErr(t, exitUsage, "usage: snitch default", args...)
	}

	home := t.TempDir()
	t.Setenv("HOME", home)
	writeConfigFile(t, home, "trial = \"10s\"\n")
	mustRunErr(t, exitUsage, "config.toml", "default", "deny")

	t.Setenv("HOME", t.TempDir())
	asRootPeer(t)
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	s.Refuse(true)
	mustRunErr(t, exitFail, "", "default", "-api", s.Path(), "deny")

	dead := filepath.Join(t.TempDir(), "missing.sock")
	mustRunErr(t, exitFail, "", "default", "-api", dead, "deny")
}

func TestDefaultForeignSocketRefused(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("running as root; non-root peer check requires non-root uid")
	}
	t.Setenv("HOME", t.TempDir())
	s := clienttest.Start(t, clienttest.Options{Operator: uint32(os.Getuid())})
	code, out, errOut := run("default", "-api", s.Path(), "deny")
	if code != exitFail || out != "" || !strings.Contains(errOut, "not root") {
		t.Fatalf("foreign default: code=%d out=%q err=%q", code, out, errOut)
	}
	if st := s.Facts(); st.Mode != "monitor" {
		t.Fatalf("foreign default must not write, got %#v", st)
	}
}
