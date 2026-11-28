package lsm

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	postinstRelPath = "../../packaging/postinst.sh"
	postrmRelPath   = "../../packaging/postrm.sh"
	prermRelPath    = "../../packaging/prerm.sh"
)

type scriptEnv struct {
	root, path, log string
}

func newScriptEnv(t *testing.T, withBootGrub bool, grubDefault, stubMode string) scriptEnv {
	t.Helper()
	root := t.TempDir()
	libDir := filepath.Join(root, "usr/lib/snitch")
	if err := os.MkdirAll(libDir, 0o755); err != nil {
		t.Fatal(err)
	}
	helperSrc, err := os.ReadFile(helperRelPath)
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, filepath.Join(libDir, "lsm-cmdline"), string(helperSrc), 0o755)
	if withBootGrub {
		if err := os.MkdirAll(filepath.Join(root, "boot/grub"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if grubDefault != "" {
		if err := os.MkdirAll(filepath.Join(root, "etc/default"), 0o755); err != nil {
			t.Fatal(err)
		}
		mustWrite(t, filepath.Join(root, "etc/default/grub"), grubDefault, 0o644)
	}
	safeBin := makeSafeBin(t)
	logFile := filepath.Join(t.TempDir(), "update-grub.log")
	pathEnv := safeBin
	if stubMode != "none" {
		pathEnv = makeUpdateGrubStub(t, stubMode) + ":" + safeBin
	}
	return scriptEnv{root: root, path: pathEnv, log: logFile}
}

func makeSafeBin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, tool := range []string{"sh", "cat", "stat", "grep"} {
		target, err := exec.LookPath(tool)
		if err != nil {
			t.Fatalf("LookPath(%s): %v", tool, err)
		}
		if err := os.Symlink(target, filepath.Join(dir, tool)); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func makeUpdateGrubStub(t *testing.T, mode string) string {
	t.Helper()
	dir := t.TempDir()
	exitCode := "0"
	if mode == "fail" {
		exitCode = "1"
	}
	body := "#!/bin/sh\nprintf 'called\\n' >> \"$SNITCH_STUB_LOG\"\nexit " + exitCode + "\n"
	mustWrite(t, filepath.Join(dir, "update-grub"), body, 0o755)
	return dir
}

func runMaintScript(t *testing.T, script string, env scriptEnv, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("sh", append([]string{script}, args...)...)
	cmd.Env = []string{
		"DPKG_ROOT=" + env.root,
		"PATH=" + env.path,
		"SNITCH_STUB_LOG=" + env.log,
		"LC_ALL=C",
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return string(out), 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return string(out), exitErr.ExitCode()
	}
	t.Fatalf("exec %s %v: %v", script, args, err)
	return "", -1
}

func stubCalls(t *testing.T, logFile string) int {
	t.Helper()
	raw, err := os.ReadFile(logFile)
	if os.IsNotExist(err) {
		return 0
	}
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		if line != "" {
			count++
		}
	}
	return count
}

func TestScriptsSyntaxAndPermissions(t *testing.T) {
	for _, p := range []string{postinstRelPath, postrmRelPath, prermRelPath} {
		info, err := os.Stat(p)
		if err != nil {
			t.Fatalf("stat %s: %v", p, err)
		}
		if info.Mode()&0o111 != 0o111 {
			t.Fatalf("%s mode = %v, want executable (0755)", p, info.Mode())
		}
		if out, err := exec.Command("sh", "-n", p).CombinedOutput(); err != nil {
			t.Fatalf("sh -n %s: %v: %s", p, err, out)
		}
	}
}

var postinstConfigureCases = []struct {
	name         string
	withBootGrub bool
	grubDefault  string
	stubMode     string
	wantCalls    int
	wantSub      []string
}{
	{
		name:         "grub with passing update-grub",
		withBootGrub: true,
		stubMode:     "pass",
		wantCalls:    1,
		wantSub:      []string{"snitch: "},
	},
	{
		name:         "grub with failing update-grub",
		withBootGrub: true,
		stubMode:     "fail",
		wantCalls:    1,
		wantSub:      []string{"update-grub", "failed"},
	},
	{
		name:         "grub without update-grub",
		withBootGrub: true,
		stubMode:     "none",
		wantCalls:    0,
		wantSub:      []string{"update-grub", "not", manualPrefix},
	},
	{
		name:         "without boot grub",
		withBootGrub: false,
		stubMode:     "pass",
		wantCalls:    0,
		wantSub:      []string{manualPrefix},
	},
	{
		name:         "respects GRUB_CMDLINE_LINUX_DEFAULT",
		withBootGrub: true,
		grubDefault:  "GRUB_DEFAULT=0\nGRUB_CMDLINE_LINUX_DEFAULT=\"quiet lsm=apparmor\"\n",
		stubMode:     "pass",
		wantCalls:    1,
		wantSub:      []string{"add bpf to your own lsm= setting"},
	},
	{
		name:         "respects GRUB_CMDLINE_LINUX with bpf",
		withBootGrub: true,
		grubDefault:  "GRUB_CMDLINE_LINUX=\"lsm=lockdown,bpf\"\n",
		stubMode:     "pass",
		wantCalls:    1,
		wantSub:      []string{"already in your lsm="},
	},
}

func TestScriptsPostinstConfigure(t *testing.T) {
	for _, tc := range postinstConfigureCases {
		t.Run(tc.name, func(t *testing.T) {
			env := newScriptEnv(t, tc.withBootGrub, tc.grubDefault, tc.stubMode)
			out, code := runMaintScript(t, postinstRelPath, env, "configure")
			if code != 0 {
				t.Fatalf("exit = %d, want 0; out=%q", code, out)
			}
			if got := stubCalls(t, env.log); got != tc.wantCalls {
				t.Fatalf("update-grub calls = %d, want %d; out=%q", got, tc.wantCalls, out)
			}
			for _, sub := range tc.wantSub {
				if !strings.Contains(out, sub) {
					t.Fatalf("output %q missing %q", out, sub)
				}
			}
		})
	}
}

func TestScriptsPostinstNonConfigure(t *testing.T) {
	for _, arg := range []string{"abort-upgrade", "abort-remove", ""} {
		env := newScriptEnv(t, true, "", "pass")
		out, code := runMaintScript(t, postinstRelPath, env, arg)
		if code != 0 {
			t.Fatalf("arg=%q exit = %d, want 0; out=%q", arg, code, out)
		}
		if got := stubCalls(t, env.log); got != 0 {
			t.Fatalf("arg=%q called update-grub %d times, want 0", arg, got)
		}
	}
}

func TestScriptsPostrm(t *testing.T) {
	cases := []struct {
		name         string
		action       string
		withBootGrub bool
		stubMode     string
		wantCalls    int
		wantSub      []string
	}{
		{"remove with passing update-grub", "remove", true, "pass", 1, nil},
		{"purge with passing update-grub", "purge", true, "pass", 1, nil},
		{"remove with failing update-grub", "remove", true, "fail", 1, []string{"update-grub", "failed"}},
		{"remove without boot grub", "remove", false, "pass", 0, nil},
		{"remove without update-grub", "remove", true, "none", 0, nil},
		{"upgrade does not run update-grub", "upgrade", true, "pass", 0, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newScriptEnv(t, tc.withBootGrub, "", tc.stubMode)
			out, code := runMaintScript(t, postrmRelPath, env, tc.action)
			if code != 0 {
				t.Fatalf("exit = %d, want 0; out=%q", code, out)
			}
			if got := stubCalls(t, env.log); got != tc.wantCalls {
				t.Fatalf("update-grub calls = %d, want %d; out=%q", got, tc.wantCalls, out)
			}
			for _, sub := range tc.wantSub {
				if !strings.Contains(out, sub) {
					t.Fatalf("output %q missing %q", out, sub)
				}
			}
		})
	}
}

func TestScriptsConffiles(t *testing.T) {
	raw, err := os.ReadFile("../../packaging/conffiles")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	if !strings.HasSuffix(text, "\n") || strings.HasSuffix(text, "\n\n") {
		t.Fatalf("conffiles must end with a single newline: %q", text)
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	for i, line := range lines {
		if line == "" || !strings.HasPrefix(line, "/") {
			t.Fatalf("conffiles line %d = %q, want non-empty absolute path", i+1, line)
		}
	}
}
