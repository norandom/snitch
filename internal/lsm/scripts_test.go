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

// makeSystemctlStub writes a systemctl that logs its arguments; is-active exits
// 0 when active, try-restart exits 1 when restartFails.
func makeSystemctlStub(t *testing.T, active, restartFails bool) (dir, log string) {
	return makeSystemctlStubFull(t, active, restartFails, false)
}

func makeSystemctlStubFull(t *testing.T, active, restartFails, enableFails bool) (dir, log string) {
	t.Helper()
	dir = t.TempDir()
	if dpkg, err := exec.LookPath("dpkg"); err == nil {
		if err := os.Symlink(dpkg, filepath.Join(dir, "dpkg")); err != nil {
			t.Fatal(err)
		}
	}
	log = filepath.Join(t.TempDir(), "systemctl.log")
	activeCode, restartCode := "3", "0"
	if active {
		activeCode = "0"
	}
	if restartFails {
		restartCode = "1"
	}
	enableCode := "0"
	if enableFails {
		enableCode = "1"
	}
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + log + "\n" +
		"case \"$*\" in\n\t*enable*|*disable*) exit " + enableCode + " ;;\nesac\n" +
		"case \"$1\" in\n" +
		"\tis-active) exit " + activeCode + " ;;\n" +
		"\ttry-restart) exit " + restartCode + " ;;\n" +
		"esac\nexit 0\n"
	mustWrite(t, filepath.Join(dir, "systemctl"), body, 0o755)
	return dir, log
}

func readLines(t *testing.T, path string) []string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSpace(string(raw)), "\n")
}

func TestScriptsPostinstRestart(t *testing.T) {
	cases := []struct {
		name         string
		booted       bool
		active       bool
		restartFails bool
		wantCalls    []string
		wantSub      string
		wantNot      string
	}{
		{"no booted systemd: systemctl untouched", false, true, false, nil, "", "restart"},
		{"stopped daemon is not started", true, false, false,
			[]string{"daemon-reload", "is-active --quiet snitchd.service"}, "", "restart"},
		{"running daemon is restarted", true, true, false,
			[]string{"daemon-reload", "is-active --quiet snitchd.service", "try-restart snitchd.service"},
			"snitch: restarted snitchd.service", ""},
		{"failed restart still installs", true, true, true,
			[]string{"daemon-reload", "is-active --quiet snitchd.service", "try-restart snitchd.service"},
			"snitch: restarting snitchd.service failed", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newScriptEnv(t, true, "", "pass")
			if tc.booted {
				if err := os.MkdirAll(filepath.Join(env.root, "run/systemd/system"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			stubDir, log := makeSystemctlStub(t, tc.active, tc.restartFails)
			env.path = stubDir + ":" + env.path
			out, code := runMaintScript(t, postinstRelPath, env, "configure", "1.2.0")
			if code != 0 {
				t.Fatalf("exit = %d, want 0; out=%q", code, out)
			}
			got := readLines(t, log)
			if strings.Join(got, "|") != strings.Join(tc.wantCalls, "|") {
				t.Fatalf("systemctl calls = %q, want %q", got, tc.wantCalls)
			}
			for _, c := range got {
				if strings.HasPrefix(c, "enable") || strings.HasPrefix(c, "start") {
					t.Fatalf("postinst ran systemctl %q", c)
				}
			}
			if tc.wantSub != "" && !strings.Contains(out, tc.wantSub) {
				t.Fatalf("output %q missing %q", out, tc.wantSub)
			}
			if tc.wantNot != "" && strings.Contains(out, tc.wantNot) {
				t.Fatalf("output %q contains %q", out, tc.wantNot)
			}
		})
	}
}

func TestScriptsPostinstEnable(t *testing.T) {
	cases := []struct {
		name        string
		prev        string
		enableFails bool
		wantEnable  bool
		wantSub     string
	}{
		{"fresh install enables both units", "", false, true, "snitch: enabled snitchd.service and snitchd-trial-boot.service"},
		{"upgrade from 1.1.0 enables", "1.1.0", false, true, "snitch: enabled"},
		{"upgrade from 1.2.0 keeps the operator's choice", "1.2.0", false, false, ""},
		{"failing enable still installs", "", true, true, "snitch: enabling snitchd at boot failed"},
	}
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("dpkg not on PATH: version comparison untestable here")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newScriptEnv(t, true, "", "pass")
			stubDir, log := makeSystemctlStubFull(t, false, false, tc.enableFails)
			env.path = stubDir + ":" + env.path
			args := []string{"configure"}
			if tc.prev != "" {
				args = append(args, tc.prev)
			}
			out, code := runMaintScript(t, postinstRelPath, env, args...)
			if code != 0 {
				t.Fatalf("exit = %d, want 0; out=%q", code, out)
			}
			want := "--root=" + env.root + " enable snitchd-trial-boot.service snitchd.service"
			var got []string
			for _, c := range readLines(t, log) {
				if strings.Contains(c, "enable") {
					got = append(got, c)
				}
				if strings.HasPrefix(c, "start") || strings.HasPrefix(c, "--root="+env.root+" start") {
					t.Fatalf("postinst started a unit: %q", c)
				}
			}
			if tc.wantEnable && (len(got) != 1 || got[0] != want) {
				t.Fatalf("enable calls = %q, want [%q]", got, want)
			}
			if !tc.wantEnable && len(got) != 0 {
				t.Fatalf("enable calls = %q, want none", got)
			}
			if tc.wantSub != "" && !strings.Contains(out, tc.wantSub) {
				t.Fatalf("output %q missing %q", out, tc.wantSub)
			}
		})
	}
}

func TestScriptsPrerm(t *testing.T) {
	cases := []struct {
		name      string
		action    string
		booted    bool
		wantCalls []string
	}{
		{"remove on a booted host stops and disables", "remove", true,
			[]string{"stop snitchd.service", "--root=ROOT disable snitchd.service snitchd-trial-boot.service"}},
		{"remove without booted systemd only disables", "remove", false,
			[]string{"--root=ROOT disable snitchd.service snitchd-trial-boot.service"}},
		{"upgrade leaves the units alone", "upgrade", true, nil},
		{"failed-upgrade leaves the units alone", "failed-upgrade", true, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			env := newScriptEnv(t, true, "", "pass")
			if tc.booted {
				if err := os.MkdirAll(filepath.Join(env.root, "run/systemd/system"), 0o755); err != nil {
					t.Fatal(err)
				}
			}
			stubDir, log := makeSystemctlStubFull(t, true, false, true)
			env.path = stubDir + ":" + env.path
			out, code := runMaintScript(t, prermRelPath, env, tc.action, "1.2.0")
			if code != 0 {
				t.Fatalf("exit = %d, want 0; out=%q", code, out)
			}
			var want []string
			for _, w := range tc.wantCalls {
				want = append(want, strings.ReplaceAll(w, "ROOT", env.root))
			}
			got := readLines(t, log)
			if strings.Join(got, "|") != strings.Join(want, "|") {
				t.Fatalf("systemctl calls = %q, want %q", got, want)
			}
			if tc.action == "remove" && !strings.Contains(out, "disabling snitchd at boot failed") {
				t.Fatalf("failing disable not reported: %q", out)
			}
		})
	}
}
