package lsm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	helperRelPath = "../../packaging/lsm-cmdline.sh"
	dropInRelPath = "../../packaging/grub-snitch-lsm.cfg"
	manualPrefix  = "snitch: add to the kernel command line: "
)

type helperFixture struct {
	dir, list, cmdline, boot string
}

var (
	okKernels = map[string]string{
		"6.8.0": "CONFIG_BPF_LSM=y\n",
		"7.3.4": "CONFIG_SECURITY=y\nCONFIG_BPF_LSM=y\n",
	}
	helperDecisionCases = []struct {
		name, list, cmdline, grubVars, wantOut string
		wantExplain                            []string
	}{
		{"admin at start lacks bpf", "lockdown\n", "quiet\n", "lsm=lockdown,apparmor", "", []string{"add bpf", "your own lsm="}},
		{"admin after space has bpf", "lockdown\n", "quiet\n", `quiet lsm="lockdown,bpf"`, "", []string{"already in your lsm="}},
		{"unreadable missing list", "\x00MISSING", "quiet\n", "quiet", "", []string{"cannot read the active LSM list"}},
		{"default active no cmdline lsm", "lockdown,bpf\n", "foolsm=x quiet\n", "quiet", "", []string{"already active"}},
		{"ours active with cmdline lsm", "lockdown,bpf\n", "quiet lsm=lockdown,bpf\n", "foolsm=ignored", "lsm=lockdown,bpf", []string{"active", "kept"}},
		{"add appends bpf", "lockdown,apparmor\n", "quiet splash\n", "quiet", "lsm=lockdown,apparmor,bpf", []string{"reboot", "see connections"}},
	}
	helperKernelCases = []struct {
		name       string
		list       string
		cmdline    string
		kernels    map[string]string
		unreadable string
		wantSub    []string
	}{
		{"empty bootdir", "lockdown,apparmor\n", "quiet\n", map[string]string{}, "", []string{"no kernel found"}},
		{"missing config", "lockdown,apparmor\n", "quiet\n", map[string]string{"6.8.0": "CONFIG_BPF_LSM=y\n", "7.3.4": "\x00MISSING"}, "", []string{"7.3.4", "missing config"}},
		{"lacks CONFIG_BPF_LSM=y", "lockdown,bpf\n", "lsm=lockdown,bpf\n", map[string]string{"6.8.0": "# CONFIG_BPF_LSM is not set\n"}, "", []string{"6.8.0", "lacks CONFIG_BPF_LSM=y"}},
		{"unreadable config", "lockdown,apparmor\n", "quiet\n", map[string]string{"6.8.0": "CONFIG_BPF_LSM=y\n", "7.3.4": "CONFIG_BPF_LSM=y\n"}, "7.3.4", []string{"7.3.4", "unreadable config"}},
	}
)

func newHelperFixture(t *testing.T, listText, cmdlineText string, kernels map[string]string) helperFixture {
	t.Helper()
	dir := t.TempDir()
	f := helperFixture{dir, filepath.Join(dir, "lsm"), filepath.Join(dir, "cmdline"), filepath.Join(dir, "boot")}
	if listText != "\x00MISSING" {
		mustWrite(t, f.list, listText, 0o644)
	}
	if cmdlineText != "\x00MISSING" {
		mustWrite(t, f.cmdline, cmdlineText, 0o644)
	}
	if err := os.MkdirAll(f.boot, 0o755); err != nil {
		t.Fatal(err)
	}
	for ver, cfg := range kernels {
		mustWrite(t, filepath.Join(f.boot, "vmlinuz-"+ver), "kernel", 0o644)
		if cfg != "\x00MISSING" {
			mustWrite(t, filepath.Join(f.boot, "config-"+ver), cfg, 0o644)
		}
	}
	return f
}

func mustWrite(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

func runHelper(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("sh", append([]string{helperRelPath}, args...)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper %v failed (%v): %s", args, err, out)
	}
	return strings.TrimSuffix(string(out), "\n")
}

func assertExplain(t *testing.T, exp string, subs []string) {
	t.Helper()
	for _, sub := range subs {
		if !strings.Contains(exp, sub) {
			t.Fatalf("--explain = %q, missing %q", exp, sub)
		}
	}
}

func TestHelperDecisionCases(t *testing.T) {
	for _, tc := range helperDecisionCases {
		t.Run(tc.name, func(t *testing.T) {
			f := newHelperFixture(t, tc.list, tc.cmdline, okKernels)
			if got := runHelper(t, "-l", f.list, "-c", f.cmdline, "-k", f.boot, "--", tc.grubVars); got != tc.wantOut {
				t.Fatalf("output = %q, want %q", got, tc.wantOut)
			}
			exp := runHelper(t, "--explain", "-l", f.list, "-c", f.cmdline, "-k", f.boot, "--", tc.grubVars)
			assertExplain(t, exp, tc.wantExplain)
		})
	}
}

func TestHelperValidation(t *testing.T) {
	badLists := []string{"", "   \n", "lockdown!", "lockdown;reboot", "lockdown apparmor", "lockdown\napparmor", "AppArmor"}
	for _, bad := range badLists {
		f := newHelperFixture(t, bad, "quiet\n", okKernels)
		if got := runHelper(t, "-l", f.list, "-c", f.cmdline, "-k", f.boot, "--", ""); got != "" {
			t.Fatalf("bad list %q emitted %q, want empty", bad, got)
		}
		exp := runHelper(t, "--explain", "-l", f.list, "-c", f.cmdline, "-k", f.boot, "--", "")
		assertExplain(t, exp, []string{"cannot read the active LSM list"})
	}
}

func TestHelperKernelSupport(t *testing.T) {
	for _, tc := range helperKernelCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.unreadable != "" && os.Geteuid() == 0 {
				t.Skip("root ignores chmod 0000")
			}
			f := newHelperFixture(t, tc.list, tc.cmdline, tc.kernels)
			if tc.unreadable != "" {
				p := filepath.Join(f.boot, "config-"+tc.unreadable)
				if err := os.Chmod(p, 0o000); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = os.Chmod(p, 0o644) })
			}
			if got := runHelper(t, "-l", f.list, "-c", f.cmdline, "-k", f.boot, "--", ""); got != "" {
				t.Fatalf("emitted %q, want empty", got)
			}
			exp := runHelper(t, "--explain", "-l", f.list, "-c", f.cmdline, "-k", f.boot, "--", "")
			assertExplain(t, exp, tc.wantSub)
		})
	}
}

func TestHelperManual(t *testing.T) {
	cases := []struct{ name, list, want string }{
		{"without bpf", "lockdown,apparmor\n", manualPrefix + "lsm=lockdown,apparmor,bpf"},
		{"with bpf", "lockdown,bpf\n", manualPrefix + "lsm=lockdown,bpf"},
		{"unreadable", "\x00MISSING", manualPrefix + "lsm=<your list>,bpf"},
		{"invalid char", "lockdown;bad\n", manualPrefix + "lsm=<your list>,bpf"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newHelperFixture(t, tc.list, "quiet\n", nil)
			got := runHelper(t, "--manual", "-l", f.list, "-c", f.cmdline, "-k", f.boot)
			if !strings.HasPrefix(got, manualPrefix) || got != tc.want {
				t.Fatalf("--manual = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestHelperPID1Guard(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires non-root where /proc/1/root is unreadable")
	}
	f := newHelperFixture(t, "\x00MISSING", "quiet lsm=lockdown\n", map[string]string{"7.3.4": "CONFIG_BPF_LSM=y\n"})
	if got := runHelper(t, "-c", f.cmdline, "-k", f.boot, "--", ""); got != "" {
		t.Fatalf("expected empty output under PID-1 guard, got %q", got)
	}
	if exp := runHelper(t, "--explain", "-c", f.cmdline, "-k", f.boot); exp == "" {
		t.Fatal("expected --explain to still print under PID-1 guard")
	}
	if man := runHelper(t, "--manual", "-c", f.cmdline, "-k", f.boot); !strings.HasPrefix(man, manualPrefix) {
		t.Fatalf("--manual = %q under PID-1 guard", man)
	}
}

func TestHelperDropIn(t *testing.T) {
	if out, err := exec.Command("sh", "-n", dropInRelPath).CombinedOutput(); err != nil {
		t.Fatalf("sh -n drop-in: %v: %s", err, out)
	}
	raw, err := os.ReadFile(dropInRelPath)
	if err != nil {
		t.Fatal(err)
	}
	const prodHelper = "/usr/lib/snitch/lsm-cmdline"
	if !strings.Contains(string(raw), prodHelper) {
		t.Fatalf("drop-in does not reference %s", prodHelper)
	}
	dir := t.TempDir()
	mockOut := filepath.Join(dir, "emit")
	mockEmpty := filepath.Join(dir, "empty")
	mustWrite(t, mockOut, "#!/bin/sh\necho 'lsm=lockdown,apparmor,bpf'\n", 0o755)
	mustWrite(t, mockEmpty, "#!/bin/sh\nexit 0\n", 0o755)

	checkDropIn := func(helperPath, initDefault, want string) {
		cfg := filepath.Join(dir, filepath.Base(helperPath)+".cfg")
		mustWrite(t, cfg, strings.ReplaceAll(string(raw), prodHelper, helperPath), 0o644)
		script := "GRUB_CMDLINE_LINUX='ro'\nGRUB_CMDLINE_LINUX_DEFAULT='" + initDefault + "'\n. '" + cfg + "'\nprintf '%s' \"$GRUB_CMDLINE_LINUX_DEFAULT\"\n"
		out, err := exec.Command("sh", "-eu", "-c", script).CombinedOutput()
		if err != nil || string(out) != want {
			t.Fatalf("helper=%s init=%q got=%q err=%v want=%q", helperPath, initDefault, out, err, want)
		}
	}
	checkDropIn(mockOut, "quiet", "quiet lsm=lockdown,apparmor,bpf")
	checkDropIn(mockOut, "", "lsm=lockdown,apparmor,bpf")
	checkDropIn(mockEmpty, "quiet", "quiet")
	checkDropIn(filepath.Join(dir, "missing"), "quiet", "quiet")
}
