package lsm

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// systemctlStub configures the fake systemctl: is-active answers active, try-restart fails
// when restartFails, and enable/disable fail when toggleFails. Every call is logged.
type systemctlStub struct {
	active, restartFails, toggleFails bool
}

// install writes the stub (and a link to the real dpkg, for version comparison) into a
// directory put first on env's PATH, optionally with a booted systemd under env.root, and
// returns the call log path.
func (s systemctlStub) install(t *testing.T, env *scriptEnv, booted bool) string {
	t.Helper()
	dir := t.TempDir()
	if dpkg, err := exec.LookPath("dpkg"); err == nil {
		if err := os.Symlink(dpkg, filepath.Join(dir, "dpkg")); err != nil {
			t.Fatal(err)
		}
	}
	if booted {
		if err := os.MkdirAll(filepath.Join(env.root, "run/systemd/system"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	code := func(fail bool) string { return map[bool]string{true: "1", false: "0"}[fail] }
	log := filepath.Join(t.TempDir(), "systemctl.log")
	body := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + log + "\n" +
		"case \"$*\" in\n\t*enable*|*disable*) exit " + code(s.toggleFails) + " ;;\nesac\n" +
		"case \"$1\" in\n\tis-active) exit " + map[bool]string{true: "0", false: "3"}[s.active] + " ;;\n" +
		"\ttry-restart) exit " + code(s.restartFails) + " ;;\nesac\nexit 0\n"
	mustWrite(t, filepath.Join(dir, "systemctl"), body, 0o755)
	env.path = dir + ":" + env.path
	return log
}

// systemdCase is one maintainer-script run against the stub: the systemctl calls it must
// make (ROOT stands for DPKG_ROOT) and a substring its output must carry.
type systemdCase struct {
	name    string
	script  string
	args    []string
	booted  bool
	stub    systemctlStub
	calls   []string
	wantSub string
}

func (c systemdCase) run(t *testing.T) {
	t.Helper()
	env := newScriptEnv(t, true, "", "pass")
	log := c.stub.install(t, &env, c.booted)
	out, code := runMaintScript(t, c.script, env, c.args...)
	if code != 0 {
		t.Fatalf("exit = %d, want 0; out=%q", code, out)
	}
	var got, want []string
	for _, l := range readLines(t, log) {
		if strings.HasPrefix(strings.TrimPrefix(l, "--root="+env.root+" "), "start") {
			t.Fatalf("a maintainer script started a unit: %q", l)
		}
		got = append(got, l)
	}
	for _, w := range c.calls {
		want = append(want, strings.ReplaceAll(w, "ROOT", env.root))
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("systemctl calls = %q, want %q", got, want)
	}
	if c.wantSub != "" && !strings.Contains(out, c.wantSub) {
		t.Fatalf("output %q missing %q", out, c.wantSub)
	}
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

const (
	enableBoth = "--root=ROOT enable snitchd-trial-boot.service snitchd.service"
	isActive   = "is-active --quiet snitchd.service"
	tryRestart = "try-restart snitchd.service"
)

func runSystemdCases(t *testing.T, cases []systemdCase) {
	t.Helper()
	if _, err := exec.LookPath("dpkg"); err != nil {
		t.Skip("dpkg not on PATH: version comparison untestable here")
	}
	for _, c := range cases {
		t.Run(c.name, c.run)
	}
}

// An upgrade from 1.2.0 never enables, so these cases see only the restart path.
func TestScriptsPostinstRestart(t *testing.T) {
	up := []string{"configure", "1.2.0"}
	runSystemdCases(t, []systemdCase{
		{"no booted systemd: systemctl untouched", postinstRelPath, up, false, systemctlStub{active: true}, nil, ""},
		{"stopped daemon is not started", postinstRelPath, up, true, systemctlStub{}, []string{"daemon-reload", isActive}, ""},
		{"running daemon is restarted", postinstRelPath, up, true, systemctlStub{active: true},
			[]string{"daemon-reload", isActive, tryRestart}, "snitch: restarted snitchd.service"},
		{"failed restart still installs", postinstRelPath, up, true, systemctlStub{active: true, restartFails: true},
			[]string{"daemon-reload", isActive, tryRestart}, "snitch: restarting snitchd.service failed"},
	})
}

func TestScriptsPostinstEnable(t *testing.T) {
	runSystemdCases(t, []systemdCase{
		{"fresh install enables both units", postinstRelPath, []string{"configure"}, false, systemctlStub{},
			[]string{enableBoth}, "snitch: enabled snitchd.service and snitchd-trial-boot.service"},
		{"upgrade from 1.1.0 enables", postinstRelPath, []string{"configure", "1.1.0"}, false, systemctlStub{},
			[]string{enableBoth}, "snitch: enabled"},
		{"upgrade from 1.2.0 keeps the operator's choice", postinstRelPath, []string{"configure", "1.2.0"}, false,
			systemctlStub{}, nil, ""},
		{"failing enable still installs", postinstRelPath, []string{"configure"}, false, systemctlStub{toggleFails: true},
			[]string{enableBoth}, "snitch: enabling snitchd at boot failed"},
	})
}

func TestScriptsPrerm(t *testing.T) {
	disable := "--root=ROOT disable snitchd.service snitchd-trial-boot.service"
	failing := systemctlStub{active: true, toggleFails: true}
	runSystemdCases(t, []systemdCase{
		{"remove on a booted host stops and disables", prermRelPath, []string{"remove", "1.2.0"}, true, failing,
			[]string{"stop snitchd.service", disable}, "disabling snitchd at boot failed"},
		{"remove without booted systemd only disables", prermRelPath, []string{"remove", "1.2.0"}, false, failing,
			[]string{disable}, "disabling snitchd at boot failed"},
		{"upgrade leaves the units alone", prermRelPath, []string{"upgrade", "1.2.0"}, true, failing, nil, ""},
		{"failed-upgrade leaves the units alone", prermRelPath, []string{"failed-upgrade", "1.2.0"}, true, failing, nil, ""},
	})
}
