// pins_test.go: wire, network, and runtime-isolation pins (8.1, 8.5, 13.9) over the
// non-test sources of all twelve packages that link into the snitch binary.
// Request literals follow a per-package allowlist (learned/unsubscribe stay forbidden
// everywhere except client.Send's refusal); no package opens a listener, dials anything
// except the daemon's unix socket, or names protocol literals; the seven new packages
// name no mkfifo/Mkfifo or XDG_RUNTIME_DIR. Helpers clienttest, snitest, fakedaemon stay outside.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

var pinPkgs = []string{
	module + "/cmd/snitch",
	module + "/internal/client",
	module + "/internal/ask",
	module + "/internal/tray",
	module + "/internal/sni",
	module + "/internal/clean",
	module + "/internal/conf",
	module + "/internal/logfile",
	module + "/internal/table",
	module + "/internal/tui",
	module + "/internal/term",
	module + "/internal/verbs",
}

var newPinPkgs = map[string]bool{
	module + "/internal/clean":   true,
	module + "/internal/conf":    true,
	module + "/internal/logfile": true,
	module + "/internal/table":   true,
	module + "/internal/tui":     true,
	module + "/internal/term":    true,
	module + "/internal/verbs":   true,
}

func reqSet(reqs ...string) map[string]bool {
	m := make(map[string]bool, len(reqs))
	for _, r := range reqs {
		m[r] = true
	}
	return m
}

var (
	trayReqs  = reqSet("status", "subscribe", "rule.add")
	cmdReqs   = reqSet("status", "subscribe", "rule.add", "snapshot")
	tableReqs = reqSet("rule.add", "rule.remove")
	tuiReqs   = reqSet("status", "subscribe", "rule.add", "snapshot", "rules", "programs",
		"rule.remove", "trial", "keep", "unkeep", "end")
	noReqs = reqSet()
)

var allowedRequests = map[string]map[string]bool{
	module + "/cmd/snitch":       cmdReqs,
	module + "/internal/client":  trayReqs,
	module + "/internal/ask":     trayReqs,
	module + "/internal/tray":    trayReqs,
	module + "/internal/sni":     trayReqs,
	module + "/internal/table":   tableReqs,
	module + "/internal/tui":     tuiReqs,
	module + "/internal/verbs":   tuiReqs,
	module + "/internal/clean":   noReqs,
	module + "/internal/conf":    noReqs,
	module + "/internal/logfile": noReqs,
	module + "/internal/term":    noReqs,
}

type pinFile struct {
	pkg, name string
	lines     []string
}

func pinDirs(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("go", append([]string{"list", "-f", "{{.Dir}}"}, pinPkgs...)...).Output()
	if err != nil {
		t.Fatalf("go list -f Dir %v: %v", pinPkgs, err)
	}
	return strings.Fields(string(out))
}

func readPkgSources(t *testing.T, pkg, dir string) []pinFile {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var files []pinFile
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		files = append(files, pinFile{pkg: pkg, name: e.Name(), lines: strings.Split(string(b), "\n")})
	}
	return files
}

// pinSources reads every non-test .go file of the pinned packages, requiring at least one per package.
func pinSources(t *testing.T) []pinFile {
	t.Helper()
	dirs := pinDirs(t)
	if len(dirs) != len(pinPkgs) {
		t.Fatalf("go list answered %d dirs for %d packages", len(dirs), len(pinPkgs))
	}
	var files []pinFile
	for i, dir := range dirs {
		pkgFiles := readPkgSources(t, pinPkgs[i], dir)
		if len(pkgFiles) == 0 {
			t.Fatalf("%s has no non-test .go files: the scan read nothing", pinPkgs[i])
		}
		files = append(files, pkgFiles...)
	}
	return files
}

// onSendGuardLine allows client.Send's contract.Require precondition to name refused request types.
func onSendGuardLine(f pinFile, i int) bool {
	if f.pkg != module+"/internal/client" || f.name != "client.go" {
		return false
	}
	return strings.Contains(f.lines[i], "contract.Require") ||
		(i > 0 && strings.Contains(f.lines[i-1], "contract.Require"))
}

// onConfTagLine allows internal/conf/conf.go's `toml:"trial"` tag when no other "trial" appears on that line.
func onConfTagLine(f pinFile, line string) bool {
	if f.pkg != module+"/internal/conf" || f.name != "conf.go" {
		return false
	}
	const tag = "`toml:\"trial\"`"
	return strings.Contains(line, tag) && !strings.Contains(strings.ReplaceAll(line, tag, ""), `"trial"`)
}

// onCoverProtoLine allows internal/table/cover.go's isTCPOrUDP helper; cover.go is pinned to never import "net".
func onCoverProtoLine(f pinFile, line string) bool {
	return f.pkg == module+"/internal/table" && f.name == "cover.go" &&
		strings.HasPrefix(strings.TrimSpace(line), "func isTCPOrUDP(")
}

func allowRequestMention(f pinFile, i int, typ string) bool {
	if allowedRequests[f.pkg][typ] {
		return true
	}
	if (typ == "snapshot" || typ == "unsubscribe") && onSendGuardLine(f, i) {
		return true
	}
	return typ == "trial" && onConfTagLine(f, f.lines[i])
}

// TestConstraintPinsRequestLiterals enforces the per-package request-type allowlist.
func TestConstraintPinsRequestLiterals(t *testing.T) {
	for _, f := range pinSources(t) {
		if _, ok := allowedRequests[f.pkg]; !ok {
			t.Fatalf("package %s has no request allowlist entry", f.pkg)
		}
		for i, line := range f.lines {
			for _, typ := range daemonRequests {
				if strings.Contains(line, `"`+typ+`"`) && !allowRequestMention(f, i, typ) {
					t.Fatalf("%s/%s:%d mentions forbidden request type %q", f.pkg, f.name, i+1, typ)
				}
			}
		}
	}
}

func lineContains(lines []string, sub string) bool {
	for _, l := range lines {
		if strings.Contains(l, sub) {
			return true
		}
	}
	return false
}

// TestConstraintPinsLegalRequestLiteralsExist pins the pin itself against an empty scan.
func TestConstraintPinsLegalRequestLiteralsExist(t *testing.T) {
	want := map[string][]string{
		module + "/internal/client": {`"status"`, `"type":"subscribe"`},
		module + "/internal/ask":    {`"rule.add"`},
		module + "/internal/table":  {`"rule.add"`, `"rule.remove"`},
		module + "/internal/tui":    {`"snapshot"`, `"rules"`, `"programs"`, `"trial"`, `"keep"`, `"unkeep"`, `"end"`},
		module + "/internal/verbs":  {`"trial"`, `"keep"`, `"end"`},
	}
	seen := map[string]map[string]bool{}
	for _, f := range pinSources(t) {
		for _, lit := range want[f.pkg] {
			if lineContains(f.lines, lit) {
				if seen[f.pkg] == nil {
					seen[f.pkg] = map[string]bool{}
				}
				seen[f.pkg][lit] = true
			}
		}
	}
	for pkg, lits := range want {
		for _, lit := range lits {
			if !seen[pkg][lit] {
				t.Fatalf("%s is missing expected legal request literal %s", pkg, lit)
			}
		}
	}
}

var daemonRequests = []string{"status", "rules", "programs", "learned", "snapshot",
	"subscribe", "unsubscribe", "trial", "keep", "unkeep", "end", "rule.add", "rule.remove"}

var bannedNet = []string{"net.Listen", "net.Dial(", "net.DialContext(", "net.DialTCP",
	"net.DialUDP", "net.ListenTCP", "net.ListenUDP", `"tcp"`, `"udp"`, `"tcp4"`,
	`"tcp6"`, `"udp4"`, `"udp6"`}

func isNetImport(line string) bool {
	trimmed := strings.TrimSpace(line)
	return trimmed == `"net"` || strings.HasSuffix(trimmed, ` "net"`)
}

func checkBannedNetLine(t *testing.T, f pinFile, i int, line string) {
	t.Helper()
	for _, word := range bannedNet {
		if strings.Contains(line, word) && !((word == `"tcp"` || word == `"udp"`) && onCoverProtoLine(f, line)) {
			t.Fatalf("%s/%s:%d names %q, which opens a network the binary must not have", f.pkg, f.name, i+1, word)
		}
	}
	if strings.Contains(line, ".DialContext(") && !strings.Contains(line, `"unix"`) {
		t.Fatalf("%s/%s:%d dials without naming the unix network", f.pkg, f.name, i+1)
	}
}

// TestConstraintPinsDialOnlyDaemonsUnixSocket enforces 8.5 and 13.9: no listener,
// no non-unix dialer, no protocol literals, and no "net" import in internal/table/cover.go.
func TestConstraintPinsDialOnlyDaemonsUnixSocket(t *testing.T) {
	for _, f := range pinSources(t) {
		isCover := f.pkg == module+"/internal/table" && f.name == "cover.go"
		for i, line := range f.lines {
			if isCover && isNetImport(line) {
				t.Fatalf("%s/%s:%d imports \"net\", which cover.go must not do", f.pkg, f.name, i+1)
			}
			checkBannedNetLine(t, f, i, line)
		}
	}
}

var bannedNewPkg = []string{"mkfifo", "Mkfifo", "XDG_RUNTIME_DIR"}

// TestConstraintPinsNewPackageBans enforces 13.9's named-pipe and runtime-dir bans across the seven new packages.
func TestConstraintPinsNewPackageBans(t *testing.T) {
	for _, f := range pinSources(t) {
		if !newPinPkgs[f.pkg] {
			continue
		}
		for i, line := range f.lines {
			for _, word := range bannedNewPkg {
				if strings.Contains(line, word) {
					t.Fatalf("%s/%s:%d names %q, which the new packages must not use", f.pkg, f.name, i+1, word)
				}
			}
		}
	}
}

func TestConstraintPinsGuardHelpers(t *testing.T) {
	confFile := pinFile{pkg: module + "/internal/conf", name: "conf.go"}
	if !onConfTagLine(confFile, "\tTrial *string `toml:\"trial\"`") ||
		onConfTagLine(confFile, "\tTrial *string `toml:\"trial\"` // \"trial\"") ||
		onConfTagLine(pinFile{pkg: module + "/internal/conf", name: "other.go"}, "\tTrial *string `toml:\"trial\"`") {
		t.Fatal("onConfTagLine guard failed")
	}
	coverFile := pinFile{pkg: module + "/internal/table", name: "cover.go"}
	if !onCoverProtoLine(coverFile, `func isTCPOrUDP(p string) bool { return p == "tcp" || p == "udp" }`) ||
		onCoverProtoLine(coverFile, `return p == "tcp"`) ||
		onCoverProtoLine(pinFile{pkg: module + "/internal/table", name: "tree.go"}, `func isTCPOrUDP(p string) bool {}`) {
		t.Fatal("onCoverProtoLine guard failed")
	}
}
