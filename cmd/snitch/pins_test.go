// pins_test.go: the wire pins of 8.1 and 8.5 over the SOURCE of the tray's five
// packages (cmd/snitch, internal/client, internal/ask, internal/tray, internal/sni),
// the same set the import pin guards by dependency. Two things are pinned. First,
// the only request types that appear as literals in those packages' non-test
// sources are status, the connection's subscribe line and rule.add of an answer:
// a trial verb, the kill switch, rule.remove or a snapshot can then neither be
// written nor be asked for without failing this test (6.12: nothing but rule.add
// is ever written). Second, the binary opens no listener and dials no network but
// the daemon's unix socket: an address typed into a dialer would be a network
// leak of what the daemon said (8.5). The scan is over source lines, not imports,
// because a unix client needs the net package (the 1.1 note); the test helpers
// clienttest and snitest and the dev tool fakedaemon script the full API by
// design and stay outside the scan for both pins.
package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// pinPkgs are the packages that link into the snitch binary; their own source
// files (never their test helpers' subpackages) are what the pins read.
var pinPkgs = []string{
	module + "/cmd/snitch",
	module + "/internal/client",
	module + "/internal/ask",
	module + "/internal/tray",
	module + "/internal/sni",
}

// pinFile is one scannable source file: its name within the package and its lines.
type pinFile struct {
	pkg, name string
	lines     []string
}

// pinDirs asks go list for each package's directory.
func pinDirs(t *testing.T) []string {
	t.Helper()
	out, err := exec.Command("go", append([]string{"list", "-f", "{{.Dir}}"}, pinPkgs...)...).Output()
	if err != nil {
		t.Fatalf("go list -f Dir %v: %v", pinPkgs, err)
	}
	return strings.Fields(string(out))
}

// pinSources reads every non-test .go file of the pinned packages. Only the
// package's own directory is read, so subpackages (clienttest, snitest) that
// a later dependency might add stay outside the scan, and so do test files.
// The pin would pass for nothing without at least one file per package; that
// is checked after reading, like the import pin checks for the module's paths.
func pinSources(t *testing.T) []pinFile {
	t.Helper()
	dirs := pinDirs(t)
	if len(dirs) != len(pinPkgs) {
		t.Fatalf("go list answered %d dirs for %d packages", len(dirs), len(pinPkgs))
	}
	var files []pinFile
	for i, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
				strings.HasSuffix(e.Name(), "_test.go") {
				continue
			}
			b, err := os.ReadFile(filepath.Join(dir, e.Name()))
			if err != nil {
				t.Fatalf("read %s: %v", e.Name(), err)
			}
			files = append(files, pinFile{pkg: pinPkgs[i], name: e.Name(),
				lines: strings.Split(string(b), "\n")})
		}
	}
	if len(files) < len(pinPkgs) {
		t.Fatalf("only %d source files for %d packages: the scan read nothing important", len(files), len(pinPkgs))
	}
	return files
}

// onSendGuardLine is the one exception the request pin allows: the client's
// Send precondition refuses requests with no single answer (snapshot, subscribe,
// unsubscribe) by naming them, which is the ban itself, not a request the tray
// can send. The Require spans two source lines in internal/client's client.go;
// a request literal there and on its continuation is a refused mention at
// most.
func onSendGuardLine(f pinFile, i int) bool {
	if f.pkg != module+"/internal/client" || f.name != "client.go" {
		return false
	}
	return strings.Contains(f.lines[i], "contract.Require") ||
		(i > 0 && strings.Contains(f.lines[i-1], "contract.Require"))
}

// TestRequestsPinnedToStatusSubscribeAdd is 6.12 and 8.1 as a source pin. The
// daemon knows thirteen request types (examples/api.md "Requests"); the tray's
// packages may speak three on their own — status each poll, the subscribe line
// once per connection, rule.add on an answer's click — and mention the
// answerless ones only inside Send's refusal.
func TestConstraintRequestLiteralsAreStatusSubscribeAddOnly(t *testing.T) {
	alwaysFine := map[string]bool{"status": true, "subscribe": true, "rule.add": true}
	guardOnly := map[string]bool{"snapshot": true, "unsubscribe": true}
	for _, f := range pinSources(t) {
		for i, line := range f.lines {
			for _, typ := range daemonRequests {
				if alwaysFine[typ] || !strings.Contains(line, `"`+typ+`"`) {
					continue
				}
				if guardOnly[typ] && onSendGuardLine(f, i) {
					continue
				}
				t.Fatalf("%s/%s:%d mentions the request type %q the tray may not send", f.pkg, f.name, i+1, typ)
			}
		}
	}
}

// TestTheThreeLegalRequestsExist pins the pin itself: each of the three legal
// literals must exist in the sources, in the package that owns it, or the scan
// above would pass on an empty world.
func TestConstraintLegalRequestLiteralsExist(t *testing.T) {
	want := map[string]int{
		module + "/internal/client": 2, // the subscribe line and status
		module + "/internal/ask":    1, // rule.add
	}
	found := map[string]int{}
	for _, f := range pinSources(t) {
		for _, line := range f.lines {
			for _, lit := range []string{`"status"`, `"type":"subscribe"`, `"rule.add"`} {
				if strings.Contains(line, lit) {
					found[f.pkg]++
				}
			}
		}
	}
	for pkg, n := range want {
		if found[pkg] < n {
			t.Fatalf("%s carries %d of the three legal request literals, want at least %d", pkg, found[pkg], n)
		}
	}
}

// daemonRequests are the thirteen request types the daemon knows
// (examples/api.md "Requests"); the pin below decides per type where the tray's
// sources may mention them.
var daemonRequests = []string{"status", "rules", "programs", "learned", "snapshot",
	"subscribe", "unsubscribe", "trial", "keep", "unkeep", "end", "rule.add", "rule.remove"}

// bannedNet are the package-level listener and dialer functions and network
// literals the binary's packages may not name: what 8.5 allows is one delegate
// dial of the daemon's unix socket, wired in cmd/snitch's tray.go.
var bannedNet = []string{"net.Listen", "net.Dial(", "net.DialContext(", "net.DialTCP",
	"net.DialUDP", "net.ListenTCP", "net.ListenUDP", `"tcp"`, `"udp"`, `"tcp4"`,
	`"tcp6"`, `"udp4"`, `"udp6"`}

// TestNetworkIsTheDaemonsSocketOnly is 8.5 as a source pin: no listener and no
// dial of any network but unix anywhere in the binary's packages, and every
// DialContext call names the unix driver on its own line. A net.Dialer method
// like dialUnix passes the pin; a package-level net.Dial or any tcp/udp word
// fails it.
func TestConstraintDialOnlyTheDaemonsUnixSocket(t *testing.T) {
	for _, f := range pinSources(t) {
		for i, line := range f.lines {
			for _, word := range bannedNet {
				if strings.Contains(line, word) {
					t.Fatalf("%s/%s:%d names %q, which opens a network the tray must not have", f.pkg, f.name, i+1, word)
				}
			}
			if strings.Contains(line, ".DialContext(") && !strings.Contains(line, `"unix"`) {
				t.Fatalf("%s/%s:%d dials without naming the unix network", f.pkg, f.name, i+1)
			}
		}
	}
}
