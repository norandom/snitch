// apiwrite_rules_test.go: rule.add and rule.remove over the API (design "Overlay", Req 5.2,
// 5.3, 5.7) on real files in a temp dir: what the overlay holds afterwards, and what the 2 s
// watch would load from it (loadRules over the same two files, seen through rulesView).
package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/api"
)

const baseCurl = "[[program]]\nname = \"curl\"\npaths = []\n\n[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1/32\"\nproto = \"tcp\"\nport = 443\nverdict = \"allow\"\n"

const overlayHeaderLine = "# local rules written by snitchd's API"

// editFixture is a daemon over a deployed file and an overlay path in one temp dir, its
// snapshot loaded from them the way startup does.
type editFixture struct {
	t                  *testing.T
	d                  *daemon
	dir, base, overlay string
}

func newEditFixture(t *testing.T, baseBody string) *editFixture {
	t.Helper()
	dir := t.TempDir()
	x := &editFixture{t: t, dir: dir, base: filepath.Join(dir, "rules.toml"), overlay: filepath.Join(dir, "local.toml")}
	if err := os.WriteFile(x.base, []byte(baseBody), 0o644); err != nil {
		t.Fatal(err)
	}
	x.d = &daemon{cfg: config{rules: x.base, overlay: x.overlay}, log: func(string) {}}
	x.reload()
	return x
}

// reload is what the watch does within 2 s of a write: the snapshot from both files.
func (x *editFixture) reload() *snapshot {
	x.t.Helper()
	snap, err := loadRules(x.base, x.overlay, func(string) {})
	if err != nil || snap.rulesErr != nil {
		x.t.Fatalf("load: %v / %v", err, snap.rulesErr)
	}
	x.d.st.publish(snap)
	return snap
}

func (x *editFixture) edit(req api.Request) (string, error) { return x.d.apiRuleEdit(req, 1000) }

func (x *editFixture) must(req api.Request) {
	x.t.Helper()
	if _, err := x.edit(req); err != nil {
		x.t.Fatal(err)
	}
}

func (x *editFixture) overlayText() string {
	b, err := os.ReadFile(x.overlay)
	if err != nil {
		return ""
	}
	return string(b)
}

// exe writes an executable file in the fixture's dir for the by-path cases.
func (x *editFixture) exe(name string) string {
	x.t.Helper()
	p := filepath.Join(x.dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"), 0o755); err != nil {
		x.t.Fatal(err)
	}
	return p
}

func add(program, to, proto string, port int, verdict string) api.Request {
	return api.Request{Type: "rule.add", Program: program, To: to, Proto: proto, Port: port, Verdict: verdict}
}

func byPath(path, to string) api.Request {
	return api.Request{Type: "rule.add", Path: path, To: to, Verdict: "deny"}
}

func remove(program, to, proto string, port int) api.Request {
	return api.Request{Type: "rule.remove", Program: program, To: to, Proto: proto, Port: port}
}

// Req 5.2: a rule for a declared program lands in the overlay under the header, parses back,
// and the reload shows it with its source; an overlay rule for a deployed key takes precedence.
func TestApiWriteRuleAddByName(t *testing.T) {
	x := newEditFixture(t, baseCurl)
	req := add("curl", "9.9.9.9", "tcp", 53, "deny")
	req.Note = "dns over tcp"
	text, err := x.edit(req)
	if err != nil || text != "rule added: curl to 9.9.9.9/32 tcp port 53 deny (applies within 5 s)" {
		t.Fatalf("text %q err %v", text, err)
	}
	if !strings.HasPrefix(x.overlayText(), overlayHeaderLine+"\n") {
		t.Fatalf("overlay:\n%s", x.overlayText())
	}
	rs, _ := rulesView(x.reload())
	want := api.RuleView{Id: 2, Program: "curl", To: "9.9.9.9/32", Protocol: "tcp", Port: 53, Verdict: "deny", Note: "dns over tcp", Source: x.overlay}
	if len(rs) != 2 || rs[1] != want {
		t.Fatalf("effective rules %+v", rs)
	}
	x.must(add("any", "10.9.0.0/16", "", 0, "allow"))
	x.must(add("curl", "1.1.1.1", "tcp", 443, "deny")) // the deployed key: shadowed, not duplicated
	rs, _ = rulesView(x.reload())
	last := api.RuleView{Id: 3, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "deny", Source: x.overlay}
	if len(rs) != 3 || rs[2] != last {
		t.Fatalf("after the shadowing add: %+v", rs)
	}
}

// Design "Overlay": a path nobody declares becomes an ad hoc program named after its base
// name, resolved on the reload; the same path again reuses the declaration.
func TestApiWriteRuleAddByPath(t *testing.T) {
	x := newEditFixture(t, baseCurl)
	tool := x.exe("tool")
	text, err := x.edit(byPath(tool, "9.9.9.9"))
	if err != nil || text != "rule added: tool to 9.9.9.9/32 deny (applies within 5 s)" {
		t.Fatalf("text %q err %v", text, err)
	}
	x.must(byPath(tool, "8.8.8.8"))
	snap := x.reload()
	_, ps := rulesView(snap)
	if len(ps) != 2 || ps[1].Name != "tool" || !ps[1].Resolved || ps[1].Source != x.overlay {
		t.Fatalf("programs %+v", ps)
	}
	if len(snap.res.File.Rules) != 3 {
		t.Fatalf("want three rules, got %d", len(snap.res.File.Rules))
	}
}

// A base name a program already uses gets a suffix.
func TestApiWriteRuleAddByPathNameCollision(t *testing.T) {
	x := newEditFixture(t, baseCurl+"\n[[program]]\nname = \"tool\"\npaths = []\n")
	text, err := x.edit(byPath(x.exe("tool"), "9.9.9.9"))
	if err != nil || !strings.HasPrefix(text, "rule added: tool-2 to ") {
		t.Fatalf("text %q err %v", text, err)
	}
	if _, ps := rulesView(x.reload()); len(ps) != 3 || ps[2].Name != "tool-2" {
		t.Fatalf("programs %+v", ps)
	}
}

// An executable a program already owns (mapped, or declared by its literal path and not yet
// resolved) is refused with that program's name: the rule belongs to the name, and a second
// declaration would be a resolver conflict on the next reload.
func TestApiWriteRuleAddByClaimedPath(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	wget := filepath.Join(t.TempDir(), "wget")
	x := newEditFixture(t, "[[program]]\nname = \"me\"\npaths = [\""+self+"\"]\n\n[[program]]\nname = \"wget\"\npaths = [\""+wget+"\"]\n")
	if len(x.d.st.current().res.Programs) != 1 {
		t.Fatal("the test binary must resolve")
	}
	if err := os.WriteFile(wget, []byte("#!/bin/sh\n"), 0o755); err != nil { // appears after the snapshot
		t.Fatal(err)
	}
	for path, program := range map[string]string{self: "me", wget: "wget"} {
		_, err := x.edit(byPath(path, "9.9.9.9"))
		if want := "executable " + path + " is program " + program + ": use that name"; errText(err) != want {
			t.Errorf("got %v, want %q", err, want)
		}
	}
	if x.overlayText() != "" {
		t.Fatalf("a refusal wrote the overlay:\n%s", x.overlayText())
	}
}

// Req 5.7 and design "Error Handling": bad input and an invalid merge are errors that leave
// the file (and so the effective rules) untouched.
func TestApiWriteRuleAddRefusalsLeaveTheFileAlone(t *testing.T) {
	x := newEditFixture(t, baseCurl)
	x.must(add("curl", "9.9.9.9", "tcp", 53, "deny"))
	before := x.overlayText()
	x.reload()
	cases := []struct {
		name, want string
		req        api.Request
	}{
		{"verdict", `verdict "maybe": want allow or deny`, add("curl", "9.9.9.9", "", 0, "maybe")},
		{"to", `to "nowhere": not an address or prefix`, add("curl", "nowhere", "", 0, "deny")},
		{"zone", `to "fe80::1%eth0": not an address or prefix`, add("curl", "fe80::1%eth0", "", 0, "deny")},
		{"proto", `proto "icmp": want tcp, udp or any`, add("curl", "9.9.9.9", "icmp", 0, "deny")},
		{"port", "port 70000: want 1-65535, or 0 for any", add("curl", "9.9.9.9", "tcp", 70000, "deny")},
		{"unknown program", `unknown program "wget": declare it in the rules file, or give its path`, add("wget", "9.9.9.9", "", 0, "deny")},
		{"missing path", "no such file", byPath(filepath.Join(x.dir, "none"), "9.9.9.9")},
		{"neither", "program or path", add("", "9.9.9.9", "", 0, "deny")},
		{"duplicate key (merge)", "duplicates the rule", add("curl", "9.9.9.9", "tcp", 53, "allow")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			text, err := x.edit(c.req)
			if text != "" || !strings.Contains(errText(err), c.want) {
				t.Fatalf("text %q err %v, want %q", text, err, c.want)
			}
			if x.overlayText() != before {
				t.Fatalf("the file changed:\n%s", x.overlayText())
			}
		})
	}
	if rs := x.reload().res.File.Rules; len(rs) != 2 {
		t.Fatalf("effective rules changed: %+v", rs)
	}
}

// Req 5.3: a key the deployed file holds names that file to edit; a key nobody holds, a bad
// key and a missing overlay are errors; none of them writes.
func TestApiWriteRuleRemoveRefusals(t *testing.T) {
	x := newEditFixture(t, baseCurl)
	x.must(add("curl", "9.9.9.9", "tcp", 53, "deny"))
	x.reload()
	before := x.overlayText()
	cases := []struct {
		name, want string
		req        api.Request
	}{
		{"deployed", "rule 1 (curl to 1.1.1.1/32 tcp port 443) is in the deployed file: edit " + x.base, remove("curl", "1.1.1.1", "tcp", 443)},
		{"unknown", "no overlay rule matches curl to 9.9.9.9/32 udp port 53", remove("curl", "9.9.9.9", "udp", 53)},
		{"bad key", `to "x": not an address or prefix`, remove("curl", "x", "", 0)},
	}
	for _, c := range cases {
		if text, err := x.edit(c.req); text != "" || errText(err) != c.want || x.overlayText() != before {
			t.Errorf("%s: text %q err %v (want %q), file changed %v", c.name, text, err, c.want, x.overlayText() != before)
		}
	}
	y := newEditFixture(t, baseCurl) // no overlay file at all
	if _, err := y.edit(remove("curl", "9.9.9.9", "", 0)); !strings.HasPrefix(errText(err), "no overlay rule matches") || y.overlayText() != "" {
		t.Fatalf("no overlay: err %v file %q", err, y.overlayText())
	}
}

// Req 5.3: removal by key drops the overlay rule and the reload no longer has it.
func TestApiWriteRuleRemove(t *testing.T) {
	x := newEditFixture(t, baseCurl)
	x.must(add("curl", "9.9.9.9", "tcp", 53, "deny"))
	x.must(add("any", "10.9.0.0/16", "", 0, "allow"))
	x.reload()
	text, err := x.edit(remove("curl", "9.9.9.9", "tcp", 53))
	if err != nil || text != "rule removed: curl to 9.9.9.9/32 tcp port 53 (applies within 5 s)" {
		t.Fatalf("text %q err %v", text, err)
	}
	rs, _ := rulesView(x.reload())
	if len(rs) != 2 || rs[1].Program != "any" || !strings.HasPrefix(x.overlayText(), overlayHeaderLine) {
		t.Fatalf("after the removal: %+v\n%s", rs, x.overlayText())
	}
}

// Req 5.7: a write that fails (an unwritable directory) is the error; the effective rules are
// the ones before.
func TestApiWriteRuleWriteFailureLeavesTheRulesAlone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can write anywhere")
	}
	x := newEditFixture(t, baseCurl)
	locked := filepath.Join(x.dir, "locked")
	if err := os.Mkdir(locked, 0o500); err != nil {
		t.Fatal(err)
	}
	x.overlay = filepath.Join(locked, "local.toml")
	x.d.cfg.overlay = x.overlay
	text, err := x.edit(add("curl", "9.9.9.9", "", 0, "deny"))
	if err == nil || text != "" || !strings.Contains(err.Error(), "permission denied") {
		t.Fatalf("text %q err %v", text, err)
	}
	if rs := x.reload().res.File.Rules; len(rs) != 1 || x.overlayText() != "" {
		t.Fatalf("rules %+v, overlay %q", rs, x.overlayText())
	}
}

// Only the two edits reach the delegate; anything else is an error, not a panic.
func TestApiWriteRuleUnknownVerb(t *testing.T) {
	if _, err := newEditFixture(t, baseCurl).edit(api.Request{Type: "rules"}); err == nil || !strings.Contains(err.Error(), "rules") {
		t.Fatalf("err %v", err)
	}
}

// A relative path is refused before anything is resolved or written.
func TestApiWriteRuleAddRelativePathRefused(t *testing.T) {
	x := newEditFixture(t, baseCurl)
	_, err := x.d.apiRuleEdit(api.Request{Type: "rule.add", Path: "usr/bin/curl", To: "9.9.9.9", Verdict: "deny"}, 0)
	if err == nil || !strings.Contains(err.Error(), "not absolute") {
		t.Fatalf("want a not-absolute error, got %v", err)
	}
}
