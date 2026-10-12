// Name edits use the shared rules grammar and preserve the overlay on refusals.
package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/rules"
)

func TestApiWriteNameAddRoundTrip(t *testing.T) {
	x := newEditFixture(t, baseCurl)
	text, err := x.edit(add("curl", "Example.COM.", "tcp", 443, "allow"))
	if err != nil || text != "rule added: curl to example.com tcp port 443 allow (applies within 5 s)" {
		t.Fatalf("text %q err %v", text, err)
	}
	if !strings.Contains(strings.Join(strings.Fields(x.overlayText()), " "), `to = "example.com"`) {
		t.Fatalf("overlay: %s", x.overlayText())
	}
	ov, err := rules.LoadOverlay(x.overlay)
	if err != nil || len(ov.Rules) != 1 {
		t.Fatalf("overlay %+v err %v", ov, err)
	}
	checkNameRule(t, ov.Rules[0])
	if len(x.reload().res.File.Rules) != 2 {
		t.Fatal("name rule missing from merged file")
	}
}

func checkNameRule(t *testing.T, r rules.Rule) {
	t.Helper()
	if r.Name != "example.com" || r.To.IsValid() || !r.IsName() {
		t.Fatalf("rule %+v", r)
	}
}

func TestApiWriteNameRemoveExactKey(t *testing.T) {
	x := newEditFixture(t, baseCurl)
	reqs := []struct {
		program, name, proto string
		port                 int
	}{
		{"curl", "example.com", "tcp", 443},
		{"curl", "child.example.com", "tcp", 443},
		{"any", "example.com", "tcp", 443},
		{"curl", "example.com", "udp", 443},
		{"curl", "example.com", "tcp", 80},
	}
	for _, r := range reqs {
		x.must(add(r.program, r.name, r.proto, r.port, "allow"))
	}
	x.reload()
	text, err := x.edit(remove("curl", "EXAMPLE.COM.", "tcp", 443))
	if err != nil || text != "rule removed: curl to example.com tcp port 443 (applies within 5 s)" {
		t.Fatalf("text %q err %v", text, err)
	}
	ov, err := rules.LoadOverlay(x.overlay)
	if err != nil || len(ov.Rules) != 4 {
		t.Fatalf("overlay %+v err %v", ov, err)
	}
	for i, want := range reqs[1:] {
		r := ov.Rules[i]
		got := fmt.Sprintf("%s %s %s %d", r.Program, r.Dest(), protoWire(uint8(r.Proto)), r.Ports[0])
		expected := fmt.Sprintf("%s %s %s %d", want.program, want.name, want.proto, want.port)
		if got != expected {
			t.Fatalf("remaining rule %s want %s", got, expected)
		}
	}
	before := x.overlayText()
	_, err = x.edit(remove("curl", "example.com", "tcp", 443))
	if errText(err) != "no overlay rule matches curl to example.com tcp port 443" || x.overlayText() != before {
		t.Fatalf("miss err %v, overlay changed %v", err, x.overlayText() != before)
	}
}

func TestApiWriteNameDenyLeavesOverlayUntouched(t *testing.T) {
	x := newEditFixture(t, baseCurl)
	x.must(add("curl", "9.9.9.9", "", 0, "allow"))
	before := x.overlayText()
	req := byPath(x.exe("tool"), "Example.COM.")
	text, err := x.edit(req)
	want := `to "Example.COM.": a deny by name is not supported (deny stays a timed trial)`
	if text != "" || errText(err) != want || x.overlayText() != before {
		t.Fatalf("text %q err %v, changed %v", text, err, x.overlayText() != before)
	}
	x.d.cfg.overlay = "" // refusal precedes even loading the overlay
	if _, err := x.edit(req); errText(err) != want {
		t.Fatalf("err %v", err)
	}
}

func TestEditKeyNameGrammarAndAddressRegression(t *testing.T) {
	for _, name := range []string{"bad..name", "-x"} {
		for _, req := range []struct{ verb string }{{"rule.add"}, {"rule.remove"}} {
			x := newEditFixture(t, baseCurl)
			r := add("curl", name, "", 0, "allow")
			r.Type = req.verb
			_, err := x.edit(r)
			if want := fmt.Sprintf("to %q: not an address, prefix or domain name", name); errText(err) != want {
				t.Errorf("%s: err %v want %q", req.verb, err, want)
			}
		}
	}
	for _, dest := range []string{"nowhere", "x", "9.9.9.9", "2001:db8::1", "10.0.0.1/24"} {
		x := newEditFixture(t, baseCurl)
		x.must(add("curl", dest, "", 0, "allow"))
		x.must(remove("curl", dest, "", 0))
	}
}

func TestApiWriteNameByPathLoadsAsStandaloneFile(t *testing.T) {
	x := newEditFixture(t, baseCurl)
	req := byPath(x.exe("tool"), "example.com")
	req.Verdict = "allow"
	x.must(req)
	f, err := rules.Load(x.overlay)
	if err != nil || len(f.Rules) != 1 || f.Rules[0].Name != "example.com" {
		t.Fatalf("file %+v err %v", f, err)
	}
}

func TestApiWriteNameNinthRuleReturnsValidatorText(t *testing.T) {
	x := newEditFixture(t, baseCurl)
	for port := 1; port <= rules.NameSlots; port++ {
		x.must(add("curl", "x", "tcp", port, "allow"))
	}
	before := x.overlayText()
	text, err := x.edit(add("curl", "x", "tcp", rules.NameSlots+1, "allow"))
	want := `name "x": at most 8 rules (protocol and port combinations) per name`
	if text != "" || !strings.Contains(errText(err), want) || x.overlayText() != before {
		t.Fatalf("text %q err %v overlay changed %v", text, err, x.overlayText() != before)
	}
}
