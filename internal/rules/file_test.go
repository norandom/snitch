package rules_test

import (
	"errors"
	"io/fs"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/rules"
)

func load(t *testing.T, name string) *rules.File {
	t.Helper()
	f, err := rules.Load(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("load %s: %v", name, err)
	}
	return f
}

func TestDecodeValidFixture(t *testing.T) {
	f := load(t, "valid.toml")
	src := filepath.Join("testdata", "valid.toml") // every record names the file it came from
	wantPrograms := []rules.Program{
		{Name: "curl", Paths: []string{"/usr/bin/curl"}, Note: "general purpose", ID: 1, Line: 3, Source: src},
		{Name: "claude", Paths: []string{"/home/*/.local/share/claude/versions/*", "/opt/claude/bin/claude"}, ID: 2, Line: 8, Source: src},
	}
	utc := func(h, m int) time.Time { return time.Date(2026, 10, 10, h, m, 0, 0, time.UTC) }
	wantRules := []rules.Rule{
		{Program: "curl", To: netip.MustParsePrefix("1.1.1.1/32"), Proto: rules.TCP, Ports: []uint16{443},
			Verdict: rules.Allow, Note: "the one address the test allows", ID: 1, Line: 12, Source: src},
		{Program: "claude", To: netip.MustParsePrefix("::/0"), Verdict: rules.Allow, ID: 2, Line: 20, Source: src},
		{Program: "any", To: netip.MustParsePrefix("9.9.9.9/32"), Proto: rules.UDP, Ports: []uint16{67, 68},
			Verdict: rules.Deny, Count: 12, First: utc(6, 0), Last: utc(6, 30), ID: 3, Line: 25, Source: src},
	}
	if !reflect.DeepEqual(f.Programs, wantPrograms) {
		t.Fatalf("programs:\n got %+v\nwant %+v", f.Programs, wantPrograms)
	}
	if !reflect.DeepEqual(f.Rules, wantRules) {
		t.Fatalf("rules:\n got %+v\nwant %+v", f.Rules, wantRules)
	}
}

func TestDecodeSyntaxErrorHasLine(t *testing.T) {
	src := "[[program]]\nname = \"curl\"\npaths = [/usr/bin/curl]\n\n[[rule]]\n"
	_, err := rules.Parse(strings.NewReader(src), "broken.toml")
	var e *rules.Error
	if !errors.As(err, &e) || e.File != "broken.toml" || e.Line != 3 {
		t.Fatalf("want broken.toml:3, got %v", err)
	}
}

func TestDecodeUnknownKeyHasLine(t *testing.T) {
	src := "[[program]]\nname = \"curl\"\npaths = [\"/usr/bin/curl\"]\ncolour = \"blue\"\n"
	_, err := rules.Parse(strings.NewReader(src), "odd.toml")
	var e *rules.Error
	if !errors.As(err, &e) || e.Line != 4 || !strings.Contains(e.Msg, "colour") {
		t.Fatalf("want line 4 naming colour, got %v", err)
	}
}

func TestDecodeBadValueNamesTheTableLine(t *testing.T) {
	src := "[[program]]\nname = \"curl\"\npaths = [\"/usr/bin/curl\"]\n\n[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1/32\"\nport = 44.5\nverdict = \"allow\"\n"
	_, err := rules.Parse(strings.NewReader(src), "r.toml")
	var e *rules.Error
	if !errors.As(err, &e) || e.Line != 5 || !strings.Contains(e.Msg, "port") {
		t.Fatalf("want an error at the rule table line 5 naming port, got %v", err)
	}
}

func TestLoadMissingFileIsNotExist(t *testing.T) {
	_, err := rules.Load(filepath.Join(t.TempDir(), "none.toml"))
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("want fs.ErrNotExist, got %v", err)
	}
}

func TestErrorFormatsAsFileLineMsg(t *testing.T) {
	e := &rules.Error{File: "x.toml", Line: 7, Msg: "boom"}
	if e.Error() != "x.toml:7: boom" {
		t.Fatalf("got %q", e.Error())
	}
}

func TestDecodeInlineArrayFormIsAnErrorNotAPanic(t *testing.T) {
	src := "program = [{ name = \"curl\", paths = [\"/usr/bin/curl\"] }]\n"
	_, err := rules.Parse(strings.NewReader(src), "inline.toml")
	var e *rules.Error
	if !errors.As(err, &e) || !strings.Contains(e.Msg, "[[program]]") {
		t.Fatalf("want an *Error asking for [[program]] tables, got %v", err)
	}
}

func TestDecodeRejectsZonedAddress(t *testing.T) {
	src := "[[program]]\nname = \"curl\"\npaths = []\n\n[[rule]]\nprogram = \"curl\"\nto = \"fe80::1%eth0\"\nverdict = \"allow\"\n"
	_, err := rules.Parse(strings.NewReader(src), "zone.toml")
	var e *rules.Error
	if !errors.As(err, &e) || e.Line != 5 || !strings.Contains(e.Msg, "fe80::1%eth0") {
		t.Fatalf("want a line-5 error naming the zoned address, got %v", err)
	}
}

// The documented example (examples/rules.toml) must stay loadable: it is the operator's
// reference and the enforce test's template.
func TestExampleRulesFileLoads(t *testing.T) {
	f, err := rules.Load(filepath.Join("..", "..", "examples", "rules.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Programs) != 4 || len(f.Rules) != 7 {
		t.Fatalf("want 4 programs and 7 rules, got %d and %d", len(f.Programs), len(f.Rules))
	}
	if f.Rules[5].Program != "any" || f.Rules[5].Verdict != rules.Deny {
		t.Fatalf("example rule 6 should be the any-program deny, got %+v", f.Rules[5])
	}
}

func TestRuleDestAndIsName(t *testing.T) {
	f := parse(t, ruleTable("any", "GitHub.COM.", "", "", "allow")+ruleTable("any", "1.1.1.1", "", "", "allow"))
	n, p := f.Rules[0], f.Rules[1]
	if n.Name != "github.com" || n.Dest() != "github.com" || !n.IsName() || n.To != (netip.Prefix{}) {
		t.Fatalf("got %+v", n)
	}
	if p.Dest() != "1.1.1.1/32" || p.IsName() || p.Name != "" {
		t.Fatalf("got %+v", p)
	}
}
