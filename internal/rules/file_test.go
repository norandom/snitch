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
	wantPrograms := []rules.Program{
		{Name: "curl", Paths: []string{"/usr/bin/curl"}, Note: "general purpose", Line: 3},
		{Name: "claude", Paths: []string{"/home/*/.local/share/claude/versions/*", "/opt/claude/bin/claude"}, Line: 8},
	}
	utc := func(h, m int) time.Time { return time.Date(2026, 10, 10, h, m, 0, 0, time.UTC) }
	wantRules := []rules.Rule{
		{Program: "curl", To: netip.MustParsePrefix("1.1.1.1/32"), Proto: rules.TCP, Ports: []uint16{443},
			Verdict: rules.Allow, Note: "the one address the test allows", Line: 12},
		{Program: "claude", To: netip.MustParsePrefix("::/0"), Verdict: rules.Allow, Line: 20},
		{Program: "any", To: netip.MustParsePrefix("9.9.9.9/32"), Proto: rules.UDP, Ports: []uint16{67, 68},
			Verdict: rules.Deny, Count: 12, First: utc(6, 0), Last: utc(6, 30), Line: 25},
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
