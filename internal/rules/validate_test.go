package rules_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/rules"
)

const okProgram = "[[program]]\nname = \"curl\"\npaths = [\"/usr/bin/curl\"]\n\n"

func parseErr(t *testing.T, src string) *rules.Error {
	t.Helper()
	_, err := rules.Parse(strings.NewReader(src), "t.toml")
	var e *rules.Error
	if !errors.As(err, &e) {
		t.Fatalf("want *rules.Error, got %v", err)
	}
	return e
}

func TestValidateRejectsEachInvalidCase(t *testing.T) {
	rule := func(body string) string { return okProgram + "[[rule]]\n" + body }
	cases := []struct {
		name, src string
		line      int
		msg       string
	}{
		{"duplicate name", okProgram + "[[program]]\nname = \"curl\"\npaths = []\n", 5, "already declared at line 1"},
		{"reserved name", "[[program]]\nname = \"any\"\npaths = []\n", 1, "reserved"},
		{"empty name", "[[program]]\npaths = []\n", 1, "without a name"},
		{"undeclared program", rule("program = \"wget\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\n"), 5, "undeclared program \"wget\""},
		{"bad prefix", rule("program = \"curl\"\nto = \"1.1.1.300/8\"\nverdict = \"allow\"\n"), 5, "to \"1.1.1.300/8\""},
		{"port 0", rule("program = \"curl\"\nto = \"1.1.1.1\"\nport = 0\nverdict = \"allow\"\n"), 5, "port 0-0"},
		{"port 70000", rule("program = \"curl\"\nto = \"1.1.1.1\"\nport = 70000\nverdict = \"allow\"\n"), 5, "port 70000-70000"},
		{"range too wide", rule("program = \"curl\"\nto = \"1.1.1.1\"\nport = \"1-257\"\nverdict = \"allow\"\n"), 5, "at most 256 ports"},
		{"range backwards", rule("program = \"curl\"\nto = \"1.1.1.1\"\nport = \"80-70\"\nverdict = \"allow\"\n"), 5, "low before high"},
		{"range garbage", rule("program = \"curl\"\nto = \"1.1.1.1\"\nport = \"http\"\nverdict = \"allow\"\n"), 5, "port \"http\""},
		{"bad proto", rule("program = \"curl\"\nto = \"1.1.1.1\"\nproto = \"tpc\"\nverdict = \"allow\"\n"), 5, "proto \"tpc\""},
		{"bad verdict", rule("program = \"curl\"\nto = \"1.1.1.1\"\nverdict = \"block\"\n"), 5, "verdict \"block\""},
		{"missing verdict", rule("program = \"curl\"\nto = \"1.1.1.1\"\n"), 5, "verdict \"\""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := parseErr(t, c.src)
			if e.Line != c.line || !strings.Contains(e.Msg, c.msg) {
				t.Fatalf("want line %d containing %q, got %v", c.line, c.msg, e)
			}
		})
	}
}

func TestValidateAssignsDenseIDs(t *testing.T) {
	f := load(t, "valid.toml")
	for i, p := range f.Programs {
		if p.ID != uint32(i+1) {
			t.Fatalf("program %d has id %d", i, p.ID)
		}
	}
	for i, r := range f.Rules {
		if r.ID != uint32(i+1) {
			t.Fatalf("rule %d has id %d", i, r.ID)
		}
	}
}

func TestValidateKeepsLearnedFieldsAndAnyProgram(t *testing.T) {
	f := load(t, "valid.toml")
	r := f.Rules[2]
	if r.Program != rules.AnyProgram || r.Count != 12 || r.First.IsZero() || r.Last.IsZero() {
		t.Fatalf("learned fields or any-program lost: %+v", r)
	}
}

func TestValidateEmptyFileIsFine(t *testing.T) {
	f, err := rules.Parse(strings.NewReader("# nothing yet\n"), "empty.toml")
	if err != nil || len(f.Programs) != 0 || len(f.Rules) != 0 {
		t.Fatalf("want an empty file, got %v, %v", f, err)
	}
}

func TestValidateAcceptsARangeOfExactly256Ports(t *testing.T) {
	f, err := rules.Parse(strings.NewReader(okProgram+"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nport = \"1-256\"\nverdict = \"allow\"\n"), "cap.toml")
	if err != nil || len(f.Rules[0].Ports) != 256 {
		t.Fatalf("want 256 ports accepted, got %v, %v", err, f)
	}
}
