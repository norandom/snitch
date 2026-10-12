package rules_test

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/rules"
)

// parseNamed parses src as the file called name (the Source every record must carry).
func parseNamed(t *testing.T, name, src string) *rules.File {
	t.Helper()
	f, err := rules.Parse(strings.NewReader(src), name)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return f
}

// overlay parses src as an overlay: its rules may name programs the base declares.
func overlay(t *testing.T, src string) *rules.File {
	t.Helper()
	f, err := rules.ParseOverlay(strings.NewReader(src), "overlay.toml")
	if err != nil {
		t.Fatalf("overlay.toml: %v", err)
	}
	return f
}

func merge(t *testing.T, base, over *rules.File) *rules.File {
	t.Helper()
	m, err := rules.Merge(base, over)
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// rule renders one [[rule]] table; proto and port may be empty for "any".
func ruleTable(program, to, proto, port, verdict string) string {
	var b strings.Builder
	b.WriteString("\n[[rule]]\nprogram = \"" + program + "\"\nto = \"" + to + "\"\n")
	if proto != "" {
		b.WriteString("proto = \"" + proto + "\"\n")
	}
	if port != "" {
		b.WriteString("port = " + port + "\n")
	}
	b.WriteString("verdict = \"" + verdict + "\"\n")
	return b.String()
}

const baseCurl = "[[program]]\nname  = \"curl\"\npaths = [\"/usr/bin/curl\"]\n"

func keyOf(r rules.Rule) string {
	return r.Program + " " + r.Dest() + " " + map[rules.Proto]string{rules.TCP: "tcp", rules.UDP: "udp", rules.AnyProto: "any"}[r.Proto]
}

func TestMergeOverlayRuleReplacesTheBaseRuleWithTheSameKey(t *testing.T) {
	base := parseNamed(t, "base.toml", baseCurl+ruleTable("curl", "1.1.1.1", "tcp", "443", "allow"))
	over := overlay(t, ruleTable("curl", "1.1.1.1", "tcp", "443", "deny"))
	m := merge(t, base, over)
	if len(m.Rules) != 1 || m.Rules[0].Verdict != rules.Deny || m.Rules[0].Source != "overlay.toml" {
		t.Fatalf("want the overlay's deny alone, got %+v", m.Rules)
	}
}

func TestMergeAnyProtoOverlayDropsBothHalvesOfABasePair(t *testing.T) {
	base := parseNamed(t, "base.toml", baseCurl+
		ruleTable("curl", "1.1.1.1", "tcp", "443", "allow")+
		ruleTable("curl", "1.1.1.1", "udp", "443", "allow")+
		ruleTable("curl", "9.9.9.9", "tcp", "443", "allow"))
	over := overlay(t, ruleTable("curl", "1.1.1.1", "", "443", "deny"))
	m := merge(t, base, over)
	var got []string
	for _, r := range m.Rules {
		got = append(got, keyOf(r)+" "+r.Source)
	}
	want := []string{"curl 9.9.9.9/32 tcp base.toml", "curl 1.1.1.1/32 any overlay.toml"}
	if strings.Join(got, ";") != strings.Join(want, ";") {
		t.Fatalf("an any-proto overlay rule replaces the tcp and the udp base rule alike:\n got %v\nwant %v", got, want)
	}
}

func TestMergeProtoOverlayReplacesAnAnyProtoBaseRule(t *testing.T) {
	// the base rule expands to tcp and udp; the overlay's tcp key touches it, so the whole
	// base rule goes (udp 443 is no longer allowed): a merge that compared only the base rule's
	// own proto would report a cross-file duplicate instead
	base := parseNamed(t, "base.toml", baseCurl+ruleTable("curl", "1.1.1.1", "", "443", "allow"))
	over := overlay(t, ruleTable("curl", "1.1.1.1", "tcp", "443", "deny"))
	m := merge(t, base, over)
	if len(m.Rules) != 1 || m.Rules[0].Proto != rules.TCP || m.Rules[0].Verdict != rules.Deny || m.Rules[0].Source != "overlay.toml" {
		t.Fatalf("want the overlay's tcp deny alone, got %+v", m.Rules)
	}
}

func TestMergeADifferentPortLeavesTheBaseRule(t *testing.T) {
	base := parseNamed(t, "base.toml", baseCurl+ruleTable("curl", "1.1.1.1", "tcp", "443", "allow"))
	over := overlay(t, ruleTable("curl", "1.1.1.1", "tcp", "80", "deny"))
	m := merge(t, base, over)
	if len(m.Rules) != 2 || m.Rules[0].Source != "base.toml" || m.Rules[1].Source != "overlay.toml" {
		t.Fatalf("want base then overlay, got %+v", m.Rules)
	}
	if m.Rules[0].Ports[0] != 443 || m.Rules[1].Ports[0] != 80 {
		t.Fatalf("ports: %+v", m.Rules)
	}
}

func TestMergeAnyProgramOverlayDoesNotShadowAProgramRule(t *testing.T) {
	base := parseNamed(t, "base.toml", baseCurl+ruleTable("curl", "1.1.1.1", "tcp", "443", "allow"))
	over := overlay(t, ruleTable("any", "1.1.1.1", "tcp", "443", "deny"))
	if m := merge(t, base, over); len(m.Rules) != 2 {
		t.Fatalf("program and any-program rules are different keys, got %+v", m.Rules)
	}
}

func TestMergeSameProgramNameNamesBothFiles(t *testing.T) {
	base := parseNamed(t, "base.toml", baseCurl)
	over := overlay(t, "\n[[program]]\nname  = \"curl\"\npaths = [\"/opt/curl\"]\n")
	_, err := rules.Merge(base, over)
	var e *rules.Error
	if !errors.As(err, &e) || e.File != "overlay.toml" || e.Line != 2 {
		t.Fatalf("want an error at overlay.toml:2, got %v", err)
	}
	if !strings.Contains(e.Msg, "base.toml") || !strings.Contains(e.Msg, `"curl"`) {
		t.Fatalf("the message names the other file and the program: %q", e.Msg)
	}
}

func TestMergeEveryRecordHasItsSource(t *testing.T) {
	base := parseNamed(t, "base.toml", baseCurl+ruleTable("curl", "1.1.1.1", "tcp", "443", "allow"))
	over := overlay(t, "[[program]]\nname = \"git\"\npaths = [\"/usr/bin/git\"]\n"+ruleTable("git", "2.2.2.2", "tcp", "22", "allow"))
	m := merge(t, base, over)
	wantP := []string{"base.toml", "overlay.toml"}
	for i, p := range m.Programs {
		if p.Source != wantP[i] {
			t.Fatalf("program %d source %q, want %q", i, p.Source, wantP[i])
		}
	}
	for i, r := range m.Rules {
		if r.Source != wantP[i] {
			t.Fatalf("rule %d source %q, want %q", i, r.Source, wantP[i])
		}
	}
	if base.Rules[0].Source != "base.toml" || over.Rules[0].Source != "overlay.toml" {
		t.Fatal("Parse sets the Source on the records it produces")
	}
}

func TestMergeIDsAreDenseInMergedOrder(t *testing.T) {
	base := parseNamed(t, "base.toml", baseCurl+
		ruleTable("curl", "1.1.1.1", "tcp", "443", "allow")+
		ruleTable("curl", "3.3.3.3", "tcp", "443", "allow")+
		ruleTable("curl", "4.4.4.4", "tcp", "443", "allow"))
	over := overlay(t, "[[program]]\nname = \"git\"\npaths = []\n"+
		ruleTable("curl", "3.3.3.3", "tcp", "443", "deny")+ruleTable("git", "5.5.5.5", "", "", "allow"))
	m := merge(t, base, over)
	for i, p := range m.Programs {
		if p.ID != uint32(i+1) {
			t.Fatalf("program ids: %+v", m.Programs)
		}
	}
	wantTo := []string{"1.1.1.1/32", "4.4.4.4/32", "3.3.3.3/32", "5.5.5.5/32"}
	for i, r := range m.Rules {
		if r.ID != uint32(i+1) || r.Dest() != wantTo[i] {
			t.Fatalf("rule %d: id %d to %s, want id %d to %s", i, r.ID, r.To, i+1, wantTo[i])
		}
	}
	if base.Rules[1].ID != 2 || len(base.Rules) != 3 {
		t.Fatal("Merge must not touch its inputs")
	}
}

func TestMergeDuplicateInsideTheOverlayNamesTheOverlay(t *testing.T) {
	_, err := rules.ParseOverlay(strings.NewReader(ruleTable("curl", "1.1.1.1", "tcp", "443", "deny")+
		ruleTable("curl", "1.1.1.1", "", "443", "deny")), "overlay.toml")
	var e *rules.Error
	if !errors.As(err, &e) || e.File != "overlay.toml" || !strings.Contains(e.Msg, "duplicates the rule at line 2") {
		t.Fatalf("want the overlay's own duplicate reported against overlay.toml, got %v", err)
	}
}

func TestMergeOverlayRuleForAnUnknownProgramFails(t *testing.T) {
	base := parseNamed(t, "base.toml", baseCurl)
	over := overlay(t, ruleTable("ghost", "1.1.1.1", "tcp", "443", "deny"))
	_, err := rules.Merge(base, over)
	var e *rules.Error
	if !errors.As(err, &e) || e.File != "overlay.toml" || !strings.Contains(e.Msg, `undeclared program "ghost"`) {
		t.Fatalf("the undeclared check runs against the union, got %v", err)
	}
}

func TestMergeConflictNamesTheOverlaySource(t *testing.T) {
	base := parseNamed(t, "base.toml", baseCurl)
	over := overlay(t, "[[program]]\nname  = \"fetch\"\npaths = [\"/usr/bin/curl\"]\n")
	m := merge(t, base, over)
	_, err := rules.Resolve(m, world.fs())
	var e *rules.Error
	if !errors.As(err, &e) || e.File != "overlay.toml" || e.Line != 1 {
		t.Fatalf("want the conflict at overlay.toml:1, got %v", err)
	}
	if !strings.Contains(e.Msg, `"curl"`) || !strings.Contains(e.Msg, `"fetch"`) {
		t.Fatalf("names both programs: %q", e.Msg)
	}
}

func TestMergeEmptyOverlayKeepsTheBase(t *testing.T) {
	base := parseNamed(t, "base.toml", baseCurl+ruleTable("curl", "1.1.1.1", "tcp", "443", "allow"))
	m := merge(t, base, overlay(t, ""))
	if len(m.Programs) != 1 || len(m.Rules) != 1 || m.Rules[0].Source != "base.toml" || m.Rules[0].ID != 1 {
		t.Fatalf("got %+v", m)
	}
}

func TestMergeContracts(t *testing.T) {
	f := parseNamed(t, "base.toml", baseCurl)
	contracttest.Panics(t, contract.Precondition, func() { rules.Merge(nil, f) })
	contracttest.Panics(t, contract.Precondition, func() { rules.Merge(f, nil) })
	// a hand-built file never went through Parse: its rules carry no Source
	bare := &rules.File{Programs: []rules.Program{{Name: "a", Source: "x"}},
		Rules: []rules.Rule{{Program: "a", To: netip.MustParsePrefix("1.1.1.1/32"), Verdict: rules.Allow}}}
	contracttest.Panics(t, contract.Postcondition, func() { rules.Merge(bare, &rules.File{}) })
}

func TestMergeNameShadowingKeepsOtherIdentitiesAndDenseIDs(t *testing.T) {
	base := parseNamed(t, "base.toml", baseCurl+
		ruleTable("curl", "github.com", "", "443", "allow")+
		ruleTable("curl", "api.github.com", "tcp", "443", "allow")+
		ruleTable("any", "github.com", "tcp", "443", "allow")+
		ruleTable("curl", "github.com", "udp", "53", "allow"))
	over := overlay(t, ruleTable("curl", "GitHub.COM.", "tcp", "443", "allow"))
	m := merge(t, base, over)
	if len(m.Rules) != 4 || m.Rules[0].Name != "api.github.com" || m.Rules[3].Source != "overlay.toml" {
		t.Fatalf("got %+v", m.Rules)
	}
	r, err := rules.Resolve(m, world.fs())
	if err != nil {
		t.Fatal(err)
	}
	for i := range m.Rules {
		id := uint32(i + 1)
		if m.Rules[i].ID != id || r.ByID[id] != &m.Rules[i] {
			t.Fatalf("bad ids: %+v", r.ByID)
		}
	}
	if base.Rules[0].ID != 1 || len(base.Rules) != 4 {
		t.Fatal("Merge changed base")
	}
}
