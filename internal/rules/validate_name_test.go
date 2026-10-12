// Name identities and slot limits keep file rules within the DNS compiler's fixed slots.
package rules_test

import (
	"strconv"
	"strings"
	"testing"
)

func TestValidateRefusesFiveRulesOnOneName(t *testing.T) {
	src := ""
	for i := 1; i <= 4; i++ {
		src += ruleTable("any", "GitHub.COM.", "tcp", strconv.Itoa(i), "allow")
	}
	parse(t, src)
	e := parseErr(t, src+ruleTable("any", "github.com", "tcp", "5", "allow"))
	if e.Msg != `name "github.com": at most 4 rules per name` {
		t.Fatalf("got %v", e)
	}
}

func TestValidateNameParentAndChildAreDistinct(t *testing.T) {
	f := parse(t, ruleTable("any", "github.com", "", "", "allow")+ruleTable("any", "api.github.com", "", "", "allow"))
	if len(f.Rules) != 2 || f.Rules[0].ID != 1 || f.Rules[1].ID != 2 {
		t.Fatalf("got %+v", f.Rules)
	}
}

func TestValidateNameDuplicatePrintsDest(t *testing.T) {
	src := ruleTable("any", "github.com", "tcp", "443", "allow") + ruleTable("any", "GitHub.COM.", "", "443", "allow")
	e := parseErr(t, src)
	if !strings.Contains(e.Msg, "any github.com tcp port 443") {
		t.Fatalf("got %v", e)
	}
}

func TestValidateNameSlotsCountRulesRatherThanExpandedKeys(t *testing.T) {
	src := ruleTable("any", "github.com", "", `"1-256"`, "allow")
	for i := 257; i <= 259; i++ {
		src += ruleTable("any", "github.com", "tcp", strconv.Itoa(i), "allow")
	}
	if f := parse(t, src); len(f.Rules) != 4 {
		t.Fatalf("got %+v", f.Rules)
	}
}
