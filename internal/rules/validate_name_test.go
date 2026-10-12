// Name identities and slot limits keep file rules within the DNS compiler's fixed slots.
package rules_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/rules"
)

func TestValidateRefusesFiveRulesOnOneName(t *testing.T) {
	src := ""
	for i := 1; i <= rules.NameSlots; i++ {
		src += ruleTable("any", "GitHub.COM.", "tcp", strconv.Itoa(i), "allow")
	}
	parse(t, src)
	e := parseErr(t, src+ruleTable("any", "github.com", "tcp", strconv.Itoa(rules.NameSlots+1), "allow"))
	if e.Msg != `name "github.com": at most 8 rules (protocol and port combinations) per name` {
		t.Fatalf("got %v", e)
	}
}

func TestValidateCountsProtocolPortCombinationsPerName(t *testing.T) {
	// any-proto with a port is two kernel slots (tcp, udp): four such rules fill a name
	four := ""
	for _, port := range []string{"443", "80", "8080", "8443"} {
		four += ruleTable("any", "github.com", "", port, "allow")
	}
	parse(t, four)
	if e := parseErr(t, four+ruleTable("any", "github.com", "tcp", "22", "allow")); !strings.Contains(e.Msg, `name "github.com"`) {
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

func TestValidateNamePortRangeExceedsTheKernelSlots(t *testing.T) {
	// a port range expands to one kernel slot per port and protocol; a name has NameSlots slots
	e := parseErr(t, ruleTable("any", "github.com", "tcp", `"1-9"`, "allow"))
	if !strings.Contains(e.Msg, `name "github.com"`) {
		t.Fatalf("got %v", e)
	}
	parse(t, ruleTable("any", "github.com", "tcp", `"1-8"`, "allow"))
}
