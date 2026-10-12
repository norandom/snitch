// Name decoding tests pin operator errors and preserve prefix-first interpretation.
package rules_test

import (
	"fmt"
	"strings"
	"testing"
)

func TestValidateRefusesDenyByName(t *testing.T) {
	src := baseCurl + ruleTable("curl", "1.1.1.1", "", "", "allow") + ruleTable("curl", "github.com", "", "", "deny")
	e := parseErr(t, src)
	want := fmt.Sprintf("rule %d: a deny by name is not supported (deny stays a timed trial)", e.Line)
	if e.Msg != want || e.Line != 10 {
		t.Fatalf("got %v; want line 10: %s", e, want)
	}
}

func TestDecodeNameErrorTexts(t *testing.T) {
	for _, c := range []struct{ to, msg string }{
		{"a..b", "not an address, prefix or domain name"},
		{strings.Repeat("a", 63), "a name has at most 62 characters and 16 labels"},
	} {
		e := parseErr(t, ruleTable("any", c.to, "", "", "allow"))
		if want := fmt.Sprintf("to %q: %s", c.to, c.msg); e.Msg != want {
			t.Fatalf("got %v; want %s", e, want)
		}
	}
}
