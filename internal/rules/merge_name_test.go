// Name merge tests keep slot limits global across files and count each rule once.
package rules_test

import (
	"errors"
	"strconv"
	"testing"

	"github.com/norandom/snitch/internal/rules"
)

func TestMergeNameSlotLimitAppliesToTheUnion(t *testing.T) {
	src := baseCurl
	for i := 1; i <= 4; i++ {
		src += ruleTable("curl", "github.com", "tcp", strconv.Itoa(i), "allow")
	}
	base := parseNamed(t, "base.toml", src)
	over := overlay(t, ruleTable("any", "github.com", "udp", "53", "allow"))
	_, err := rules.Merge(base, over)
	var e *rules.Error
	if !errors.As(err, &e) || e.File != "overlay.toml" || e.Line != 2 || e.Msg != `name "github.com": at most 8 rules (protocol and port combinations) per name` {
		t.Fatalf("got %v", err)
	}
}

func TestMergeNameReplacementDoesNotConsumeAnotherSlot(t *testing.T) {
	src := ""
	for i := 1; i <= 4; i++ {
		src += ruleTable("any", "github.com", "tcp", strconv.Itoa(i), "allow")
	}
	m := merge(t, parseNamed(t, "base.toml", src), overlay(t, ruleTable("any", "github.com", "tcp", "1", "allow")))
	if len(m.Rules) != 4 || m.Rules[3].Source != "overlay.toml" {
		t.Fatalf("got %+v", m.Rules)
	}
}
