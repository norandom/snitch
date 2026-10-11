package rules_test

import (
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/rules"
)

// ParsePrefix is the one reading of a rule's `to`, shared by the file parser and the API's
// rule.add/rule.remove: a CIDR prefix is masked to its network, a bare address is a /32 or
// /128, a zoned address or anything else is an error naming the text.
func TestParsePrefix(t *testing.T) {
	good := map[string]string{
		"1.1.1.7/24":        "1.1.1.0/24",
		"10.0.0.0/8":        "10.0.0.0/8",
		"9.9.9.9":           "9.9.9.9/32",
		"2001:db8::1":       "2001:db8::1/128",
		"2001:db8:1::/48":   "2001:db8:1::/48",
		"2001:db8::ffff/32": "2001:db8::/32",
		"::/0":              "::/0",
	}
	for in, want := range good {
		p, err := rules.ParsePrefix(in)
		if err != nil || p.String() != want || p != p.Masked() {
			t.Errorf("%q: got %v %v, want %s canonical", in, p, err, want)
		}
	}
	for _, in := range []string{"", "curl", "1.1.1.1/33", "fe80::1%eth0", "1.1.1", "1.1.1.1/-1"} {
		if p, err := rules.ParsePrefix(in); err == nil || !strings.Contains(err.Error(), in) || p.IsValid() {
			t.Errorf("%q: got %v %v, want an error naming the text and no prefix", in, p, err)
		}
	}
}
