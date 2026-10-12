// Name grammar tests distinguish malformed labels from the kernel's destination bounds.
package rules_test

import (
	"fmt"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/rules"
)

func TestParseNameGrammar(t *testing.T) {
	cases := []struct{ in, want, msg string }{
		{"GitHub.COM", "github.com", ""}, {"api.github.com.", "api.github.com", ""},
		{"x", "x", ""}, {"a-9.b", "a-9.b", ""},
		{strings.Repeat("a", 62), strings.Repeat("a", 62), ""},
		{strings.TrimSuffix(strings.Repeat("a.", 16), "."), strings.TrimSuffix(strings.Repeat("a.", 16), "."), ""},
		{strings.Repeat("a", 63), "", "a name has at most 62 characters and 16 labels"},
		{strings.TrimSuffix(strings.Repeat("a.", 17), "."), "", "a name has at most 62 characters and 16 labels"},
		{strings.Repeat("a", 64), "", "not an address, prefix or domain name"},
		{".a", "", "not an address, prefix or domain name"},
		{"*.a", "", "not an address, prefix or domain name"},
		{"a..b", "", "not an address, prefix or domain name"},
		{"-x", "", "not an address, prefix or domain name"},
		{"x-", "", "not an address, prefix or domain name"},
		{"", "", "not an address, prefix or domain name"},
		{"a..", "", "not an address, prefix or domain name"},
		{"é.com", "", "not an address, prefix or domain name"},
		{"a_b", "", "not an address, prefix or domain name"},
	}
	for _, c := range cases {
		t.Run(c.in, func(t *testing.T) {
			got, err := rules.ParseName(c.in)
			if c.msg == "" {
				if err != nil || got != c.want {
					t.Fatalf("got %q, %v; want %q", got, err, c.want)
				}
				return
			}
			want := fmt.Sprintf("to %q: %s", c.in, c.msg)
			if err == nil || err.Error() != want || got != "" {
				t.Fatalf("got %q, %v; want %s", got, err, want)
			}
		})
	}
}
