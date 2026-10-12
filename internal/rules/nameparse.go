// Name parsing bounds destinations to the DNS tap's fixed key and label storage.
package rules

import (
	"fmt"
	"strings"
)

// ParseName is the shared domain grammar; matching later covers up to eight subdomain levels.
// It returns complete operator messages (including the original `to`), so convertRule returns
// its error unchanged after ParsePrefix fails. Malformed labels take precedence over bounds.
func ParseName(s string) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(s), ".")
	labels := strings.Split(name, ".")
	for _, label := range labels {
		if !validNameLabel(label) {
			return "", fmt.Errorf("to %q: not an address, prefix or domain name", s)
		}
	}
	if len(name) > 62 || len(labels) > 16 {
		return "", fmt.Errorf("to %q: a name has at most 62 characters and 16 labels", s)
	}
	return name, nil
}

// validNameLabel is RFC 1123's letter-digit-hyphen rule: a hyphen never starts or ends a
// label, so a mistyped flag such as "-x" is refused instead of becoming a name that never
// resolves.
func validNameLabel(label string) bool {
	if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for _, c := range label {
		if !labelByte(c) {
			return false
		}
	}
	return true
}

func labelByte(c rune) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-'
}
