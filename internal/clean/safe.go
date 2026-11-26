// Package clean is the module's only producer of text that may be drawn on the terminal
// or written to the log file (requirements 13.3, 13.4). Untrusted strings from the daemon
// pass through Text (or the name/path/cut helpers) to yield a Safe value; other packages
// cannot convert values to Safe or pass non-literals to Const (enforced by safe_test.go).
//
// safe.go: defines Safe, the Text sanitiser, Const for repository literals and Join.
//
// Fail-safe implications: none on kernel egress. This package is pure string transformation
// and never opens sockets, files or BPF maps.
package clean

import (
	"strings"
	"unicode/utf8"

	"github.com/norandom/snitch/internal/contract"
)

// Safe is a string verified to contain only valid UTF-8 and no terminal-acting,
// direction-changing or invisible formatting runes. Only this package constructs it.
type Safe string

const replacement = '·'

// replacedRanges lists every rune replaced by Text (design "clean"): C0 (< 0x20),
// DEL and C1 (0x7f..0x9f), bidi controls (U+061C, U+200E/F, U+202A..E, U+2066..9),
// and zero-width / invisible formatters (U+200B..D, U+2060, U+FEFF).
var replacedRanges = [][2]rune{
	{0x0000, 0x001f},
	{0x007f, 0x009f},
	{0x061c, 0x061c},
	{0x200b, 0x200f},
	{0x202a, 0x202e},
	{0x2060, 0x2060},
	{0x2066, 0x2069},
	{0xfeff, 0xfeff},
}

// Text replaces every control character, escape, C1 control, bidi control, invisible
// formatter and invalid UTF-8 sequence in s with '·', keeping one input on one line.
func Text(s string) Safe {
	if isSafeString(s) {
		return Safe(s)
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || isReplaced(r) {
			b.WriteRune(replacement)
		} else {
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	out := b.String()
	contract.Ensure(isSafeString(out), "clean.Text: output violates Safe invariant")
	return Safe(out)
}

// Const wraps a repository string literal as Safe. Other packages may pass only a string
// literal to Const (enforced by safe_test.go); any unsafe rune is a contract violation.
func Const(s string) Safe {
	contract.Require(isSafeString(s), "clean.Const: literal contains unsafe rune or invalid UTF-8")
	return Safe(s)
}

// Join concatenates Safe values without breaking the Safe invariant.
func Join(parts ...Safe) Safe {
	if len(parts) == 0 {
		return ""
	}
	if len(parts) == 1 {
		contract.Ensure(isSafeString(string(parts[0])), "clean.Join: part violates Safe invariant")
		return parts[0]
	}
	n := 0
	for _, p := range parts {
		n += len(p)
	}
	var b strings.Builder
	b.Grow(n)
	for _, p := range parts {
		b.WriteString(string(p))
	}
	out := b.String()
	contract.Ensure(isSafeString(out), "clean.Join: output violates Safe invariant")
	return Safe(out)
}

func isSafeString(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || isReplaced(r) {
			return false
		}
		i += size
	}
	return true
}

func isReplaced(r rune) bool {
	for _, span := range replacedRanges {
		if r >= span[0] && r <= span[1] {
			return true
		}
	}
	return false
}
