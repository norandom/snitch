// Package clean's destination name (RFC 3492 punycode) and executable path helpers.
//
// name.go: implements Name (non-ASCII labels encoded as xn--... without lowercasing or
// resolving, then passed through Text) and Path (full executable path passed through Text).
//
// Fail-safe implications: none on kernel egress. Pure string transformation with no DNS
// lookups, file I/O or BPF access.
package clean

import (
	"math"
	"strings"
)

const (
	punyBase        = 36
	punyTMin        = 1
	punyTMax        = 26
	punySkew        = 38
	punyDamp        = 700
	punyInitialBias = 72
	punyInitialN    = 0x80
)

// Name returns host safe for terminal and log display, encoding any label containing a
// non-ASCII rune (U+0080 or above) as RFC 3492 punycode ("xn--..."). Nothing is
// lower-cased or resolved; the result is passed through Text.
func Name(host string) Safe {
	if !hasNonASCII(host) {
		return Text(host)
	}
	labels := strings.Split(host, ".")
	for i, label := range labels {
		if !hasNonASCII(label) {
			continue
		}
		if enc, ok := punycodeEncode(label); ok {
			labels[i] = "xn--" + enc
		}
	}
	return Text(strings.Join(labels, "."))
}

// Path returns an executable's full path sanitised for display and logging.
func Path(p string) Safe {
	return Text(p)
}

func hasNonASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return true
		}
	}
	return false
}

func punycodeEncode(s string) (string, bool) {
	runes := []rune(s)
	var b strings.Builder
	basic := writeBasicPrefix(&b, runes)
	n, delta, bias, h := rune(punyInitialN), 0, punyInitialBias, basic
	for h < len(runes) {
		m := nextCodePoint(runes, n)
		step := int(m - n)
		if step > (math.MaxInt-delta)/(h+1) {
			return "", false
		}
		delta += step * (h + 1)
		n = m
		var ok bool
		delta, bias, h, ok = encodeCodePoints(&b, runes, n, delta, bias, h, basic)
		if !ok || delta == math.MaxInt {
			return "", false
		}
		delta++
		n++
	}
	return b.String(), true
}

func writeBasicPrefix(b *strings.Builder, runes []rune) int {
	basic := 0
	for _, r := range runes {
		if r < punyInitialN {
			b.WriteByte(byte(r))
			basic++
		}
	}
	if basic > 0 {
		b.WriteByte('-')
	}
	return basic
}

func encodeCodePoints(b *strings.Builder, runes []rune, n rune, delta, bias, h, basic int) (int, int, int, bool) {
	for _, c := range runes {
		if c < n {
			if delta == math.MaxInt {
				return 0, 0, 0, false
			}
			delta++
		}
		if c == n {
			writeVariableInt(b, delta, bias)
			bias = punycodeAdapt(delta, h+1, h == basic)
			delta = 0
			h++
		}
	}
	return delta, bias, h, true
}

func nextCodePoint(runes []rune, minN rune) rune {
	best := rune(math.MaxInt32)
	for _, r := range runes {
		if r >= minN && r < best {
			best = r
		}
	}
	return best
}

func writeVariableInt(b *strings.Builder, q, bias int) {
	for k := punyBase; ; k += punyBase {
		t := punyThreshold(k, bias)
		if q < t {
			b.WriteByte(punycodeDigit(q))
			return
		}
		b.WriteByte(punycodeDigit(t + (q-t)%(punyBase-t)))
		q = (q - t) / (punyBase - t)
	}
}

func punyThreshold(k, bias int) int {
	switch {
	case k <= bias+punyTMin:
		return punyTMin
	case k >= bias+punyTMax:
		return punyTMax
	default:
		return k - bias
	}
}

func punycodeAdapt(delta, numPoints int, first bool) int {
	if first {
		delta /= punyDamp
	} else {
		delta /= 2
	}
	delta += delta / numPoints
	k := 0
	for delta > ((punyBase-punyTMin)*punyTMax)/2 {
		delta /= punyBase - punyTMin
		k += punyBase
	}
	return k + ((punyBase-punyTMin+1)*delta)/(delta+punySkew)
}

func punycodeDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}
