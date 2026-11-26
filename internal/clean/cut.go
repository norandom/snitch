// cut.go implements cell-width measurement, middle truncation keeping the tail,
// and byte size and age formatting matching the reference Python client.
//
// Fail-safe implications: none on kernel egress. Pure string and time formatting.
package clean

import (
	"math"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"

	"github.com/norandom/snitch/internal/contract"
)

type cellSpan struct {
	start, end, width int
}

var sizeUnits = []struct {
	unit  byte
	div   uint64
	limit uint64
}{
	{'B', 1, 1 << 10},
	{'K', 1 << 10, 1 << 20},
	{'M', 1 << 20, 1 << 30},
	{'G', 1 << 30, 1 << 40},
	{'T', 1 << 40, math.MaxUint64},
}

var ageUnits = []struct {
	unit byte
	secs int64
}{
	{'d', 86400},
	{'h', 3600},
	{'m', 60},
	{'s', 1},
}

// Width returns the terminal cell width of s using the renderer's wcwidth rule.
func Width(s Safe) int {
	return ansi.StringWidthWc(string(s))
}

// Middle shortens s to at most cells terminal columns by eliding the middle with "…",
// keeping the tail (such as the last labels of a name or the file name of a path).
func Middle(s Safe, cells int) Safe {
	contract.Require(isSafeString(string(s)), "clean.Middle: input violates Safe invariant")
	if cells <= 0 {
		return ""
	}
	raw := string(s)
	spans, total := splitSpans(raw)
	if total <= cells {
		return s
	}
	if cells == 1 {
		return Safe("…")
	}
	out := cutMiddle(raw, spans, cells)
	contract.Ensure(isSafeString(out) && ansi.StringWidthWc(out) <= cells, "clean.Middle: output violates width or Safe invariant")
	return Safe(out)
}

// Size formats a byte count as 0B..1024T, matching the reference Python client.
func Size(n uint64) Safe {
	for _, u := range sizeUnits {
		if n < u.limit || u.unit == 'T' {
			v := uint64(math.RoundToEven(float64(n) / float64(u.div)))
			return Safe(strconv.FormatUint(v, 10) + string(u.unit))
		}
	}
	return Safe("0B")
}

// Age formats the elapsed time from t to now as "-", "now", "5s", "3m", "2h", or "4d",
// matching the reference Python client.
func Age(t, now time.Time) Safe {
	if t.IsZero() {
		return Safe("-")
	}
	d := now.Sub(t)
	if d < 5*time.Second {
		return Safe("now")
	}
	secs := int64(d / time.Second)
	for _, u := range ageUnits {
		if secs >= u.secs {
			return Safe(strconv.FormatInt(secs/u.secs, 10) + string(u.unit))
		}
	}
	return Safe("now")
}

func splitSpans(s string) ([]cellSpan, int) {
	spans := make([]cellSpan, 0, len(s))
	total := 0
	for i := 0; i < len(s); {
		r, sz := utf8.DecodeRuneInString(s[i:])
		w := runeCellWidth(r, s[i:i+sz])
		if w == 0 && len(spans) > 0 {
			spans[len(spans)-1].end = i + sz
		} else {
			spans = append(spans, cellSpan{start: i, end: i + sz, width: w})
			total += w
		}
		i += sz
	}
	return spans, total
}

func runeCellWidth(r rune, enc string) int {
	if r >= 0x20 && r <= 0x7e {
		return 1
	}
	return ansi.StringWidthWc(enc)
}

func cutMiddle(raw string, spans []cellSpan, cells int) string {
	rem := cells - 1
	hCount, hUsed := takeHead(spans, rem/3)
	tStart, tUsed := takeTail(spans[hCount:], rem-hUsed)
	tStart += hCount
	if tStart == len(spans) && spans[len(spans)-1].width <= rem {
		tStart, tUsed = takeTail(spans, rem)
		hCount, _ = takeHead(spans[:tStart], rem-tUsed)
	}
	headEnd := 0
	if hCount > 0 {
		headEnd = spans[hCount-1].end
	}
	tailStart := len(raw)
	if tStart < len(spans) {
		tailStart = spans[tStart].start
	}
	return raw[:headEnd] + "…" + raw[tailStart:]
}

func takeHead(spans []cellSpan, limit int) (count, used int) {
	for count < len(spans) && used+spans[count].width <= limit {
		used += spans[count].width
		count++
	}
	return count, used
}

func takeTail(spans []cellSpan, limit int) (start, used int) {
	start = len(spans)
	for start > 0 && used+spans[start-1].width <= limit {
		start--
		used += spans[start].width
	}
	return start, used
}
