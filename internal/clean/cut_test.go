// cut_test.go tests internal/clean's Width, Middle, Size, Age and fuzz target.
package clean

import (
	"math"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/x/ansi"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

func TestWidth(t *testing.T) {
	cases := []struct {
		name string
		in   Safe
		want int
	}{
		{"empty", Const(""), 0},
		{"ascii", Const("curl"), 4},
		{"ellipsis", Const("…"), 1},
		{"cjk", Const("日本語"), 6},
		{"combining", Const("e\u0301"), 1},
		{"skin_tone_wc_rule", Const("👩🏽"), ansi.StringWidthWc("👩🏽")},
	}
	for _, tc := range cases {
		if got := Width(tc.in); got != tc.want {
			t.Errorf("%s: Width(%q) = %d, want %d", tc.name, tc.in, got, tc.want)
		}
	}
}

func TestMiddle(t *testing.T) {
	cases := []struct {
		name  string
		in    Safe
		cells int
		want  string
	}{
		{"zero_cells", Const("abcdef"), 0, ""},
		{"negative_cells", Const("abcdef"), -3, ""},
		{"one_cell", Const("abcdef"), 1, "…"},
		{"exact_fit", Const("abcdef"), 6, "abcdef"},
		{"room_to_spare", Const("abcdef"), 10, "abcdef"},
		{"empty_zero", Const(""), 0, ""},
		{"two_cells", Const("abcdef"), 2, "…f"},
		{"four_cells", Const("abcdef"), 4, "a…ef"},
		{"wide_fits", Const("日本語"), 6, "日本語"},
		{"wide_one_cell", Const("日本語"), 1, "…"},
		{"wide_tail_exact", Const("a界"), 3, "a界"},
		{"wide_tail_kept", Const("ab界"), 3, "…界"},
		{"wide_tail_four_cells", Const("ab界"), 4, "ab界"},
		{"wide_tail_with_head", Const("abc界"), 4, "a…界"},
		{"wide_too_narrow_for_tail", Const("a界"), 2, "…"},
		{"combining_not_orphaned", Const("abc\u0301de"), 4, "a…de"},
		{"combining_kept_with_base_tail", Const("abcd\u0301e"), 4, "a…d\u0301e"},
		{"combining_kept_with_base_head", Const("a\u0301bcde"), 4, "a\u0301…de"},
	}
	for _, tc := range cases {
		got := Middle(tc.in, tc.cells)
		if string(got) != tc.want {
			t.Errorf("%s: Middle(%q, %d) = %q, want %q", tc.name, tc.in, tc.cells, got, tc.want)
		}
		if tc.cells >= 0 && Width(got) > tc.cells {
			t.Errorf("%s: Width(%q) = %d > %d", tc.name, got, Width(got), tc.cells)
		}
	}
	contracttest.Panics(t, contract.Precondition, func() { _ = Middle(Safe("\n"), 4) })
}

func TestMiddleKeepsTailOfNamesAndPaths(t *testing.T) {
	host := Const("very-long-service-name.us-east-1.amazonaws.com")
	gotHost := Middle(host, 24)
	if !strings.HasSuffix(string(gotHost), "amazonaws.com") || !strings.Contains(string(gotHost), "…") {
		t.Fatalf("host middle cut = %q, want head…amazonaws.com", gotHost)
	}
	if Width(gotHost) > 24 {
		t.Fatalf("host width = %d > 24", Width(gotHost))
	}

	path := Const("/usr/local/lib/python3.12/site-packages/my-daemon")
	gotPath := Middle(path, 25)
	if !strings.HasSuffix(string(gotPath), "my-daemon") || !strings.HasPrefix(string(gotPath), "/usr") {
		t.Fatalf("path middle cut = %q, want /usr…my-daemon", gotPath)
	}
	if Width(gotPath) > 25 {
		t.Fatalf("path width = %d > 25", Width(gotPath))
	}
}

func TestSize(t *testing.T) {
	const (
		k = uint64(1024)
		m = k * 1024
		g = m * 1024
		T = g * 1024
	)
	cases := []struct {
		in   uint64
		want string
	}{
		{0, "0B"},
		{1, "1B"},
		{1023, "1023B"},
		{1024, "1K"},
		{1535, "1K"},
		{1536, "2K"},
		{2560, "2K"},
		{m - 1, "1024K"},
		{m, "1M"},
		{g - 1, "1024M"},
		{g, "1G"},
		{T - 1, "1024G"},
		{T, "1T"},
		{1024 * T, "1024T"},
		{math.MaxUint64, "16777216T"},
	}
	for _, tc := range cases {
		if got := Size(tc.in); string(got) != tc.want {
			t.Errorf("Size(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestAge(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	cases := []struct {
		name string
		at   time.Time
		want string
	}{
		{"zero", time.Time{}, "-"},
		{"future", now.Add(10 * time.Second), "now"},
		{"same", now, "now"},
		{"under_5s", now.Add(-4*time.Second - 900*time.Millisecond), "now"},
		{"5s", now.Add(-5 * time.Second), "5s"},
		{"59s", now.Add(-59 * time.Second), "59s"},
		{"1m", now.Add(-60 * time.Second), "1m"},
		{"3m", now.Add(-3*time.Minute - 45*time.Second), "3m"},
		{"59m", now.Add(-59*time.Minute - 59*time.Second), "59m"},
		{"1h", now.Add(-time.Hour), "1h"},
		{"2h", now.Add(-2*time.Hour - 30*time.Minute), "2h"},
		{"23h", now.Add(-23*time.Hour - 59*time.Minute), "23h"},
		{"1d", now.Add(-24 * time.Hour), "1d"},
		{"4d", now.Add(-4*24*time.Hour - 12*time.Hour), "4d"},
	}
	for _, tc := range cases {
		if got := Age(tc.at, now); string(got) != tc.want {
			t.Errorf("%s: Age = %q, want %q", tc.name, got, tc.want)
		}
	}
}

func FuzzMiddle_clean(f *testing.F) {
	for _, seed := range []struct {
		s     string
		cells int
	}{
		{"", 0}, {"", 5}, {"curl", 0}, {"curl", 1}, {"curl", 2}, {"curl", 4},
		{"/usr/local/bin/snitchd", 12}, {"very-long-host.example.com", 15},
		{"日本語テスト", 5}, {"a界", 2}, {"a界", 3},
		{"e\u0301\u0302abc\u0301def", 4}, {"\x1b[31mred\u202e\u200b\xff", 5}, {"👨\u200d👩\u200d👧\u200d👦", 4},
	} {
		f.Add(seed.s, seed.cells)
	}
	f.Fuzz(func(t *testing.T, s string, cells int) {
		in := Text(s)
		checkMiddlePostconditions(t, in, cells, Middle(in, cells))
	})
}

func checkMiddlePostconditions(t *testing.T, in Safe, cells int, out Safe) {
	t.Helper()
	raw := string(out)
	if !utf8.ValidString(raw) {
		t.Fatalf("Middle(%q, %d) produced invalid UTF-8 %q", in, cells, raw)
	}
	for _, r := range raw {
		if isForbiddenForTest(r) {
			t.Fatalf("Middle(%q, %d) kept forbidden rune U+%04X", in, cells, r)
		}
	}
	if Text(raw) != out {
		t.Fatalf("Middle(%q, %d) not clean.Text-idempotent: %q", in, cells, raw)
	}
	if cells <= 0 {
		if raw != "" {
			t.Fatalf("Middle(%q, %d) = %q, want empty", in, cells, raw)
		}
		return
	}
	if w := Width(out); w > cells {
		t.Fatalf("Width(Middle(%q, %d)) = %d > %d (out=%q)", in, cells, w, cells, raw)
	}
	if Width(in) <= cells && out != in {
		t.Fatalf("Middle(%q, %d) altered fitting string to %q", in, cells, raw)
	}
}
