// name_test.go tests internal/clean's RFC 3492 punycode encoder, Name, Path and fuzz target.
package clean

import (
	"strings"
	"testing"
	"unicode/utf8"
)

func TestPunycodeRFC3492Vectors(t *testing.T) {
	vectors := []struct {
		name, in, want string
	}{
		{"A_arabic", "\u0644\u064a\u0647\u0645\u0627\u0628\u062a\u0643\u0644\u0645\u0648\u0634\u0639\u0631\u0628\u064a\u061f", "egbpdaj6bu4bxfgehfvwxn"},
		{"B_chinese_simp", "\u4ed6\u4eec\u4e3a\u4ec0\u4e48\u4e0d\u8bf4\u4e2d\u6587", "ihqwcrb4cv8a8dqg056pqjye"},
		{"C_chinese_trad", "\u4ed6\u5011\u7232\u4ec0\u9ebd\u4e0d\u8aaa\u4e2d\u6587", "ihqwctvzc91f659drss3x8bo0yb"},
		{"D_czech", "Pro\u010dprost\u011bnemluv\u00ed\u010desky", "Proprostnemluvesky-uyb24dma41a"},
		{"E_hebrew", "\u05dc\u05de\u05d4\u05d4\u05dd\u05e4\u05e9\u05d5\u05d8\u05dc\u05d0\u05de\u05d3\u05d1\u05e8\u05d9\u05dd\u05e2\u05d1\u05e8\u05d9\u05ea", "4dbcagdahymbxekheh6e0a7fei0b"},
		{"F_hindi", "\u092f\u0939\u0932\u094b\u0917\u0939\u093f\u0928\u094d\u0926\u0940\u0915\u094d\u092f\u094b\u0902\u0928\u0939\u0940\u0902\u092c\u094b\u0932\u0938\u0915\u0924\u0947\u0939\u0948\u0902", "i1baa7eci9glrd9b2ae1bj0hfcgg6iyaf8o0a1dig0cd"},
		{"G_japanese", "\u306a\u305c\u307f\u3093\u306a\u65e5\u672c\u8a9e\u3092\u8a71\u3057\u3066\u304f\u308c\u306a\u3044\u306e\u304b", "n8jok5ay5dzabd5bym9f0cm5685rrjetr6pdxa"},
		{"H_korean", "\uc138\uacc4\uc758\ubaa8\ub4e0\uc0ac\ub78c\ub4e4\uc774\ud55c\uad6d\uc5b4\ub97c\uc774\ud574\ud55c\ub2e4\uba74\uc5bc\ub9c8\ub098\uc88b\uc744\uae4c", "989aomsvi5e83db1d2a355cv1e0vak1dwrv93d5xbh15a0dt30a5jpsd879ccm6fea98c"},
		{"I_russian", "\u043f\u043e\u0447\u0435\u043c\u0443\u0436\u0435\u043e\u043d\u0438\u043d\u0435\u0433\u043e\u0432\u043e\u0440\u044f\u0442\u043f\u043e\u0440\u0443\u0441\u0441\u043a\u0438", "b1abfaaepdrnnbgefbadotcwatmq2g4l"},
		{"J_spanish", "Porqu\u00e9nopuedensimplementehablarenEspa\u00f1ol", "PorqunopuedensimplementehablarenEspaol-fmd56a"},
		{"K_vietnamese", "T\u1ea1isaoh\u1ecdkh\u00f4ngth\u1ec3ch\u1ec9n\u00f3iti\u1ebfngVi\u1ec7t", "TisaohkhngthchnitingVit-kjcr8268qyxafd2f1b9g"},
		{"L_3B", "3\u5e74B\u7d44\u91d1\u516b\u5148\u751f", "3B-ww4c5e180e575a65lsy2b"},
		{"M_super_monkeys", "\u5b89\u5ba4\u5948\u7f8e\u6075-with-SUPER-MONKEYS", "-with-SUPER-MONKEYS-pc58ag80a8qai00g7n9n"},
		{"N_hello_another_way", "Hello-Another-Way-\u305d\u308c\u305e\u308c\u306e\u5834\u6240", "Hello-Another-Way--fc4qua05auwb3674vfr0b"},
		{"O_hitotsu", "\u3072\u3068\u3064\u5c4b\u6839\u306e\u4e0b2", "2-u9tlzr9756bt3uc0v"},
		{"P_maji", "Maji\u3067Koi\u3059\u308b5\u79d2\u524d", "MajiKoi5-783gue6qz075azm5e"},
		{"Q_puffy", "\u30d1\u30d5\u30a3\u30fcde\u30eb\u30f3\u30d0", "de-jg4avhby1noc0d"},
		{"R_speed", "\u305d\u306e\u30b9\u30d4\u30fc\u30c9\u3067", "d9juau41awczczp"},
		{"S_ascii_only", "-> $1.00 <-", "-> $1.00 <--"},
	}
	for _, tc := range vectors {
		got, ok := punycodeEncode(tc.in)
		if !ok || got != tc.want {
			t.Errorf("%s: punycodeEncode(%q) = (%q, %v), want (%q, true)", tc.name, tc.in, got, ok, tc.want)
		}
	}
}

func TestNamePunycodeAndSanitisation(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"plain_ascii", "api.github.com", "api.github.com"},
		{"preserves_case", "Api.GitHub.COM", "Api.GitHub.COM"},
		{"ipv4", "192.0.2.1", "192.0.2.1"},
		{"ipv6_literal", "[2001:db8::1]", "[2001:db8::1]"},
		{"existing_punycode", "xn--bcher-kva.example", "xn--bcher-kva.example"},
		{"idn_tld_and_label", "例え.jp", "xn--r8jz45g.jp"},
		{"mixed_labels_preserve_case", "sub.Bücher.Example", "sub.xn--Bcher-kva.Example"},
		{"trailing_dot", "café.com.", "xn--caf-dma.com."},
		{"empty_labels", "a..café", "a..xn--caf-dma"},
		{"control_in_ascii", "bad\x1b[31mhost\n.com", "bad·[31mhost·.com"},
		{"bidi_in_label_becomes_punycode", "a\u202eb.com", "xn--ab-g4t.com"},
		{"zero_width_in_label_becomes_punycode", "pay\u200bpal.com", "xn--paypal-df0c.com"},
	}
	for _, tc := range cases {
		got := Name(tc.in)
		if string(got) != tc.want {
			t.Errorf("%s: Name(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
		if Text(string(got)) != got {
			t.Errorf("%s: Name output not clean.Text-idempotent: %q", tc.name, got)
		}
	}
}

func TestPath(t *testing.T) {
	cases := []struct{ name, in, want string }{
		{"empty", "", ""},
		{"normal", "/usr/local/bin/curl", "/usr/local/bin/curl"},
		{"unicode_dir", "/home/alice/café/tool", "/home/alice/café/tool"},
		{"not_cleaned", "/usr/bin/../bin/curl", "/usr/bin/../bin/curl"},
		{"escape_and_bidi", "/tmp/\x1b[31m\u202eevil\n/bin", "/tmp/·[31m·evil·/bin"},
		{"invalid_utf8", "/tmp/\xff/bin", "/tmp/·/bin"},
	}
	for _, tc := range cases {
		got := Path(tc.in)
		if string(got) != tc.want {
			t.Errorf("%s: Path(%q) = %q, want %q", tc.name, tc.in, got, tc.want)
		}
	}
}

func FuzzName_clean(f *testing.F) {
	seeds := []string{
		"",
		"localhost",
		"api.github.com",
		"例え.jp",
		"Bücher.DE",
		"xn--bcher-kva.de",
		"a\x1b[31m.b\nc",
		"pay\u200bpal.com",
		"a\u202eb.com",
		"\xff\xc0\xaf.example",
		strings.Repeat("ä", 64) + ".com",
	}
	for _, s := range seeds {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		got := Name(s)
		raw := string(got)
		if !utf8.ValidString(raw) {
			t.Fatalf("Name(%q) produced invalid UTF-8 %q", s, raw)
		}
		for _, r := range raw {
			if isForbiddenForTest(r) {
				t.Fatalf("Name(%q) kept forbidden rune U+%04X", s, r)
			}
			if r >= 0x80 && r != replacement {
				t.Fatalf("Name(%q) left non-ASCII rune U+%04X in %q", s, r, raw)
			}
		}
		if Text(raw) != got {
			t.Fatalf("Name(%q) not clean.Text-idempotent: %q", s, raw)
		}
	})
}
