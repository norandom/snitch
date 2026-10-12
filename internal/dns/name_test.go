// Name tests pin the kernel key layout and prevent suffix overmatching.
package dns

import (
	"os"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/rules"
)

func TestCovers(t *testing.T) {
	for _, tt := range []struct {
		rule, name string
		want       bool
	}{
		{"github.com", "github.com", true}, {"github.com", "api.github.com", true},
		{"github.com", "notgithub.com", false}, {"github.com", "github.com.evil", false},
	} {
		if got := Covers(tt.rule, tt.name); got != tt.want {
			t.Errorf("Covers(%q, %q) = %v", tt.rule, tt.name, got)
		}
	}
}

func TestKeyKernelForm(t *testing.T) {
	name, err := rules.ParseName("API.GitHub.COM.")
	if err != nil {
		t.Fatal(err)
	}
	var want [64]byte
	// read_qname replaces each length byte with a dot after lowercasing.
	copy(want[:], []byte{'.', 'a', 'p', 'i', '.', 'g', 'i', 't', 'h', 'u', 'b', '.', 'c', 'o', 'm'})
	if got := Key(name); got != want {
		t.Fatalf("key = %q, want %q", got, want)
	}
}

func TestKeyRequiresBound(t *testing.T) {
	defer func() {
		v, ok := recover().(*contract.Violation)
		if !ok || v.Kind != contract.Precondition {
			t.Fatalf("panic = %v", v)
		}
	}()
	Key(strings.Repeat("a", NameMax-1))
}

func TestKeyAcceptsTheLongestParsedName(t *testing.T) {
	key := Key(strings.Repeat("a", NameMax-2))
	if key[0] != '.' || key[NameMax-2] != 'a' || key[NameMax-1] != 0 {
		t.Fatalf("key = %q", key[:])
	}
}

func TestSuffixes(t *testing.T) {
	want := []string{"a.b.c.d", "b.c.d", "c.d", "d"}
	if got := Suffixes(want[0]); !reflect.DeepEqual(got, want) {
		t.Fatal(got)
	}
}

func TestSuffixesCap(t *testing.T) {
	got := Suffixes("a.b.c.d.e.f.g.h.i.j")
	if len(got) != LevelsMax || got[LevelsMax-1] != "h.i.j" {
		t.Fatal(got)
	}
}

func TestMirrorKernelConstants(t *testing.T) {
	raw, err := os.ReadFile("../../bpf/dns.bpf.c")
	if err != nil {
		t.Fatal(err)
	}
	for name, want := range map[string]int{"NAME_MAX": NameMax, "LABELS_MAX": LabelsMax, "LEVELS_MAX": LevelsMax, "SLOTS_MAX": SlotsMax, "ADDRS_MAX": AddrsMax} {
		match := regexp.MustCompile(`(?m)^#define\s+` + name + `\s+(\d+)\b`).FindSubmatch(raw)
		if len(match) != 2 {
			t.Fatalf("missing %s", name)
		}
		got, err := strconv.Atoi(string(match[1]))
		if err != nil || got != want {
			t.Errorf("%s = %d, Go = %d", name, got, want)
		}
	}
}
