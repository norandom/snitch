// conf_test.go tests config defaults, loading, validation floors/bounds, --since and fuzzing.
package conf

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

var wantWindows = []string{"15m", "30m", "1h", "24h", "7d"}

func TestDefault(t *testing.T) {
	c := Default()
	if !reflect.DeepEqual(c.Periods, wantWindows) || c.Since != "1h" {
		t.Fatalf("Periods/Since = %v/%q, want %v/1h", c.Periods, c.Since, wantWindows)
	}
	if !reflect.DeepEqual(c.Protect, []string{"hypr-rdp", "sshd"}) {
		t.Fatalf("Protect = %v, want [hypr-rdp sshd]", c.Protect)
	}
	wantResort := []time.Duration{10 * time.Second, 20 * time.Second}
	if !reflect.DeepEqual(c.Resort, wantResort) || c.Trial != 10*time.Minute {
		t.Fatalf("Resort/Trial = %v/%v, want %v/10m", c.Resort, c.Trial, wantResort)
	}
	// Mutating returned slices must not affect a later Default() call.
	c.Periods[0], c.Protect[0], c.Resort[0] = "mutated", "mutated", 99*time.Second
	if d := Default(); d.Periods[0] != "15m" || d.Protect[0] != "hypr-rdp" || d.Resort[0] != 10*time.Second {
		t.Fatalf("Default() shared mutable slice state: %+v", d)
	}
}

func TestLoadMissingAndReadErrors(t *testing.T) {
	for _, err := range []error{os.ErrNotExist, fmt.Errorf("open ~/.config/snitch/config.toml: %w", os.ErrNotExist)} {
		got, gotErr := Load(func() ([]byte, error) { return nil, err })
		if gotErr != nil || !reflect.DeepEqual(got, Default()) {
			t.Fatalf("missing file (%v): got (%+v, %v), want (Default(), nil)", err, got, gotErr)
		}
	}
	if got, err := Load(func() ([]byte, error) { return []byte(""), nil }); err != nil || !reflect.DeepEqual(got, Default()) {
		t.Fatalf("empty file: got (%+v, %v), want (Default(), nil)", got, err)
	}
	_, err := Load(func() ([]byte, error) { return nil, os.ErrPermission })
	if err == nil || !strings.Contains(err.Error(), "config.toml") || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("read failure error = %v, want config.toml and wrapped os.ErrPermission", err)
	}
}

func TestLoadValidOverrides(t *testing.T) {
	src := `
periods = ["7d", "15m", "7d"]
since = "24h"
protect = ["curl", "sshd", "git"]
resort = [5, 30]
trial = "15m"
`
	got, err := Load(func() ([]byte, error) { return []byte(src), nil })
	if err != nil {
		t.Fatalf("Load valid config: %v", err)
	}
	want := Config{
		Periods: []string{"7d", "15m"},
		Since:   "24h",
		Protect: []string{"hypr-rdp", "sshd", "curl", "git"},
		Resort:  []time.Duration{5 * time.Second, 30 * time.Second},
		Trial:   15 * time.Minute,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v, want %+v", got, want)
	}
	for _, tc := range []struct {
		raw  string
		want time.Duration
	}{{`trial = "1m"`, time.Minute}, {`trial = "1h"`, time.Hour}} {
		if c, err := Load(func() ([]byte, error) { return []byte(tc.raw), nil }); err != nil || c.Trial != tc.want {
			t.Fatalf("Load(%q) = (%+v, %v), want Trial=%v", tc.raw, c, err, tc.want)
		}
	}
}

func TestLoadIgnoresPopupAndUnknownKeys(t *testing.T) {
	src := `
temporary = "15m"
snooze = "10m"
session = "/usr/bin/start-hyprland"
terminal = "foot --app-id=snitch-alert -e"
future_option = true

[extra]
ignored = 42
`
	got, err := Load(func() ([]byte, error) { return []byte(src), nil })
	if err != nil || !reflect.DeepEqual(got, Default()) {
		t.Fatalf("Load ignored keys: got (%+v, %v), want (Default(), nil)", got, err)
	}
}

func TestLoadProtectFloorCannotBeEmptied(t *testing.T) {
	for _, src := range []string{`protect = []`, `protect = ["", "curl"]`} {
		got, err := Load(func() ([]byte, error) { return []byte(src), nil })
		if err != nil {
			t.Fatalf("Load(%q): %v", src, err)
		}
		if !slices.Contains(got.Protect, "hypr-rdp") || !slices.Contains(got.Protect, "sshd") {
			t.Fatalf("Load(%q) Protect = %v, must keep hypr-rdp and sshd", src, got.Protect)
		}
	}
}

type loadErrCase struct {
	name        string
	src         string
	wantSubstrs []string
}

func assertLoadErrorCases(t *testing.T, cases []loadErrCase) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(func() ([]byte, error) { return []byte(tc.src), nil })
			if err == nil {
				t.Fatalf("Load(%q) succeeded, expected error", tc.src)
			}
			for _, sub := range tc.wantSubstrs {
				if !strings.Contains(err.Error(), sub) {
					t.Errorf("error %q missing substring %q", err.Error(), sub)
				}
			}
		})
	}
}

func TestLoadWindowAndTrialErrors(t *testing.T) {
	assertLoadErrorCases(t, []loadErrCase{
		{"unserved_period", `periods = ["15m", "5m"]`, append([]string{"config.toml", "periods", "5m"}, wantWindows...)},
		{"empty_periods", `periods = []`, append([]string{"config.toml", "periods"}, wantWindows...)},
		{"unserved_since", `since = "2h"`, append([]string{"config.toml", "since", "2h"}, wantWindows...)},
		{"empty_since", `since = ""`, append([]string{"config.toml", "since"}, wantWindows...)},
		{"trial_too_short", `trial = "59s"`, []string{"config.toml", "trial", "1m", "1h"}},
		{"trial_too_long", `trial = "61m"`, []string{"config.toml", "trial", "1m", "1h"}},
		{"trial_invalid_duration", `trial = "bogus"`, []string{"config.toml", "trial"}},
	})
}

func TestLoadResortAndSyntaxErrors(t *testing.T) {
	assertLoadErrorCases(t, []loadErrCase{
		{"resort_empty", `resort = []`, []string{"config.toml", "resort"}},
		{"resort_zero", `resort = [10, 0]`, []string{"config.toml", "resort"}},
		{"resort_negative", `resort = [-5]`, []string{"config.toml", "resort"}},
		{"resort_overflow", `resort = [9223372036854775807]`, []string{"config.toml", "resort"}},
		{"resort_wrong_type", `resort = "10s"`, []string{"config.toml", "resort"}},
		{"broken_toml", `periods = [`, []string{"config.toml"}},
	})
}

func TestWithSince(t *testing.T) {
	base := Default()
	for _, w := range wantWindows {
		got, err := base.WithSince(w)
		if err != nil || got.Since != w {
			t.Fatalf("WithSince(%q) = (%q, %v)", w, got.Since, err)
		}
	}
	if base.Since != "1h" {
		t.Fatalf("WithSince mutated receiver: %q", base.Since)
	}
	for _, bad := range []string{"", "5m", "2h", "1d"} {
		_, err := base.WithSince(bad)
		if err == nil || !strings.Contains(err.Error(), "--since") {
			t.Fatalf("WithSince(%q) error = %v, want --since", bad, err)
		}
		for _, w := range wantWindows {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("WithSince(%q) error %q missing served window %q", bad, err.Error(), w)
			}
		}
	}
}

func FuzzLoad_conf(f *testing.F) {
	for _, s := range []string{
		"",
		"periods = [\"15m\", \"1h\"]\nsince = \"15m\"\nprotect = []\nresort = [10, 20]\ntrial = \"10m\"\n",
		"temporary = \"15m\"\nsnooze = \"10m\"\nsession = \"/usr/bin/start-hyprland\"\nterminal = \"foot\"\n",
		"periods = [\"5m\"]\n",
		"since = \"invalid\"\n",
		"trial = \"0s\"\n",
		"trial = \"2h\"\n",
		"resort = [9223372036854775807]\n",
		"periods = [\xff]\n",
		"[broken",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := Load(func() ([]byte, error) { return data, nil })
		if err != nil {
			if err.Error() == "" {
				t.Fatalf("Load returned empty error string")
			}
			return
		}
		assertValidConfig(t, c)
	})
}

func assertValidConfig(t *testing.T, c Config) {
	t.Helper()
	if !slices.Contains(c.Protect, "hypr-rdp") || !slices.Contains(c.Protect, "sshd") {
		t.Fatalf("Protect missing floor: %v", c.Protect)
	}
	if len(c.Periods) == 0 || !slices.Contains(wantWindows, c.Since) || len(c.Resort) == 0 {
		t.Fatalf("invalid config fields: %+v", c)
	}
	if c.Trial < time.Minute || c.Trial > time.Hour {
		t.Fatalf("Trial %v out of bounds", c.Trial)
	}
	assertValidSlices(t, c)
}

func assertValidSlices(t *testing.T, c Config) {
	t.Helper()
	for _, p := range c.Periods {
		if !slices.Contains(wantWindows, p) {
			t.Fatalf("invalid Period %q", p)
		}
	}
	for _, d := range c.Resort {
		if d <= 0 {
			t.Fatalf("non-positive Resort %v", d)
		}
	}
}
