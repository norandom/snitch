// Package conf loads and validates ~/.config/snitch/config.toml (requirements 3.1, 6.5,
// 11.1–11.7). It supplies the Python client's defaults when the file is absent, ignores the
// popup keys and unknown keys, keeps hypr-rdp and sshd in Protect regardless of file contents,
// and bounds trial durations and time windows to what the daemon accepts.
//
// Fail-safe implications: none on kernel egress. The file is user-owned; Protect can only
// grow beyond the hypr-rdp/sshd floor, and Trial stays within the daemon's 1m..1h bounds.
package conf

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"

	"github.com/norandom/snitch/internal/contract"
)

const (
	configFile       = "config.toml"
	minTrial         = time.Minute
	maxTrial         = time.Hour
	defaultTrial     = 10 * time.Minute
	maxResortSeconds = math.MaxInt64 / int64(time.Second)
	servedWindowsStr = "15m, 30m, 1h, 24h, 7d"
)

var (
	servedWindows  = []string{"15m", "30m", "1h", "24h", "7d"}
	defaultProtect = []string{"hypr-rdp", "sshd"}
	defaultResort  = []time.Duration{10 * time.Second, 20 * time.Second}
)

// Config holds the operator settings honoured by the TUI and one-shot verbs.
type Config struct {
	Periods []string        // subset of 15m 30m 1h 24h 7d, in file order
	Since   string          // starting time window; one of the five served windows
	Protect []string        // always contains hypr-rdp, sshd; the file only adds
	Resort  []time.Duration // activity re-sort intervals; default 10s, 20s
	Trial   time.Duration   // default-deny trial duration, bounded to 1m..1h
}

type rawConfig struct {
	Periods *[]string `toml:"periods"`
	Since   *string   `toml:"since"`
	Protect *[]string `toml:"protect"`
	Resort  *[]int64  `toml:"resort"`
	Trial   *string   `toml:"trial"`
}

// Default returns the built-in configuration used when config.toml does not exist.
func Default() Config {
	return Config{
		Periods: slices.Clone(servedWindows),
		Since:   "1h",
		Protect: slices.Clone(defaultProtect),
		Resort:  slices.Clone(defaultResort),
		Trial:   defaultTrial,
	}
}

// Load reads and validates config.toml through read, returning Default when read reports
// os.ErrNotExist. Popup keys (temporary, snooze, session, terminal) and unknown keys are
// ignored; errors name config.toml, the offending key, and (for windows) the five served ones.
func Load(read func() ([]byte, error)) (Config, error) {
	contract.Require(read != nil, "conf.Load: nil reader")
	src, err := read()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Default(), nil
		}
		return Config{}, fmt.Errorf("%s: %w", configFile, err)
	}
	var raw rawConfig
	if err := toml.NewDecoder(bytes.NewReader(src)).Decode(&raw); err != nil {
		return Config{}, decodeError(err)
	}
	return buildConfig(raw)
}

// WithSince returns a copy of c whose starting time window is w after checking that the
// daemon serves w.
func (c Config) WithSince(w string) (Config, error) {
	if err := validateWindow("--since", w); err != nil {
		return Config{}, err
	}
	c.Since = w
	return c, nil
}

func buildConfig(raw rawConfig) (Config, error) {
	cfg := Default()
	var err error
	if cfg.Periods, err = parsePeriods(raw.Periods, cfg.Periods); err != nil {
		return Config{}, err
	}
	if raw.Since != nil {
		if err := validateWindow("since", *raw.Since); err != nil {
			return Config{}, fmt.Errorf("%s: %w", configFile, err)
		}
		cfg.Since = *raw.Since
	}
	cfg.Protect = mergeProtect(raw.Protect)
	if cfg.Resort, err = parseResort(raw.Resort, cfg.Resort); err != nil {
		return Config{}, err
	}
	if cfg.Trial, err = parseTrial(raw.Trial, cfg.Trial); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func decodeError(err error) error {
	var de *toml.DecodeError
	if errors.As(err, &de) {
		row, _ := de.Position()
		if key := strings.Join(de.Key(), "."); key != "" {
			return fmt.Errorf("%s: line %d (%s): %s", configFile, row, key, de.Error())
		}
		return fmt.Errorf("%s: line %d: %s", configFile, row, de.Error())
	}
	return fmt.Errorf("%s: %w", configFile, err)
}

func parsePeriods(raw *[]string, fallback []string) ([]string, error) {
	if raw == nil {
		return fallback, nil
	}
	if len(*raw) == 0 {
		return nil, fmt.Errorf("%s: periods cannot be empty; daemon serves %s", configFile, servedWindowsStr)
	}
	out := make([]string, 0, len(*raw))
	seen := make(map[string]bool, len(*raw))
	for _, w := range *raw {
		if err := validateWindow("periods", w); err != nil {
			return nil, fmt.Errorf("%s: %w", configFile, err)
		}
		if !seen[w] {
			seen[w] = true
			out = append(out, w)
		}
	}
	return out, nil
}

func validateWindow(key, w string) error {
	if !slices.Contains(servedWindows, w) {
		return fmt.Errorf("%s: unknown window %q; daemon serves %s", key, w, servedWindowsStr)
	}
	return nil
}

func mergeProtect(raw *[]string) []string {
	out := slices.Clone(defaultProtect)
	if raw == nil {
		return out
	}
	seen := map[string]bool{"hypr-rdp": true, "sshd": true}
	for _, p := range *raw {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

func parseResort(raw *[]int64, fallback []time.Duration) ([]time.Duration, error) {
	if raw == nil {
		return fallback, nil
	}
	if len(*raw) == 0 {
		return nil, fmt.Errorf("%s: resort cannot be empty", configFile)
	}
	out := make([]time.Duration, 0, len(*raw))
	for _, sec := range *raw {
		if sec <= 0 || sec > maxResortSeconds {
			return nil, fmt.Errorf("%s: resort: interval %ds must be positive", configFile, sec)
		}
		out = append(out, time.Duration(sec)*time.Second)
	}
	return out, nil
}

func parseTrial(raw *string, fallback time.Duration) (time.Duration, error) {
	if raw == nil {
		return fallback, nil
	}
	d, err := time.ParseDuration(*raw)
	if err != nil {
		return 0, fmt.Errorf("%s: trial %q: %w", configFile, *raw, err)
	}
	if d < minTrial || d > maxTrial {
		return 0, fmt.Errorf("%s: trial %v: must be between 1m and 1h", configFile, d)
	}
	return d, nil
}
