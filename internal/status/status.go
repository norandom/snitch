// Package status is the daemon's facts for the command line: one small file the daemon
// rewrites while it runs and `snitchd status` reads back. A missing file means the daemon
// never ran (or its tmpfs was cleared by a reboot), which the CLI reports as "not running".
package status

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/contract"
)

// Record is what the daemon knows and the CLI shows (Req 7.1). Written is the time of the
// write itself, so a stale file (a crashed daemon) is visible by its age.
type Record struct {
	PID       int
	Mode      string // monitor | enforce
	Source    string // flag | files
	Learning  bool
	Trial     string // RFC3339 deadline or ""
	Kept      bool
	RulesFile string
	// The rules summary the daemon prints at startup and after a reload.
	Programs, Resolved, Executables, Rules int

	Written time.Time // when the daemon wrote the file; read back in UTC to the second
	// DNS is omitted when empty; otherwise off: <reason> or on seen N ignored N cache N names N compiled N.
	DNS     string
	Version string // the daemon's build (spec deploy-service, Req 1.2); the record's last key
}

// keys is the file's line order, the same as the struct's, so a console `cat` reads top down
// in the order the CLI prints. Read requires these keys except the optional dns.
// version is last (added by spec deploy-service) so the earlier lines keep their place.
var keys = []string{"pid", "mode", "source", "learning", "trial", "kept", "rules_file",
	"programs", "resolved", "executables", "rules", "written", "dns", "version"}

// Write replaces the file at path with r as key=value lines, one per field, a trailing
// newline, Written in UTC to the second. The write is atomic (a 0600 temp file in the same
// directory, then rename): the CLI sees the old record or the new, never a part. The
// directory is created 0700 when missing, so a hand-started daemon works without systemd's
// RuntimeDirectory. Requires a path and values without newlines (one line per field).
func Write(path string, r Record) error {
	contract.Require(path != "", "status: empty path")
	contract.Require(!strings.ContainsAny(r.Mode+r.Source+r.Trial+r.RulesFile+r.DNS+r.Version, "\n"),
		"status: newline in a value")
	return writeAtomic(path, []byte(format(r)))
}

func format(r Record) string {
	values := []string{strconv.Itoa(r.PID), r.Mode, r.Source, strconv.FormatBool(r.Learning),
		r.Trial, strconv.FormatBool(r.Kept), r.RulesFile, strconv.Itoa(r.Programs),
		strconv.Itoa(r.Resolved), strconv.Itoa(r.Executables), strconv.Itoa(r.Rules),
		r.Written.UTC().Format(time.RFC3339), r.DNS, r.Version}
	var b strings.Builder
	for i, k := range keys {
		if k == "dns" && r.DNS == "" {
			continue
		}
		b.WriteString(k + "=" + values[i] + "\n")
	}
	return b.String()
}

// writeAtomic is the shape of trial.writeAtomic: the directory first, then temp + rename.
func writeAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*") // 0600 by CreateTemp
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	_, err = tmp.Write(data)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// Read gives back the record Write put at path. A missing file is an error for which
// errors.Is(err, fs.ErrNotExist) holds (the CLI's "daemon not running"); any other failure
// names the file and what is wrong, with a zero record.
func Read(path string) (Record, error) {
	contract.Require(path != "", "status: empty path")
	b, err := os.ReadFile(path) // its error already names the path
	if err != nil {
		return Record{}, err
	}
	var r Record
	kv, err := parseKV(b)
	if err == nil {
		r, err = recordOf(kv)
	}
	if err != nil {
		return Record{}, fmt.Errorf("%s: %w", path, err)
	}
	return r, nil
}

// parseKV splits "key=value" lines (blank lines skipped); a line without "=" or a key
// given twice is an error. The first "=" splits, so a path value may contain one.
func parseKV(b []byte) (map[string]string, error) {
	kv := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		key, value, ok := strings.Cut(line, "=")
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !ok {
			return nil, fmt.Errorf("line %q is not key=value", line)
		}
		if _, dup := kv[key]; dup {
			return nil, fmt.Errorf("key %q given twice", key)
		}
		kv[key] = value
	}
	return kv, nil
}

// recordOf converts the required and optional keys into a Record; the first bad value ends it.
func recordOf(kv map[string]string) (Record, error) {
	var r Record
	if err := onlyKeys(kv); err != nil {
		return r, err
	}
	r.Mode, r.Source, r.Trial, r.RulesFile = kv["mode"], kv["source"], kv["trial"], kv["rules_file"]
	r.Version, r.DNS = kv["version"], kv["dns"]
	ints := []struct {
		key string
		dst *int
	}{{"pid", &r.PID}, {"programs", &r.Programs}, {"resolved", &r.Resolved},
		{"executables", &r.Executables}, {"rules", &r.Rules}}
	for _, f := range ints {
		n, err := strconv.Atoi(kv[f.key])
		if err != nil {
			return r, fmt.Errorf("%s: %v", f.key, err)
		}
		*f.dst = n
	}
	return r, flagsAndTimes(kv, &r)
}

func flagsAndTimes(kv map[string]string, r *Record) error {
	var err error
	if r.Learning, err = strconv.ParseBool(kv["learning"]); err != nil {
		return fmt.Errorf("learning: %v", err)
	}
	if r.Kept, err = strconv.ParseBool(kv["kept"]); err != nil {
		return fmt.Errorf("kept: %v", err)
	}
	if r.Written, err = time.Parse(time.RFC3339, kv["written"]); err != nil {
		return fmt.Errorf("written: %v", err)
	}
	if r.Trial != "" { // the deadline stays a string; it only has to be one the CLI can parse
		if _, err = time.Parse(time.RFC3339, r.Trial); err != nil {
			return fmt.Errorf("trial: %v", err)
		}
	}
	return nil
}

// onlyKeys checks that kv holds the required keys and only keys Write produces.
func onlyKeys(kv map[string]string) error {
	for _, k := range keys {
		if _, ok := kv[k]; !ok && k != "dns" {
			return fmt.Errorf("missing key %q", k)
		}
	}
	for k := range kv {
		if !slices.Contains(keys, k) {
			return fmt.Errorf("unknown key %q", k)
		}
	}
	return nil
}
