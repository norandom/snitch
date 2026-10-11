package rules

import (
	"bytes"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable"
)

// The TOML shape. Unknown keys are rejected; typed conversion happens afterwards so that
// every error can name the [[table]] line it belongs to.
type rawFile struct {
	Program []rawProgram `toml:"program"`
	Rule    []rawRule    `toml:"rule"`
}

type rawProgram struct {
	Name  string   `toml:"name"`
	Paths []string `toml:"paths"`
	Note  string   `toml:"note"`
}

type rawRule struct {
	Program string    `toml:"program"`
	To      string    `toml:"to"`
	Proto   string    `toml:"proto"`
	Port    any       `toml:"port"` // integer, "a-b", or absent
	Verdict string    `toml:"verdict"`
	Note    string    `toml:"note"`
	Count   uint64    `toml:"count"`
	First   time.Time `toml:"first"`
	Last    time.Time `toml:"last"`
}

const maxPortsPerRule = 256

// decode parses and validates; declared false defers the undeclared-program check to Merge
// (an overlay's rules name the base's programs).
func decode(src []byte, name string, declared bool) (*File, error) {
	var raw rawFile
	d := toml.NewDecoder(bytes.NewReader(src))
	d.DisallowUnknownFields()
	if err := d.Decode(&raw); err != nil {
		return nil, tomlError(err, name)
	}
	lines, err := tableLines(src)
	if err != nil {
		return nil, &Error{File: name, Msg: err.Error()}
	}
	// the inline form `program = [{...}]` decodes too but has no header lines to report
	if len(lines["program"]) != len(raw.Program) || len(lines["rule"]) != len(raw.Rule) {
		return nil, &Error{File: name, Msg: "programs and rules must be written as [[program]] and [[rule]] tables"}
	}
	f := &File{Name: name}
	for i, p := range raw.Program {
		f.Programs = append(f.Programs, Program{Name: p.Name, Paths: p.Paths, Note: p.Note, Line: lines["program"][i], Source: name})
	}
	for i, r := range raw.Rule {
		rule, err := convertRule(r, lines["rule"][i])
		if err != nil {
			return nil, &Error{File: name, Line: rule.Line, Msg: err.Error()}
		}
		rule.Source = name
		f.Rules = append(f.Rules, rule)
	}
	if err := validate(f, declared); err != nil {
		return nil, err
	}
	return f, nil
}

// tomlError turns go-toml's errors into *Error with the line of the offending token.
func tomlError(err error, name string) error {
	var strict *toml.StrictMissingError
	if errors.As(err, &strict) && len(strict.Errors) > 0 {
		e := &strict.Errors[0]
		row, _ := e.Position()
		return &Error{File: name, Line: row, Msg: "unknown key " + strings.Join(e.Key(), ".")}
	}
	var de *toml.DecodeError
	if errors.As(err, &de) {
		row, _ := de.Position()
		return &Error{File: name, Line: row, Msg: de.Error()}
	}
	return &Error{File: name, Msg: err.Error()}
}

// tableLines maps each array-table name ("program", "rule") to the header lines of its
// tables, in document order: the i-th [[rule]] header is the line of raw.Rule[i].
func tableLines(src []byte) (map[string][]int, error) {
	p := &unstable.Parser{}
	p.Reset(src)
	out := map[string][]int{}
	for p.NextExpression() {
		n := p.Expression()
		if n.Kind != unstable.ArrayTable {
			continue
		}
		key := n.Key()
		if !key.Next() {
			continue
		}
		head := string(key.Node().Data)
		out[head] = append(out[head], p.Shape(key.Node().Raw).Start.Line)
	}
	return out, p.Error()
}

func convertRule(r rawRule, line int) (Rule, error) {
	rule := Rule{Program: r.Program, Note: r.Note, Count: r.Count, First: r.First, Last: r.Last, Line: line}
	var err error
	if rule.To, err = parsePrefix(r.To); err != nil {
		return rule, err
	}
	if rule.Proto, err = parseProto(r.Proto); err != nil {
		return rule, err
	}
	if rule.Ports, err = parsePorts(r.Port); err != nil {
		return rule, err
	}
	rule.Verdict, err = parseVerdict(r.Verdict)
	return rule, err
}

// parsePrefix accepts a CIDR prefix or a bare address (a /32 or /128), canonicalised.
func parsePrefix(s string) (netip.Prefix, error) {
	if p, err := netip.ParsePrefix(s); err == nil {
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, fmt.Errorf("to %q: not an address or prefix", s)
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

func parseProto(s string) (Proto, error) {
	switch s {
	case "", "any":
		return AnyProto, nil
	case "tcp":
		return TCP, nil
	case "udp":
		return UDP, nil
	}
	return 0, fmt.Errorf("proto %q: want tcp, udp or any", s)
}

func parseVerdict(s string) (Verdict, error) {
	switch s {
	case "allow":
		return Allow, nil
	case "deny":
		return Deny, nil
	}
	return 0, fmt.Errorf("verdict %q: want allow or deny", s)
}

// parsePorts: absent = any (nil); an integer = that port; "a-b" = the inclusive range.
func parsePorts(v any) ([]uint16, error) {
	switch p := v.(type) {
	case nil:
		return nil, nil
	case int64:
		return portRange(p, p)
	case string:
		lo, hi, ok := strings.Cut(p, "-")
		a, errA := strconv.ParseInt(strings.TrimSpace(lo), 10, 64)
		b, errB := strconv.ParseInt(strings.TrimSpace(hi), 10, 64)
		if !ok || errA != nil || errB != nil {
			return nil, fmt.Errorf("port %q: want a number or a range a-b", p)
		}
		return portRange(a, b)
	}
	return nil, fmt.Errorf("port %v: want a number or a range a-b", v)
}

func portRange(lo, hi int64) ([]uint16, error) {
	if lo < 1 || hi > 65535 || lo > hi {
		return nil, fmt.Errorf("port %d-%d: want 1-65535, low before high", lo, hi)
	}
	if hi-lo+1 > maxPortsPerRule {
		return nil, fmt.Errorf("port %d-%d: a rule covers at most %d ports", lo, hi, maxPortsPerRule)
	}
	ports := make([]uint16, 0, hi-lo+1)
	for p := lo; p <= hi; p++ {
		ports = append(ports, uint16(p))
	}
	return ports, nil
}
