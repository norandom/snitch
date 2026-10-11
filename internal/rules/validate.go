package rules

import (
	"fmt"
	"net/netip"

	"github.com/norandom/snitch/internal/contract"
)

// validate applies the cross-record rules and assigns ids in declaration order. Value-level
// checks (prefix, proto, ports, verdict) already happened in convertRule. Errors name the
// record's Source: after a Merge the records come from two files. declared false skips the
// undeclared-program check (an overlay on its own; Merge runs it against the union).
func validate(f *File, declared bool) error {
	seen := make(map[string]*Program, len(f.Programs))
	for i := range f.Programs {
		p := &f.Programs[i]
		if err := checkProgramName(p, seen); err != nil {
			return &Error{File: p.Source, Line: p.Line, Msg: err.Error()}
		}
		seen[p.Name] = p
		p.ID = uint32(i + 1)
	}
	for i := range f.Rules {
		r := &f.Rules[i]
		if _, ok := seen[r.Program]; declared && !ok && r.Program != anyProgram {
			return &Error{File: r.Source, Line: r.Line, Msg: fmt.Sprintf("rule for undeclared program %q", r.Program)}
		}
		r.ID = uint32(i + 1)
	}
	if err := checkDuplicateKeys(f); err != nil {
		return err
	}
	assertDenseIDs(f)
	return nil
}

// ruleKey is what two rules must not share: they would encode to the same trie entry and the
// later one would silently replace the earlier (the kernel keeps one value per key).
type ruleKey struct {
	program string
	to      netip.Prefix
	proto   Proto
	port    uint16
}

// expandedKeys lists the trie keys a rule encodes to, the way the encoder does (any proto
// with ports → tcp and udp; no ports → the any-port key).
func expandedKeys(r *Rule) []ruleKey {
	var keys []ruleKey
	for _, proto := range protosOf(r) {
		for _, port := range portsOf(r) {
			keys = append(keys, ruleKey{r.Program, r.To, proto, port})
		}
	}
	return keys
}

// checkDuplicateKeys rejects a key declared twice, naming both rules (and the other rule's
// file when it is a different one).
func checkDuplicateKeys(f *File) error {
	seen := map[ruleKey]*Rule{}
	for i := range f.Rules {
		r := &f.Rules[i]
		for _, k := range expandedKeys(r) {
			if other, dup := seen[k]; dup {
				return &Error{File: r.Source, Line: r.Line, Msg: fmt.Sprintf("rule duplicates the rule %s (%s %s %s port %d)", at(other.Source, other.Line, r.Source), r.Program, r.To, protoName(k.proto), k.port)}
			}
			seen[k] = r
		}
	}
	return nil
}

// at says where an earlier record is: "at line N", or "in <file> at line N" from another file.
func at(source string, line int, from string) string {
	if source != from {
		return fmt.Sprintf("in %s at line %d", source, line)
	}
	return fmt.Sprintf("at line %d", line)
}

func protoName(p Proto) string {
	switch p {
	case TCP:
		return "tcp"
	case UDP:
		return "udp"
	}
	return "any"
}

func checkProgramName(p *Program, seen map[string]*Program) error {
	switch {
	case p.Name == "":
		return fmt.Errorf("program without a name")
	case p.Name == anyProgram:
		return fmt.Errorf("program name %q is reserved for rules that apply to every program", anyProgram)
	}
	if other, dup := seen[p.Name]; dup {
		return fmt.Errorf("program %q already declared %s", p.Name, at(other.Source, other.Line, p.Source))
	}
	return nil
}

// assertDenseIDs is the model invariant the encoder relies on: ids are 1..n in slice order.
func assertDenseIDs(f *File) {
	for i, p := range f.Programs {
		contract.Invariant(p.ID == uint32(i+1), "program ids must be 1..n in declaration order")
	}
	for i, r := range f.Rules {
		contract.Invariant(r.ID == uint32(i+1), "rule ids must be 1..n in declaration order")
	}
}
