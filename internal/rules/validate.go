package rules

import (
	"fmt"
	"net/netip"

	"github.com/norandom/snitch/internal/contract"
)

// validate applies the cross-record rules and assigns ids in declaration order. Value-level
// checks (prefix, proto, ports, verdict) already happened in convertRule.
func validate(f *File, name string) error {
	seen := make(map[string]int, len(f.Programs))
	for i := range f.Programs {
		p := &f.Programs[i]
		if err := checkProgramName(p.Name, seen); err != nil {
			return &Error{File: name, Line: p.Line, Msg: err.Error()}
		}
		seen[p.Name] = p.Line
		p.ID = uint32(i + 1)
	}
	for i := range f.Rules {
		r := &f.Rules[i]
		if _, ok := seen[r.Program]; !ok && r.Program != AnyProgram {
			return &Error{File: name, Line: r.Line, Msg: fmt.Sprintf("rule for undeclared program %q", r.Program)}
		}
		r.ID = uint32(i + 1)
	}
	if err := checkDuplicateKeys(f, name); err != nil {
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

// checkDuplicateKeys expands each rule the way the encoder does (any proto with ports → tcp
// and udp) and rejects a key declared twice, naming both rules.
func checkDuplicateKeys(f *File, name string) error {
	seen := map[ruleKey]int{}
	for i := range f.Rules {
		r := &f.Rules[i]
		for _, proto := range protosOf(r) {
			for _, port := range portsOf(r) {
				k := ruleKey{r.Program, r.To, proto, port}
				if line, dup := seen[k]; dup {
					return &Error{File: name, Line: r.Line, Msg: fmt.Sprintf("rule duplicates the rule at line %d (%s %s %s port %d)", line, r.Program, r.To, protoName(proto), port)}
				}
				seen[k] = r.Line
			}
		}
	}
	return nil
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

func checkProgramName(n string, seen map[string]int) error {
	switch {
	case n == "":
		return fmt.Errorf("program without a name")
	case n == AnyProgram:
		return fmt.Errorf("program name %q is reserved for rules that apply to every program", AnyProgram)
	}
	if line, dup := seen[n]; dup {
		return fmt.Errorf("program %q already declared at line %d", n, line)
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
