package rules

import (
	"fmt"

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
	assertDenseIDs(f)
	return nil
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
