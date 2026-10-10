package rules

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// Every documented contract has a test that trips it (design "Code contracts").

func TestContractObserveNeedsAnAddress(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { NewLearned(nil).Observe(Observation{}) })
}

func TestContractResolveNeedsACompleteFS(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { Resolve(&File{}, FS{Glob: nil}) })
}

func TestContractIDsMustBeDense(t *testing.T) {
	f := &File{Programs: []Program{{Name: "a", ID: 2}}}
	contracttest.Panics(t, contract.InvariantKind, func() { assertDenseIDs(f) })
	g := &File{Rules: []Rule{{Program: "a", ID: 1}, {Program: "a", ID: 1}}}
	contracttest.Panics(t, contract.InvariantKind, func() { assertDenseIDs(g) })
}

func TestContractResolvedIsConsistent(t *testing.T) {
	r := &Resolved{File: &File{}, Programs: map[ExeKey]uint32{{Ino: 1}: 7}, Names: map[uint32]string{}, ByID: map[uint32]*Rule{}}
	contracttest.Panics(t, contract.InvariantKind, func() { r.assertConsistent() })
	ok := &Resolved{File: &File{Rules: []Rule{{ID: 1}}}, Programs: map[ExeKey]uint32{}, Names: map[uint32]string{}, ByID: map[uint32]*Rule{}}
	contracttest.Panics(t, contract.Postcondition, func() { ok.assertConsistent() })
}

func TestContractEncodeRejectsAnUndeclaredProgram(t *testing.T) {
	f, err := Parse(strings.NewReader("[[program]]\nname = \"a\"\npaths = []\n\n[[rule]]\nprogram = \"a\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\n"), "t")
	if err != nil {
		t.Fatal(err)
	}
	r := &Resolved{File: f, Programs: map[ExeKey]uint32{}, Names: map[uint32]string{}, ByID: map[uint32]*Rule{}}
	f.Rules[0].Program = "ghost" // validation would never let this through; the encoder's invariant must
	contracttest.Panics(t, contract.InvariantKind, func() { Encode(r) })
	_ = netip.Addr{}
}
