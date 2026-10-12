// Apply tests protect file ownership, including deletion and the postcondition fence.
package dns

import (
	"net/netip"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/rules"
)

func TestContractApplyNeverTouchesFileKeys(t *testing.T) {
	var c Compiled
	addr := netip.MustParseAddr("192.0.2.1")
	want := c.Compute(compilerRules(nameRule(1, 0)), addr, []string{"example.com"})
	file := map[rules.RuleKey]rules.RuleVal{}
	for k := range want {
		file[k] = rules.RuleVal{Verdict: uint8(rules.Deny), Id: 99}
	}
	puts, dels := c.Apply(addr, want, file)
	if len(puts)+len(dels)+c.Len() != 0 {
		t.Fatalf("file key retained: %v %v len=%d", puts, dels, c.Len())
	}
	c.Apply(addr, want, nil)
	puts, dels = c.Apply(addr, nil, file)
	if len(puts)+len(dels)+c.Len() != 0 {
		t.Fatalf("file key deleted: %v %v len=%d", puts, dels, c.Len())
	}
	// The output checker is also exercised with impossible outputs to prove the Ensure exists.
	contracttest.Panics(t, contract.Postcondition, func() { compiledOutputs(file, nil, file) })
	for k := range file {
		contracttest.Panics(t, contract.Postcondition, func() { compiledOutputs(nil, []rules.RuleKey{k}, file) })
	}
}

func TestApplyDiffAndNameOf(t *testing.T) {
	var c Compiled
	addr := netip.MustParseAddr("192.0.2.1")
	want := c.Compute(compilerRules(nameRule(1, 0)), addr, []string{"api.example.com"})
	puts, dels := c.Apply(addr, want, nil)
	compiledLengths(t, puts, dels, &c, 1, 0, 1)
	puts, dels = c.Apply(addr, want, nil)
	if len(puts)+len(dels) != 0 {
		t.Fatal(puts, dels)
	}
	for k := range want {
		want[k] = Entry{ID: 2, Name: "example.com"}
	}
	puts, _ = c.Apply(addr, want, nil)
	if len(puts) != 1 {
		t.Fatal(puts)
	}
	if name, ok := c.NameOf(addr, 2); !ok || name != "example.com" {
		t.Fatal(name, ok)
	}
	if _, ok := c.NameOf(addr, 1); ok {
		t.Fatal("stale id")
	}
	// A caller's later mutation cannot change the retained snapshot.
	clear(want)
	if c.Len() != 1 {
		t.Fatal(c.Len())
	}
	_, dels = c.Apply(addr, nil, nil)
	compiledLengths(t, nil, dels, &c, 0, 1, 0)
	if _, ok := c.NameOf(addr, 2); ok {
		t.Fatal("removed address")
	}
	if Max != 16384 {
		t.Fatal(Max)
	}
}

func compiledLengths(t *testing.T, puts map[rules.RuleKey]rules.RuleVal, dels []rules.RuleKey, c *Compiled, p, d, n int) {
	t.Helper()
	if len(puts) != p || len(dels) != d || c.Len() != n {
		t.Fatalf("lengths = %d/%d/%d; want %d/%d/%d", len(puts), len(dels), c.Len(), p, d, n)
	}
}

func TestCompiledInvariantRejectsDeny(t *testing.T) {
	puts := map[rules.RuleKey]rules.RuleVal{{}: {Verdict: uint8(rules.Deny)}}
	contracttest.Panics(t, contract.InvariantKind, func() { compiledOutputs(puts, nil, nil) })
}

func TestApplyKeepsOtherAddresses(t *testing.T) {
	var c Compiled
	res := compilerRules(nameRule(1, 0))
	a, b := netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("192.0.2.2")
	c.Apply(a, c.Compute(res, a, []string{"example.com"}), nil)
	c.Apply(b, c.Compute(res, b, []string{"api.example.com"}), nil)
	puts, dels := c.Apply(a, nil, nil)
	compiledLengths(t, puts, dels, &c, 0, 1, 1)
	if name, ok := c.NameOf(b, 1); !ok || name != "api.example.com" {
		t.Fatal(name, ok)
	}
}
