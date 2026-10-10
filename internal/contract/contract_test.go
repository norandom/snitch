package contract_test

import (
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

func TestRequireFailsAsPrecondition(t *testing.T) {
	v := contracttest.Panics(t, contract.Precondition, func() { contract.Require(1 > 2, "one exceeds two") })
	if v.Msg != "one exceeds two" || v.Error() != "contract require: one exceeds two" {
		t.Fatalf("message lost: %q / %q", v.Msg, v.Error())
	}
}

func TestEnsureFailsAsPostcondition(t *testing.T) {
	contracttest.Panics(t, contract.Postcondition, func() { contract.Ensure(false, "result empty") })
}

func TestInvariantFailsAsInvariant(t *testing.T) {
	contracttest.Panics(t, contract.InvariantKind, func() { contract.Invariant(false, "ids not dense") })
}

func TestSatisfiedContractsAreSilent(t *testing.T) {
	contract.Require(true, "")
	contract.Ensure(true, "")
	contract.Invariant(true, "")
}

// fakeTB records a Fatalf instead of ending the test; the sentinel panic stops the helper
// where runtime.Goexit would have.
type fakeTB struct {
	testing.TB
	failed bool
}

type stop struct{}

func (f *fakeTB) Helper()               {}
func (f *fakeTB) Fatalf(string, ...any) { f.failed = true; panic(stop{}) }
func (f *fakeTB) Failed() bool          { return f.failed }
func runHelper(fake *fakeTB, kind contract.Kind, fn func()) {
	defer func() {
		if r := recover(); r != nil {
			if _, ok := r.(stop); !ok {
				panic(r)
			}
		}
	}()
	contracttest.Panics(fake, kind, fn)
}

func TestHelperFailsWhenNothingPanics(t *testing.T) {
	fake := &fakeTB{}
	runHelper(fake, contract.Precondition, func() {})
	if !fake.Failed() {
		t.Fatal("helper accepted a function that returned normally")
	}
}

func TestHelperFailsOnTheWrongKind(t *testing.T) {
	fake := &fakeTB{}
	runHelper(fake, contract.Postcondition, func() { contract.Require(false, "x") })
	if !fake.Failed() {
		t.Fatal("helper accepted a require violation as an ensure violation")
	}
}

func TestHelperLetsOtherPanicsEscape(t *testing.T) {
	defer func() {
		if r := recover(); r != "boom" {
			t.Fatalf("want the original panic to escape, got %v", r)
		}
	}()
	runHelper(&fakeTB{}, contract.Precondition, func() { panic("boom") })
}
