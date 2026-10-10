// Package contracttest asserts in tests that a function violates a contract.
package contracttest

import (
	"errors"
	"testing"

	"github.com/norandom/snitch/internal/contract"
)

// Panics fails the test unless fn panics with a *contract.Violation of the given kind.
// It returns the violation for further assertions on its message.
func Panics(t testing.TB, kind contract.Kind, fn func()) *contract.Violation {
	t.Helper()
	v := recovered(fn)
	if v == nil {
		t.Fatalf("want a %s violation, function returned normally", kind)
	}
	if v.Kind != kind {
		t.Fatalf("want a %s violation, got %s: %s", kind, v.Kind, v.Msg)
	}
	return v
}

func recovered(fn func()) (v *contract.Violation) {
	defer func() {
		r := recover()
		if r == nil {
			return
		}
		err, ok := r.(error)
		if !ok || !errors.As(err, &v) {
			panic(r) // not a contract violation: let the test crash with the real panic
		}
	}()
	fn()
	return nil
}
