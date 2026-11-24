// trayend_test.go: the contract of the wiring's end (design, Binary: the exit
// table). trayEnd maps only the ends the design names — the loop's nil, the
// adapter's ErrBusLost — and any other end is a wiring bug that panics as a
// contract violation, which main turns into exit 70 with the stack on stderr.
// The check is direct: no run can be driven to an unnamed end, so the guard is
// tripped with an error nobody names, the same honesty as snitchd's version
// checks.
package main

import (
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// The unnamed end is an Invariant (the state machine of exits cannot produce
// it), not a Require: the error value itself is legal, only a wiring that lets
// one through is not.
func TestTrayEndUnknownEndIsAContractViolation(t *testing.T) {
	cfg := trayConfig{stderr: io.Discard}
	v := contracttest.Panics(t, contract.InvariantKind,
		func() { trayEnd(cfg, nil, errors.New("launched itself to the moon")) })
	if !strings.Contains(v.Msg, "the run ended in a way the design does not name") {
		t.Fatalf("want the violation to name the unnamed end, got: %s", v.Msg)
	}
}
