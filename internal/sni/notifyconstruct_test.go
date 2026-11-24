// notifyconstruct_test.go: the constructor contracts of the notification side,
// which notify_test.go could no longer take (its file sits at the line cap) and
// which Tray's identical guards front on the public path. notify is an internal
// step of the composition, so the panics are tripped directly here, like
// ItemConstructorContracts does for its constructor.
//
// Fail-safe implications: none. Each case only proves the guards of a
// programming error; nothing here touches a bus, real or fake.
package sni

import (
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// Precondition: the notification side needs what every constructor needs — a
// live bus and the two delegates. A violation is a wiring error of the
// composition, never an operator's error.
func TestNotificationsConstructorContracts(t *testing.T) {
	privateBus(t)
	b := openBus(t)
	var nilBus *Bus
	var sink func(any)
	var log func(string)
	contracttest.Panics(t, contract.Precondition, func() { _, _ = nilBus.notify(sink, log) })
	contracttest.Panics(t, contract.Precondition, func() { _, _ = b.notify(nil, log) })
	contracttest.Panics(t, contract.Precondition, func() { _, _ = b.notify(sink, nil) })
	b.Close()
	contracttest.Panics(t, contract.Precondition, func() { _, _ = b.notify(sink, log) })
}
