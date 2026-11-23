// Package sni is the only code of the snitch binary that speaks D-Bus: the session bus, the
// instance name, and (later tasks) the tray item, its menu and the notifications.
//
// bus.go: opening the session bus and claiming the instance name (requirements 1.2, 1.5).
// Fail-safe implications: none on egress. The tray only ever talks to the user's session bus,
// never the system bus, so nothing here can reach the daemon's kernel state; a missing bus is
// an operator error ("no desktop session") and a second tray is refused by the bus daemon's
// name ownership, not by a lock file that a crash could leave behind.
package sni

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/norandom/snitch/internal/contract"
)

// InstanceName is the well-known name one tray per session owns (research.md, "single
// instance by a bus name"). The bus daemon drops it when the process dies.
const InstanceName = "io.github.norandom.snitch.Tray"

// callTimeout bounds every call on the bus, so a wedged session bus cannot hang the tray.
const callTimeout = 2 * time.Second

// ErrNoSession is wrapped by Open's error when no session bus is reachable.
var ErrNoSession = errors.New("no desktop session")

// Bus is a private connection to the session bus, owned by this process.
type Bus struct {
	conn   *dbus.Conn
	closed atomic.Bool
}

// Open connects to the session bus named by DBUS_SESSION_BUS_ADDRESS (or godbus's usual
// discovery of /run/user/<uid>/bus). It never launches a bus and never uses the system bus.
func Open() (*Bus, error) {
	// NoAutoStartup: the other session constructors run dbus-launch when no address is
	// found, which would conjure a bus no desktop listens on instead of saying there is none.
	conn, err := dbus.SessionBusPrivateNoAutoStartup()
	if err != nil {
		return nil, noSession(err)
	}
	if err := handshake(conn, callTimeout); err != nil {
		_ = conn.Close()
		return nil, noSession(err)
	}
	return &Bus{conn: conn}, nil
}

// handshake authenticates and says Hello. Neither godbus call takes a context, so a timer
// closes the connection when the bus does not answer in time, which unblocks both.
func handshake(conn *dbus.Conn, limit time.Duration) error {
	timer := time.AfterFunc(limit, func() { _ = conn.Close() })
	err := conn.Auth(nil)
	if err == nil {
		err = conn.Hello()
	}
	if !timer.Stop() {
		return fmt.Errorf("the session bus did not answer within %v", limit)
	}
	return err
}

func noSession(err error) error {
	return fmt.Errorf("%w (session bus: %v)", ErrNoSession, err)
}

// Claim requests the instance name without queueing. When another tray owns it, the error
// is "already running (pid N)" with the owner's pid as the bus daemon knows it.
func (b *Bus) Claim() error {
	contract.Require(b != nil && b.conn != nil, "sni: Claim on a nil bus")
	contract.Require(!b.closed.Load(), "sni: Claim on a closed bus")
	var reply uint32
	err := b.call("org.freedesktop.DBus.RequestName", InstanceName, uint32(dbus.NameFlagDoNotQueue)).Store(&reply)
	if err != nil {
		return fmt.Errorf("claim %s: %w", InstanceName, err)
	}
	switch dbus.RequestNameReply(reply) {
	case dbus.RequestNameReplyPrimaryOwner, dbus.RequestNameReplyAlreadyOwner:
		return nil
	case dbus.RequestNameReplyExists:
		return b.running()
	default:
		// DoNotQueue never yields InQueue; any other reply is the bus daemon's bug, and the
		// tray must not run without the name, so it is an error, not a violation.
		return fmt.Errorf("claim %s: unexpected reply %v", InstanceName, dbus.RequestNameReply(reply))
	}
}

// running names the owner of the instance name by its pid.
func (b *Bus) running() error {
	var pid uint32
	err := b.call("org.freedesktop.DBus.GetConnectionUnixProcessID", InstanceName).Store(&pid)
	if err != nil {
		// The owner may have exited between the two calls; the refusal still stands.
		return fmt.Errorf("already running (pid unknown: %v)", err)
	}
	return fmt.Errorf("already running (pid %d)", pid)
}

// call invokes a method of the bus daemon with the call timeout.
func (b *Bus) call(method string, args ...any) *dbus.Call {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	return b.conn.BusObject().CallWithContext(ctx, method, 0, args...)
}

// Close ends the connection, which releases every name it owns. It is safe to call more than
// once and on a nil bus: it sits in defers and on several exit paths.
func (b *Bus) Close() {
	if b == nil || b.closed.Swap(true) {
		return
	}
	_ = b.conn.Close()
}
