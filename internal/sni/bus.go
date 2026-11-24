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

// Owner answers who owns the well-known name right now. An absent name is a
// normal state of a session (no system tray yet, no notification service), not
// an error; only a transport failure is. This and WatchOwner are the whole name
// owner facility: the item watches the tray watcher with it (4.2) and the
// notifications side watches its service the same way (4.4).
func (b *Bus) Owner(name string) (owner string, owned bool, err error) {
	var who string
	err = b.call("org.freedesktop.DBus.GetNameOwner", name).Store(&who)
	if err == nil {
		return who, true, nil
	}
	var derr dbus.Error
	if errors.As(err, &derr) && derr.Name == "org.freedesktop.DBus.Error.NameHasNoOwner" {
		return "", false, nil
	}
	return "", false, fmt.Errorf("owner of %s: %w", name, err)
}

// WatchOwner reports every ownership change of the well-known name on the
// returned channel: the new owner's unique name, or the empty string when the
// name was released. The channel closes when this connection loses the bus, so
// a watcher loop reads it until the bus is gone. The NameOwnerChanged delivery
// is the bus daemon's own signal, so nothing here polls.
func (b *Bus) WatchOwner(name string) (<-chan string, error) {
	contract.Require(b != nil && b.conn != nil, "sni: WatchOwner on a nil bus")
	contract.Require(!b.closed.Load(), "sni: WatchOwner on a closed bus")
	in := make(chan *dbus.Signal, 16)
	b.conn.Signal(in)
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()
	err := b.conn.AddMatchSignalContext(ctx,
		dbus.WithMatchInterface("org.freedesktop.DBus"),
		dbus.WithMatchMember("NameOwnerChanged"),
		dbus.WithMatchArg(0, name))
	if err != nil {
		b.conn.RemoveSignal(in)
		return nil, fmt.Errorf("watch the owner of %s: %w", name, err)
	}
	out := make(chan string, 8)
	go forwardOwners(in, out, name)
	return out, nil
}

// forwardOwners narrows the signal stream to the ownership changes of one name
// (every channel of the connection sees every matched signal) and ends with its
// input: the bus closing closes in, then out, which is the loss a watcher loop
// reports. Buffered, because a full channel hands each signal to a goroutine
// of its own, which can reorder them.
func forwardOwners(in <-chan *dbus.Signal, out chan<- string, name string) {
	defer close(out)
	for sig := range in {
		if sig.Name != "org.freedesktop.DBus.NameOwnerChanged" || len(sig.Body) < 3 {
			continue
		}
		if n, _ := sig.Body[0].(string); n != name {
			continue
		}
		if owner, ok := sig.Body[2].(string); ok {
			out <- owner
		}
	}
}
