// bus_test.go: opening the session bus and claiming the instance name (requirements 1.2,
// 1.5), on a private dbus-daemon from snitest. The tests point Open at that bus through
// DBUS_SESSION_BUS_ADDRESS, so they never touch the developer's session and cannot run in
// parallel (t.Setenv).
package sni

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/godbus/dbus/v5"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/sni/snitest"
)

// privateBus starts a private bus and makes it the session bus for this test.
func privateBus(t *testing.T) string {
	t.Helper()
	addr := snitest.Start(t)
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", addr)
	return addr
}

func openBus(t *testing.T) *Bus {
	t.Helper()
	b, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(b.Close)
	return b
}

func TestOpenConnectsToThePrivateSessionBus(t *testing.T) {
	privateBus(t)
	openBus(t)
}

func TestOpenWithAnUnreachableBusSaysThereIsNoDesktopSession(t *testing.T) {
	gone := filepath.Join(t.TempDir(), "no-bus")
	t.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path="+gone)
	b, err := Open()
	if err == nil {
		b.Close()
		t.Fatal("Open succeeded without a bus")
	}
	if !errors.Is(err, errNoSession) || !strings.Contains(err.Error(), "no desktop session") {
		t.Fatalf("err = %v, want the no-session error", err)
	}
	if strings.Contains(err.Error(), "\n") {
		t.Fatalf("err = %q, want one line", err)
	}
}

func TestClaimTakesTheInstanceName(t *testing.T) {
	addr := privateBus(t)
	b := openBus(t)
	if err := b.Claim(); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	var owner string
	raw := snitest.Conn(t, addr)
	if err := raw.BusObject().Call("org.freedesktop.DBus.GetNameOwner", 0, instanceName).Store(&owner); err != nil {
		t.Fatalf("GetNameOwner: %v", err)
	}
	if owner != b.conn.Names()[0] {
		t.Fatalf("owner = %q, want this bus %q", owner, b.conn.Names()[0])
	}
}

// A bus that accepts the connection and never answers must not hang Open.
func TestHandshakeGivesUpOnASilentBus(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "silent")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	conn, err := dbus.Dial("unix:path=" + sock)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	start := time.Now()
	err = handshake(conn, 100*time.Millisecond)
	if err == nil || !strings.Contains(err.Error(), "did not answer") {
		t.Fatalf("handshake = %v, want a timeout", err)
	}
	if time.Since(start) > time.Second {
		t.Fatalf("handshake took %v", time.Since(start))
	}
}

func TestSecondClaimNamesTheRunningOnesPid(t *testing.T) {
	privateBus(t)
	if err := openBus(t).Claim(); err != nil {
		t.Fatalf("first Claim: %v", err)
	}
	err := openBus(t).Claim()
	want := fmt.Sprintf("already running (pid %d)", os.Getpid())
	if err == nil || err.Error() != want {
		t.Fatalf("second Claim = %v, want %q", err, want)
	}
}

func TestClaimFailsWhenAnotherConnectionOwnsTheName(t *testing.T) {
	addr := privateBus(t)
	raw := snitest.Conn(t, addr)
	reply, err := raw.RequestName(instanceName, dbus.NameFlagDoNotQueue)
	if err != nil || reply != dbus.RequestNameReplyPrimaryOwner {
		t.Fatalf("raw RequestName = %v, %v", reply, err)
	}
	err = openBus(t).Claim()
	if err == nil || !strings.HasPrefix(err.Error(), "already running (pid ") {
		t.Fatalf("Claim = %v, want already running", err)
	}
}

func TestClaimAfterCloseIsAContractViolation(t *testing.T) {
	privateBus(t)
	b, err := Open()
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	b.Close()
	b.Close() // twice is harmless: Close sits in defers and on several exit paths
	defer wantViolation(t)
	_ = b.Claim()
}

func TestClaimOnANilBusIsAContractViolation(t *testing.T) {
	defer wantViolation(t)
	var b *Bus
	_ = b.Claim()
}

func wantViolation(t *testing.T) {
	t.Helper()
	v, ok := recover().(*contract.Violation)
	if !ok || v.Kind != contract.Precondition {
		t.Fatalf("panic = %v, want a precondition violation", v)
	}
}
