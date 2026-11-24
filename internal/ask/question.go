// Package ask is the tray's question policy, pure: which kernel event becomes a question, the
// key that dedupes questions, the waiting list (queue.go) and the rule.add request an answer
// stands for (rule.go). It has no clock of its own; every function that needs time takes now.
//
// question.go: From turns an event into a question. Only the two verdicts no rule decided ask
// (deny-default, allow-monitor; 5.1, 5.2, 5.3), and with the enforce-only scope only
// deny-default (5.9). The key is who, destination, protocol and port (5.4), the destination by
// name when the event has one (research.md "one question per program and name").
//
// Fail-safe implications: a question can lead to a rule, so a destination on the local network
// never asks (fail-safe 2, 8.3), even though the kernel allows those before any rule and never
// reports them with these verdicts: defence in depth. An address that does not parse asks
// nothing. Only egress events reach this code (fail-safe 1); nothing here writes.
package ask

import (
	"net/netip"

	"github.com/norandom/snitch/internal/api"
)

// Scope says which verdicts ask: All asks about deny-default and allow-monitor, Enforce only
// about deny-default (the tray started with questions in monitor mode switched off, 5.9).
type Scope int

const (
	All Scope = iota
	Enforce
)

// Unknown is the program name the daemon reports for an executable no rule declares.
const Unknown = "unknown"

// Key identifies a question for dedupe: who (program, or path for an unknown program),
// destination (name, else address), protocol and port.
type Key struct {
	Who, Dest, Proto string
	Port             uint16
}

// Question is one connection to ask about. Blocked is true for deny-default (the connection
// was blocked) and false for allow-monitor (allowed, not yet decided on).
type Question struct {
	Key     Key
	Event   api.Event
	Blocked bool
}

// localPrefixes are fail-safe 2's prefixes; the kernel allows them before any rule.
var localPrefixes = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("::1/128"),
}

// From returns the question an event stands for, or false when it asks nothing.
func From(ev api.Event, scope Scope) (Question, bool) {
	blocked, ok := asks(ev.Verdict, scope)
	if !ok {
		return Question{}, false
	}
	addr, err := netip.ParseAddr(ev.Addr)
	if err != nil || local(addr) {
		return Question{}, false
	}
	return Question{Key: keyOf(ev), Event: ev, Blocked: blocked}, true
}

// asks reports whether a verdict asks in a scope and whether it means blocked.
func asks(verdict string, scope Scope) (blocked, ok bool) {
	switch verdict {
	case "deny-default":
		return true, true
	case "allow-monitor":
		return false, scope == All
	}
	return false, false
}

// local reports whether an address is on the local network of fail-safe 2. An IPv4-mapped
// IPv6 address is judged by its IPv4 form; the zone of a link-local address is ignored.
func local(addr netip.Addr) bool {
	addr = addr.Unmap().WithZone("")
	for _, p := range localPrefixes {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// keyOf is the dedupe key of an event.
func keyOf(ev api.Event) Key {
	who := ev.Program
	if who == Unknown {
		who = ev.Path
	}
	dest := ev.Name
	if dest == "" {
		dest = ev.Addr
	}
	return Key{Who: who, Dest: dest, Proto: ev.Protocol, Port: ev.Port}
}
