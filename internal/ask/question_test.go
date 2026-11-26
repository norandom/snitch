// question_test.go: the seven verdicts in both scopes, each local prefix (IPv4, IPv6,
// IPv4-mapped), an unparsable address, and the key forms.
package ask

import (
	"net/netip"
	"testing"

	"github.com/norandom/snitch/internal/api"
)

func event(verdict, addr string) api.Event {
	return api.Event{Type: "event", Program: "firefox", Path: "/usr/lib/firefox/firefox",
		Addr: addr, Port: 443, Protocol: "tcp", Verdict: verdict}
}

func TestFromVerdictsAndScopes(t *testing.T) {
	cases := []struct {
		verdict      string
		all, enforce bool
		blocked      bool
	}{
		{"deny-default", true, true, true},
		{"allow-monitor", true, false, false},
		{"allow-local", false, false, false},
		{"allow-rule", false, false, false},
		{"deny-rule", false, false, false},
		{"allow-stale", false, false, false},
		{"allow-kill", false, false, false},
	}
	for _, c := range cases {
		for _, s := range []struct {
			scope Scope
			want  bool
		}{{All, c.all}, {Enforce, c.enforce}} {
			ev := event(c.verdict, "140.82.112.5")
			q, ok := From(ev, s.scope)
			if ok != s.want {
				t.Fatalf("%s scope %d: ok %v, want %v", c.verdict, s.scope, ok, s.want)
			}
			if !ok {
				if q != (Question{}) {
					t.Fatalf("%s scope %d: question %+v without ok", c.verdict, s.scope, q)
				}
				continue
			}
			if q.Blocked != c.blocked || q.Event != ev || q.Key != keyOf(ev) {
				t.Fatalf("%s scope %d: %+v", c.verdict, s.scope, q)
			}
		}
	}
}

func TestLocalPrefixes(t *testing.T) {
	locals := []string{
		"10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.1.1",
		"169.254.1.1", "127.0.0.1", "127.1.2.3", "fc00::1", "fdff::1", "fe80::1", "fe80::1%eth0",
		"febf::1", "::1", "::ffff:10.0.0.1", "::ffff:172.16.5.5", "::ffff:192.168.0.1",
		"::ffff:169.254.0.1", "::ffff:127.0.0.1",
	}
	remote := []string{
		"9.255.255.255", "11.0.0.1", "172.15.255.255", "172.32.0.1", "192.167.255.255",
		"192.169.0.1", "169.253.0.1", "128.0.0.1", "0.0.0.1", "8.8.8.8", "fbff::1", "fec0::1",
		"::2", "2001:db8::1", "::ffff:8.8.8.8", "::ffff:172.32.0.1",
	}
	for _, s := range locals {
		if !local(netip.MustParseAddr(s)) {
			t.Fatalf("%s: not local", s)
		}
		for _, v := range []string{"deny-default", "allow-monitor"} {
			if _, ok := From(event(v, s), All); ok {
				t.Fatalf("%s %s: asks", v, s)
			}
		}
	}
	for _, s := range remote {
		if local(netip.MustParseAddr(s)) {
			t.Fatalf("%s: local", s)
		}
		if _, ok := From(event("deny-default", s), All); !ok {
			t.Fatalf("%s: does not ask", s)
		}
	}
}

func TestFromUnparsableAddress(t *testing.T) {
	for _, s := range []string{"", "nonsense", "10.0.0.0/8", "300.1.1.1"} {
		if _, ok := From(event("deny-default", s), All); ok {
			t.Fatalf("%q: asks", s)
		}
	}
}

func TestKeyForms(t *testing.T) {
	named := event("deny-default", "140.82.112.5")
	named.Name = "api.github.com"
	unknown := event("allow-monitor", "2001:db8::1")
	unknown.Program, unknown.Path, unknown.Protocol, unknown.Port = "unknown", "/opt/x/bin/x", "udp", 53
	cases := []struct {
		ev   api.Event
		want Key
	}{
		{event("deny-default", "140.82.112.5"), Key{"firefox", "140.82.112.5", "tcp", 443}},
		{named, Key{"firefox", "api.github.com", "tcp", 443}},
		{unknown, Key{"/opt/x/bin/x", "2001:db8::1", "udp", 53}},
	}
	for _, c := range cases {
		if got := keyOf(c.ev); got != c.want {
			t.Fatalf("key %+v, want %+v", got, c.want)
		}
		q, ok := From(c.ev, All)
		if !ok || q.Key != c.want {
			t.Fatalf("From key %+v ok %v, want %+v", q.Key, ok, c.want)
		}
	}
	// Two addresses behind one name share a key: one question per program and name.
	other := named
	other.Addr = "140.82.112.6"
	if keyOf(other) != keyOf(named) {
		t.Fatal("same name, different key")
	}
}

func TestLocal(t *testing.T) {
	locals := []string{
		"10.0.0.0", "10.255.255.255", "172.16.0.0", "172.31.255.255",
		"192.168.0.0", "192.168.255.255", "169.254.0.0", "169.254.255.255",
		"127.0.0.0", "127.255.255.255", "fc00::", "fdff::1",
		"fe80::", "fe80::1%eth0", "febf::1", "::1", "::1%lo",
		"::ffff:10.0.0.1", "::ffff:172.16.0.1", "::ffff:192.168.1.1",
		"::ffff:169.254.1.1", "::ffff:127.0.0.1",
	}
	remote := []string{
		"9.255.255.255", "11.0.0.0", "172.15.255.255", "172.32.0.0",
		"192.167.255.255", "192.169.0.0", "169.253.255.255", "169.255.0.0",
		"126.255.255.255", "128.0.0.0", "fbff::1", "fe00::", "fe7f::1", "fec0::",
		"::", "::2", "2001:db8::1", "::ffff:8.8.8.8", "::ffff:172.32.0.1",
	}
	for _, s := range locals {
		if !Local(netip.MustParseAddr(s)) {
			t.Fatalf("%s: Local = false, want true", s)
		}
	}
	for _, s := range remote {
		if Local(netip.MustParseAddr(s)) {
			t.Fatalf("%s: Local = true, want false", s)
		}
	}
	if Local(netip.Addr{}) {
		t.Fatal("zero Addr: Local = true, want false")
	}
}
