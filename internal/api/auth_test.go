package api

import (
	"testing"

	"golang.org/x/sys/unix"
)

// Req 1.3: root and the operator write, everyone else reads; operator 0 means none configured.
func TestRoleFor(t *testing.T) {
	cases := []struct {
		name     string
		cred     *unix.Ucred
		operator uint32
		want     Role
	}{
		{"root", &unix.Ucred{Uid: 0, Pid: 1}, 1000, Writer},
		{"root without operator", &unix.Ucred{Uid: 0}, 0, Writer},
		{"operator", &unix.Ucred{Uid: 1000}, 1000, Writer},
		{"other user", &unix.Ucred{Uid: 1001}, 1000, Reader},
		{"operator unset: uid 0 is root, not the operator", &unix.Ucred{Uid: 1000}, 0, Reader},
		{"unknown creds", nil, 1000, Reader},
		{"unknown creds, root operator", nil, 0, Reader},
	}
	for _, c := range cases {
		if got := RoleFor(c.cred, c.operator); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, got, c.want)
		}
	}
}

// Design "Contracts": auth.Role ensures reader for unknown creds (TestRoleUnknownIsReader).
func TestRoleUnknownIsReader(t *testing.T) {
	if RoleFor(nil, 0) != Reader || RoleFor(nil, 4294967295) != Reader {
		t.Fatal("unknown credentials must read only")
	}
	if Reader.String() != "reader" || Writer.String() != "writer" {
		t.Fatalf("role names: %s %s", Reader, Writer)
	}
}

func TestIsWrite(t *testing.T) {
	for _, typ := range []string{"trial", "keep", "unkeep", "end", "rule.add", "rule.remove"} {
		if !IsWrite(typ) {
			t.Errorf("%s is a write", typ)
		}
	}
	for _, typ := range []string{"status", "rules", "programs", "learned", "snapshot", "subscribe", "unsubscribe", "bogus", ""} {
		if IsWrite(typ) {
			t.Errorf("%s is not a write", typ)
		}
	}
}
