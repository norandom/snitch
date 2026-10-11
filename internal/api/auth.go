// auth.go: the client's role from the kernel's peer credentials (SO_PEERCRED). Root and the
// configured operator write; everyone else, and a peer whose credentials could not be read,
// only reads. Decided once per connection, never by a token.
package api

import (
	"github.com/norandom/snitch/internal/contract"
	"golang.org/x/sys/unix"
)

// Role is what a connection may do.
type Role int

const (
	Reader Role = iota // status, rules, programs, learned, snapshot, subscribe, unsubscribe
	Writer             // the above plus the trial verbs and rule edits
)

func (r Role) String() string {
	if r == Writer {
		return "writer"
	}
	return "reader"
}

// RoleFor decides the role: uid 0 or the operator uid write. operator 0 means none is
// configured (root is a writer regardless). A nil cred (getsockopt failed) is a reader.
func RoleFor(cred *unix.Ucred, operator uint32) Role {
	role := Reader
	if cred != nil && (cred.Uid == 0 || (operator != 0 && cred.Uid == operator)) {
		role = Writer
	}
	contract.Ensure(cred != nil || role == Reader, "unknown peer credentials must read only")
	return role
}

// writes is the set of request types that need a Writer (design "Decision table").
var writes = map[string]bool{"trial": true, "keep": true, "unkeep": true, "end": true,
	"rule.add": true, "rule.remove": true}

// IsWrite reports whether a request type is in the write set.
func IsWrite(typ string) bool { return writes[typ] }
