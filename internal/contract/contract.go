// Package contract is the code-contract fence: Require, Ensure and Invariant panic with a
// *Violation on a programming error. They are always compiled in; the checks are comparisons.
//
// A violation is a bug, never an operator error (those return error values). In snitchd a
// violation ends the process, which detaches the kernel programs: contracts fail open.
package contract

// Kind names which contract failed.
type Kind string

const (
	Precondition  Kind = "require"
	Postcondition Kind = "ensure"
	InvariantKind Kind = "invariant"
)

// Violation is the panic value of a failed contract.
type Violation struct {
	Kind Kind
	Msg  string
}

func (v *Violation) Error() string { return "contract " + string(v.Kind) + ": " + v.Msg }

// Require asserts a precondition on the inputs of a function.
func Require(ok bool, msg string) { check(ok, Precondition, msg) }

// Ensure asserts a postcondition on a result before it is returned.
func Ensure(ok bool, msg string) { check(ok, Postcondition, msg) }

// Invariant asserts a property of a data structure, after it is built or changed.
func Invariant(ok bool, msg string) { check(ok, InvariantKind, msg) }

func check(ok bool, kind Kind, msg string) {
	if !ok {
		panic(&Violation{Kind: kind, Msg: msg})
	}
}
