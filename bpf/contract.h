// contract.h: build-time and runtime contracts for the kernel programs.
//
// Build-time forms (C11 _Static_assert, no code emitted):
//   CONTRACT_SIZE(type, bytes)            sizeof(type) == bytes
//   CONTRACT_OFFSET(type, member, bytes)  offset of member in type == bytes
//   CONTRACT_CONST(expr, msg)             a relation of constants holds; msg is a string literal
// They pin the layouts shared with the daemon and the relations the bounded walks rely on,
// so a change that would corrupt a shared structure fails the generation of the bindings
// instead of reaching a running system. Each message names the type, member or relation it
// guards, so the failing build says which contract broke.
//
// Runtime form:
//   CONTRACT(cond, on_violation)          1 if cond holds; otherwise runs on_violation, 0
// cond is evaluated exactly once. Precondition: on_violation is a counter increment and has
// no other effect. CONTRACT never returns from the enclosing function and never decides: the
// call site writes the fail-safe branch (allow for egress, pass for the DNS tap), so a
// violated contract resolves to the fail-open outcome there, visible in review, and is
// counted. Returning from inside a macro would hide that verdict and skip releases the
// verifier tracks (the exe file reference in the LSM hook).
//
// No includes: the BPF build has no <stddef.h>, hence __builtin_offsetof. Valid C11, so a
// host compiler and cppcheck read it as well.
#ifndef SNITCH_CONTRACT_H
#define SNITCH_CONTRACT_H

#define CONTRACT_SIZE(type, bytes)                                                         \
	_Static_assert(sizeof(type) == (bytes), "contract: sizeof(" #type ") == " #bytes)

#define CONTRACT_OFFSET(type, member, bytes)                                               \
	_Static_assert(__builtin_offsetof(type, member) == (bytes),                         \
		       "contract: offsetof(" #type ", " #member ") == " #bytes)

#define CONTRACT_CONST(expr, msg) _Static_assert(expr, "contract: " msg ": " #expr)

// A conditional expression, not a statement expression: plain C11, one evaluation of cond,
// and the violation branch's value is discarded so a void counter call is accepted.
#define CONTRACT(cond, on_violation) ((cond) ? 1 : ((void)(on_violation), 0))

#endif // SNITCH_CONTRACT_H
