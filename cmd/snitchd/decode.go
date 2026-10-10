package main

import (
	"net/netip"
	"unsafe"

	"golang.org/x/sys/unix"

	snitchbpf "github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/contract"
)

// eventSize is the kernel struct's size; ring buffer records are at least that long.
const eventSize = int(unsafe.Sizeof(snitchbpf.SnitchEvent{}))

const (
	verdictAllowMonitor = 0 // no rule, monitor mode: what learning records
	hookSendmsg         = 1
)

var verdicts = [...]string{"allow (monitor)", "allow (rule)", "DENY (rule)", "DENY (default)",
	"allow (local net)", "allow (heartbeat stale)", "allow (kill switch)"}

// decodeEvent copies a ring buffer record into the generated struct (same layout as the C
// struct, host byte order), without reflection.
func decodeEvent(raw []byte) snitchbpf.SnitchEvent {
	contract.Require(len(raw) >= eventSize, "ring buffer record shorter than struct event")
	var e snitchbpf.SnitchEvent
	copy((*[eventSize]byte)(unsafe.Pointer(&e))[:], raw[:eventSize])
	return e
}

// addrOf is the destination; v4 lives in the first four bytes (the kernel already unmapped
// v4-mapped v6 addresses and set the family accordingly).
func addrOf(e *snitchbpf.SnitchEvent) netip.Addr {
	if e.Family == unix.AF_INET {
		return netip.AddrFrom4([4]byte(e.Addr[:4]))
	}
	return netip.AddrFrom16(e.Addr)
}

// pathOf is the exe path the kernel wrote, up to its NUL; the bytes after it are stale ring
// buffer memory and must not be read.
func pathOf(e *snitchbpf.SnitchEvent) string { return cstring(e.Path[:]) }

func commOf(e *snitchbpf.SnitchEvent) string { return cstring(e.Comm[:]) }

func hookName(e *snitchbpf.SnitchEvent) string {
	if e.Hook == hookSendmsg {
		return "sendmsg"
	}
	return "connect"
}

func verdictName(e *snitchbpf.SnitchEvent) string {
	if int(e.Verdict) < len(verdicts) {
		return verdicts[e.Verdict]
	}
	return "?"
}

// cstring turns a NUL-terminated C char array (int8 in Go) into a string.
func cstring(c []int8) string {
	n := 0
	for n < len(c) && c[n] != 0 {
		n++
	}
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(c[i])
	}
	return string(b)
}
