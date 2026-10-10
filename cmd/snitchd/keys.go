package main

import (
	snitchbpf "github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/rules"
)

// exeKey is the kernel's programs-map key for a resolved executable (the pad is zero).
func exeKey(k rules.ExeKey) snitchbpf.SnitchExeKey {
	return snitchbpf.SnitchExeKey{Ino: k.Ino, Dev: k.Dev}
}
