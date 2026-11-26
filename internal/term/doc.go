// Package term is the Bubble Tea v2 and Lip Gloss v2 adapter for the snitch TUI.
//
// No other package in this module may import charm.land/...; cmd/snitch/imports_test.go
// enforces this pin so untrusted strings from the daemon cannot reach the terminal renderer
// without passing through internal/clean and internal/tui first.
//
// Fail-safe implications: none on egress. This package speaks only to the user's terminal
// and never opens BPF maps, sockets or runtime files.
package term

import (
	_ "charm.land/bubbletea/v2"
	_ "charm.land/lipgloss/v2"
)
