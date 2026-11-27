// hook.go handles the kernel hook inactive (Blind) state in the tray: condition
// detection, the menu's RowHook status row, and the one-shot transition note on entry.
//
// Fail-safe implications: none on kernel egress. Display and notification text only;
// untrusted Hook.Reason passes through clean.Text and no mode or rule is ever changed.
package tray

import (
	"github.com/norandom/snitch/internal/api"
)

func hookInactive(st *api.Status) bool {
	return st != nil && st.Hook != nil && st.Hook.State == api.HookInactive
}

func hookRow(st api.Status) (Row, bool) {
	if !hookInactive(&st) {
		return Row{}, false
	}
	switch {
	case st.Hook.Unsupported:
		return info(RowHook, "Kernel hook: kernel lacks BPF LSM"), true
	case st.Hook.Pending:
		return info(RowHook, "Kernel hook: reboot pending"), true
	default:
		return info(RowHook, "Kernel hook: boot not configured"), true
	}
}

func hookNote(old, cur api.Status) (Note, bool) {
	if !hookInactive(&old) && hookInactive(&cur) {
		return noteBlind(cur.Hook), true
	}
	return Note{}, false
}
