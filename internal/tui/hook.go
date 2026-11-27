// hook.go renders the kernel hook header tag and bottom warning/notice line from fixed
// constants so an inactive or unknown BPF LSM hook is impossible to overlook at 80x20.
//
// Fail-safe implications: none on kernel egress. Pure rendering over clean.Const
// literals; never reads Hook.Reason or touches files or sockets.
package tui

import (
	"slices"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
)

func withHookTag(m Model, l Line) Line {
	if m.status == nil || m.status.Hook == nil || m.status.Hook.State != api.HookInactive || len(l) == 0 {
		return l
	}
	return slices.Insert(slices.Clone(l), 1, Span{Text: clean.Const(" NO KERNEL HOOK |"), Style: Bad})
}

func withHookLine(m Model, lines []Line) []Line {
	if len(lines) <= 5 || m.confirm != nil || m.search != nil || m.notice != "" {
		return lines
	}
	msg, style := hookBottomNotice(m.status)
	if msg == "" {
		return lines
	}
	out := slices.Clone(lines)
	out[5] = Line{{Text: clean.Join(clean.Const(" "), msg), Style: style}}
	return out
}

func hookBottomNotice(st *api.Status) (clean.Safe, Style) {
	if st == nil || st.Hook == nil {
		return "", Plain
	}
	h := st.Hook
	switch h.State {
	case api.HookInactive:
		switch {
		case h.Unsupported:
			return clean.Const("kernel hook unavailable: kernel built without BPF LSM - snitch cannot work"), Bad
		case h.Pending:
			return clean.Const("kernel hook inactive: connections not seen or blocked - reboot to activate"), Bad
		default:
			return clean.Const("kernel hook inactive: connections not seen or blocked - boot not configured"), Bad
		}
	case api.HookUnknown:
		return clean.Const("kernel hook could not be checked"), Warn
	default:
		return "", Plain
	}
}
