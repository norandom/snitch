// hook.go: the stand-in's kernel hook status: SetHook and the `hook` script command.
//
// Fail-safe implications: none. Changes only the stand-in's in-memory Status.Hook; never
// reads /sys, /boot, or any host state.
package clienttest

import (
	"errors"
	"fmt"

	"github.com/norandom/snitch/internal/api"
)

var hookStates = map[string]*api.HookStatus{
	"active": {
		State:  api.HookActive,
		Reason: "kernel hook active",
	},
	"inactive": {
		State:  api.HookInactive,
		Reason: "kernel hook inactive: bpf is not in the kernel's LSM list and the next boot is not configured for it; connections are neither seen nor blocked",
	},
	"pending": {
		State:   api.HookInactive,
		Pending: true,
		Reason:  "kernel hook inactive: reboot to activate it; until then connections are neither seen nor blocked",
	},
	"unknown": {
		State:  api.HookUnknown,
		Reason: "kernel hook not checked: the kernel's LSM list could not be read",
	},
	"none": nil,
}

// SetHook updates the stand-in's reported kernel hook status without sending a state line;
// nil clears it to "not reported". A non-nil value is cloned so caller mutations cannot race.
func (s *StandIn) SetHook(h *api.HookStatus) {
	var cp *api.HookStatus
	if h != nil {
		v := *h
		cp = &v
	}
	s.change(func(st *api.Status) { st.Hook = cp })
}

func cmdHook(s *StandIn, args []string) error {
	if len(args) != 1 {
		return errors.New("want hook active|inactive|pending|unknown|none")
	}
	h, ok := hookStates[args[0]]
	if !ok {
		return fmt.Errorf("hook %q: want active, inactive, pending, unknown, or none", args[0])
	}
	s.SetHook(h)
	return nil
}
