package main

// apievent.go converts what the daemon knows into the API's wire shapes: a kernel event into
// api.Event, the snapshot into rule and program views, the learned set into observations.
// Pure projections: nothing here touches BPF, the maps or the learned file's write cycle.

import (
	"fmt"
	"time"

	"github.com/norandom/snitch/internal/api"
	snitchbpf "github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/rules"
)

// verdictWire names the kernel's enum verdict (bpf/snitch.bpf.c) on the wire, by value.
var verdictWire = [...]string{"allow-monitor", "allow-rule", "deny-rule", "deny-default",
	"allow-local", "allow-stale", "allow-kill"}

// toEvent is the pump's conversion (Req 2.1, 2.6). The program is its configured name or
// "unknown"; the path is what the kernel wrote (unknown programs, or with the flag), else one
// /proc lookup through exe, else "". A rule reference needs a rule the snapshot knows: an id
// from a rule set a reload just replaced is no reference.
func toEvent(e *snitchbpf.SnitchEvent, snap *snapshot, exe func(uint32) string, now time.Time) api.Event {
	contract.Require(e != nil && exe != nil, "toEvent needs the event and the exe fallback")
	contract.Require(!now.IsZero(), "an event carries its time")
	name, known := programOf(e, snap, exe)
	if !known {
		name = "unknown"
	}
	path := pathOf(e)
	if path == "" {
		path = exe(e.Pid)
	}
	ev := api.Event{Type: "event", Time: now, Program: name, Path: path, Pid: e.Pid, Ppid: e.Ppid, Comm: commOf(e),
		Addr: addrOf(e).String(), Port: e.Dport, Protocol: protoWire(e.Proto), Verdict: verdictWireOf(e.Verdict),
		Hook: hookName(e), Cookie: e.Cookie}
	if r := ruleOf(e, snap); r != nil {
		ev.Rule = &api.RuleRef{Id: int(r.ID), Note: r.Note, Source: r.Source}
	}
	return ev
}

func verdictWireOf(v uint8) string {
	if int(v) < len(verdictWire) {
		return verdictWire[v]
	}
	return fmt.Sprintf("verdict-%d", v)
}

// protoWire is "tcp" or "udp"; any other transport (the kernel reports them, rules cannot
// name them) is its number. AnyProto (a rule's "any") is "".
func protoWire(p uint8) string {
	switch rules.Proto(p) {
	case rules.AnyProto:
		return ""
	case rules.TCP:
		return "tcp"
	case rules.UDP:
		return "udp"
	}
	return fmt.Sprint(p)
}

// rulesView lists the snapshot's rules and programs (Req 4.2, 4.3) in file order with the
// file each came from. A program is resolved when at least one executable maps to it (the
// summary line's rule); Executables is how many do. Port is the rule's single port, or 0 for
// any; a port range has no single port on the wire and is reported as 0 too.
func rulesView(snap *snapshot) ([]api.RuleView, []api.ProgramView) {
	contract.Require(snap != nil && snap.res != nil, "rulesView needs a built snapshot")
	res := snap.res
	rs := make([]api.RuleView, 0, len(res.File.Rules))
	for _, r := range res.File.Rules {
		rs = append(rs, api.RuleView{Id: int(r.ID), Program: r.Program, To: r.To.String(), Protocol: protoWire(uint8(r.Proto)),
			Port: singlePort(r.Ports), Verdict: verdictWord(r.Verdict), Note: r.Note, Source: r.Source})
	}
	mapped := map[uint32]int{}
	for _, id := range res.Programs {
		mapped[id]++
	}
	ps := make([]api.ProgramView, 0, len(res.File.Programs))
	for _, p := range res.File.Programs {
		ps = append(ps, api.ProgramView{Name: p.Name, Paths: p.Paths, Resolved: mapped[p.ID] > 0, Executables: mapped[p.ID], Source: p.Source})
	}
	return rs, ps
}

func singlePort(ports []uint16) int {
	if len(ports) == 1 {
		return int(ports[0])
	}
	return 0
}

// learnedView converts the learner's projection to the wire (Req 4.4); times are RFC 3339
// in UTC. Never nil: an empty learned set is an empty list on the wire.
func learnedView(in []rules.Observed) []api.Observation {
	out := make([]api.Observation, 0, len(in))
	for _, o := range in {
		out = append(out, api.Observation{Program: o.Program, Path: o.Path, Addr: o.Addr.String(), Protocol: protoWire(uint8(o.Proto)),
			Port: int(o.Port), Count: int(o.Count), First: o.First.UTC().Format(time.RFC3339), Last: o.Last.UTC().Format(time.RFC3339)})
	}
	return out
}
