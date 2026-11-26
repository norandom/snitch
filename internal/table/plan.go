// plan.go maps a connection tree row and current coverage into either the daemon rule
// requests (`rule.add` / `rule.remove`) for `x` or space, or a sanitised refusal text.
//
// Fail-safe implications: local-network addresses (ask.Local) are never blocked or included
// in host-level blocks (fail-safe 2); program-level blocks carry the note that the local
// network stays reachable. Postcondition contracts enforce that no request names a local
// address and that every plan yields requests or a refusal, never both or neither.
package table

import (
	"net/netip"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/ask"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/contract"
)

const planNoteLayout = "2006-01-02 15:04"

// Plan is the outcome of pressing `x` or space on a row: either daemon requests to send
// (adding or removing deny rules) or a Refusal explaining why no rule can be changed.
type Plan struct {
	Requests []api.Request
	Refusal  clean.Safe
	Unblock  bool
	Note     clean.Safe
}

type removeKey struct {
	program, to, proto string
	port               int
}

// MakePlan computes the block/unblock plan or refusal for row against store s and rules r.
func MakePlan(row Row, s Store, r Rules, now time.Time) Plan {
	contract.Require(row.Level >= Program && row.Level <= Bucket, "table.MakePlan: unknown row level")
	if row.Level == Bucket || len(row.Keys) == 0 {
		return finishPlan(Plan{Refusal: clean.Const("no rule can name it")})
	}
	prog, path, ok := subjectFor(row.Keys[0], s, r.Programs)
	if !ok {
		return finishPlan(Plan{Refusal: clean.Const("no rule can name it")})
	}
	switch row.Level {
	case Address:
		return finishPlan(planAddress(row.Keys[0], s, r, prog, path, now))
	case Host, Group:
		return finishPlan(planGroup(row, s, r, prog, path, now))
	default:
		return finishPlan(planProgram(row, r, prog, path, now))
	}
}

func subjectFor(k Key, s Store, programs []api.ProgramView) (prog, path string, ok bool) {
	if e, has := s.Get(k); has {
		if e.Program != "" && e.Program != ask.Unknown {
			return e.Program, "", true
		}
		if e.Path == "" {
			return "", "", false
		}
		if name := declaredByPath(e.Path, programs); name != "" {
			return name, "", true
		}
		return "", e.Path, true
	}
	if k.Who == "" || k.Who == ask.Unknown {
		return "", "", false
	}
	if strings.HasPrefix(k.Who, "/") {
		if name := declaredByPath(k.Who, programs); name != "" {
			return name, "", true
		}
		return "", k.Who, true
	}
	return k.Who, "", true
}

func declaredByPath(path string, programs []api.ProgramView) string {
	for _, p := range programs {
		if p.Name != "" && pathMatches(p.Paths, path) {
			return p.Name
		}
	}
	return ""
}

func planAddress(k Key, s Store, r Rules, prog, path string, now time.Time) Plan {
	addr, ok := parseKeyAddr(k.Addr)
	if !ok {
		return Plan{Refusal: clean.Const("no rule can name it")}
	}
	if ask.Local(addr) {
		return Plan{Refusal: clean.Const("the local network is always allowed")}
	}
	e, _ := s.Get(k)
	cov := Cover(r, k, e.Name, Address)
	if !cov.Found || cov.Rule.Verdict != "deny" {
		to := netip.PrefixFrom(addr, addr.BitLen()).String()
		return Plan{Requests: []api.Request{addDenyReq(prog, path, to, k.Proto, int(k.Port), now)}}
	}
	if cov.Own {
		return Plan{Requests: []api.Request{removeReq(cov.Rule)}, Unblock: true}
	}
	return Plan{Refusal: refusalFor(cov)}
}

func planGroup(row Row, s Store, r Rules, prog, path string, now time.Time) Plan {
	var adds []api.Request
	var blocked []Covering
	var sawLocal bool
	for _, k := range row.Keys {
		addr, ok := parseKeyAddr(k.Addr)
		if !ok {
			continue
		}
		if ask.Local(addr) {
			sawLocal = true
			continue
		}
		e, _ := s.Get(k)
		cov := Cover(r, k, e.Name, row.Level)
		if !cov.Found || cov.Rule.Verdict != "deny" {
			to := netip.PrefixFrom(addr, addr.BitLen()).String()
			adds = append(adds, addDenyReq(prog, path, to, k.Proto, int(k.Port), now))
			continue
		}
		blocked = append(blocked, cov)
	}
	if len(adds) > 0 {
		return Plan{Requests: adds}
	}
	if len(blocked) > 0 {
		return planUnblockGroup(blocked)
	}
	if sawLocal {
		return Plan{Refusal: clean.Const("the local network is always allowed")}
	}
	return Plan{Refusal: clean.Const("no rule can name it")}
}

func planUnblockGroup(blocked []Covering) Plan {
	var rems []api.Request
	seen := make(map[removeKey]bool, len(blocked))
	for _, cov := range blocked {
		if !cov.Own && cov.By != Address {
			continue
		}
		req := removeReq(cov.Rule)
		rk := removeKey{req.Program, req.To, req.Proto, req.Port}
		if !seen[rk] {
			seen[rk] = true
			rems = append(rems, req)
		}
	}
	if len(rems) > 0 {
		return Plan{Requests: rems, Unblock: true}
	}
	return Plan{Refusal: refusalFor(blocked[0])}
}

func planProgram(row Row, r Rules, prog, path string, now time.Time) Plan {
	who := row.Keys[0].Who
	cov4 := Cover(r, Key{Who: who, Addr: "0.0.0.0"}, "", Program)
	cov6 := Cover(r, Key{Who: who, Addr: "::"}, "", Program)
	deny4 := cov4.Found && cov4.Rule.Verdict == "deny"
	deny6 := cov6.Found && cov6.Rule.Verdict == "deny"
	if (deny4 && cov4.Own) || (deny6 && cov6.Own) {
		return programUnblockPlan(cov4, cov6, deny4, deny6)
	}
	if cov, blocked := programEnclosing(row.Keys, cov4, cov6, deny4, deny6); blocked {
		return Plan{Refusal: refusalFor(cov)}
	}
	return Plan{
		Requests: []api.Request{
			addDenyReq(prog, path, "0.0.0.0/0", "", 0, now),
			addDenyReq(prog, path, "::/0", "", 0, now),
		},
		Note: clean.Const("the local network stays reachable"),
	}
}

func programUnblockPlan(cov4, cov6 Covering, deny4, deny6 bool) Plan {
	var rems []api.Request
	if deny4 && cov4.Own {
		rems = append(rems, removeReq(cov4.Rule))
	}
	if deny6 && cov6.Own {
		rems = append(rems, removeReq(cov6.Rule))
	}
	return Plan{Requests: rems, Unblock: true}
}

func programEnclosing(keys []Key, cov4, cov6 Covering, deny4, deny6 bool) (Covering, bool) {
	has4, has6 := rowFamilies(keys)
	if deny4 && (deny6 || !has6) {
		return cov4, true
	}
	if deny6 && !has4 {
		return cov6, true
	}
	return Covering{}, false
}

func rowFamilies(keys []Key) (has4, has6 bool) {
	for _, k := range keys {
		addr, ok := parseKeyAddr(k.Addr)
		if !ok {
			continue
		}
		if addr.Is4() {
			has4 = true
		} else {
			has6 = true
		}
	}
	return has4, has6
}

func addDenyReq(prog, path, to, proto string, port int, now time.Time) api.Request {
	return api.Request{
		Type:    "rule.add",
		Program: prog,
		Path:    path,
		To:      to,
		Proto:   proto,
		Port:    port,
		Verdict: "deny",
		Note:    "snitch tui " + now.Local().Format(planNoteLayout),
	}
}

func removeReq(rv api.RuleView) api.Request {
	proto := rv.Protocol
	if strings.EqualFold(proto, "any") {
		proto = ""
	}
	return api.Request{
		Type: "rule.remove", Program: rv.Program, To: rv.To, Proto: proto, Port: rv.Port,
	}
}

func refusalFor(cov Covering) clean.Safe {
	if isAnyProg(cov.Rule.Program) {
		return withSource(clean.Join(clean.Const("blocked by any-program rule "), clean.Text(cov.Rule.To)), cov)
	}
	var label clean.Safe
	switch cov.By {
	case Program:
		label = clean.Join(clean.Const("blocked by program "), clean.Text(cov.Rule.Program))
	case Host:
		label = clean.Join(clean.Const("blocked by host rule "), clean.Text(cov.Rule.To))
	case Group:
		label = clean.Join(clean.Const("blocked by IP Addresses rule "), clean.Text(cov.Rule.To))
	default:
		label = clean.Join(clean.Const("blocked by rule "), clean.Text(cov.Rule.To))
	}
	return withSource(label, cov)
}

func withSource(msg clean.Safe, cov Covering) clean.Safe {
	if !cov.Overlay && cov.Rule.Source != "" {
		return clean.Join(msg, clean.Const(" in "), clean.Text(cov.Rule.Source))
	}
	return msg
}

func finishPlan(p Plan) Plan {
	hasReqs := len(p.Requests) > 0
	hasRefusal := p.Refusal != ""
	contract.Ensure(hasReqs != hasRefusal, "table.MakePlan: plan must have requests or a refusal, never both or neither")
	for _, req := range p.Requests {
		contract.Ensure(!namesLocalAddress(req.To), "table.MakePlan: request names a local address")
	}
	return p
}

func namesLocalAddress(to string) bool {
	if addr, err := netip.ParseAddr(to); err == nil {
		return ask.Local(addr)
	}
	if pfx, err := netip.ParsePrefix(to); err == nil {
		return ask.Local(pfx.Addr())
	}
	return false
}
