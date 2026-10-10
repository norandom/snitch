package rules

import (
	"github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/contract"
)

// RuleKey and RuleVal are the kernel's trie key and value (generated from the C structs).
type (
	RuleKey = bpf.SnitchRuleKey
	RuleVal = bpf.SnitchRuleVal
)

const (
	familyV4      = 2  // AF_INET
	familyV6      = 10 // AF_INET6
	fixedKeyBits  = 64 // program + family + proto + port: always inside the prefix
	anyProgramID  = 0
	anyPortOrProt = 0
)

// Entries is the kernel view of a Resolved: exactly the map entries that must exist.
type Entries struct {
	Programs map[ExeKey]uint32
	Rules    map[RuleKey]RuleVal
}

// Changes turns one Entries into another: puts (new or changed) then deletes (removed).
type Changes struct {
	PutPrograms map[ExeKey]uint32
	DelPrograms []ExeKey
	PutRules    map[RuleKey]RuleVal
	DelRules    []RuleKey
}

// Encode produces the map entries for a Resolved. A rule with ports but no protocol becomes
// TCP and UDP entries per port: the kernel probes (proto, port), (proto, 0), (0, 0), never
// (0, port).
func Encode(r *Resolved) Entries {
	contract.Require(r != nil && r.File != nil, "Encode needs a Resolved")
	e := Entries{Programs: make(map[ExeKey]uint32, len(r.Programs)), Rules: map[RuleKey]RuleVal{}}
	for k, id := range r.Programs {
		e.Programs[k] = id
	}
	for i := range r.File.Rules {
		encodeRule(&r.File.Rules[i], programID(r, r.File.Rules[i].Program), e.Rules)
	}
	return e
}

func programID(r *Resolved, name string) uint32 {
	if name == anyProgram {
		return anyProgramID
	}
	for id, n := range r.Names {
		if n == name {
			return id
		}
	}
	contract.Invariant(false, "rule references a program that validation did not declare")
	return 0
}

func encodeRule(rule *Rule, program uint32, out map[RuleKey]RuleVal) {
	contract.Require(rule.To.IsValid() && rule.To == rule.To.Masked(), "rule prefix must be valid and canonical")
	val := RuleVal{Verdict: uint8(rule.Verdict), Id: rule.ID}
	base := RuleKey{Prefixlen: fixedKeyBits + uint32(rule.To.Bits()), Program: program}
	if rule.To.Addr().Is4() {
		a := rule.To.Addr().As4()
		base.Family = familyV4
		copy(base.Addr[:], a[:])
	} else {
		base.Family = familyV6
		base.Addr = rule.To.Addr().As16()
	}
	for _, proto := range protosOf(rule) {
		for _, port := range portsOf(rule) {
			k := base
			k.Proto, k.Port = uint8(proto), port
			out[k] = val
		}
	}
	contract.Ensure(base.Prefixlen >= fixedKeyBits, "prefixlen covers the fixed key part")
}

func protosOf(rule *Rule) []Proto {
	if rule.Proto == AnyProto && len(rule.Ports) > 0 {
		return []Proto{TCP, UDP}
	}
	return []Proto{rule.Proto}
}

func portsOf(rule *Rule) []uint16 {
	if len(rule.Ports) == 0 {
		return []uint16{anyPortOrProt}
	}
	return rule.Ports
}

// Diff computes the puts and deletes that turn old into new. Identical inputs give no changes.
func Diff(old, now Entries) Changes {
	var ch Changes
	ch.PutPrograms, ch.DelPrograms = diffMap(old.Programs, now.Programs)
	ch.PutRules, ch.DelRules = diffMap(old.Rules, now.Rules)
	// identical inputs give an empty change set: pinned by TestDiffIdenticalIsEmpty (a runtime
	// check would have to recompute the equality it is meant to verify)
	return ch
}

// diffMap: entries new or changed in now are puts, entries only in old are deletes.
func diffMap[K, V comparable](old, now map[K]V) (put map[K]V, del []K) {
	put = map[K]V{}
	for k, v := range now {
		if prev, ok := old[k]; !ok || prev != v {
			put[k] = v
		}
	}
	for k := range old {
		if _, ok := now[k]; !ok {
			del = append(del, k)
		}
	}
	return put, del
}
