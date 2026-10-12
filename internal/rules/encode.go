package rules

import (
	"net/netip"

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

// Empty says whether the diff changes nothing in the maps.
func (c Changes) Empty() bool {
	return len(c.PutPrograms)+len(c.DelPrograms)+len(c.PutRules)+len(c.DelRules) == 0
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
		if r.File.Rules[i].IsName() {
			continue
		}
		encodeRule(&r.File.Rules[i], ProgramID(r, r.File.Rules[i].Program), e.Rules)
	}
	return e
}

// ProgramID returns zero for "any", otherwise the id in Resolved.Names.
// An undeclared name violates the validated-file invariant, just as in Encode.
func ProgramID(r *Resolved, name string) uint32 {
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
	base := prefixKey(rule.To, program)
	for _, pp := range Expand(rule) {
		k := base
		k.Proto, k.Port = uint8(pp.Proto), pp.Port
		out[k] = RuleVal{Verdict: uint8(rule.Verdict), Id: rule.ID}
	}
}

// EncodeAddr builds one host key using r.Proto and the first port (zero if absent).
// Callers use Expand and set Proto/Ports for each pair before calling.
// IPv4-mapped addresses retain the same family and bits as encodeRule.
func EncodeAddr(r *Rule, program uint32, addr netip.Addr) (RuleKey, RuleVal) {
	k := prefixKey(netip.PrefixFrom(addr, addr.BitLen()), program)
	k.Proto, k.Port = uint8(r.Proto), portsOf(r)[0]
	return k, RuleVal{Verdict: uint8(r.Verdict), Id: r.ID}
}

func prefixKey(prefix netip.Prefix, program uint32) RuleKey {
	contract.Require(prefix.IsValid() && prefix == prefix.Masked(), "rule prefix must be valid and canonical")
	base := RuleKey{Prefixlen: fixedKeyBits + uint32(prefix.Bits()), Program: program}
	if prefix.Addr().Is4() {
		a := prefix.Addr().As4()
		base.Family = familyV4
		copy(base.Addr[:], a[:])
	} else {
		base.Family = familyV6
		base.Addr = prefix.Addr().As16()
	}
	contract.Ensure(base.Prefixlen >= fixedKeyBits, "prefixlen covers the fixed key part")
	return base
}

// ProtoPort is one kernel lookup combination; zero denotes any protocol or port.
type ProtoPort struct {
	Proto Proto
	Port  uint16
}

// Expand shares Encode's transport expansion so compiled rules use reachable keys.
func Expand(r *Rule) []ProtoPort {
	var out []ProtoPort
	for _, proto := range protosOf(r) {
		for _, port := range portsOf(r) {
			out = append(out, ProtoPort{Proto: proto, Port: port})
		}
	}
	return out
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
