// Compilation adds allows only; file keys are never touched. Contract failures stop the
// daemon and detach enforcement, preserving the fail-open boundary.
package dns

import (
	"fmt"
	"net/netip"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/rules"
)

// Max is the daemon's compiled-entry budget; the owner evicts cache addresses above it.
const Max = 16384

// Entry keeps the rule attribution only. Lifetimes belong to Cache; Compiled groups keys
// by address so expiry or eviction can remove every allow contributed by that address.
type Entry struct {
	ID   uint32
	Name string
}

// Compiled has a ready zero value. Its owner serializes access with cache and trie updates.
type Compiled struct {
	entries map[netip.Addr]map[rules.RuleKey]Entry
	count   int
}

// Slots supplies the whole domains map; the validator normally catches overflow first.
func Slots(res *rules.Resolved) (map[[NameMax]byte][SlotsMax]Slot, error) {
	contract.Require(res != nil && res.File != nil, "Slots needs resolved rules")
	out := make(map[[NameMax]byte][SlotsMax]Slot)
	counts := make(map[[NameMax]byte]int)
	for i := range res.File.Rules {
		r := &res.File.Rules[i]
		if !r.IsName() {
			continue
		}
		// One slot per protocol/port combination the encoder would produce, so the kernel's
		// inserts are exactly the keys decide() looks up (an any-proto rule with a port is tcp
		// and udp, never proto 0 with a port). The validator counts the same combinations.
		key := Key(r.Name)
		program := rules.ProgramID(res, r.Program)
		for _, pp := range rules.Expand(r) {
			n := counts[key]
			if n == SlotsMax {
				return nil, fmt.Errorf("domain %q exceeds %d slots", r.Name, SlotsMax)
			}
			slots := out[key]
			slots[n] = Slot{Program: program, Proto: pp.Proto, Port: pp.Port, ID: r.ID}
			out[key], counts[key] = slots, n+1
		}
	}
	return out, nil
}

// Compute shares the address encoder and transport expansion with file rules.
func (c *Compiled) Compute(res *rules.Resolved, addr netip.Addr, names []string) map[rules.RuleKey]Entry {
	contract.Require(res != nil && res.File != nil, "Compute needs resolved rules")
	want := make(map[rules.RuleKey]Entry)
	for i := range res.File.Rules {
		r := &res.File.Rules[i]
		if !r.IsName() {
			continue
		}
		name, ok := coveringName(r.Name, names)
		if !ok {
			continue
		}
		k, _ := rules.EncodeAddr(r, rules.ProgramID(res, r.Program), addr)
		for _, pp := range rules.Expand(r) {
			key := k
			key.Proto, key.Port = uint8(pp.Proto), pp.Port
			want[key] = Entry{ID: r.ID, Name: name}
		}
	}
	return want
}

func coveringName(rule string, names []string) (string, bool) {
	for _, name := range names {
		if Covers(rule, name) {
			return name, true
		}
	}
	return "", false
}

// Apply forgets file-owned keys even when they were formerly compiled keys.
func (c *Compiled) Apply(addr netip.Addr, want map[rules.RuleKey]Entry, file map[rules.RuleKey]rules.RuleVal) (puts map[rules.RuleKey]rules.RuleVal, dels []rules.RuleKey) {
	puts = make(map[rules.RuleKey]rules.RuleVal)
	dels = c.apply(addr, want, file, puts, false)
	compiledOutputs(puts, dels, file)
	return puts, dels
}

func (c *Compiled) apply(addr netip.Addr, want map[rules.RuleKey]Entry, file map[rules.RuleKey]rules.RuleVal, puts map[rules.RuleKey]rules.RuleVal, force bool) []rules.RuleKey {
	old := c.entries[addr]
	next := compiledWanted(want, old, file, puts, force)
	var dels []rules.RuleKey
	for k := range old {
		if _, kept := next[k]; kept {
			continue
		}
		if _, owned := file[k]; !owned {
			dels = append(dels, k)
		}
	}
	c.count += len(next) - len(old)
	if len(next) == 0 {
		delete(c.entries, addr)
	} else {
		if c.entries == nil {
			c.entries = make(map[netip.Addr]map[rules.RuleKey]Entry)
		}
		c.entries[addr] = next
	}
	return dels
}

func compiledWanted(want, old map[rules.RuleKey]Entry, file map[rules.RuleKey]rules.RuleVal, puts map[rules.RuleKey]rules.RuleVal, force bool) map[rules.RuleKey]Entry {
	next := make(map[rules.RuleKey]Entry, len(want))
	for k, entry := range want {
		if _, owned := file[k]; owned {
			continue
		}
		next[k] = entry
		if prev, ok := old[k]; force || !ok || prev.ID != entry.ID {
			puts[k] = rules.RuleVal{Verdict: uint8(rules.Allow), Id: entry.ID}
		}
	}
	return next
}

// compiledOutputs is a second fence: a subtraction bug must fail open, not alter file rules.
func compiledOutputs(puts map[rules.RuleKey]rules.RuleVal, dels []rules.RuleKey, file map[rules.RuleKey]rules.RuleVal) {
	for k, val := range puts {
		_, owned := file[k]
		contract.Ensure(!owned, "compiled put never touches a file key")
		contract.Invariant(val.Verdict == uint8(rules.Allow), "compiled values are allow only")
	}
	for _, k := range dels {
		_, owned := file[k]
		contract.Ensure(!owned, "compiled delete never touches a file key")
	}
}

// Recompile re-puts all live keys with current ids to correct any earlier kernel insert.
func (c *Compiled) Recompile(res *rules.Resolved, cache *Cache, file map[rules.RuleKey]rules.RuleVal) (puts map[rules.RuleKey]rules.RuleVal, dels []rules.RuleKey) {
	contract.Require(res != nil && res.File != nil, "Recompile needs resolved rules")
	puts = make(map[rules.RuleKey]rules.RuleVal)
	seen := make(map[netip.Addr]bool)
	cache.Each(func(addr netip.Addr, names []string) {
		seen[addr] = true
		dels = append(dels, c.apply(addr, c.Compute(res, addr, names), file, puts, true)...)
	})
	for addr := range c.entries {
		if !seen[addr] {
			dels = append(dels, c.apply(addr, nil, file, puts, false)...)
		}
	}
	compiledOutputs(puts, dels, file)
	return puts, dels
}

// NameOf returns the learned name that contributed this rule's address key.
func (c *Compiled) NameOf(addr netip.Addr, ruleID uint32) (string, bool) {
	for _, entry := range c.entries[addr] {
		if entry.ID == ruleID {
			return entry.Name, true
		}
	}
	return "", false
}

// Len counts keys, including each transport expansion, for the daemon's capacity policy.
func (c *Compiled) Len() int { return c.count }
