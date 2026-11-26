// cover.go finds the effective rule covering a connection key at a given tree level in the
// kernel's documented lookup order, classifying whether the match is the row's own rule,
// comes from the overlay, and which level holds it.
//
// Fail-safe implications: none on kernel egress. Advisory read-only lookup over RuleViews;
// kernel enforcement lives in BPF maps.
package table

import (
	"cmp"
	"net/netip"
	"path/filepath"
	"strings"

	"github.com/norandom/snitch/internal/api"
)

// Covering describes the effective rule that covers a connection key at a tree level.
type Covering struct {
	Rule    api.RuleView
	Own     bool
	Overlay bool
	By      Level
	Found   bool
}

type matchRank struct {
	progSpec   int
	protoPort  int
	prefixBits int
	isCIDR     int
	nameLen    int
	overlay    int
	id         int
}

// Cover returns the highest-precedence rule in r covering k (with optional DNS name) at
// tree level at, following the kernel's lookup order.
func Cover(r Rules, k Key, name string, at Level) Covering {
	if at == Bucket {
		return Covering{}
	}
	progs := resolveProgram(k.Who, r.Programs)
	addr, hasAddr := parseKeyAddr(k.Addr)
	var (
		best     api.RuleView
		bestRank matchRank
		found    bool
	)
	for _, rule := range r.Views {
		rank, ok := evalRule(rule, k, name, at, hasAddr, addr, progs, r.Overlay)
		if !ok {
			continue
		}
		if !found || compareRank(rank, bestRank) > 0 {
			best, bestRank, found = rule, rank, true
		}
	}
	if !found {
		return Covering{}
	}
	return classifyCovering(best, k, at, r.Overlay)
}

func evalRule(rule api.RuleView, k Key, name string, at Level, hasAddr bool, addr netip.Addr, progs map[string]bool, overlay string) (matchRank, bool) {
	if at == Program {
		return matchProgramRule(rule, hasAddr, addr, progs, overlay)
	}
	return matchRule(rule, k, name, hasAddr, addr, progs, overlay)
}

func matchProgramRule(rule api.RuleView, hasAddr bool, addr netip.Addr, progs map[string]bool, overlay string) (matchRank, bool) {
	if !isProgWide(rule) {
		return matchRank{}, false
	}
	progSpec, ok := matchProg(rule.Program, progs)
	if !ok {
		return matchRank{}, false
	}
	if hasAddr && ((addr.Is4() && rule.To != "0.0.0.0/0") || (addr.Is6() && rule.To != "::/0")) {
		return matchRank{}, false
	}
	return matchRank{progSpec: progSpec, overlay: overlayBit(rule, overlay), id: rule.Id}, true
}

func matchRule(rule api.RuleView, k Key, name string, hasAddr bool, addr netip.Addr, progs map[string]bool, overlay string) (matchRank, bool) {
	progSpec, ok := matchProg(rule.Program, progs)
	if !ok {
		return matchRank{}, false
	}
	ppRank, ok := matchProtoPort(rule.Protocol, rule.Port, k.Proto, k.Port)
	if !ok {
		return matchRank{}, false
	}
	bits, isCIDR, nameLen, ok := matchDest(rule.To, hasAddr, addr, name)
	if !ok {
		return matchRank{}, false
	}
	return matchRank{
		progSpec: progSpec, protoPort: ppRank, prefixBits: bits,
		isCIDR: isCIDR, nameLen: nameLen, overlay: overlayBit(rule, overlay), id: rule.Id,
	}, true
}

func resolveProgram(who string, programs []api.ProgramView) map[string]bool {
	if who == "" {
		return nil
	}
	matched := map[string]bool{who: true}
	for _, p := range programs {
		if p.Name != "" && (p.Name == who || pathMatches(p.Paths, who)) {
			matched[p.Name] = true
		}
	}
	return matched
}

func pathMatches(paths []string, who string) bool {
	for _, pat := range paths {
		if strings.ContainsAny(pat, "*?[") {
			if ok, err := filepath.Match(pat, who); err == nil && ok {
				return true
			}
		} else if pat == who {
			return true
		}
	}
	return false
}

func matchProg(ruleProg string, progs map[string]bool) (int, bool) {
	if isAnyProg(ruleProg) {
		return 0, true
	}
	if progs[ruleProg] {
		return 1, true
	}
	return 0, false
}

func matchProtoPort(ruleProto string, rulePort int, keyProto string, keyPort uint16) (int, bool) {
	if isAnyProto(ruleProto) {
		if rulePort == 0 {
			return 0, true
		}
		if isTCPOrUDP(keyProto) && exactPort(rulePort, keyPort) {
			return 2, true
		}
		return 0, false
	}
	if !exactProto(ruleProto, keyProto) {
		return 0, false
	}
	if exactPort(rulePort, keyPort) {
		return 2, true
	}
	if rulePort == 0 {
		return 1, true
	}
	return 0, false
}

func matchDest(to string, hasAddr bool, addr netip.Addr, name string) (bits, isCIDR, nameLen int, ok bool) {
	if pfx, err := netip.ParsePrefix(to); err == nil {
		return matchCIDR(pfx.Masked(), hasAddr, addr)
	}
	return matchDomain(to, hasAddr, addr, name)
}

func matchCIDR(pfx netip.Prefix, hasAddr bool, addr netip.Addr) (bits, isCIDR, nameLen int, ok bool) {
	if !hasAddr || pfx.Addr().Is4() != addr.Is4() || !pfx.Contains(addr) {
		return 0, 0, 0, false
	}
	return pfx.Bits(), 1, 0, true
}

func matchDomain(to string, hasAddr bool, addr netip.Addr, name string) (bits, isCIDR, nameLen int, ok bool) {
	cleanTo := strings.TrimRight(strings.ToLower(to), ".")
	cleanName := strings.TrimRight(strings.ToLower(name), ".")
	if cleanTo == "" || cleanName == "" {
		return 0, 0, 0, false
	}
	if cleanName != cleanTo && !strings.HasSuffix(cleanName, "."+cleanTo) {
		return 0, 0, 0, false
	}
	hostBits := 32
	if hasAddr && addr.Is6() {
		hostBits = 128
	}
	return hostBits, 0, len(cleanTo), true
}

func parseKeyAddr(raw string) (netip.Addr, bool) {
	if raw == "" {
		return netip.Addr{}, false
	}
	addr, err := netip.ParseAddr(raw)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.WithZone("").Unmap(), true
}

func compareRank(a, b matchRank) int {
	return cmp.Or(
		cmp.Compare(a.progSpec, b.progSpec),
		cmp.Compare(a.protoPort, b.protoPort),
		cmp.Compare(a.prefixBits, b.prefixBits),
		cmp.Compare(a.isCIDR, b.isCIDR),
		cmp.Compare(a.nameLen, b.nameLen),
		cmp.Compare(a.overlay, b.overlay),
		cmp.Compare(a.id, b.id),
	)
}

func classifyCovering(best api.RuleView, k Key, at Level, overlay string) Covering {
	progSpec := !isAnyProg(best.Program)
	progWide := isProgWide(best)
	exactAddr := progSpec && hostCIDR(best.To, k.Addr) && exactProto(best.Protocol, k.Proto) &&
		exactPort(best.Port, k.Port)
	by := classifyBy(progSpec, progWide, exactAddr, best.To, at)
	return Covering{
		Rule:    best,
		Own:     classifyOwn(progSpec, progWide, exactAddr, by, at),
		Overlay: isOverlay(best, overlay),
		By:      by,
		Found:   true,
	}
}

func classifyBy(progSpec, progWide, exactAddr bool, to string, at Level) Level {
	if !progSpec || progWide {
		return Program
	}
	if exactAddr {
		return Address
	}
	if at == Group && isCIDRRule(to) {
		return Group
	}
	return Host
}

func classifyOwn(progSpec, progWide, exactAddr bool, by, at Level) bool {
	switch at {
	case Program:
		return progSpec && progWide
	case Address:
		return exactAddr
	case Host, Group:
		return progSpec && by == at
	default:
		return false
	}
}

func isAnyProg(p string) bool  { return p == "" || p == "any" }
func isAnyProto(p string) bool { return p == "" || strings.EqualFold(p, "any") }
func isProgWide(r api.RuleView) bool {
	return (r.To == "0.0.0.0/0" || r.To == "::/0") && isAnyProto(r.Protocol) && r.Port == 0
}
func exactProto(rp, kp string) bool    { return !isAnyProto(rp) && kp != "" && strings.EqualFold(rp, kp) }
func exactPort(rp int, kp uint16) bool { return rp > 0 && rp <= 65535 && uint16(rp) == kp }
func isTCPOrUDP(p string) bool         { return strings.EqualFold(p, "tcp") || strings.EqualFold(p, "udp") }
func isOverlay(r api.RuleView, overlay string) bool {
	return r.Source != "" && overlay != "" && r.Source == overlay
}

func overlayBit(r api.RuleView, overlay string) int {
	if isOverlay(r, overlay) {
		return 1
	}
	return 0
}

func hostCIDR(to, addrStr string) bool {
	pfx, err := netip.ParsePrefix(to)
	if err != nil {
		return false
	}
	pfx = pfx.Masked()
	addr, ok := parseKeyAddr(addrStr)
	if !ok || !pfx.IsSingleIP() {
		return false
	}
	return pfx.Addr().Is4() == addr.Is4() && pfx.Contains(addr)
}

func isCIDRRule(to string) bool {
	_, err := netip.ParsePrefix(to)
	return err == nil
}
