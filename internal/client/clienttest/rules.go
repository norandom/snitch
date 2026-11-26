package clienttest

import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strconv"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/rules"
)

const (
	baseFilePath    = "/etc/snitch/rules.toml"
	overlayFilePath = "/etc/snitch/rules.d/local.toml"
)

func (s *StandIn) ruleCount() int {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	return len(s.merged.Rules)
}

func (s *StandIn) rulesFacts() ([]api.RuleView, []api.ProgramView) {
	s.fmu.Lock()
	defer s.fmu.Unlock()
	rs := make([]api.RuleView, 0, len(s.merged.Rules))
	for _, r := range s.merged.Rules {
		rs = append(rs, api.RuleView{
			Id: int(r.ID), Program: r.Program, To: r.Dest(), Protocol: protoWire(r.Proto),
			Port: singlePort(r.Ports), Verdict: verdictWord(r.Verdict), Note: r.Note, Source: r.Source,
		})
	}
	ps := make([]api.ProgramView, 0, len(s.merged.Programs))
	for _, p := range s.merged.Programs {
		ps = append(ps, api.ProgramView{
			Name: p.Name, Paths: slices.Clone(p.Paths), Resolved: len(p.Paths) > 0,
			Executables: len(p.Paths), Source: p.Source,
		})
	}
	return rs, ps
}

func (s *StandIn) ruleEdit(req api.Request, _ uint32) (string, error) {
	if s.refuse.Load() {
		return "", errors.New(req.Type + ": refused by the stand-in")
	}
	var (
		text string
		err  error
	)
	s.fmu.Lock()
	switch req.Type {
	case "rule.add":
		text, err = s.ruleAddLocked(req)
	case "rule.remove":
		text, err = s.ruleRemoveLocked(req)
	default:
		err = fmt.Errorf("%s: not a rule edit", req.Type)
	}
	if err == nil {
		s.edits = append(s.edits, req)
	}
	s.fmu.Unlock()
	if err != nil {
		return "", err
	}
	if s.o.Record != nil {
		s.o.Record(req)
	}
	s.later(s.o.ReloadAfter, func() { s.announce(s.Facts(), reasonReloaded, true) })
	return text, nil
}

func (s *StandIn) ruleAddLocked(req api.Request) (string, error) {
	verdict, err := parseEditVerdict(req.Verdict)
	if err != nil {
		return "", err
	}
	key, err := parseEditKey(req)
	if err != nil {
		return "", err
	}
	if key.name != "" && verdict == rules.Deny {
		return "", fmt.Errorf("to %q: a deny by name is not supported (deny stays a timed trial)", req.To)
	}
	nextOv := &rules.File{Name: s.overlay.Name, Programs: slices.Clone(s.overlay.Programs), Rules: slices.Clone(s.overlay.Rules)}
	if key.program, err = s.editProgramLocked(nextOv, req.Program, req.Path); err != nil {
		return "", err
	}
	if key.program == "any" && verdict == rules.Deny {
		return "", errors.New("a deny for every program is deny by default without a deadline: use snitchd trial")
	}
	nextOv.Rules = append(nextOv.Rules, rules.Rule{
		Program: key.program, To: key.to, Name: key.name, Proto: key.proto,
		Ports: key.ports(), Verdict: verdict, Note: req.Note, Source: overlayFilePath,
	})
	return s.commitOverlayLocked(nextOv, fmt.Sprintf("rule added: %s %s (applies within 5 s)", key, req.Verdict))
}

func (s *StandIn) ruleRemoveLocked(req api.Request) (string, error) {
	key, err := parseEditKey(req)
	if err != nil {
		return "", err
	}
	for i := range s.merged.Rules {
		if r := &s.merged.Rules[i]; key.matches(r) && r.Source != overlayFilePath {
			return "", fmt.Errorf("rule %d (%s) is in the deployed file: edit %s", r.ID, key, r.Source)
		}
	}
	nextOv := &rules.File{Name: s.overlay.Name, Programs: slices.Clone(s.overlay.Programs),
		Rules: slices.DeleteFunc(slices.Clone(s.overlay.Rules), func(r rules.Rule) bool { return key.matches(&r) })}
	if len(nextOv.Rules) == len(s.overlay.Rules) {
		return "", fmt.Errorf("no overlay rule matches %s", key)
	}
	return s.commitOverlayLocked(nextOv, fmt.Sprintf("rule removed: %s (applies within 5 s)", key))
}

func (s *StandIn) commitOverlayLocked(nextOv *rules.File, reply string) (string, error) {
	merged, err := rules.Merge(s.base, nextOv)
	if err != nil {
		return "", err
	}
	s.overlay, s.merged = nextOv, merged
	s.syncRuleCountsLocked()
	return reply, nil
}

func (s *StandIn) editProgramLocked(ov *rules.File, name, path string) (string, error) {
	switch {
	case name != "":
		if name == "any" || slices.ContainsFunc(s.merged.Programs, func(p rules.Program) bool { return p.Name == name }) {
			return name, nil
		}
		return "", fmt.Errorf("unknown program %q: declare it in the rules file, or give its path", name)
	case path == "":
		return "", errors.New("missing field: program or path")
	case !filepath.IsAbs(path):
		return "", fmt.Errorf("path %q is not absolute", path)
	}
	for _, p := range s.base.Programs {
		if slices.Contains(p.Paths, path) {
			return "", fmt.Errorf("executable %s is program %s: use that name", path, p.Name)
		}
	}
	for _, p := range ov.Programs {
		if slices.Contains(p.Paths, path) {
			return p.Name, nil
		}
	}
	name = adHocName(filepath.Base(path), s.merged, ov)
	ov.Programs = append(ov.Programs, rules.Program{Name: name, Paths: []string{path}, Source: overlayFilePath})
	return name, nil
}

func adHocName(base string, merged, ov *rules.File) string {
	taken := map[string]bool{"any": true}
	for _, p := range merged.Programs {
		taken[p.Name] = true
	}
	for _, p := range ov.Programs {
		taken[p.Name] = true
	}
	name := base
	for i := 2; taken[name]; i++ {
		name = fmt.Sprintf("%s-%d", base, i)
	}
	return name
}

type editKey struct {
	program string
	to      netip.Prefix
	name    string
	proto   rules.Proto
	port    uint16
}

func parseEditKey(req api.Request) (editKey, error) {
	k := editKey{program: req.Program}
	var err error
	if k.to, err = rules.ParsePrefix(req.To); err != nil {
		if k.name, err = rules.ParseName(req.To); err != nil {
			return k, err
		}
	}
	if k.proto, err = parseEditProto(req.Proto); err != nil {
		return k, err
	}
	if req.Port < 0 || req.Port > 65535 {
		return k, fmt.Errorf("port %d: want 1-65535, or 0 for any", req.Port)
	}
	k.port = uint16(req.Port)
	return k, nil
}

func parseEditProto(s string) (rules.Proto, error) {
	switch s {
	case "", "any":
		return rules.AnyProto, nil
	case "tcp":
		return rules.TCP, nil
	case "udp":
		return rules.UDP, nil
	}
	return 0, fmt.Errorf("proto %q: want tcp, udp or any", s)
}

func parseEditVerdict(s string) (rules.Verdict, error) {
	switch s {
	case "allow":
		return rules.Allow, nil
	case "deny":
		return rules.Deny, nil
	}
	return 0, fmt.Errorf("verdict %q: want allow or deny", s)
}

func (k editKey) destination() string { return (rules.Rule{To: k.to, Name: k.name}).Dest() }
func (k editKey) ports() []uint16 {
	if k.port == 0 {
		return nil
	}
	return []uint16{k.port}
}

func (k editKey) matches(r *rules.Rule) bool {
	port := r.Ports == nil && k.port == 0 || len(r.Ports) == 1 && r.Ports[0] == k.port
	return r.Program == k.program && r.Dest() == k.destination() && r.Proto == k.proto && port
}

func (k editKey) String() string {
	s := k.program + " to " + k.destination()
	if k.proto != rules.AnyProto {
		s += " " + protoWire(k.proto)
	}
	if k.port != 0 {
		s += " port " + strconv.Itoa(int(k.port))
	}
	return s
}

func protoWire(p rules.Proto) string {
	switch p {
	case rules.TCP:
		return "tcp"
	case rules.UDP:
		return "udp"
	}
	return ""
}

func singlePort(ports []uint16) int {
	if len(ports) == 1 {
		return int(ports[0])
	}
	return 0
}

func verdictWord(v rules.Verdict) string {
	if v == rules.Deny {
		return "deny"
	}
	return "allow"
}
