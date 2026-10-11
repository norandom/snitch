// apiwrite_rules.go: rule.add and rule.remove behind the API (design "Overlay", Req 5.2, 5.3,
// 5.7). Both edit the local overlay file alone: load, mutate, merge over the deployed file to
// validate as the reload will, write (temp file and rename); the 2 s watch then reloads and
// publishes, so a rule applies within 5 s and the state event follows. A key the deployed
// file holds is never edited here: the answer names the file. Nothing is written when a check
// or the merge fails, so the effective rules never change on an error. The dispatcher audits
// every write (dispatch.go); nothing here logs.
package main

import (
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/rules"
)

// overlayHeader is the written overlay's comment line (design "Overlay").
const overlayHeader = "local rules written by snitchd's API"

// apiRuleEdit is the server's RuleEdit delegate (the server refused readers already; who is
// the dispatcher's to audit).
func (d *daemon) apiRuleEdit(req api.Request, _ uint32) (string, error) {
	d.editMu.Lock() // two writers at once would lose one edit of the overlay
	defer d.editMu.Unlock()
	switch req.Type {
	case "rule.add":
		return d.ruleAdd(req)
	case "rule.remove":
		return d.ruleRemove(req)
	}
	return "", fmt.Errorf("%s: not a rule edit", req.Type)
}

// editKey is a request's rule key, checked: the address or prefix canonical like the rules
// file's (a bare address is a /32 or /128), the protocol (empty is any), the port (0 is any).
type editKey struct {
	program string
	to      netip.Prefix
	proto   rules.Proto
	port    uint16
}

func parseEditKey(req api.Request) (editKey, error) {
	k := editKey{program: req.Program}
	var err error
	if k.to, err = rules.ParsePrefix(req.To); err != nil {
		return k, err
	}
	switch req.Proto {
	case "", "any":
		k.proto = rules.AnyProto
	case "tcp":
		k.proto = rules.TCP
	case "udp":
		k.proto = rules.UDP
	default:
		return k, fmt.Errorf("proto %q: want tcp, udp or any", req.Proto)
	}
	if req.Port < 0 || req.Port > 65535 {
		return k, fmt.Errorf("port %d: want 1-65535, or 0 for any", req.Port)
	}
	k.port = uint16(req.Port)
	return k, nil
}

func (k editKey) String() string {
	s := k.program + " to " + k.to.String()
	if k.proto != rules.AnyProto {
		s += " " + protoWire(uint8(k.proto))
	}
	if k.port != 0 {
		s += fmt.Sprintf(" port %d", k.port)
	}
	return s
}

// matches says whether r is exactly this key; a port range has no single port and never
// matches (the rules reply lists it with port 0: a schema limit, examples/api.md).
func (k editKey) matches(r *rules.Rule) bool {
	port := r.Ports == nil && k.port == 0 || len(r.Ports) == 1 && r.Ports[0] == k.port
	return r.Program == k.program && r.To == k.to && r.Proto == k.proto && port
}

func (k editKey) ports() []uint16 {
	if k.port == 0 {
		return nil
	}
	return []uint16{k.port}
}

func editVerdict(s string) (rules.Verdict, error) {
	switch s {
	case "allow":
		return rules.Allow, nil
	case "deny":
		return rules.Deny, nil
	}
	return 0, fmt.Errorf("verdict %q: want allow or deny", s)
}

// ruleAdd: every check first (nothing is written on an error), then the overlay with the rule
// appended, validated merged over the deployed file, then written.
func (d *daemon) ruleAdd(req api.Request) (string, error) {
	verdict, err := editVerdict(req.Verdict)
	if err != nil {
		return "", err
	}
	key, err := parseEditKey(req)
	if err != nil {
		return "", err
	}
	snap := d.st.current()
	contract.Require(snap != nil, "ruleAdd before the first snapshot")
	ov, err := d.loadOverlay()
	if err != nil {
		return "", err
	}
	if key.program, err = d.editProgram(snap, ov, req.Program, req.Path); err != nil {
		return "", err
	}
	if key.program == "any" && verdict == rules.Deny {
		return "", errors.New("a deny for every program is deny by default without a deadline: use snitchd trial")
	}
	ov.Rules = append(ov.Rules, rules.Rule{Program: key.program, To: key.to, Proto: key.proto, Ports: key.ports(),
		Verdict: verdict, Note: req.Note, Source: d.cfg.overlay})
	if err := d.writeOverlay(ov); err != nil {
		return "", err
	}
	return fmt.Sprintf("rule added: %s %s (applies within 5 s)", key, verdictWord(verdict)), nil
}

// editProgram is the rule's program: a name the snapshot knows (or any); or, for a path, the
// program owning that executable (refused with its name: the rule belongs there, and a second
// declaration would be a resolver conflict on the next reload), the overlay's own declaration
// from an earlier add the watch has not loaded yet, or a new ad hoc program named after the
// path's base name, with a suffix when the name is taken.
func (d *daemon) editProgram(snap *snapshot, ov *rules.File, name, path string) (string, error) {
	switch {
	case name != "":
		if name == "any" || slices.ContainsFunc(snap.res.File.Programs, func(p rules.Program) bool { return p.Name == name }) {
			return name, nil
		}
		return "", fmt.Errorf("unknown program %q: declare it in the rules file, or give its path", name)
	case path == "":
		return "", errors.New("missing field: program or path")
	case !filepath.IsAbs(path):
		return "", fmt.Errorf("path %q is not absolute", path)
	}
	owner, err := claimedBy(snap, path, rules.OSFS(d.log))
	if err != nil {
		return "", err
	}
	if owner != "" {
		return "", fmt.Errorf("executable %s is program %s: use that name", path, owner)
	}
	for _, p := range ov.Programs {
		if slices.Contains(p.Paths, path) {
			return p.Name, nil
		}
	}
	name = adHocName(filepath.Base(path), snap, ov)
	ov.Programs = append(ov.Programs, rules.Program{Name: name, Paths: []string{path}, Source: d.cfg.overlay})
	return name, nil
}

// claimedBy names the program owning path in the snapshot: one declaring it literally
// (resolved or not), or one the resolver mapped its executable to; "" when none does.
func claimedBy(snap *snapshot, path string, fsys rules.FS) (string, error) {
	for _, p := range snap.res.File.Programs {
		if slices.Contains(p.Paths, path) {
			return p.Name, nil
		}
	}
	target, err := fsys.EvalSymlink(path)
	if err != nil {
		return "", err
	}
	key, err := fsys.Identity(target)
	if err != nil {
		return "", err
	}
	if id, ok := snap.res.Programs[key]; ok {
		return snap.res.Names[id], nil
	}
	return "", nil
}

// adHocName is base, or base-2, base-3, ... past the names the snapshot and the overlay
// already use (and the reserved any).
func adHocName(base string, snap *snapshot, ov *rules.File) string {
	taken := map[string]bool{"any": true}
	for _, p := range snap.res.File.Programs {
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

// ruleRemove: a matching rule in the effective set that is not the overlay's names its file to
// edit (Req 5.3); otherwise the overlay's matching rules go and the file is written.
func (d *daemon) ruleRemove(req api.Request) (string, error) {
	key, err := parseEditKey(req)
	if err != nil {
		return "", err
	}
	snap := d.st.current()
	contract.Require(snap != nil, "ruleRemove before the first snapshot")
	for i := range snap.res.File.Rules {
		if r := &snap.res.File.Rules[i]; key.matches(r) && r.Source != d.cfg.overlay {
			return "", fmt.Errorf("rule %d (%s) is in the deployed file: edit %s", r.ID, key, r.Source)
		}
	}
	ov, err := d.loadOverlay()
	if err != nil {
		return "", err
	}
	left := slices.DeleteFunc(slices.Clone(ov.Rules), func(r rules.Rule) bool { return key.matches(&r) })
	if len(left) == len(ov.Rules) {
		return "", fmt.Errorf("no overlay rule matches %s", key)
	}
	ov.Rules = left
	if err := d.writeOverlay(ov); err != nil {
		return "", err
	}
	return fmt.Sprintf("rule removed: %s (applies within 5 s)", key), nil
}

// loadOverlay reads the overlay file; none yet is an empty one. No overlay path configured
// (-overlay "") leaves nothing to edit.
func (d *daemon) loadOverlay() (*rules.File, error) {
	if d.cfg.overlay == "" {
		return nil, errors.New("no overlay file configured (-overlay): nothing to edit")
	}
	f, err := rules.LoadOverlay(d.cfg.overlay)
	if errors.Is(err, fs.ErrNotExist) {
		return &rules.File{Name: d.cfg.overlay}, nil
	}
	return f, err
}

// writeOverlay validates ov merged over the deployed file as the reload will (an invalid
// union is the error and nothing is written), then writes it under the header; the
// directory is created for a first write.
func (d *daemon) writeOverlay(ov *rules.File) error {
	base, err := rules.Load(d.cfg.rules)
	if errors.Is(err, fs.ErrNotExist) {
		base, err = &rules.File{Name: d.cfg.rules}, nil
	}
	if err != nil {
		return err
	}
	if _, err := rules.Merge(base, ov); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(d.cfg.overlay), 0o755); err != nil {
		return err
	}
	return rules.WriteWith(d.cfg.overlay, ov, overlayHeader)
}
