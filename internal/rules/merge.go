package rules

import "github.com/norandom/snitch/internal/contract"

// Merge lays overlay over base into a new File (both inputs stay untouched): programs base
// then overlay (a name declared in both is an error naming both files); a base rule is dropped
// whole when any of its expanded keys is one an overlay rule encodes to (an any-proto overlay
// rule for a port removes the base's tcp and udp rules for that key alike; nothing residual is
// synthesised); overlay rules are appended; validation re-runs against the union, so an
// overlay rule for an unknown program fails here and ids are dense in merged order.
func Merge(base, overlay *File) (*File, error) {
	contract.Require(base != nil && overlay != nil, "Merge needs both files")
	out := &File{Name: base.Name}
	out.Programs = append(append(make([]Program, 0, len(base.Programs)+len(overlay.Programs)), base.Programs...), overlay.Programs...)
	shadow := map[ruleKey]bool{}
	for i := range overlay.Rules {
		for _, k := range expandedKeys(&overlay.Rules[i]) {
			shadow[k] = true
		}
	}
	out.Rules = make([]Rule, 0, len(base.Rules)+len(overlay.Rules))
	for i := range base.Rules {
		if !shadowed(&base.Rules[i], shadow) {
			out.Rules = append(out.Rules, base.Rules[i])
		}
	}
	out.Rules = append(out.Rules, overlay.Rules...)
	if err := validate(out, true); err != nil {
		return nil, err
	}
	assertSourced(out)
	return out, nil
}

func shadowed(r *Rule, keys map[ruleKey]bool) bool {
	for _, k := range expandedKeys(r) {
		if keys[k] {
			return true
		}
	}
	return false
}

// assertSourced: every merged record says which file it came from (validate already asserted
// dense ids); a File built by hand instead of by Parse trips it.
func assertSourced(f *File) {
	for _, p := range f.Programs {
		contract.Ensure(p.Source != "", "every merged program has a Source")
	}
	for _, r := range f.Rules {
		contract.Ensure(r.Source != "", "every merged rule has a Source")
	}
}
