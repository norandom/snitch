// Name destinations aggregate rotating addresses without broadening learned allow rules.
package rules

import "net/netip"

// A name owns the destination identity; retaining the address would split rotating answers.
func destinationKey(s subject, name string, addr netip.Addr, proto Proto, port uint16) learnKey {
	if name != "" {
		addr = netip.Addr{}
	}
	return learnKey{subject: s, name: name, addr: addr, proto: proto, port: port}
}

func setLearnedDestination(r *Rule, k learnKey) {
	if k.name != "" {
		r.Name = k.name
		return
	}
	r.To = netip.PrefixFrom(k.addr, k.addr.BitLen())
}
