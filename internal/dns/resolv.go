// Resolver helpers read configuration without sending queries or touching kernel maps.
package dns

import (
	"bufio"
	"io"
	"net/netip"
	"strings"
)

const ResolversMax = 16

// Resolvers preserves configuration order while bounding the kernel resolver map.
func Resolvers(r io.Reader) []netip.Addr {
	var out []netip.Addr
	seen := make(map[netip.Addr]bool)
	scanner := bufio.NewScanner(r)
	for scanner.Scan() && len(out) < ResolversMax {
		a, ok := resolverLine(scanner.Text())
		if !ok || seen[a] {
			continue
		}
		seen[a] = true
		out = append(out, a)
	}
	return out
}

func resolverLine(line string) (netip.Addr, bool) {
	if i := strings.IndexAny(line, "#;"); i >= 0 {
		line = line[:i]
	}
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "nameserver" {
		return netip.Addr{}, false
	}
	text, _, _ := strings.Cut(fields[1], "%")
	a, err := netip.ParseAddr(text)
	return a.Unmap(), err == nil
}

// ResolverKey uses snitchd's left-aligned IPv4 convention, including mapped IPv6 input.
func ResolverKey(a netip.Addr) [16]byte {
	a = a.Unmap()
	if a.Is4() {
		var key [16]byte
		v4 := a.As4()
		copy(key[:], v4[:])
		return key
	}
	return a.As16()
}
