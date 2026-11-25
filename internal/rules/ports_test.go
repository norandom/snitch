package rules

import "testing"

// portRange at its edges: one port at each end of 1-65535 (no wrap after 65535), exactly the
// rule limit of 256 ports and one more, and the refused bounds.

func TestPortRangeEdges(t *testing.T) {
	for _, c := range []struct {
		lo, hi int64
		n      int
		ok     bool
	}{{1, 1, 1, true}, {65535, 65535, 1, true}, {65280, 65535, 256, true}, {65279, 65535, 0, false}, {0, 5, 0, false}, {5, 65536, 0, false}, {9, 3, 0, false}} {
		p, err := portRange(c.lo, c.hi)
		if (err == nil) != c.ok || len(p) != c.n || (c.ok && (p[0] != uint16(c.lo) || p[len(p)-1] != uint16(c.hi))) {
			t.Fatalf("%+v: %v %v", c, len(p), err)
		}
	}
}
