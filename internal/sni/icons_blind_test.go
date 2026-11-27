package sni

import (
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/tray"
)

func isPixelColor(p Pixmap, x, y int, c rgba) bool {
	i := (y*p.W + x) * 4
	return p.ARGB[i] == c.a && p.ARGB[i+1] == c.r && p.ARGB[i+2] == c.g && p.ARGB[i+3] == c.b
}

// 6.1: the Blind pixmap draws a red horizontal bar across the shield's middle extending past
// the shield outline on both left and right sides at both 22 px and 44 px.
func TestBlindPixmapHasExtendedRedBar(t *testing.T) {
	for _, size := range [2]int{22, 44} {
		p := pixmapOf(tray.Blind, size)
		midY := size / 2
		leftRed, rightRed := size, -1
		for x := 0; x < size; x++ {
			if isPixelColor(p, x, midY, colRed) {
				if x < leftRed {
					leftRed = x
				}
				if x > rightRed {
					rightRed = x
				}
			}
		}
		// Shield outline sits at ~0.15..0.85; bar must reach outside both edges.
		leftEdge := int(0.15*float64(size)) - 1
		rightEdge := int(0.85*float64(size)) + 1
		if leftRed >= leftEdge || rightRed <= rightEdge {
			t.Errorf("%d px: red bar [%d..%d] does not extend past shield edges (<%d and >%d)",
				size, leftRed, rightRed, leftEdge, rightEdge)
		}
		if opaqueOf(tray.Blind, size) <= opaqueOf(tray.Monitor, size) {
			t.Errorf("%d px: blind icon has no extra mark over monitor", size)
		}
	}
}

// Verify the 8th value (Monitor + 1) triggers the precondition contract violation.
func TestPixmapsOutOfRangeEighthValue(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() {
		Pixmaps(tray.Monitor + 1)
	})
}
