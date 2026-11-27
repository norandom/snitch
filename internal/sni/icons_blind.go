// icons_blind.go draws the Blind state's mark: a red horizontal bar across the shield's
// middle that extends past the outline on both sides, distinct in shape from Kill's diagonal
// slash and Gone's dashed outline.
//
// Fail-safe implications: none on egress; pure pixel geometry.
package sni

// blindMark returns the horizontal red bar across the shield's mid-height, extending past
// the shield's flanks (0.15..0.85) on both sides while keeping room for the light halo.
func blindMark(size int) mark {
	px := float64(size)
	return mark{
		strokes: []path{linePath(pt{0.10 * px, shieldMid * px}, pt{0.90 * px, shieldMid * px})},
		c:       colRed,
	}
}
