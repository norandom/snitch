// icons.go: the six state icons as pixmaps drawn by the program (requirements
// 2.1, 2.7; research.md "icons are pixmaps the program draws"): all six share
// one shield outline, drawn per state as outline, lower half filled, filled,
// outline with a slash, outline with an exclamation mark, dashed outline with
// a cross. Pure drawing — no bus, no clocks, no input. Fail-safe implications:
// none on egress: a change here can only alter what the operator sees.
package sni

import (
	"math"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/tray"
)

// Pixmap is one icon size in the StatusNotifierItem wire format: width, height
// and tightly packed ARGB32 rows in network byte order — one pixel four bytes,
// alpha first, then red, green, blue (the stride is 4*W).
type Pixmap struct {
	W, H int
	ARGB []byte
}

// iconSizes are the sizes the item advertises: the 22 px of the panel and the
// 44 px the desktop may scale for hidpi or larger trays.
var iconSizes = [...]int{22, 44}

// The palette: shape carries the state and ink with its light halo carries the
// geometry (the halo keeps a dark stroke legible on a light and on a dark
// panel, 2.7). Pixels are fully opaque or transparent, so straight alpha
// equals premultiplied on the wire.
var (
	colInk   = rgba{r: 0x1c, g: 0x1c, b: 0x1c, a: 0xff}
	colLight = rgba{r: 0xff, g: 0xff, b: 0xff, a: 0xff}
	colAmber = rgba{r: 0xe8, g: 0x84, b: 0x00, a: 0xff}
	colGreen = rgba{r: 0x1f, g: 0x8a, b: 0x3c, a: 0xff}
	colRed   = rgba{r: 0xd2, g: 0x1f, b: 0x2b, a: 0xff}
)

// Band widths as fractions of the size, so one set of fractions draws the same
// icon at both sizes.
const (
	haloHalf    = 0.10 // light band around an ink stroke
	inkHalf     = 0.05 // stroke half-width of the shield's outline
	markHalf    = 0.06 // mark strokes draw a touch wider than the outline
	dashCell    = 0.30 // the gone icon's dash cell along its outline
	dashOnCell  = 0.55 // the on-share of one dash cell
	shieldMid   = 0.49 // the trial fill's cut line: the shield's mid-height
	shieldSteps = 10   // curve samples per flank
)

// Pixmaps draws the 22 px and the 44 px icon of the state (design "Icons").
// The result is freshly drawn; the caller only reads it.
func Pixmaps(s tray.State) []Pixmap {
	contract.Require(s >= tray.Gone && s <= tray.Monitor, "sni: Pixmaps of an unknown tray state")
	out := make([]Pixmap, len(iconSizes))
	for i, size := range iconSizes {
		out[i] = drawState(s, size)
	}
	return out
}

// drawState paints one state at one size: the shield's halo, then the fill (if
// any), then the mark (if any), and the shield's own stroke last, so a mark's
// halo cannot bite into the shared outline.
func drawState(s tray.State, size int) Pixmap {
	img := make([]rgba, size*size)
	shield := shieldPath(size)
	px := float64(size)
	period := 0.0
	if s == tray.Gone {
		period = dashCell * px // the gone icon alone dashes its outline
	}
	band(img, size, shield.segs, haloHalf*px, period, colLight)
	fillShield(img, size, s, shield.pts)
	paintMark(img, size, markOf(s, size))
	band(img, size, shield.segs, inkHalf*px, period, colInk)
	return encode(img, size)
}

// fillShield paints the filled states: the trial icon fills the lower half, the
// kept icon the whole shield. The others stay outlines.
func fillShield(img []rgba, size int, s tray.State, poly []pt) {
	if s == tray.Kept {
		each(img, size, func(p pt) bool { return inside(poly, p) }, colGreen)
		return
	}
	if s == tray.Trial {
		cut := shieldMid * float64(size)
		each(img, size, func(p pt) bool { return p.y >= cut && inside(poly, p) }, colAmber)
	}
}

// mark is the symbol a state draws inside the shield: stroked paths, plus a
// filled dot for the exclamation mark. dotR 0 means no dot; coordinates are
// pixels of this size's canvas.
type mark struct {
	strokes []path
	dot     pt
	dotR    float64
	c       rgba
}

// markOf returns the state's symbol: the kill switch's slash, the rules error's
// exclamation mark, the gone icon's cross. The others have none.
func markOf(s tray.State, size int) mark {
	px := float64(size)
	u := func(x, y float64) pt { return pt{x * px, y * px} }
	switch s {
	case tray.Kill:
		return mark{strokes: []path{linePath(u(0.30, 0.21), u(0.70, 0.67))}, c: colRed}
	case tray.RulesError:
		return mark{
			strokes: []path{linePath(u(0.5, 0.26), u(0.5, 0.485))},
			dot:     u(0.5, 0.67), dotR: 0.072 * px, c: colAmber,
		}
	case tray.Gone:
		return mark{strokes: []path{
			linePath(u(0.375, 0.33), u(0.625, 0.59)),
			linePath(u(0.625, 0.33), u(0.375, 0.59)),
		}, c: colInk}
	}
	return mark{}
}

// paintMark draws the mark with the halo every dark stroke carries (2.7). The
// shield's stroke painted after it keeps the shared outline whole where the
// mark's halo reaches it.
func paintMark(img []rgba, size int, m mark) {
	px := float64(size)
	half, halo := markHalf*px, (markHalf+inkHalf)*px
	if len(m.strokes) == 0 && m.dotR == 0 {
		return
	}
	for _, p := range m.strokes {
		band(img, size, p.segs, halo, 0, colLight)
	}
	if m.dotR > 0 { // no dot: not even its halo, or a blob lands in a corner
		disk(img, size, m.dot, m.dotR+haloHalf*px, colLight)
	}
	for _, p := range m.strokes {
		band(img, size, p.segs, half, 0, m.c)
	}
	if m.dotR > 0 {
		disk(img, size, m.dot, m.dotR, m.c)
	}
}

// pt is a point on a size-px canvas; paths live in pixel space so the unit
// fractions above draw every size.
type pt struct{ x, y float64 }

// path is a stroked shape: its outline points and the straight pieces between
// them. seg.start is the path length where a piece begins, so halo and stroke
// of one path share a single dash phase along the whole outline.
type path struct {
	pts  []pt
	segs []seg
}

type seg struct {
	a, b  pt
	start float64
}

// linePath turns a polyline into an open path; ringPath turns outline points
// into a closed one whose pieces wrap back to the first.
func linePath(pts ...pt) path { return buildPath(pts, false) }
func ringPath(pts ...pt) path { return buildPath(pts, true) }

// buildPath numbers each piece's starting length along the path.
func buildPath(pts []pt, closed bool) path {
	at, segs := 0.0, make([]seg, 0, len(pts))
	for i := range pts {
		next := i + 1
		if next == len(pts) {
			if !closed {
				break
			}
			next = 0
		}
		segs = append(segs, seg{a: pts[i], b: pts[next], start: at})
		at += dist(pts[i], pts[next])
	}
	return path{pts: pts, segs: segs}
}

// shieldPath is the badge all six states share: a flat top, straight upper
// flanks and curved lower flanks that meet in a tip, placed to leave room for
// the halo at both sizes.
func shieldPath(size int) path {
	px := float64(size)
	u := func(x, y float64) pt { return pt{x * px, y * px} }
	pts := []pt{u(0.15, 0.12), u(0.85, 0.12), u(0.85, 0.42)}
	pts = append(pts, quad(u(0.85, 0.42), u(0.83, 0.66), u(0.5, 0.86), shieldSteps)...)
	pts = append(pts, u(0.5, 0.86)) // the tip itself: quad omits endpoints, the flanks must meet in a point
	pts = append(pts, quad(u(0.5, 0.86), u(0.17, 0.66), u(0.15, 0.42), shieldSteps)...)
	return ringPath(pts...)
}

// quad samples the quadratic Bézier from a to c under the control point b,
// without its endpoints: the callers already have them on their point lists.
func quad(a, b, c pt, n int) []pt {
	out := make([]pt, 0, n-1)
	for i := 1; i < n; i++ {
		t := float64(i) / float64(n)
		s := 1 - t
		out = append(out, pt{
			x: s*s*a.x + 2*s*t*b.x + t*t*c.x,
			y: s*s*a.y + 2*s*t*b.y + t*t*c.y,
		})
	}
	return out
}

// rgba is one drawing colour; icons are painted as opaque layers over nothing.
type rgba struct{ r, g, b, a uint8 }

// each runs over all pixel centres and paints the ones pred accepts.
func each(img []rgba, size int, pred func(p pt) bool, c rgba) {
	for y := 0; y < size; y++ {
		p := pt{y: float64(y) + 0.5}
		for x := 0; x < size; x++ {
			p.x = float64(x) + 0.5
			if pred(p) {
				img[y*size+x] = c
			}
		}
	}
}

// band paints the pixel centres within half of the path, dashing when period
// is above zero. Halo and stroke passed the same period therefore show the
// same dash windows.
func band(img []rgba, size int, segs []seg, half, period float64, c rgba) {
	each(img, size, func(p pt) bool { return inBand(segs, p, half, period) }, c)
}

// inBand reports whether any piece has p within the band with its dash cell on.
func inBand(segs []seg, p pt, half, period float64) bool {
	for _, s := range segs {
		d, along := distSeg(s, p)
		if d <= half && (period == 0 || math.Mod((s.start+along)/period, 1) < dashOnCell) {
			return true
		}
	}
	return false
}

// distSeg returns the distance from p to the piece and the position of the
// closest point along it, in path-length units.
func distSeg(s seg, p pt) (d, along float64) {
	bx, by := s.b.x-s.a.x, s.b.y-s.a.y
	l2 := bx*bx + by*by
	t := 0.0
	if l2 > 0 {
		t = min(max(((p.x-s.a.x)*bx+(p.y-s.a.y)*by)/l2, 0), 1)
	}
	cx, cy := s.a.x+t*bx, s.a.y+t*by
	return math.Hypot(p.x-cx, p.y-cy), t * math.Sqrt(l2)
}

// dist is the distance between two points.
func dist(a, b pt) float64 { return math.Hypot(a.x-b.x, a.y-b.y) }

// disk paints a filled circle of radius r around at (0 draws nothing).
func disk(img []rgba, size int, at pt, r float64, c rgba) {
	each(img, size, func(p pt) bool { return dist(p, at) <= r }, c)
}

// inside is the crossing-number point-in-polygon test; it skips horizontal
// edges, so the shield's flat top never counts as a crossing.
func inside(poly []pt, p pt) bool {
	in := false
	j := len(poly) - 1
	for i := range poly {
		pi, pj := poly[i], poly[j]
		if (pi.y > p.y) != (pj.y > p.y) && p.x < pj.x+(p.y-pj.y)/(pi.y-pj.y)*(pi.x-pj.x) {
			in = !in
		}
		j = i
	}
	return in
}

// encode serialises the raster for the wire: ARGB32 in network byte order —
// alpha, red, green, blue — rows tightly packed, so byte 4*i is pixel i's alpha.
func encode(img []rgba, size int) Pixmap {
	out := make([]byte, len(img)*4)
	for i, p := range img {
		out[i*4], out[i*4+1], out[i*4+2], out[i*4+3] = p.a, p.r, p.g, p.b
	}
	return Pixmap{W: size, H: size, ARGB: out}
}
