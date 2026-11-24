// icons_test.go: the six state icons as pixmaps (requirements 2.1, 2.7): every
// state drawn at both sizes in the StatusNotifierItem wire format, no two states
// alike, and every pixmap carrying a light and a dark opaque pixel, which is the
// halo trick that keeps the icon readable on a light and on a dark panel. The PNG
// helper renders the twelve icons for human eyes. None of this needs a bus.
package sni

import (
	"bytes"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"os"
	"path/filepath"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/tray"
)

// allStates lists the six states in the design's order.
var allStates = [...]tray.State{tray.Gone, tray.Kill, tray.RulesError, tray.Kept, tray.Trial, tray.Monitor}

// stateNames names the PNG files (tray-gone-22.png and so on).
var stateNames = [...]string{"gone", "kill", "rules-error", "kept", "trial", "monitor"}

// pngEnv names the directory the PNG helper writes the twelve icons into, for
// looking at them by hand and for the README's icon set (task 5.3).
const pngEnv = "SNITCH_TRAY_ICONS"

func TestPixmapsComeInBothSizesWithWireLength(t *testing.T) {
	for _, s := range allStates {
		pm := Pixmaps(s)
		if len(pm) != 2 {
			t.Fatalf("%s: %d pixmaps, want the 22 px and the 44 px one", s, len(pm))
		}
		for i, want := range [2]int{22, 44} {
			p := pm[i]
			if p.W != want || p.H != want {
				t.Errorf("%s: pixmap %d is %dx%d, want %d px square", s, i, p.W, p.H, want)
			}
			if n := len(p.ARGB); n != 4*want*want {
				t.Errorf("%s: %d ARGB bytes at %d px, want %d (4*W*H, stride 4*W)", s, n, want, 4*want*want)
			}
		}
	}
}

// No pixmap is empty: each icon is really there, not a blank or a stray dot.
func TestPixmapsAreNotEmpty(t *testing.T) {
	for _, s := range allStates {
		for _, p := range Pixmaps(s) {
			n := 0
			for y := 0; y < p.H; y++ {
				n += rowOpaque(p, y)
			}
			// At least 5% drawn, and never zero: an icon must be there at all.
			want := p.W * p.H / 20
			if n == 0 || n < want {
				t.Errorf("%s at %d px: %d of %d pixels opaque, want at least %d", s, p.W, n, p.W*p.H, want)
			}
		}
	}
}

// The six differ at each size: no two states draw the same bytes, so the icon
// alone tells the state (2.1).
func TestPixmapsDifferPairwiseAtEachSize(t *testing.T) {
	for _, size := range [2]int{22, 44} {
		seen := make([][]byte, len(allStates))
		for i, s := range allStates {
			seen[i] = pixmapOf(s, size).ARGB
		}
		for i := 1; i < len(seen); i++ {
			for j := 0; j < i; j++ {
				if bytes.Equal(seen[i], seen[j]) {
					t.Errorf("%s and %s draw the same %d px pixmap", allStates[i], allStates[j], size)
				}
			}
		}
	}
}

// Every pixmap carries a light and a dark opaque pixel: the dark strokes with
// their light halo are what keeps the icon legible on a light and on a dark
// panel (2.7). Luma as the eye weights it: 0.299R + 0.587G + 0.114B.
func TestPixmapsReadOnLightAndDarkPanels(t *testing.T) {
	for _, s := range allStates {
		for _, p := range Pixmaps(s) {
			if !hasTone(p, 160, true) {
				t.Errorf("%s at %d px has no light opaque pixel (the halo is missing)", s, p.W)
			}
			if !hasTone(p, 96, false) {
				t.Errorf("%s at %d px has no dark opaque pixel (the stroke is missing)", s, p.W)
			}
		}
	}
}

// The states differ in shape, not only in colour (design "Icons"): the marked
// states have more opaque pixels than the bare outline, and the filled states
// grow with their fills.
func TestPixmapShapesGrowWithMarksAndFills(t *testing.T) {
	for _, size := range [2]int{22, 44} {
		n := map[tray.State]int{}
		for _, s := range allStates {
			n[s] = opaqueOf(s, size)
		}
		if n[tray.Monitor] >= n[tray.Trial] || n[tray.Trial] >= n[tray.Kept] {
			t.Errorf("%d px: fill grows nothing: monitor %d, trial %d, kept %d", size, n[tray.Monitor], n[tray.Trial], n[tray.Kept])
		}
		if n[tray.Monitor] >= n[tray.Kill] || n[tray.Monitor] >= n[tray.RulesError] {
			t.Errorf("%d px: marks add nothing: monitor %d, kill %d, rules error %d", size, n[tray.Monitor], n[tray.Kill], n[tray.RulesError])
		}
	}
}

// A state outside the six is a wiring bug, not a seventh icon, so it is a
// precondition violation (house rule: a contract needs a violation test).
func TestPixmapsOfAnUnknownStateIsAViolation(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() {
		Pixmaps(tray.State(len(allStates)))
	})
}

// TestPixmapsPNGHelper writes the twelve PNGs (six states, both sizes) into the
// directory named by SNITCH_TRAY_ICONS, for looking at the icons and for the
// README's icon set (task 5.3). It skips when the variable is unset, so an
// ordinary test run writes nothing.
func TestPixmapsPNGHelper(t *testing.T) {
	dir := os.Getenv(pngEnv)
	if dir == "" {
		t.Skipf("set %s to a directory to write the icon PNGs into", pngEnv)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("%s: %v", dir, err)
	}
	for i, s := range allStates {
		for _, p := range Pixmaps(s) {
			name := filepath.Join(dir, fmt.Sprintf("tray-%s-%d.png", stateNames[i], p.W))
			if err := writePNG(name, p); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
	}
}

// writePNG renders one pixmap as a PNG file. The palette is fully opaque or
// fully transparent, so straight alpha equals premultiplied and NRGBA is exact.
func writePNG(name string, p Pixmap) error {
	img := image.NewRGBA(image.Rect(0, 0, p.W, p.H))
	for y := 0; y < p.H; y++ {
		for x := 0; x < p.W; x++ {
			i := (y*p.W + x) * 4
			img.Set(x, y, color.NRGBA{A: p.ARGB[i], R: p.ARGB[i+1], G: p.ARGB[i+2], B: p.ARGB[i+3]})
		}
	}
	f, err := os.Create(name)
	if err != nil {
		return err
	}
	if err := png.Encode(f, img); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// rowOpaque counts the fully opaque pixels of one pixmap row.
func rowOpaque(p Pixmap, y int) int {
	n := 0
	for x := 0; x < p.W; x++ {
		if p.ARGB[(y*p.W+x)*4] == 0xff {
			n++
		}
	}
	return n
}

// opaqueOf counts the opaque pixels of the state's icon at one size.
func opaqueOf(s tray.State, size int) (n int) {
	p := pixmapOf(s, size)
	for y := 0; y < p.H; y++ {
		n += rowOpaque(p, y)
	}
	return n
}

// pixmapOf picks the state's pixmap of one size out of its pair.
func pixmapOf(s tray.State, size int) Pixmap {
	for _, p := range Pixmaps(s) {
		if p.W == size {
			return p
		}
	}
	return Pixmap{} // unreachable while both sizes ship
}

// hasTone reports whether an opaque pixel sits at or beyond the luma cut:
// at or above it when light, at or below it when dark.
func hasTone(p Pixmap, cut int, light bool) bool {
	for i := 0; i+3 < len(p.ARGB); i += 4 {
		pix := p.ARGB[i : i+4 : i+4]
		if pix[0] != 0xff {
			continue
		}
		luma := (299*int(pix[1]) + 587*int(pix[2]) + 114*int(pix[3])) / 1000
		if light && luma >= cut || !light && luma <= cut {
			return true
		}
	}
	return false
}
