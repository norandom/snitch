// egress.go aggregates egress byte flows per sender and destination for the egress graph,
// and computes the logarithmic bar scale (1 KiB to largest flow) and eighth-cell bars.
//
// Fail-safe implications: none on kernel egress. Pure data transformation over store entries.
package table

import (
	"cmp"
	"math"
	"slices"
	"strings"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/ask"
	"github.com/norandom/snitch/internal/clean"
)

const (
	scaleFloorBytes = 1024 // 1 KiB lower bound of the logarithmic scale
	scaleMinBiggest = 2048 // 2 KiB denominator floor avoids ln(1) = 0
	scaleMinFrac    = 0.04
)

var barBlocks = []rune{' ', '▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'}

// Dest is one destination under a sender in the egress graph, named by hostname when known
// or by IP address otherwise.
type Dest struct {
	Name  clean.Safe
	Bytes uint64
}

// Flow is one sender program's aggregated egress bytes, rate, top destinations, and the
// count and byte total of any remaining destinations.
type Flow struct {
	Sender    clean.Safe
	Total     uint64
	Rate      float64
	Dests     []Dest
	More      int
	MoreBytes uint64
}

type destKey struct {
	named bool
	label clean.Safe
}

type senderFlow struct {
	who    string
	isPath bool
	total  uint64
	rate   float64
	dests  map[destKey]uint64
}

// Flows returns up to top programs that sent bytes, ordered largest Total first, each with
// up to per destinations ordered largest Bytes first and any remainder summed into More
// and MoreBytes.
func Flows(s Store, top, per int) []Flow {
	if s.Len() == 0 || top <= 0 {
		return nil
	}
	if per < 0 {
		per = 0
	}
	senders := groupFlows(s)
	if len(senders) == 0 {
		return nil
	}
	if len(senders) > top {
		senders = senders[:top]
	}
	out := make([]Flow, len(senders))
	for i, sf := range senders {
		out[i] = buildFlow(sf, per)
	}
	return out
}

func groupFlows(s Store) []*senderFlow {
	byWho := make(map[string]*senderFlow)
	for k, e := range s.entries {
		if e.BytesSent == 0 || isBucket(e) || (e.Name == "" && e.Addr == "") {
			continue
		}
		sf := byWho[k.Who]
		if sf == nil {
			sf = &senderFlow{
				who:    k.Who,
				isPath: e.Program == ask.Unknown && e.Path != "",
				dests:  make(map[destKey]uint64),
			}
			byWho[k.Who] = sf
		}
		sf.total += e.BytesSent
		sf.rate += e.Rate
		sf.dests[flowDestKey(e)] += e.BytesSent
	}
	out := make([]*senderFlow, 0, len(byWho))
	for _, sf := range byWho {
		out = append(out, sf)
	}
	slices.SortFunc(out, func(a, b *senderFlow) int {
		return cmp.Or(cmp.Compare(b.total, a.total), cmp.Compare(a.who, b.who))
	})
	return out
}

func flowDestKey(e api.Entry) destKey {
	if e.Name != "" {
		return destKey{named: true, label: clean.Name(e.Name)}
	}
	return destKey{label: clean.Text(e.Addr)}
}

func buildFlow(sf *senderFlow, per int) Flow {
	dests := make([]Dest, 0, len(sf.dests))
	for dk, bytes := range sf.dests {
		dests = append(dests, Dest{Name: dk.label, Bytes: bytes})
	}
	slices.SortFunc(dests, func(a, b Dest) int {
		return cmp.Or(cmp.Compare(b.Bytes, a.Bytes), cmp.Compare(a.Name, b.Name))
	})
	var more int
	var moreBytes uint64
	if len(dests) > per {
		for _, d := range dests[per:] {
			moreBytes += d.Bytes
		}
		more = len(dests) - per
		dests = dests[:per]
	}
	return Flow{
		Sender:    progTitle(sf.who, sf.isPath),
		Total:     sf.total,
		Rate:      sf.rate,
		Dests:     dests,
		More:      more,
		MoreBytes: moreBytes,
	}
}

// Scale maps a byte count b against biggest onto [0, 1] using a logarithmic scale from
// 1 KiB to max(biggest, 2 KiB), floored at 0.04 for positive counts so small flows stay visible.
func Scale(b, biggest uint64) float64 {
	if b == 0 {
		return 0
	}
	num := math.Log(float64(max(b, scaleFloorBytes)) / scaleFloorBytes)
	den := math.Max(1e-9, math.Log(float64(max(biggest, scaleMinBiggest))/scaleFloorBytes))
	return min(1.0, max(scaleMinFrac, num/den))
}

// Bar renders frac (in [0, 1]) as up to width horizontal block characters at 1/8-cell
// precision, returning at least one eighth-block when frac > 0 and width > 0.
func Bar(frac float64, width int) clean.Safe {
	if !(frac > 0) || width <= 0 {
		return ""
	}
	frac = min(frac, 1.0)
	cells := frac * float64(width)
	var b strings.Builder
	b.Grow(width * 3)
	for i := range width {
		part := min(1.0, max(0.0, cells-float64(i)))
		if part <= 0 {
			break
		}
		idx := max(1, int(math.RoundToEven(part*8)))
		b.WriteRune(barBlocks[idx])
	}
	return clean.Text(b.String())
}
