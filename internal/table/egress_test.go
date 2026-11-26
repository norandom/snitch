package table

import (
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
)

const (
	kib uint64 = 1024
	mib uint64 = 1024 * kib
	gib uint64 = 1024 * mib
)

func topTenFixture() Store {
	var entries []api.Entry
	for i := 1; i <= 12; i++ {
		entries = append(entries, api.Entry{
			Program: fmt.Sprintf("prog%02d", i), Addr: fmt.Sprintf("198.51.100.%d", i),
			Port: 443, Protocol: "tcp", BytesSent: uint64(i) * 1000, Rate: float64(i) * 1.5,
		})
	}
	entries = append(entries,
		api.Entry{Program: "prog12", Addr: "203.0.113.1", Port: 80, Protocol: "tcp", BytesSent: 500, Rate: 2.5},
		api.Entry{Program: "unknown", Path: "/opt/bin/tool", Addr: "9.9.9.9", Port: 53, Protocol: "udp", BytesSent: 11500, Rate: 4.0},
		api.Entry{Program: "silent", Addr: "1.1.1.1", Port: 443, Protocol: "tcp", BytesSent: 0, Rate: 0},
		api.Entry{Program: "unknown", BytesSent: 999999, Rate: 99},
	)
	return (Store{}).Replace(entries)
}

func assertFlowHead(t *testing.T, got Flow, sender string, total uint64, rate float64) {
	t.Helper()
	if string(got.Sender) != sender || got.Total != total || got.Rate != rate {
		t.Fatalf("flow = %+v, want sender=%q total=%d rate=%v", got, sender, total, rate)
	}
}

func TestFlowsTopTenAndSortOrder(t *testing.T) {
	if got := Flows(Store{}, 10, 5); len(got) != 0 {
		t.Fatalf("empty store Flows = %+v, want empty", got)
	}
	s := topTenFixture()
	if got := Flows(s, 0, 5); len(got) != 0 {
		t.Fatalf("top=0 Flows = %+v, want empty", got)
	}
	flows := Flows(s, 10, 5)
	if len(flows) != 10 {
		t.Fatalf("len(flows) = %d, want 10", len(flows))
	}
	assertFlowHead(t, flows[0], "prog12", 12500, 20.5)
	assertFlowHead(t, flows[1], "/opt/bin/tool", 11500, 4.0)
	assertFlowHead(t, flows[9], "prog04", 4000, 6.0)
	for i := 1; i < len(flows); i++ {
		if flows[i].Total > flows[i-1].Total {
			t.Fatalf("flows not descending at %d: %d > %d", i, flows[i].Total, flows[i-1].Total)
		}
		if flows[i].Sender == "silent" || flows[i].Sender == "unknown" {
			t.Fatalf("unexpected sender %q in flows", flows[i].Sender)
		}
	}
}

func destsFixture() Store {
	return (Store{}).Replace([]api.Entry{
		{Program: "curl\x1b[31m", Addr: "1.1.1.1", Name: "api.example.com", Port: 443, Protocol: "tcp", BytesSent: 1000},
		{Program: "curl\x1b[31m", Addr: "2001:db8::1", Name: "api.example.com", Port: 443, Protocol: "tcp", BytesSent: 2000},
		{Program: "curl\x1b[31m", Addr: "9.9.9.9", Port: 53, Protocol: "udp", BytesSent: 1500},
		{Program: "curl\x1b[31m", Addr: "9.9.9.9", Port: 853, Protocol: "tcp", BytesSent: 1000},
		{Program: "curl\x1b[31m", Addr: "192.0.2.1", Name: "bücher.example", Port: 443, Protocol: "tcp", BytesSent: 2000},
		{Program: "curl\x1b[31m", Addr: "192.0.2.2", Name: "cdn.example", Port: 443, Protocol: "tcp", BytesSent: 1800},
		{Program: "curl\x1b[31m", Addr: "192.0.2.3", Port: 443, Protocol: "tcp", BytesSent: 1600},
		{Program: "curl\x1b[31m", Addr: "192.0.2.4", Name: "tail1.example", Port: 443, Protocol: "tcp", BytesSent: 400},
		{Program: "curl\x1b[31m", Addr: "192.0.2.5", Port: 443, Protocol: "tcp", BytesSent: 200},
		{Program: "curl\x1b[31m", Addr: "192.0.2.6", Port: 443, Protocol: "tcp", BytesSent: 0},
	})
}

func TestFlowsDestsAndMore(t *testing.T) {
	s := destsFixture()
	flows := Flows(s, 10, 5)
	if len(flows) != 1 {
		t.Fatalf("len(flows) = %d, want 1", len(flows))
	}
	assertFlowHead(t, flows[0], "curl·[31m", 11500, 0)
	wantDests := []Dest{
		{Name: clean.Const("api.example.com"), Bytes: 3000},
		{Name: clean.Const("9.9.9.9"), Bytes: 2500},
		{Name: clean.Const("xn--bcher-kva.example"), Bytes: 2000},
		{Name: clean.Const("cdn.example"), Bytes: 1800},
		{Name: clean.Const("192.0.2.3"), Bytes: 1600},
	}
	if len(flows[0].Dests) != len(wantDests) {
		t.Fatalf("len(Dests) = %d, want %d: %+v", len(flows[0].Dests), len(wantDests), flows[0].Dests)
	}
	for i, w := range wantDests {
		if flows[0].Dests[i] != w {
			t.Fatalf("Dests[%d] = %+v, want %+v", i, flows[0].Dests[i], w)
		}
	}
	if flows[0].More != 2 || flows[0].MoreBytes != 600 {
		t.Fatalf("More/MoreBytes = %d/%d, want 2/600", flows[0].More, flows[0].MoreBytes)
	}
}

func TestFlowsPerZeroPacksAllIntoMore(t *testing.T) {
	perZero := Flows(destsFixture(), 10, 0)
	if len(perZero) != 1 || len(perZero[0].Dests) != 0 {
		t.Fatalf("per=0 Dests = %+v, want 1 flow with 0 dests", perZero)
	}
	if perZero[0].More != 7 || perZero[0].MoreBytes != 11500 {
		t.Fatalf("per=0 More/MoreBytes = %d/%d, want 7/11500", perZero[0].More, perZero[0].MoreBytes)
	}
}

func TestScaleLogarithmicAndFloor(t *testing.T) {
	wantSmall := math.Log(50) / math.Log(float64(12*gib/kib))
	for _, tc := range []struct {
		b, big uint64
		want   float64
	}{
		{0, 12 * gib, 0},
		{0, 0, 0},
		{12 * gib, 12 * gib, 1.0},
		{512, 12 * gib, 0.04},
		{kib, kib, 0.04},
		{50 * kib, 12 * gib, wantSmall},
	} {
		if got := Scale(tc.b, tc.big); math.Abs(got-tc.want) > 1e-9 {
			t.Fatalf("Scale(%d, %d) = %v, want %v", tc.b, tc.big, got, tc.want)
		}
	}
	vals := []float64{
		Scale(10*kib, 12*gib),
		Scale(50*kib, 12*gib),
		Scale(mib, 12*gib),
		Scale(gib, 12*gib),
	}
	for i := 1; i < len(vals); i++ {
		if vals[i] <= vals[i-1] {
			t.Fatalf("Scale not strictly increasing at %d: %v <= %v", i, vals[i], vals[i-1])
		}
	}
}

func TestBarEighthsPrecision(t *testing.T) {
	for _, tc := range []struct {
		frac float64
		w    int
		want string
	}{
		{0, 10, ""}, {-0.2, 10, ""}, {math.NaN(), 10, ""}, {0.5, 0, ""},
		{1.0 / 8.0, 1, "▏"}, {2.0 / 8.0, 1, "▎"}, {3.0 / 8.0, 1, "▍"}, {4.0 / 8.0, 1, "▌"},
		{5.0 / 8.0, 1, "▋"}, {6.0 / 8.0, 1, "▊"}, {7.0 / 8.0, 1, "▉"}, {8.0 / 8.0, 1, "█"},
		{0.001, 1, "▏"}, {0.5, 4, "██"}, {1.5, 4, "████"},
	} {
		if got := string(Bar(tc.frac, tc.w)); got != tc.want {
			t.Fatalf("Bar(%v, %d) = %q, want %q", tc.frac, tc.w, got, tc.want)
		}
	}
}

func TestBarSmallFlowNextToLargeFlow(t *testing.T) {
	s := (Store{}).Replace([]api.Entry{
		{Program: "big", Addr: "1.1.1.1", Port: 443, Protocol: "tcp", BytesSent: 12 * gib},
		{Program: "small", Addr: "9.9.9.9", Port: 443, Protocol: "tcp", BytesSent: 50 * kib},
	})
	flows := Flows(s, 10, 5)
	if len(flows) != 2 {
		t.Fatalf("len(flows) = %d, want 2", len(flows))
	}
	biggest := flows[0].Total
	bigBar := Bar(Scale(flows[0].Total, biggest), 20)
	smallBar := Bar(Scale(flows[1].Total, biggest), 20)
	if string(bigBar) != strings.Repeat("█", 20) {
		t.Fatalf("12G bar = %q, want 20 full blocks", bigBar)
	}
	if w := clean.Width(smallBar); w < 4 {
		t.Fatalf("50K bar %q width = %d, want >= 4 visible cells", smallBar, w)
	}
}
