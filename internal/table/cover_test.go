package table

import (
	"testing"

	"github.com/norandom/snitch/internal/api"
)

const (
	testBase    = "/etc/snitch/rules.toml"
	testOverlay = "/etc/snitch/rules.d/local.toml"
)

type coverOrderCase struct {
	name   string
	rules  []api.RuleView
	wantID int
}

var coverOrderingCases = []coverOrderCase{
	{
		name: "program-specific beats any-program despite narrower dest/proto/port",
		rules: []api.RuleView{
			{Id: 10, Program: "any", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "allow", Source: testBase},
			{Id: 1, Program: "curl", To: "0.0.0.0/0", Protocol: "", Port: 0, Verdict: "deny", Source: testBase},
		},
		wantID: 1,
	},
	{
		name: "exact proto and port beats exact proto with port 0 despite shorter prefix",
		rules: []api.RuleView{
			{Id: 10, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 0, Verdict: "allow", Source: testBase},
			{Id: 2, Program: "curl", To: "1.1.0.0/16", Protocol: "tcp", Port: 443, Verdict: "deny", Source: testBase},
		},
		wantID: 2,
	},
	{
		name: "exact proto with port 0 beats any proto with port 0 despite shorter prefix",
		rules: []api.RuleView{
			{Id: 10, Program: "curl", To: "1.1.1.1/32", Protocol: "any", Port: 0, Verdict: "allow", Source: testBase},
			{Id: 3, Program: "curl", To: "1.1.0.0/16", Protocol: "tcp", Port: 0, Verdict: "deny", Source: testBase},
		},
		wantID: 3,
	},
	{
		name: "longest prefix wins within same program and proto/port tier",
		rules: []api.RuleView{
			{Id: 10, Program: "curl", To: "1.0.0.0/8", Protocol: "tcp", Port: 443, Verdict: "allow", Source: testBase},
			{Id: 4, Program: "curl", To: "1.1.1.0/24", Protocol: "tcp", Port: 443, Verdict: "deny", Source: testBase},
			{Id: 5, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "allow", Source: testBase},
		},
		wantID: 5,
	},
	{
		name: "explicit host CIDR beats name rule",
		rules: []api.RuleView{
			{Id: 10, Program: "curl", To: "api.example.com", Protocol: "tcp", Port: 443, Verdict: "allow", Source: testBase},
			{Id: 6, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "deny", Source: testBase},
		},
		wantID: 6,
	},
	{
		name: "longer domain name beats shorter suffix and beats non-host CIDR",
		rules: []api.RuleView{
			{Id: 1, Program: "curl", To: "1.1.1.0/24", Protocol: "tcp", Port: 443, Verdict: "allow", Source: testBase},
			{Id: 2, Program: "curl", To: "example.com", Protocol: "tcp", Port: 443, Verdict: "allow", Source: testBase},
			{Id: 3, Program: "curl", To: "API.Example.COM.", Protocol: "tcp", Port: 443, Verdict: "deny", Source: testBase},
		},
		wantID: 3,
	},
}

func TestCoverOrderingSteps(t *testing.T) {
	k := Key{Who: "curl", Addr: "1.1.1.1", Proto: "tcp", Port: 443}
	for _, tc := range coverOrderingCases {
		t.Run(tc.name, func(t *testing.T) {
			got := Cover(Rules{Views: tc.rules, Overlay: testOverlay}, k, "api.example.com.", Address)
			if !got.Found || got.Rule.Id != tc.wantID {
				t.Fatalf("got Found=%v Id=%d, want Found=true Id=%d", got.Found, got.Rule.Id, tc.wantID)
			}
		})
	}
}

func TestCoverAddressFamilies(t *testing.T) {
	rules := Rules{
		Overlay: testOverlay,
		Views: []api.RuleView{
			{Id: 1, Program: "curl", To: "0.0.0.0/0", Protocol: "", Port: 0, Verdict: "deny", Source: testBase},
			{Id: 2, Program: "curl", To: "::/0", Protocol: "", Port: 0, Verdict: "allow", Source: testBase},
			{Id: 3, Program: "curl", To: "2001:db8::/32", Protocol: "tcp", Port: 443, Verdict: "deny", Source: testBase},
			{Id: 4, Program: "curl", To: "api.example.com", Protocol: "tcp", Port: 443, Verdict: "allow", Source: testBase},
			{Id: 5, Program: "curl", To: "2001:db8::1/128", Protocol: "tcp", Port: 443, Verdict: "deny", Source: testBase},
		},
	}
	// IPv4-mapped IPv6 unmaps to IPv4 and matches 0.0.0.0/0, not ::/0.
	got4 := Cover(rules, Key{Who: "curl", Addr: "::ffff:9.9.9.9", Proto: "udp", Port: 53}, "", Address)
	if !got4.Found || got4.Rule.Id != 1 {
		t.Fatalf("v4-mapped got Found=%v Id=%d, want Id=1", got4.Found, got4.Rule.Id)
	}
	// Zone-stripped IPv6 /128 beats name rule and /32.
	got6 := Cover(rules, Key{Who: "curl", Addr: "2001:db8::1%eth0", Proto: "tcp", Port: 443}, "api.example.com", Address)
	if !got6.Found || got6.Rule.Id != 5 {
		t.Fatalf("v6 /128 got Found=%v Id=%d, want Id=5", got6.Found, got6.Rule.Id)
	}
	// Name rule (/128 rank) beats /32 on IPv6 when no /128 CIDR exists.
	gotName6 := Cover(rules, Key{Who: "curl", Addr: "2001:db8::2", Proto: "tcp", Port: 443}, "api.example.com", Address)
	if !gotName6.Found || gotName6.Rule.Id != 4 {
		t.Fatalf("v6 name got Found=%v Id=%d, want Id=4", gotName6.Found, gotName6.Rule.Id)
	}
}

func TestCoverProgramResolution(t *testing.T) {
	r := Rules{
		Overlay: testOverlay,
		Programs: []api.ProgramView{
			{Name: "dig", Paths: []string{"/usr/bin/dig", "/usr/local/bin/*"}, Source: testOverlay},
		},
		Views: []api.RuleView{
			{Id: 1, Program: "", To: "0.0.0.0/0", Verdict: "allow", Source: testBase},
			{Id: 2, Program: "dig", To: "8.8.8.8/32", Protocol: "udp", Port: 53, Verdict: "deny", Source: testOverlay},
		},
	}
	for _, who := range []string{"dig", "/usr/bin/dig", "/usr/local/bin/dig"} {
		got := Cover(r, Key{Who: who, Addr: "8.8.8.8", Proto: "udp", Port: 53}, "", Address)
		if !got.Found || got.Rule.Id != 2 {
			t.Fatalf("who=%q got Found=%v Id=%d, want Id=2", who, got.Found, got.Rule.Id)
		}
	}
	// Unmatched program falls back to any-program rule (Id 1).
	gotOther := Cover(r, Key{Who: "/opt/other", Addr: "8.8.8.8", Proto: "udp", Port: 53}, "", Address)
	if !gotOther.Found || gotOther.Rule.Id != 1 {
		t.Fatalf("other who got Found=%v Id=%d, want Id=1", gotOther.Found, gotOther.Rule.Id)
	}
}

func TestCoverLevelsAndClassification(t *testing.T) {
	r := Rules{
		Overlay: testOverlay,
		Views: []api.RuleView{
			{Id: 1, Program: "any", To: "0.0.0.0/0", Verdict: "deny", Source: testBase},
			{Id: 2, Program: "curl", To: "0.0.0.0/0", Verdict: "deny", Source: testOverlay},
			{Id: 3, Program: "curl", To: "1.1.1.0/24", Protocol: "tcp", Port: 0, Verdict: "deny", Source: testBase},
			{Id: 4, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "deny", Source: testBase},
		},
	}
	k := Key{Who: "curl", Addr: "1.1.1.1", Proto: "tcp", Port: 443}
	kSub := Key{Who: "curl", Addr: "1.1.1.2", Proto: "tcp", Port: 443}
	if got := Cover(r, k, "", Bucket); got.Found {
		t.Fatalf("Bucket should not match, got %+v", got)
	}
	cases := []struct {
		name              string
		k                 Key
		dns               string
		at                Level
		wantID            int
		wantOwn, wantOver bool
		wantBy            Level
	}{
		{"Program own", k, "", Program, 2, true, true, Program},
		{"Program any-rule", Key{Who: "other", Addr: "1.1.1.1"}, "", Program, 1, false, false, Program},
		{"Address own file", k, "", Address, 4, true, false, Address},
		{"Address via subnet", kSub, "", Address, 3, false, false, Host},
		{"Group own subnet", kSub, "", Group, 3, true, false, Group},
		{"Host own subnet", kSub, "h.example", Host, 3, true, false, Host},
		{"Host by address rule", k, "h.example", Host, 4, false, false, Address},
		{"Group by address rule", k, "", Group, 4, false, false, Address},
	}
	for _, tc := range cases {
		got := Cover(r, tc.k, tc.dns, tc.at)
		want := Covering{Found: true, Own: tc.wantOwn, Overlay: tc.wantOver, By: tc.wantBy}
		if !got.Found || got.Rule.Id != tc.wantID || got.Own != want.Own || got.Overlay != want.Overlay || got.By != want.By {
			t.Fatalf("%s: got %+v, want Id=%d %+v", tc.name, got, tc.wantID, want)
		}
	}
}

func TestCoverProgramEmptyAddrFamilyFilter(t *testing.T) {
	r := Rules{
		Overlay: testOverlay,
		Views: []api.RuleView{
			{Id: 1, Program: "curl", To: "::/0", Protocol: "any", Port: 0, Verdict: "deny", Source: testOverlay},
			{Id: 2, Program: "curl", To: "0.0.0.0/0", Protocol: "tcp", Port: 0, Verdict: "deny", Source: testOverlay},
		},
	}
	// Id 2 has Protocol "tcp", so it is not program-wide.
	// With empty Addr, ::/0 matches; with IPv4 Addr, ::/0 does not match.
	if got := Cover(r, Key{Who: "curl"}, "", Program); !got.Found || got.Rule.Id != 1 {
		t.Fatalf("empty addr Program got %+v, want Id=1", got)
	}
	if got := Cover(r, Key{Who: "curl", Addr: "1.1.1.1"}, "", Program); got.Found {
		t.Fatalf("v4 addr should not match ::/0, got %+v", got)
	}
}

func TestCoverOverlayAgainstFile(t *testing.T) {
	r := Rules{
		Overlay: testOverlay,
		Views: []api.RuleView{
			{Id: 20, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "allow", Source: testBase},
			{Id: 5, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "deny", Source: testOverlay},
		},
	}
	got := Cover(r, Key{Who: "curl", Addr: "1.1.1.1", Proto: "tcp", Port: 443}, "", Address)
	if !got.Found || got.Rule.Id != 5 || !got.Overlay || !got.Own {
		t.Fatalf("overlay tie-break got %+v, want Id=5 Overlay=true Own=true", got)
	}
	// Empty Overlay must not falsely mark rules with empty Source as Overlay.
	noOverlay := Cover(Rules{Views: []api.RuleView{{Id: 1, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443}}},
		Key{Who: "curl", Addr: "1.1.1.1", Proto: "tcp", Port: 443}, "", Address)
	if !noOverlay.Found || noOverlay.Overlay {
		t.Fatalf("empty Overlay should yield Overlay=false, got %+v", noOverlay)
	}
	// Same source tie-breaks by higher Rule.Id.
	sameSrc := Cover(Rules{
		Overlay: testOverlay,
		Views: []api.RuleView{
			{Id: 3, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "allow", Source: testBase},
			{Id: 9, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "deny", Source: testBase},
		},
	}, Key{Who: "curl", Addr: "1.1.1.1", Proto: "tcp", Port: 443}, "", Address)
	if !sameSrc.Found || sameSrc.Rule.Id != 9 {
		t.Fatalf("higher Id tie-break got %+v, want Id=9", sameSrc)
	}
}

// Known limit: snitchd reports a port-range rule with Port: 0 on the wire, so Cover treats it
// as covering every port under that protocol (wider than the kernel's actual range).
func TestCoverLimitPortRangeReportedAsPortZero(t *testing.T) {
	r := Rules{
		Views: []api.RuleView{
			{Id: 1, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 0, Verdict: "deny", Source: testBase},
		},
	}
	got := Cover(r, Key{Who: "curl", Addr: "1.1.1.1", Proto: "tcp", Port: 9000}, "", Address)
	if !got.Found || got.Rule.Id != 1 || got.Own || got.By != Host {
		t.Fatalf("port-range-as-0 got %+v, want Found=true Own=false By=Host", got)
	}
}

// Known limit: a name rule matches only when the entry carries the resolved DNS name; once the
// daemon stops attaching a name to the entry, the name rule no longer covers it in Cover.
func TestCoverLimitUnattachedNameDoesNotMatch(t *testing.T) {
	r := Rules{
		Views: []api.RuleView{
			{Id: 1, Program: "curl", To: "api.example.com", Protocol: "tcp", Port: 443, Verdict: "allow", Source: testBase},
		},
	}
	k := Key{Who: "curl", Addr: "1.1.1.1", Proto: "tcp", Port: 443}
	if got := Cover(r, k, "api.example.com", Address); !got.Found {
		t.Fatal("expected match when entry carries name")
	}
	if got := Cover(r, k, "", Address); got.Found {
		t.Fatalf("expected no match when entry has no name, got %+v", got)
	}
	if got := Cover(r, k, "notapi.example.com", Address); got.Found {
		t.Fatalf("expected label boundary not to match suffix, got %+v", got)
	}
}

func TestCoverAnyProtoWithPort(t *testing.T) {
	r := Rules{
		Overlay: testOverlay,
		Views: []api.RuleView{
			{Id: 1, Program: "curl", To: "1.1.1.1/32", Protocol: "tcp", Port: 0, Verdict: "allow", Source: testBase},
			{Id: 2, Program: "curl", To: "1.1.0.0/16", Protocol: "", Port: 443, Verdict: "deny", Source: testOverlay},
			{Id: 3, Program: "curl", To: "1.1.1.1/32", Protocol: "udp", Port: 0, Verdict: "allow", Source: testBase},
			{Id: 4, Program: "curl", To: "1.1.0.0/16", Protocol: "any", Port: 53, Verdict: "deny", Source: testOverlay},
		},
	}
	for _, tc := range []struct {
		proto     string
		port      uint16
		wantFound bool
		wantID    int
	}{
		{"tcp", 443, true, 2},
		{"UDP", 53, true, 4},
		{"icmp", 443, false, 0},
		{"1", 53, false, 0},
	} {
		got := Cover(r, Key{Who: "curl", Addr: "1.1.1.1", Proto: tc.proto, Port: tc.port}, "", Address)
		if got.Found != tc.wantFound || got.Rule.Id != tc.wantID {
			t.Fatalf("%s/%d got %+v, want Found=%v Id=%d", tc.proto, tc.port, got, tc.wantFound, tc.wantID)
		}
	}
	for _, proto := range []string{"", "any"} {
		hostAny := Rules{Overlay: testOverlay, Views: []api.RuleView{
			{Id: 5, Program: "curl", To: "1.1.1.1/32", Protocol: proto, Port: 443, Verdict: "deny", Source: testOverlay},
		}}
		got := Cover(hostAny, Key{Who: "curl", Addr: "1.1.1.1", Proto: "tcp", Port: 443}, "", Address)
		if !got.Found || got.Rule.Id != 5 || got.Own || got.By != Host {
			t.Fatalf("proto=%q Own at Address: got %+v, want Id=5 Own=false By=Host", proto, got)
		}
	}
}
