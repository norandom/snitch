// Compiler tests pin allow-only compilation and the shared address encoder.
package dns

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/rules"
)

func compilerRules(rs ...rules.Rule) *rules.Resolved {
	return &rules.Resolved{File: &rules.File{Rules: rs}, Names: map[uint32]string{7: "browser"}}
}

func nameRule(id uint32, proto rules.Proto, ports ...uint16) rules.Rule {
	return rules.Rule{Program: "any", Name: "example.com", Proto: proto, Ports: ports, ID: id, Verdict: rules.Allow}
}

func TestSlotsLayout(t *testing.T) {
	a, b, c := nameRule(1, rules.AnyProto), nameRule(2, rules.TCP, 443), nameRule(3, rules.UDP, 53)
	b.Program = "browser"
	res := compilerRules(a, b, c, rules.Rule{To: netip.MustParsePrefix("192.0.2.0/24")})
	got, err := Slots(res)
	want := [SlotsMax]Slot{{ID: 1}, {Program: 7, Proto: rules.TCP, Port: 443, ID: 2}, {Proto: rules.UDP, Port: 53, ID: 3}}
	if err != nil || len(got) != 1 || got[key("example.com")] != want {
		t.Fatalf("Slots = %v, %v; want %v", got, err, want)
	}
}

func TestSlotsRefusesOneOverTheKernelSlots(t *testing.T) {
	var full []rules.Rule
	for id := uint32(1); id <= SlotsMax; id++ {
		full = append(full, nameRule(id, 0))
	}
	res := compilerRules(full...)
	if _, err := Slots(res); err != nil {
		t.Fatal(err)
	}
	res.File.Rules = append(res.File.Rules, nameRule(SlotsMax+1, 0))
	if _, err := Slots(res); err == nil || !strings.Contains(err.Error(), "example.com") {
		t.Fatalf("missing domain error: %v", err)
	}
}

func TestSlotsExpandLikeTheEncoder(t *testing.T) {
	// an any-proto rule with a port is tcp and udp in the kernel too: a slot {proto 0, port}
	// would insert a key decide() never looks up and the daemon never produces
	r := nameRule(1, rules.AnyProto, 443)
	got, err := Slots(compilerRules(r))
	want := [SlotsMax]Slot{{Proto: rules.TCP, Port: 443, ID: 1}, {Proto: rules.UDP, Port: 443, ID: 1}}
	if err != nil || got[key("example.com")] != want {
		t.Fatalf("Slots = %v, %v; want %v", got, err, want)
	}
	nine := compilerRules(r, nameRule(2, rules.AnyProto, 80), nameRule(3, rules.AnyProto, 8080), nameRule(4, rules.AnyProto, 8443), nameRule(5, rules.TCP, 22))
	if _, err := Slots(nine); err == nil {
		t.Fatal("nine combinations on one name must be refused")
	}
}

func TestComputeExpansion(t *testing.T) {
	for _, addr := range []netip.Addr{netip.MustParseAddr("192.0.2.1"), netip.MustParseAddr("2001:db8::1")} {
		for _, rule := range []rules.Rule{nameRule(1, 0), nameRule(2, rules.TCP, 443), nameRule(3, 0, 80, 443)} {
			rule.Program = "browser"
			var c Compiled
			got := c.Compute(compilerRules(rule), addr, []string{"badexample.com", "api.example.com", "example.com"})
			host := rule
			host.Name, host.To = "", netip.PrefixFrom(addr, addr.BitLen())
			encoded := rules.Encode(compilerRules(host)).Rules
			want := map[rules.RuleKey]Entry{}
			for k := range encoded {
				want[k] = Entry{ID: rule.ID, Name: "api.example.com"}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("Compute(%v, %v) = %v; want %v", addr, rule, got, want)
			}
		}
	}
}

func TestComputeIgnoresUncoveredAndAddressRules(t *testing.T) {
	var c Compiled
	res := compilerRules(nameRule(1, 0), rules.Rule{To: netip.MustParsePrefix("192.0.2.1/32")})
	if got := c.Compute(res, netip.MustParseAddr("192.0.2.1"), []string{"badexample.com"}); len(got) != 0 {
		t.Fatal(got)
	}
}

func TestContractComputeNeedsResolved(t *testing.T) {
	var c Compiled
	contracttest.Panics(t, contract.Precondition, func() { c.Compute(nil, netip.MustParseAddr("192.0.2.1"), nil) })
}

func TestCompiledValuesAreAllow(t *testing.T) {
	var c Compiled
	rule := nameRule(1, 0)
	rule.Verdict = rules.Deny
	addr := netip.MustParseAddr("192.0.2.1")
	want := c.Compute(compilerRules(rule), addr, []string{"example.com"})
	puts, _ := c.Apply(addr, want, nil)
	if len(puts) != 1 {
		t.Fatal(puts)
	}
	for _, v := range puts {
		if v.Verdict != uint8(rules.Allow) || v.Id != 1 {
			t.Fatal(v)
		}
	}
}
