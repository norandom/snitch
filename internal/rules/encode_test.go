package rules_test

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
	"github.com/norandom/snitch/internal/rules"
)

func resolved(t *testing.T, src string) *rules.Resolved {
	t.Helper()
	r, err := rules.Resolve(parse(t, src), world.fs())
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func key(prefixlen, program uint32, family, proto uint8, port uint16, addr string) rules.RuleKey {
	k := rules.RuleKey{Prefixlen: prefixlen, Program: program, Family: family, Proto: proto, Port: port}
	a := netip.MustParseAddr(addr)
	if a.Is4() {
		b := a.As4()
		copy(k.Addr[:], b[:])
	} else {
		k.Addr = a.As16()
	}
	return k
}

const curlProgram = "[[program]]\nname = \"curl\"\npaths = [\"/usr/bin/curl\"]\n\n"

func rule(body string) string { return curlProgram + "[[rule]]\n" + body + "\n" }

func TestEncodeKeysFollowTheKernelLayout(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want map[rules.RuleKey]rules.RuleVal
	}{
		{"v4 /32 tcp 443", rule(`program = "curl"` + "\n" + `to = "1.1.1.1/32"` + "\nproto = \"tcp\"\nport = 443\nverdict = \"allow\""),
			map[rules.RuleKey]rules.RuleVal{key(96, 1, 2, 6, 443, "1.1.1.1"): {Verdict: 1, Id: 1}}},
		{"v4 /0 any program deny", rule(`program = "any"` + "\n" + `to = "0.0.0.0/0"` + "\nverdict = \"deny\""),
			map[rules.RuleKey]rules.RuleVal{key(64, 0, 2, 0, 0, "0.0.0.0"): {Verdict: 2, Id: 1}}},
		{"v6 /48 udp any port", rule(`program = "curl"` + "\n" + `to = "2001:db8:1::/48"` + "\nproto = \"udp\"\nverdict = \"allow\""),
			map[rules.RuleKey]rules.RuleVal{key(112, 1, 10, 17, 0, "2001:db8:1::"): {Verdict: 1, Id: 1}}},
		{"port range expands", rule(`program = "curl"` + "\n" + `to = "9.9.9.9"` + "\nproto = \"udp\"\nport = \"67-68\"\nverdict = \"allow\""),
			map[rules.RuleKey]rules.RuleVal{key(96, 1, 2, 17, 67, "9.9.9.9"): {Verdict: 1, Id: 1}, key(96, 1, 2, 17, 68, "9.9.9.9"): {Verdict: 1, Id: 1}}},
		{"port without proto means tcp and udp", rule(`program = "curl"` + "\n" + `to = "1.1.1.1"` + "\nport = 53\nverdict = \"allow\""),
			map[rules.RuleKey]rules.RuleVal{key(96, 1, 2, 6, 53, "1.1.1.1"): {Verdict: 1, Id: 1}, key(96, 1, 2, 17, 53, "1.1.1.1"): {Verdict: 1, Id: 1}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := rules.Encode(resolved(t, c.src)).Rules
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("\n got %+v\nwant %+v", got, c.want)
			}
		})
	}
}

func TestEncodeNeverEmitsAnyProtoWithAPort(t *testing.T) {
	e := rules.Encode(resolved(t, rule(`program = "curl"`+"\n"+`to = "1.1.1.1"`+"\nport = \"80-81\"\nverdict = \"allow\"")))
	for k := range e.Rules {
		if k.Proto == 0 && k.Port != 0 {
			t.Fatalf("dead key (proto 0, port %d): the kernel never probes it", k.Port)
		}
	}
	if len(e.Rules) != 4 {
		t.Fatalf("want 2 ports x 2 protos = 4 entries, got %d", len(e.Rules))
	}
}

func TestEncodePrecedenceTiersAreDistinctKeys(t *testing.T) {
	src := curlProgram +
		"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.0/24\"\nproto = \"tcp\"\nport = 443\nverdict = \"allow\"\n\n" +
		"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.0/24\"\nproto = \"tcp\"\nverdict = \"deny\"\n\n" +
		"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.0/24\"\nverdict = \"allow\"\n\n" +
		"[[rule]]\nprogram = \"any\"\nto = \"1.1.1.0/24\"\nverdict = \"deny\"\n"
	e := rules.Encode(resolved(t, src))
	if len(e.Rules) != 4 {
		t.Fatalf("want 4 distinct keys for the 4 tiers, got %d: %v", len(e.Rules), e.Rules)
	}
	if e.Rules[key(88, 1, 2, 6, 443, "1.1.1.0")].Id != 1 || e.Rules[key(88, 1, 2, 6, 0, "1.1.1.0")].Id != 2 ||
		e.Rules[key(88, 1, 2, 0, 0, "1.1.1.0")].Id != 3 || e.Rules[key(88, 0, 2, 0, 0, "1.1.1.0")].Id != 4 {
		t.Fatalf("tier keys do not carry their rule ids: %v", e.Rules)
	}
}

func TestEncodeCopiesResolvedPrograms(t *testing.T) {
	e := rules.Encode(resolved(t, programs))
	if len(e.Programs) != 4 || e.Programs[rules.ExeKey{Ino: 300, Dev: 8<<20 | 1}] != 3 {
		t.Fatalf("programs not copied: %v", e.Programs)
	}
}

func TestEncodeHostBitsAreZero(t *testing.T) {
	// "1.1.1.77/24" is canonicalised by the parser; the key must carry 1.1.1.0
	e := rules.Encode(resolved(t, rule(`program = "curl"`+"\n"+`to = "1.1.1.77/24"`+"\nverdict = \"allow\"")))
	if _, ok := e.Rules[key(88, 1, 2, 0, 0, "1.1.1.0")]; !ok {
		t.Fatalf("want the masked network in the key, got %v", e.Rules)
	}
}

func TestDiffFirstLoadPutsEverything(t *testing.T) {
	e := rules.Encode(resolved(t, strings.Join([]string{programs}, "")))
	ch := rules.Diff(rules.Entries{}, e)
	if len(ch.PutPrograms) != len(e.Programs) || len(ch.PutRules) != len(e.Rules) || len(ch.DelPrograms) != 0 || len(ch.DelRules) != 0 {
		t.Fatalf("first load: %+v", ch)
	}
}

func TestDiffIdenticalIsEmpty(t *testing.T) {
	e := rules.Encode(resolved(t, programs))
	ch := rules.Diff(e, e)
	if len(ch.PutPrograms)+len(ch.PutRules)+len(ch.DelPrograms)+len(ch.DelRules) != 0 {
		t.Fatalf("identical entries must diff to nothing: %+v", ch)
	}
}

func TestDiffPutsChangedAndNewDeletesRemoved(t *testing.T) {
	old := rules.Encode(resolved(t, curlProgram+
		"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\n\n"+
		"[[rule]]\nprogram = \"curl\"\nto = \"2.2.2.2\"\nverdict = \"allow\"\n"))
	now := rules.Encode(resolved(t, curlProgram+
		"[[rule]]\nprogram = \"curl\"\nto = \"1.1.1.1\"\nverdict = \"deny\"\n\n"+ // changed value
		"[[rule]]\nprogram = \"curl\"\nto = \"3.3.3.3\"\nverdict = \"allow\"\n")) // new; 2.2.2.2 removed
	ch := rules.Diff(old, now)
	k1, k2, k3 := key(96, 1, 2, 0, 0, "1.1.1.1"), key(96, 1, 2, 0, 0, "2.2.2.2"), key(96, 1, 2, 0, 0, "3.3.3.3")
	if ch.PutRules[k1].Verdict != 2 || ch.PutRules[k3].Id != 2 || len(ch.PutRules) != 2 {
		t.Fatalf("puts: %+v", ch.PutRules)
	}
	if len(ch.DelRules) != 1 || ch.DelRules[0] != k2 || len(ch.PutPrograms) != 0 || len(ch.DelPrograms) != 0 {
		t.Fatalf("deletes: %+v programs %+v/%+v", ch.DelRules, ch.PutPrograms, ch.DelPrograms)
	}
}

func TestDiffProgramsRemovedAndRemapped(t *testing.T) {
	old := rules.Encode(resolved(t, programs))
	now := rules.Encode(resolved(t, "[[program]]\nname = \"claude\"\npaths = [\"/opt/claude/*\"]\n")) // claude is now id 1
	ch := rules.Diff(old, now)
	if ch.PutPrograms[rules.ExeKey{Ino: 201, Dev: 8<<20 | 1}] != 1 || len(ch.PutPrograms) != 2 {
		t.Fatalf("remapped ids must be put: %+v", ch.PutPrograms)
	}
	if len(ch.DelPrograms) != 2 { // curl and git gone
		t.Fatalf("want curl and git deleted, got %+v", ch.DelPrograms)
	}
}

func TestEncodeContracts(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { rules.Encode(nil) })
	r := resolved(t, rule(`program = "curl"`+"\n"+`to = "1.1.1.0/24"`+"\nverdict = \"allow\""))
	r.File.Rules[0].To = netip.MustParsePrefix("1.1.1.7/24") // not canonical: host bits set
	contracttest.Panics(t, contract.Precondition, func() { rules.Encode(r) })
}

func TestEncodeSkipsNameRules(t *testing.T) {
	r := resolved(t, curlProgram+ruleTable("curl", "github.com", "tcp", "443", "allow")+ruleTable("curl", "1.1.1.1", "tcp", "443", "allow"))
	e := rules.Encode(r)
	if len(e.Rules) != 1 || e.Rules[key(96, 1, 2, 6, 443, "1.1.1.1")].Id != 2 || len(e.Programs) != 1 {
		t.Fatalf("got %+v", e)
	}
	if r.ByID[1].Name != "github.com" {
		t.Fatal("name rule must remain reachable by id")
	}
}

func TestEncodeAddrMatchesEncode(t *testing.T) {
	for _, addr := range []string{"1.1.1.1", "2001:db8::1", "::ffff:1.1.1.1"} {
		for _, verdict := range []string{"allow", "deny"} {
			r := resolved(t, curlProgram+ruleTable("curl", addr, "tcp", "443", verdict))
			a := r.File.Rules[0].To.Addr()
			k, v := rules.EncodeAddr(&r.File.Rules[0], 1, a)
			want := rules.Encode(r).Rules
			if len(want) != 1 || want[k] != v {
				t.Fatalf("%s: got %+v/%+v, want %+v", addr, k, v, want)
			}
		}
	}
}

func TestExpandMatchesEncode(t *testing.T) {
	for _, body := range []string{"", "proto = \"tcp\"\n", "proto = \"udp\"\nport = 53\n", "port = \"80-82\"\n", "proto = \"tcp\"\nport = \"80-82\"\n"} {
		r := resolved(t, rule("program = \"curl\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\n"+body))
		got := map[rules.ProtoPort]bool{}
		expansion := rules.Expand(&r.File.Rules[0])
		for _, pp := range expansion {
			got[pp] = true
		}
		want := map[rules.ProtoPort]bool{}
		for k := range rules.Encode(r).Rules {
			want[rules.ProtoPort{Proto: rules.Proto(k.Proto), Port: k.Port}] = true
		}
		if !reflect.DeepEqual(got, want) || len(expansion) != len(want) {
			t.Fatalf("%q: got %v, want %v", body, expansion, want)
		}
	}
}

func TestProgramIDUsesResolvedNames(t *testing.T) {
	r := resolved(t, programs)
	for id, name := range r.Names {
		if got := rules.ProgramID(r, name); got != id {
			t.Fatalf("%s: got %d, want %d", name, got, id)
		}
	}
	if rules.ProgramID(r, "any") != 0 {
		t.Fatal("any program must use id zero")
	}
}

func TestEncodeAddrMappedFamilyAndContracts(t *testing.T) {
	a := netip.MustParseAddr("::ffff:1.1.1.1")
	r := &rules.Rule{To: netip.PrefixFrom(a, 128), Proto: rules.UDP, Ports: []uint16{53}, Verdict: rules.Allow, ID: 7}
	res := &rules.Resolved{File: &rules.File{Rules: []rules.Rule{*r}}}
	res.File.Rules[0].Program = "any"
	k, v := rules.EncodeAddr(r, 0, a)
	if k.Family != 10 || k.Prefixlen != 192 || rules.Encode(res).Rules[k] != v {
		t.Fatalf("mapped address must match raw prefix encoding: %+v/%+v", k, v)
	}
	contracttest.Panics(t, contract.Precondition, func() {
		rules.EncodeAddr(r, 0, netip.Addr{})
	})
	contracttest.Panics(t, contract.InvariantKind, func() {
		rules.ProgramID(res, "undeclared")
	})
}
