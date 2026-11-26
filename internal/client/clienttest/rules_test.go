package clienttest

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
)

func getRules(t *testing.T, c *conn, id int) []api.RuleView {
	t.Helper()
	rep := decodeLine[api.Reply](t, rawAsk(t, c, `{"type":"rules","id":`+itoa(id)+`}`))
	if !rep.Ok {
		t.Fatalf("rules failed: %+v", rep)
	}
	return rep.Rules
}

func getPrograms(t *testing.T, c *conn, id int) []api.ProgramView {
	t.Helper()
	rep := decodeLine[api.Reply](t, rawAsk(t, c, `{"type":"programs","id":`+itoa(id)+`}`))
	if !rep.Ok {
		t.Fatalf("programs failed: %+v", rep)
	}
	return rep.Programs
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b [12]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestRulesVerb(t *testing.T) {
	s := writer(t)
	c := dial(t, s)
	rs := getRules(t, c, 1)
	if len(rs) != 13 {
		t.Fatalf("got %d initial rules, want 13", len(rs))
	}
	for i, r := range rs {
		if r.Id != i+1 || r.Source != "/etc/snitch/rules.toml" {
			t.Fatalf("rule[%d] = %+v", i, r)
		}
	}
	if rs[0].Program != "curl" || rs[0].To != "1.1.1.1/32" || rs[0].Protocol != "tcp" || rs[0].Port != 443 || rs[0].Verdict != "allow" {
		t.Fatalf("first rule = %+v", rs[0])
	}
}

func TestProgramsVerb(t *testing.T) {
	s := writer(t)
	c := dial(t, s)
	ps := getPrograms(t, c, 1)
	i := slices.IndexFunc(ps, func(p api.ProgramView) bool { return p.Name == "curl" })
	if i < 0 {
		t.Fatalf("curl missing from programs: %+v", ps)
	}
	p := ps[i]
	if !slices.Contains(p.Paths, "/usr/bin/curl") || !p.Resolved || p.Executables != 1 || p.Source != "/etc/snitch/rules.toml" {
		t.Fatalf("curl program = %+v", p)
	}
}

func TestRuleAddVerb(t *testing.T) {
	s := Start(t, Options{Operator: uint32(os.Getuid()), ReloadAfter: 20 * time.Millisecond})
	c := dial(t, s)

	l := c.ask(`{"type":"rule.add","id":2,"program":"curl","to":"9.9.9.9","proto":"tcp","port":443,"verdict":"deny","note":"n"}`)
	if !l.Ok || l.Text != "rule added: curl to 9.9.9.9/32 tcp port 443 deny (applies within 5 s)" {
		t.Fatalf("rule.add reply = %+v", l)
	}
	rs := getRules(t, c, 3)
	if len(rs) != 14 || rs[13].To != "9.9.9.9/32" || rs[13].Source != "/etc/snitch/rules.d/local.toml" || rs[13].Note != "n" {
		t.Fatalf("rules after add = %+v", rs)
	}
	if st := c.ask(`{"type":"status","id":4}`).Status; st.Rules.Rules != 14 {
		t.Fatalf("status rules count = %d, want 14", st.Rules.Rules)
	}

	checkRuleAddByPath(t, c)
	checkRuleAddRefusals(t, c)
}

func checkRuleAddByPath(t *testing.T, c *conn) {
	t.Helper()
	for _, req := range []struct {
		json, wantText, wantProg string
	}{
		{`{"type":"rule.add","id":10,"path":"/opt/bin/mytool","to":"8.8.8.8/32","verdict":"allow"}`,
			"rule added: mytool to 8.8.8.8/32 allow (applies within 5 s)", "mytool"},
		{`{"type":"rule.add","id":11,"path":"/opt/bin/mytool","to":"8.8.4.4/32","verdict":"allow"}`,
			"rule added: mytool to 8.8.4.4/32 allow (applies within 5 s)", "mytool"},
		{`{"type":"rule.add","id":12,"path":"/usr/local/bin/curl","to":"example.org","verdict":"allow"}`,
			"rule added: curl-2 to example.org allow (applies within 5 s)", "curl-2"},
		{`{"type":"rule.add","id":13,"path":"/opt/bin/any","to":"1.0.0.1/32","verdict":"allow"}`,
			"rule added: any-2 to 1.0.0.1/32 allow (applies within 5 s)", "any-2"},
	} {
		if l := c.ask(req.json); !l.Ok || l.Text != req.wantText {
			t.Fatalf("%s -> %+v, want %q", req.json, l, req.wantText)
		}
		ps := getPrograms(t, c, 14)
		i := slices.IndexFunc(ps, func(p api.ProgramView) bool { return p.Name == req.wantProg })
		if i < 0 || !ps[i].Resolved || ps[i].Source != "/etc/snitch/rules.d/local.toml" {
			t.Fatalf("program %q missing or wrong in %+v", req.wantProg, ps)
		}
	}
}

func checkRuleAddRefusals(t *testing.T, c *conn) {
	t.Helper()
	for _, tc := range []struct {
		req, wantSub string
	}{
		{`{"type":"rule.add","id":20,"path":"/usr/bin/curl","to":"1.2.3.4","verdict":"allow"}`,
			"executable /usr/bin/curl is program curl: use that name"},
		{`{"type":"rule.add","id":21,"program":"curl","to":"bad..host","verdict":"allow"}`,
			`to "bad..host": not an address, prefix or domain name`},
		{`{"type":"rule.add","id":22,"program":"curl","to":"example.com","verdict":"deny"}`,
			`to "example.com": a deny by name is not supported`},
		{`{"type":"rule.add","id":23,"program":"any","to":"0.0.0.0/0","verdict":"deny"}`,
			"a deny for every program is deny by default without a deadline"},
		{`{"type":"rule.add","id":24,"program":"ghost","to":"1.2.3.4","verdict":"allow"}`,
			`unknown program "ghost"`},
	} {
		if l := c.ask(tc.req); l.Type != "error" || !strings.Contains(l.Error, tc.wantSub) {
			t.Fatalf("%s -> %+v, want %q", tc.req, l, tc.wantSub)
		}
	}
}

func TestRuleRemoveVerb(t *testing.T) {
	s := Start(t, Options{Operator: uint32(os.Getuid()), ReloadAfter: 20 * time.Millisecond})
	c := dial(t, s)

	_ = c.ask(`{"type":"rule.add","id":2,"program":"curl","to":"9.9.9.9","proto":"tcp","port":443,"verdict":"deny"}`)
	rep := c.ask(`{"type":"rule.remove","id":3,"program":"curl","to":"9.9.9.9/32","proto":"tcp","port":443}`)
	if !rep.Ok || rep.Text != "rule removed: curl to 9.9.9.9/32 tcp port 443 (applies within 5 s)" {
		t.Fatalf("rule.remove reply = %+v", rep)
	}
	if rs := getRules(t, c, 4); len(rs) != 13 {
		t.Fatalf("rules after remove = %d, want 13", len(rs))
	}
	if l := c.ask(`{"type":"rule.remove","id":5,"program":"curl","to":"1.1.1.1/32","proto":"tcp","port":443}`); l.Type != "error" || !strings.Contains(l.Error, "edit /etc/snitch/rules.toml") {
		t.Fatalf("base rule.remove = %+v", l)
	}
	if l := c.ask(`{"type":"rule.remove","id":6,"program":"curl","to":"8.8.8.8/32"}`); l.Type != "error" || !strings.Contains(l.Error, "no overlay rule matches") {
		t.Fatalf("missing overlay rule.remove = %+v", l)
	}
}
