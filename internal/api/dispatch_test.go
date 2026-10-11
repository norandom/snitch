package api

import (
	"golang.org/x/sys/unix"
	"time"

	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
)

// writeRequests is one valid line per write type.
var writeRequests = map[string]string{
	"trial":       `{"type":"trial","id":9,"duration":"10m"}`,
	"keep":        `{"type":"keep","id":9}`,
	"unkeep":      `{"type":"unkeep","id":9}`,
	"end":         `{"type":"end","id":9}`,
	"rule.add":    `{"type":"rule.add","id":9,"program":"curl","to":"1.1.1.1","verdict":"allow"}`,
	"rule.remove": `{"type":"rule.remove","id":9,"program":"curl","to":"1.1.1.1"}`,
}

func statusOk(t *testing.T, p *peer) {
	t.Helper()
	if r := p.reply(p.ask(`{"type":"status","id":77}`)); !r.Ok || r.Id != 77 || r.Status == nil || r.Status.Pid != 7 {
		t.Fatalf("status: %+v", r)
	}
}

// Req 1.4, 5.6, design "Decision table": a reader is refused every write type with the request
// named, the connection stays open and no delegate runs.
func TestServerReaderIsRefusedWrites(t *testing.T) {
	f := newFixture(t)
	f.listen(nil)
	p := f.dial()
	for typ, line := range writeRequests {
		e := p.errorOf(p.ask(line))
		if e.Id != 9 || !strings.Contains(e.Error, "write requires the operator") || !strings.Contains(e.Error, typ) {
			t.Fatalf("%s: %+v", typ, e)
		}
	}
	statusOk(t, p)
	if calls := f.lines(&f.calls); len(calls) != 0 {
		t.Fatalf("a reader reached a delegate: %v", calls)
	}
}

// audits counts the journal lines naming the uid, carrying the request and an ok outcome.
func audits(f *fixture, uid uint32) int {
	var n int
	for _, l := range f.lines(&f.log) {
		if strings.Contains(l, fmt.Sprintf("uid %d", uid)) && strings.Contains(l, `"type":"`) && strings.Contains(l, " ok ") {
			n++
		}
	}
	return n
}

// Req 5.1, 5.2, 5.5: a writer's write goes to the delegate with its uid, the text comes back
// in the reply, and one audit line names the user, the request and the outcome.
func TestServerWriterIsDelegated(t *testing.T) {
	for _, uid := range []uint32{0, operatorUid} {
		t.Run(fmt.Sprint(uid), func(t *testing.T) {
			f := newFixture(t)
			f.uid = uid
			f.listen(nil)
			p := f.dial()
			for typ, line := range writeRequests {
				r := p.reply(p.ask(line))
				want := "trial ok " + typ
				if strings.HasPrefix(typ, "rule.") {
					want = "edit ok " + typ
				}
				if !r.Ok || r.Id != 9 || r.Text != want {
					t.Fatalf("%s: %+v", typ, r)
				}
			}
			calls := f.lines(&f.calls)
			if len(calls) != len(writeRequests) || !strings.HasSuffix(calls[0], fmt.Sprintf("uid=%d", uid)) {
				t.Fatalf("delegate calls: %v", calls)
			}
			if n := audits(f, uid); n != len(writeRequests) {
				t.Fatalf("want one audit line per write, got %d in %v", n, f.lines(&f.log))
			}
		})
	}
}

// A delegate's error is the error reply's text, and the audit line carries it.
func TestServerWriteErrorsAreReplied(t *testing.T) {
	f := newFixture(t)
	f.uid = operatorUid
	f.listen(nil)
	p := f.dial()
	e := p.errorOf(p.ask(`{"type":"trial","id":4,"duration":"fail"}`))
	if e.Id != 4 || e.Error != "refused: trial" {
		t.Fatalf("%+v", e)
	}
	e = p.errorOf(p.ask(`{"type":"rule.add","id":5,"path":"/bin/x","to":"1.1.1.1","verdict":"deny","note":"fail"}`))
	if e.Id != 5 || e.Error != "refused: rule.add" {
		t.Fatalf("%+v", e)
	}
	if log := f.lines(&f.log); len(log) != 2 || !strings.Contains(log[1], "refused: rule.add") || !strings.Contains(log[1], "uid 42") {
		t.Fatalf("audit: %v", log)
	}
}

// Req 4.1-4.3: status, rules and programs carry their payloads.
func TestServerReadRequests(t *testing.T) {
	f := newFixture(t)
	f.listen(nil)
	p := f.dial()
	statusOk(t, p)
	if r := p.reply(p.ask(`{"type":"rules","id":2}`)); len(r.Rules) != 1 || r.Rules[0].Program != "curl" || len(r.Programs) != 0 {
		t.Fatalf("rules: %+v", r)
	}
	if r := p.reply(p.ask(`{"type":"programs","id":3}`)); len(r.Programs) != 1 || r.Programs[0].Name != "curl" || len(r.Rules) != 0 {
		t.Fatalf("programs: %+v", r)
	}
}

// Req 4.4: the learned observations, and learning off says so.
func TestServerLearned(t *testing.T) {
	f := newFixture(t)
	f.listen(nil)
	p := f.dial()
	if r := p.reply(p.ask(`{"type":"learned","id":4}`)); len(r.Learned) != 1 || !r.Learning || r.Text != "" {
		t.Fatalf("learned: %+v", r)
	}
	f.learn = false
	if r := p.reply(p.ask(`{"type":"learned","id":5}`)); r.Learning || r.Text != "learning is off" {
		t.Fatalf("learned while off: %+v", r)
	}
}

// Optional delegates left nil answer "not available" instead of crashing.
func TestServerNilDelegatesAreNotAvailable(t *testing.T) {
	f := newFixtureWith(t, func(d *Deps) { d.Rules, d.Learned, d.Trial, d.RuleEdit = nil, nil, nil, nil })
	f.uid = 0
	f.listen(nil)
	p := f.dial()
	for _, typ := range []string{"rules", "programs", "learned", "keep", "rule.remove"} {
		line := writeRequests[typ]
		if line == "" {
			line = fmt.Sprintf(`{"type":%q,"id":2}`, typ)
		}
		if e := p.errorOf(p.ask(line)); e.Id == 0 || e.Error != typ+": not available" {
			t.Fatalf("%s: %+v", typ, e)
		}
	}
	statusOk(t, p)
}

// Req 1.8, 6.2: every error reply, each keeping the connection open.
func TestServerErrorReplies(t *testing.T) {
	f := newFixture(t)
	f.listen(nil)
	p := f.dial()
	cases := []struct {
		line string
		id   int
		want string
	}{
		{`{`, 0, "bad json"},
		{`[1]`, 0, "bad json"},
		{`{"id":3}`, 3, "missing field: type"},
		{`{"type":"nope","id":5}`, 5, "unknown type: nope"},
		{`{"type":"snapshot","id":6}`, 6, "missing field: window"},
		{`{"type":"rule.add","id":7,"program":"curl"}`, 7, "missing field: to"},
		{`{"type":"snapshot","id":8,"window":"2h"}`, 8, "window"},
		{strings.Repeat("x", LineLimit+1), 0, "line longer"},
	}
	for _, c := range cases {
		e := p.errorOf(p.ask(c.line))
		if e.Id != c.id || !strings.Contains(e.Error, c.want) {
			t.Fatalf("%.40q: %+v, want id %d %q", c.line, e, c.id, c.want)
		}
	}
	statusOk(t, p)
}

// Req 1.7, 2.5: every request yields exactly one reply with its id, in order; the snapshot
// serves each window and an empty cache before the first tick.
func TestServerOneReplyPerRequestAndWindows(t *testing.T) {
	f := newFixture(t)
	f.listen(nil)
	p := f.dial()
	if r := p.reply(p.ask(`{"type":"snapshot","id":1,"window":"7d"}`)); len(r.Entries) != 0 || r.Window != "7d" {
		t.Fatalf("empty snapshot: %+v", r)
	}
	f.s.Emit(f.event("1.1.1.1", "allow-rule"))
	_ = f.s.tick(nil)
	var batch strings.Builder
	for i, w := range []string{"15m", "30m", "1h", "24h", "7d"} {
		fmt.Fprintf(&batch, `{"type":"snapshot","id":%d,"window":"%s"}`+"\n", i+1, w)
	}
	batch.WriteString(`{"type":"status","id":6}` + "\n" + `{"type":"status"}` + "\n")
	p.send(strings.TrimSuffix(batch.String(), "\n"))
	for i := 1; i <= 6; i++ {
		r := p.reply(p.line())
		if r.Id != i || (i < 6 && len(r.Entries) != 1) {
			t.Fatalf("reply %d: %+v", i, r)
		}
	}
	if r := p.reply(p.line()); r.Id != 0 || r.Status == nil {
		t.Fatalf("a request without id gets a reply with id 0: %+v", r)
	}
	p.noLine()
}

// The real credential path: over a unix socket the kernel reports this process's uid, so the
// operator set to it writes and, unless we are root, operator 0 leaves us a reader.
func TestServerPeerCredentials(t *testing.T) {
	me := uint32(os.Getuid())
	f := newFixture(t)
	f.s.SetOperator(me)
	f.s.creds = peerCreds
	f.listen(nil)
	p := f.dial()
	if r := p.reply(p.ask(writeRequests["keep"])); !r.Ok || !strings.HasSuffix(f.lines(&f.calls)[0], fmt.Sprintf("uid=%d", me)) {
		t.Fatalf("operator over the socket: %+v %v", r, f.lines(&f.calls))
	}
	if me == 0 {
		t.Skip("root writes regardless")
	}
	g := newFixture(t)
	g.s.SetOperator(0)
	g.s.creds = peerCreds
	g.listen(nil)
	q := g.dial()
	if e := q.errorOf(q.ask(writeRequests["keep"])); !strings.Contains(e.Error, "write requires the operator") {
		t.Fatalf("non-operator over the socket: %+v", e)
	}
}

// Every request type the codec accepts has a handler, and nothing else does: a type in one
// table but not the other would let any local reader trip the dispatcher's invariant.
func TestServerVerbTableMatchesTheRequestTypes(t *testing.T) {
	for typ := range requestTypes {
		if _, ok := verbs[typ]; !ok {
			t.Errorf("request type %q has no handler", typ)
		}
	}
	for typ := range verbs {
		if !requestTypes[typ] {
			t.Errorf("handler %q is not a request type", typ)
		}
	}
}

// SetOperator changes who is a writer for connections from now on (the daemon follows the
// operator file); the uid from Deps is the starting value.
func TestServerSetOperatorFollowsTheFile(t *testing.T) {
	s := New(Deps{Operator: 1000, Table: NewTable(time.Now), Facts: func() Status { return Status{} },
		Log: func(string) {}, Now: time.Now})
	user := &unix.Ucred{Uid: 1000}
	if s.roleOf(user) != Writer || s.roleOf(&unix.Ucred{Uid: 1001}) != Reader {
		t.Fatal("the Deps operator is not the writer")
	}
	s.SetOperator(1001)
	if s.roleOf(user) != Reader || s.roleOf(&unix.Ucred{Uid: 1001}) != Writer {
		t.Fatal("SetOperator did not move the writer role")
	}
	s.SetOperator(0)
	if s.roleOf(user) != Reader || s.roleOf(&unix.Ucred{Uid: 0}) != Writer {
		t.Fatal("no operator: only root writes")
	}
}

// A refused write is journaled too, so a reader probing the write verbs leaves a trace: the
// line names the type and the uid, and is the only line a refusal leaves.
func TestServerRefusedWritesAreLogged(t *testing.T) {
	f := newFixture(t)
	f.listen(nil)
	p := f.dial()
	p.errorOf(p.ask(writeRequests["rule.add"]))
	p.errorOf(p.ask(writeRequests["end"]))
	statusOk(t, p)
	want := []string{"api: rule.add by uid 1000 refused: write requires the operator",
		"api: end by uid 1000 refused: write requires the operator"}
	if got := f.lines(&f.log); !reflect.DeepEqual(got, want) {
		t.Fatalf("log:\n got %q\nwant %q", got, want)
	}
}
