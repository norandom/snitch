package clienttest

import (
	"bufio"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// line is any line the server sends: the union of the fields the tests look at.
type line struct {
	Type         string      `json:"type"`
	Id           int         `json:"id"`
	Ok           bool        `json:"ok"`
	Text         string      `json:"text"`
	Error        string      `json:"error"`
	Status       *api.Status `json:"status"`
	Program      string      `json:"program"`
	Addr         string      `json:"addr"`
	Name         string      `json:"name"`
	Port         int         `json:"port"`
	Verdict      string      `json:"verdict"`
	Hook         string      `json:"hook"`
	Mode         string      `json:"mode"`
	Trial        string      `json:"trial"`
	Kept         bool        `json:"kept"`
	RulesChanged bool        `json:"rulesChanged"`
	Reason       string      `json:"reason"`
}

// conn is one client connection with a line reader and a short read deadline.
type conn struct {
	t *testing.T
	net.Conn
	r *bufio.Reader
}

func dial(t *testing.T, s *StandIn) *conn {
	t.Helper()
	c, err := net.Dial("unix", s.Path())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return &conn{t: t, Conn: c, r: bufio.NewReader(c)}
}

func (c *conn) next() line {
	c.t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, err := c.r.ReadBytes('\n')
	if err != nil {
		c.t.Fatalf("read: %v", err)
	}
	var l line
	if err := json.Unmarshal(b, &l); err != nil {
		c.t.Fatalf("decode %q: %v", b, err)
	}
	return l
}

// ask sends a request and returns its answer, skipping unsolicited lines.
func (c *conn) ask(req string) line {
	c.t.Helper()
	if _, err := c.Write([]byte(req + "\n")); err != nil {
		c.t.Fatalf("write: %v", err)
	}
	for {
		if l := c.next(); l.Id != 0 || l.Type == "error" {
			return l
		}
	}
}

// subscribed is a connection subscribed to events and state, its reply consumed.
func subscribed(t *testing.T, s *StandIn) *conn {
	c := dial(t, s)
	if l := c.ask(`{"type":"subscribe","id":1,"summary":false}`); !l.Ok {
		t.Fatalf("subscribe: %+v", l)
	}
	return c
}

func writer(t *testing.T) *StandIn { return Start(t, Options{Operator: uint32(os.Getuid())}) }

func TestStatusAnswersLikeTheExample(t *testing.T) {
	c := dial(t, writer(t))
	l := c.ask(`{"type":"status","id":1}`)
	st := l.Status
	if l.Type != "reply" || !l.Ok || st == nil {
		t.Fatalf("status: %+v", l)
	}
	got := [10]any{st.Running, st.Pid != 0, st.Version, st.Mode, st.Source, st.Rules.Rules,
		st.Rules.File != "", st.Clients, st.Started != "", st.DNS != nil && st.DNS.On}
	if got != [10]any{true, true, "fake", "monitor", "files", 13, true, 1, true, true} {
		t.Fatalf("status facts: %+v", *st)
	}
}

func TestAScriptedEventReachesASubscriber(t *testing.T) {
	s := writer(t)
	c := subscribed(t, s)
	if err := s.Do("event curl /usr/bin/curl 9.9.9.9=dns.quad9.net 443 udp deny-rule"); err != nil {
		t.Fatal(err)
	}
	l := c.next()
	if l.Type != "event" || l.Program != "curl" || l.Addr != "9.9.9.9" || l.Name != "dns.quad9.net" ||
		l.Port != 443 || l.Verdict != "deny-rule" || l.Hook != "sendmsg" {
		t.Fatalf("event: %+v", l)
	}
}

func TestKillOnShowsInTheNextStatus(t *testing.T) {
	s := writer(t)
	c := dial(t, s)
	for _, cmd := range []string{"kill on", "learning on", "error bad overlay"} {
		if err := s.Do(cmd); err != nil {
			t.Fatalf("%s: %v", cmd, err)
		}
	}
	st := c.ask(`{"type":"status","id":2}`).Status
	if !st.Kill || !st.Learning || !strings.HasSuffix(st.RulesError, ": bad overlay") {
		t.Fatalf("status: %+v", *st)
	}
	_ = s.Do("kill off")
	_ = s.Do("error none")
	if st := c.ask(`{"type":"status","id":3}`).Status; st.Kill || st.RulesError != "" {
		t.Fatalf("status after off: %+v", *st)
	}
}

func TestARuleAddIsRecordedAnsweredThenAnnounced(t *testing.T) {
	printed := make(chan api.Request, 4)
	s := Start(t, Options{Operator: uint32(os.Getuid()), Record: func(r api.Request) { printed <- r }})
	c := subscribed(t, s)
	_, _ = c.Write([]byte(`{"type":"rule.add","id":5,"program":"curl","to":"9.9.9.9/32","proto":"tcp","port":443,"verdict":"deny"}` + "\n"))
	// One connection: the daemon replies first and announces the reload after its poll.
	if l, want := c.next(), "rule added: curl to 9.9.9.9/32 tcp port 443 deny (applies within 5 s)"; l.Type != "reply" || l.Text != want {
		t.Fatalf("first line, want the reply: %+v", l)
	}
	edits := s.Edits()
	if len(edits) != 1 || edits[0].Program != "curl" || edits[0].Port != 443 || len(printed) != 1 {
		t.Fatalf("recorded: %+v printed: %+v", edits, printed)
	}
	if st := c.next(); [4]any{st.Type, st.RulesChanged, st.Reason, st.Mode} != [4]any{"state", true, ReasonReloaded, "monitor"} {
		t.Fatalf("second line, want the state: %+v", st)
	}
}

func TestRefusedRuleEditsAndTrialVerbs(t *testing.T) {
	s := writer(t)
	if err := s.Do("refuse on"); err != nil {
		t.Fatal(err)
	}
	l := dial(t, s).ask(`{"type":"rule.add","id":5,"program":"curl","to":"example.org","verdict":"allow"}`)
	if l.Type != "error" || l.Error != "rule.add: refused by the stand-in" || len(s.Edits()) != 0 {
		t.Fatalf("refusal: %+v edits %v", l, s.Edits())
	}
	if l := dial(t, s).ask(`{"type":"keep","id":4}`); l.Error != "keep: not available in the stand-in" {
		t.Fatalf("keep: %+v", l)
	}
}

func TestAnotherOperatorMakesTheConnectionAReader(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root is always a writer")
	}
	s := Start(t, Options{Operator: uint32(os.Getuid()) + 1})
	l := dial(t, s).ask(`{"type":"rule.add","id":5,"program":"curl","to":"example.org","verdict":"allow"}`)
	if l.Error != "rule.add: write requires the operator" || len(s.Edits()) != 0 {
		t.Fatalf("reader: %+v", l)
	}
}

func TestModeCommandsSendTheDaemonsStateLines(t *testing.T) {
	at := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	s := Start(t, Options{Operator: uint32(os.Getuid()), Now: func() time.Time { return at }})
	c := subscribed(t, s)
	const until = "2026-10-11T12:10:00Z"
	cases := []struct {
		cmd, mode, reason, trial string
		kept                     bool
	}{
		{"trial 10m", "enforce", "trial until ", until, false},
		{"keep", "enforce", ReasonKept, until, true},
		{"unkeep", "enforce", ReasonUnkept, until, false},
		{"end", "monitor", ReasonEnded, "", false},
		{"keep", "enforce", ReasonKept, "", true},
		{"unkeep", "monitor", ReasonUnkept, "", false},
		{"mode enforce", "enforce", ReasonMode, "", false},
		{"mode monitor", "monitor", ReasonMode, "", false},
	}
	for _, tc := range cases {
		if err := s.Do(tc.cmd); err != nil {
			t.Fatalf("%s: %v", tc.cmd, err)
		}
		l := c.next()
		got := [5]any{l.Type, l.Mode, l.Trial, l.Kept, l.RulesChanged}
		if got != [5]any{"state", tc.mode, tc.trial, tc.kept, false} || !strings.HasPrefix(l.Reason, tc.reason) {
			t.Fatalf("%s: %+v", tc.cmd, l)
		}
		if st := s.Facts(); [3]any{st.Mode, st.Trial, st.Kept} != [3]any{l.Mode, l.Trial, l.Kept} {
			t.Fatalf("%s: facts %+v against %+v", tc.cmd, st, l)
		}
	}
}

// A reload line still waiting when the stand-in stops is dropped, not sent to the next run.
func TestRestartServesTheSamePathWithTheSameFactsAndDropsWaitingLines(t *testing.T) {
	s := Start(t, Options{Operator: uint32(os.Getuid()), ReloadAfter: 300 * time.Millisecond})
	old := subscribed(t, s)
	_ = s.Do("kill on")
	if l := old.ask(`{"type":"rule.add","id":2,"program":"curl","to":"example.org","verdict":"allow"}`); !l.Ok {
		t.Fatalf("rule.add: %+v", l)
	}
	if err := s.Restart(); err != nil {
		t.Fatal(err)
	}
	_ = old.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := old.r.ReadBytes('\n'); err == nil {
		t.Fatal("the old connection survived the restart")
	}
	fresh := subscribed(t, s)
	if st := fresh.ask(`{"type":"status","id":3}`).Status; st == nil || !st.Kill {
		t.Fatalf("status after restart: %+v", st)
	}
	_ = fresh.SetReadDeadline(time.Now().Add(600 * time.Millisecond))
	if b, err := fresh.r.ReadBytes('\n'); err == nil {
		t.Fatalf("a line from before the restart: %s", b)
	}
	s.Stop()
	s.Stop() // a second stop is a no-op
	if _, err := net.Dial("unix", s.Path()); err == nil {
		t.Fatal("dial after stop succeeded")
	}
}

func TestDoRejectsBadCommands(t *testing.T) {
	s := writer(t)
	for _, cmd := range []string{"bogus", "mode fast", "trial", "trial -1m", "trial soon", "kill maybe",
		"end now", "error", "event curl /usr/bin/curl 1.1.1.1 443 tcp", "event a /b 1.1.1.1 70000 tcp allow-rule",
		"event a /b 1.1.1.1 443 icmp allow-rule", "event a /b 1.1.1.1 443 tcp allow"} {
		if err := s.Do(cmd); err == nil {
			t.Errorf("%q: no error", cmd)
		}
	}
	if err := s.Do("quit"); !errors.Is(err, ErrQuit) {
		t.Fatalf("quit: %v", err)
	}
	if err := s.Do("   "); err != nil {
		t.Fatalf("blank: %v", err)
	}
}

func TestSentence(t *testing.T) {
	for _, tc := range []struct {
		req  api.Request
		want string
	}{
		{api.Request{Type: "rule.add", Program: "curl", To: "example.org", Verdict: "allow"},
			"rule added: curl to example.org allow (applies within 5 s)"},
		{api.Request{Type: "rule.add", Path: "/opt/x/bin/tool", To: "1.1.1.1", Proto: "udp", Verdict: "deny"},
			"rule added: tool to 1.1.1.1 udp deny (applies within 5 s)"},
		{api.Request{Type: "rule.remove", Program: "curl", To: "9.9.9.9/32", Proto: "tcp", Port: 443},
			"rule removed: curl to 9.9.9.9/32 tcp port 443 (applies within 5 s)"},
	} {
		if got := Sentence(tc.req); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}

func TestNewRefusesAFileThatIsNotASocket(t *testing.T) {
	path := filepath.Join(t.TempDir(), "api.sock")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := New(path, Options{}); err == nil || !strings.Contains(err.Error(), "not a socket") {
		t.Fatalf("err: %v", err)
	}
}

// Contracts: a missing path, an unknown mode, a non-positive trial and serving twice are
// programming errors of the caller (the command parser checks operator input first).
func TestContractViolations(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { _, _ = New("", Options{}) })
	s := writer(t)
	contracttest.Panics(t, contract.Precondition, func() { s.SetMode("fast") })
	contracttest.Panics(t, contract.Precondition, func() { s.StartTrial(0) })
	contracttest.Panics(t, contract.Precondition, func() { _ = s.Serve() })
}
