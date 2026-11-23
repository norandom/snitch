package tray

import (
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/client"
)

// 7.1, 7.8: every notice is plain text with a summary, no actions, and closes on its own:
// 30 s and urgent for the attention states (kill, rules error, gone), 10 s otherwise.
func TestNoticeTexts(t *testing.T) {
	since := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		n      Note
		urgent bool
	}{
		{noteTrial(deadline, zone), false},
		{noteEnded("trial ended at boot"), false},
		{noteEnded(""), false},
		{noteKept(), false},
		{noteUnkept("", false), false},
		{noteUnkept("enforce unkept: file removed", true), false},
		{noteKill(true), true},
		{noteKill(false), false},
		{noteRulesError("rules: line 3"), true},
		{noteRulesOK(), false},
		{noteGone(client.NotRunning, since, zone), true},
		{noteBack(), false},
	}
	for _, c := range cases {
		n := c.n
		want := 10 * time.Second
		if c.urgent {
			want = 30 * time.Second
		}
		if n.Summary == "" || n.Body == "" || len(n.Actions) != 0 || n.Urgent != c.urgent || n.Timeout != want {
			t.Errorf("note %+v: want summary, body, no actions, urgent %v, timeout %v", n, c.urgent, want)
		}
		if strings.ContainsAny(n.Summary+n.Body, "<>&") {
			t.Errorf("note %+v is not plain text", n)
		}
	}
}

// 7.1: the deadline is shown in the tray's zone; a deadline that does not parse is shown as sent.
func TestNoticeTrialDeadlineLocal(t *testing.T) {
	if b := noteTrial(deadline, zone).Body; !strings.Contains(b, "14:12") {
		t.Errorf("deadline not in local time: %q", b)
	}
	if b := noteTrial("soon", zone).Body; !strings.Contains(b, "soon") {
		t.Errorf("unparsed deadline lost: %q", b)
	}
}

// 7.2, 7.6: the daemon's reason and the time of the loss are in the text.
func TestNoticeReasonAndGoneTime(t *testing.T) {
	if b := noteEnded("trial ended by the operator: file removed").Body; !strings.Contains(b, "by the operator") {
		t.Errorf("reason missing: %q", b)
	}
	since := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	n := noteGone(client.NotAnswering, since, zone)
	if !strings.Contains(n.Summary, client.NotAnswering) || !strings.Contains(n.Body, "14:00") {
		t.Errorf("gone note %+v", n)
	}
}

// Two notices from one message get two distinct fresh tokens.
func TestNoticeTokensFresh(t *testing.T) {
	m := started(t, running())
	st := running()
	st.Kill, st.RulesError = true, "rules: bad"
	m, posts := step(t, m, client.Facts{Status: st}, now)
	if len(posts) != 2 || posts[0].Token == posts[1].Token || posts[0].Token == 0 || m.nextToken != posts[1].Token {
		t.Fatalf("tokens: %+v next %d", posts, m.nextToken)
	}
}

// A failed post forgets the notice's token and records no id.
func TestNoticePostFailed(t *testing.T) {
	m, p := posted(t)
	m2, _ := step(t, m, PostFailed{Token: p.Token}, now)
	if m2.posting[p.Token] || len(m2.notices) != 0 || !m.posting[p.Token] {
		t.Fatalf("failed post kept: %v %v", m2.posting, m2.notices)
	}
}

// posted is a tray that has just posted the kill switch notice, and that Post.
func posted(t *testing.T) (Model, Post) {
	t.Helper()
	st := running()
	st.Kill = true
	m, posts := step(t, started(t, running()), client.Facts{Status: st}, now)
	one(t, "kill", posts)
	if p := posts[0]; p.Token == 0 || !m.posting[p.Token] {
		t.Fatalf("token %d not remembered: %v", p.Token, m.posting)
	}
	return m, posts[0]
}

// 1.4: a posted notice's id is kept from Posted until Closed; tokens are fresh and never 0.
func TestNoticeIdRememberedUntilClosed(t *testing.T) {
	m, p := posted(t)
	m2, _ := step(t, m, Posted{Token: p.Token, NoteID: 7}, now)
	if !m2.notices[7] || m2.posting[p.Token] || m.notices[7] || !m.posting[p.Token] {
		t.Fatalf("posted: notices %v posting %v (before: %v %v)", m2.notices, m2.posting, m.notices, m.posting)
	}
	m3, _ := step(t, m2, Posted{Token: 999, NoteID: 8}, now)
	if m3.notices[8] {
		t.Fatal("a token that is no notice's was taken as one")
	}
	m4, _ := step(t, m3, Closed{NoteID: 7}, now)
	if m4.notices[7] || !m3.notices[7] {
		t.Fatalf("closed: after %v before %v", m4.notices, m3.notices)
	}
}

// The maps of a model are copy-on-write: Post, Posted, PostFailed and Closed on a model whose
// posting and notices are not empty leave that model's maps as they were.
func TestNoticeMapsCopyOnWrite(t *testing.T) {
	m, p := posted(t)
	m, _ = step(t, m, Posted{Token: p.Token, NoteID: 7}, now)
	m, posts := step(t, m, client.Facts{Status: running()}, now) // kill cleared: a second notice
	one(t, "kill cleared", posts)
	tok := posts[0].Token
	wantPosting, wantNotices := maps.Clone(m.posting), maps.Clone(m.notices)
	if len(wantPosting) == 0 || len(wantNotices) == 0 {
		t.Fatalf("setup: posting %v notices %v", wantPosting, wantNotices)
	}
	bad := running()
	bad.RulesError = "rules: line 3"
	for _, msg := range []any{client.Facts{Status: bad}, Posted{Token: tok, NoteID: 8},
		PostFailed{Token: tok}, Closed{NoteID: 7}} {
		step(t, m, msg, now)
		if !maps.Equal(m.posting, wantPosting) || !maps.Equal(m.notices, wantNotices) {
			t.Fatalf("%T wrote through: posting %v notices %v", msg, m.posting, m.notices)
		}
	}
}
