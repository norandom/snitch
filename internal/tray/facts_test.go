package tray

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// step runs one message and checks the effect list ends with the view of the new model.
func step(t *testing.T, m Model, msg any, at time.Time) (Model, []Post) {
	t.Helper()
	m2, fx := Update(m, msg, at)
	if len(fx) == 0 {
		t.Fatalf("%T: no effects, want a show last", msg)
	}
	if show, ok := fx[len(fx)-1].(Show); !ok || !reflect.DeepEqual(show.View, Render(m2, at)) {
		t.Fatalf("%T: last effect %#v is not the new view", msg, fx[len(fx)-1])
	}
	var posts []Post
	for _, e := range fx[:len(fx)-1] {
		p, ok := e.(Post)
		if !ok {
			t.Fatalf("%T: unexpected effect %#v", msg, e)
		}
		posts = append(posts, p)
	}
	return m2, posts
}

// started is a tray with a notification service (notices are gated on it, 8.6) that has seen
// st as its first facts: the baseline.
func started(t *testing.T, st api.Status) Model {
	t.Helper()
	m, _ := step(t, NewModel(Options{Loc: zone}), Capabilities{Available: true, Actions: true}, now)
	m, posts := step(t, m, client.Up{}, now)
	m, more := step(t, m, client.Facts{Status: st}, now)
	if len(posts)+len(more) != 0 {
		t.Fatalf("start posted %v", append(posts, more...))
	}
	return m
}

// one asserts exactly one notice and returns it.
func one(t *testing.T, what string, posts []Post) Note {
	t.Helper()
	if len(posts) != 1 {
		t.Fatalf("%s: %d notices, want 1: %+v", what, len(posts), posts)
	}
	return posts[0].Note
}

// none asserts no notice.
func none(t *testing.T, what string, posts []Post) {
	t.Helper()
	if len(posts) != 0 {
		t.Fatalf("%s: unexpected notices %+v", what, posts)
	}
}

// 7.7: the state found at start notifies nothing, however alarming, and leaves the tray not gone.
func TestFactsBaselineNoNotice(t *testing.T) {
	st := running()
	st.Kill, st.RulesError, st.Mode, st.Trial = true, "rules: line 3", "enforce", deadline
	m := started(t, st)
	if m.gone || m.facts == nil || *m.facts != st {
		t.Fatalf("baseline not taken: gone %v facts %+v", m.gone, m.facts)
	}
}

// noticeCase is one pair of facts: from the baseline, a message, and the notice it gives.
type noticeCase struct {
	name     string
	base     func(*api.Status)
	msg      func(api.Status) any
	summary  string
	body     string
	urgent   bool
	duration time.Duration
}

func line(mode, trial string, kept bool, reason string) func(api.Status) any {
	return func(api.Status) any {
		return client.StateLine{State: api.State{Type: "state", Mode: mode, Trial: trial, Kept: kept, Reason: reason}}
	}
}

func factsWith(f func(*api.Status)) func(api.Status) any {
	return func(st api.Status) any { f(&st); return client.Facts{Status: st} }
}

func enforcing(st *api.Status) { st.Mode, st.Trial = "enforce", deadline }

var noticeCases = []noticeCase{
	{"trial started", nil, line("enforce", deadline, false, "trial until x"),
		"trial started", "14:12", false, 10 * time.Second},
	{"enforcement ended", enforcing, line("monitor", "", false, "trial ended at its deadline"),
		"enforcement ended", "trial ended at its deadline", false, 10 * time.Second},
	{"ended seen in facts", enforcing, factsWith(func(st *api.Status) { st.Mode, st.Trial = "monitor", "" }),
		"enforcement ended", "monitor", false, 10 * time.Second},
	{"kept", enforcing, line("enforce", deadline, true, "enforce kept"),
		"enforce kept", "", false, 10 * time.Second},
	{"unkept", func(st *api.Status) { enforcing(st); st.Kept = true },
		line("monitor", "", false, "enforce unkept: file removed"),
		"enforce unkept", "Back to monitor: enforce unkept: file removed", false, 10 * time.Second},
	{"kill set", nil, factsWith(func(st *api.Status) { st.Kill = true }),
		"kill switch set", "", true, 30 * time.Second},
	{"kill cleared", func(st *api.Status) { st.Kill = true }, factsWith(func(st *api.Status) { st.Kill = false }),
		"kill switch cleared", "", false, 10 * time.Second},
	{"rules error", nil, factsWith(func(st *api.Status) { st.RulesError = "rules: line 3: unknown key" }),
		"rules error", "rules: line 3: unknown key", true, 30 * time.Second},
	{"rules error cleared", func(st *api.Status) { st.RulesError = "rules: line 3" },
		factsWith(func(st *api.Status) { st.RulesError = "" }),
		"rules load again", "", false, 10 * time.Second},
	{"rules error replaced", func(st *api.Status) { st.RulesError = "rules: line 3" },
		factsWith(func(st *api.Status) { st.RulesError = "rules: line 9: bad port" }),
		"rules error", "rules: line 9: bad port", true, 30 * time.Second},
}

// 7.1 to 7.5, 7.8: each change between two facts gives one notice, plain, without actions.
func TestNoticeFromFactPairs(t *testing.T) {
	for _, c := range noticeCases {
		t.Run(c.name, func(t *testing.T) {
			st := running()
			if c.base != nil {
				c.base(&st)
			}
			_, posts := step(t, started(t, st), c.msg(st), now)
			n := one(t, c.name, posts)
			if !strings.Contains(strings.ToLower(n.Summary), c.summary) || !strings.Contains(n.Body, c.body) {
				t.Errorf("note %+v, want summary ~%q body ~%q", n, c.summary, c.body)
			}
			if len(n.Actions) != 0 || n.Urgent != c.urgent || n.Timeout != c.duration {
				t.Errorf("note %+v: want no actions, urgent %v, timeout %v", n, c.urgent, c.duration)
			}
		})
	}
}

// A change told by a state line is not told again by the facts that follow it.
func TestNoticeEachChangeOnce(t *testing.T) {
	m := started(t, running())
	m, posts := step(t, m, line("enforce", deadline, false, "trial until x")(api.Status{}), now)
	one(t, "state line", posts)
	st := running()
	enforcing(&st)
	_, posts = step(t, m, client.Facts{Status: st}, now)
	none(t, "facts after the state line", posts)
}

// 7.1: a trial extended to a later deadline is not a trial started again.
func TestNoticeTrialExtendedSilent(t *testing.T) {
	m := started(t, running())
	m, posts := step(t, m, line("enforce", deadline, false, "trial until x")(api.Status{}), now)
	one(t, "started", posts)
	later := "2026-10-11T13:12:00Z"
	m, posts = step(t, m, line("enforce", later, false, "trial until y")(api.Status{}), now)
	none(t, "extended by state line", posts)
	st := running()
	st.Mode, st.Trial = "enforce", "2026-10-11T14:12:00Z"
	_, posts = step(t, m, client.Facts{Status: st}, now)
	none(t, "extended in facts", posts)
}

// 7.7: a reload that changes neither mode nor error is silent, by state line or by facts.
func TestFactsSilentReload(t *testing.T) {
	m := started(t, running())
	reload := client.StateLine{State: api.State{Type: "state", Mode: "monitor", RulesChanged: true, Reason: "rules reloaded"}}
	m, posts := step(t, m, reload, now)
	none(t, "reload line", posts)
	st := running()
	st.Rules.Rules, st.Rules.Programs = 14, 19
	m, posts = step(t, m, client.Facts{Status: st}, now)
	none(t, "reload facts", posts)
	if m.facts.Rules.Rules != 14 {
		t.Fatalf("facts not replaced: %+v", m.facts.Rules)
	}
}

// A state line updates mode, trial and kept at once on a copy: the earlier model keeps its facts.
func TestFactsStateLineCopies(t *testing.T) {
	m := started(t, running())
	m2, _ := step(t, m, line("enforce", deadline, true, "enforce kept")(api.Status{}), now)
	if m.facts.Mode != "monitor" || m.facts.Kept {
		t.Fatalf("earlier model changed: %+v", *m.facts)
	}
	f := m2.facts
	if f.Mode != "enforce" || f.Trial != deadline || !f.Kept || m2.lastReason != "enforce kept" {
		t.Fatalf("state line not applied: %+v reason %q", *f, m2.lastReason)
	}
}

// 7.6: absent 9 s, nothing either way; absent 11 s, one notice on the tick and one when back.
func TestGoneNoticeAfterTenSeconds(t *testing.T) {
	m := started(t, running())
	m, _ = step(t, m, client.Down{Reason: client.NotRunning}, now)
	m, posts := step(t, m, Tick{}, now.Add(9*time.Second))
	none(t, "9 s", posts)
	m, _ = step(t, m, client.Up{}, now.Add(9*time.Second))
	m, posts = step(t, m, client.Facts{Status: running()}, now.Add(9*time.Second))
	none(t, "back after 9 s", posts)

	t1 := now.Add(time.Minute)
	m, _ = step(t, m, client.Down{Reason: client.NotRunning}, t1)
	m, posts = step(t, m, Tick{}, t1.Add(11*time.Second))
	n := one(t, "11 s", posts)
	if !strings.Contains(n.Summary, "not running") || !n.Urgent || n.Timeout != 30*time.Second || len(n.Actions) != 0 {
		t.Fatalf("gone notice %+v", n)
	}
	m, posts = step(t, m, Tick{}, t1.Add(12*time.Second))
	none(t, "second tick", posts)
	m, posts = step(t, m, client.Up{}, t1.Add(20*time.Second))
	none(t, "up", posts)
	m, posts = step(t, m, client.Facts{Status: running()}, t1.Add(20*time.Second))
	if n := one(t, "back", posts); !strings.Contains(n.Summary, "back") {
		t.Fatalf("back notice %+v", n)
	}
	if m.gone || m.goneNoticed || !m.goneSince.IsZero() || m.down != "" {
		t.Fatalf("loss not cleared: %+v", m)
	}
}

// 2.1 note: a repeated Down with another reason updates the reason, not the time of the loss.
func TestGoneRepeatedDownKeepsSince(t *testing.T) {
	m := started(t, running())
	m, _ = step(t, m, client.Down{Reason: client.NotRunning}, now)
	m, _ = step(t, m, client.Down{Reason: client.NotAnswering}, now.Add(5*time.Second))
	if !m.goneSince.Equal(now) || m.down != client.NotAnswering || !m.gone {
		t.Fatalf("since %v down %q gone %v", m.goneSince, m.down, m.gone)
	}
	_, posts := step(t, m, Tick{}, now.Add(10*time.Second))
	if n := one(t, "10 s", posts); !strings.Contains(n.Summary, client.NotAnswering) {
		t.Fatalf("gone notice %+v", n)
	}
}

// 3.1 note: Up keeps the tray gone, with the last facts as baseline, until the first Facts.
func TestGoneStaysAfterUpUntilFacts(t *testing.T) {
	m := started(t, running())
	m, _ = step(t, m, client.Down{Reason: client.NotRunning}, now)
	m, _ = step(t, m, client.Up{}, now.Add(time.Second))
	if !m.gone || m.facts == nil || Render(m, now).State != Gone {
		t.Fatalf("up cleared gone: gone %v facts %v", m.gone, m.facts)
	}
	m, _ = step(t, m, client.Facts{Status: running()}, now.Add(2*time.Second))
	if m.gone {
		t.Fatal("facts did not clear gone")
	}
}

// 7.7: a daemon absent from the start is the state found at start: no notice, however long.
func TestGoneAtStartNoNotice(t *testing.T) {
	m := NewModel(Options{Loc: zone})
	m, _ = step(t, m, client.Down{Reason: client.NotRunning}, now)
	_, posts := step(t, m, Tick{}, now.Add(time.Hour))
	none(t, "gone from the start", posts)
}

// Messages that concern nothing the model holds (an event that asks nothing, an answer and a
// press without a question, capabilities as they are) and the types later tasks handle pass
// through unchanged, with a view.
func TestFactsPassThrough(t *testing.T) {
	m := started(t, running())
	for _, msg := range []any{client.EventLine{}, client.Answered{Token: 3}, Pressed{NoteID: 1},
		MenuClick{Row: RowHeader}, Capabilities{Available: true, Actions: true}, Stop{}} {
		m2, posts := step(t, m, msg, now)
		none(t, "pass through", posts)
		if !reflect.DeepEqual(m, m2) {
			t.Errorf("%T changed the model", msg)
		}
	}
}

// Precondition: a message type outside the design's list is a wiring error.
func TestFactsUnknownMessageViolation(t *testing.T) {
	m := NewModel(Options{Loc: zone})
	contracttest.Panics(t, contract.Precondition, func() { Update(m, struct{}{}, now) })
	contracttest.Panics(t, contract.Precondition, func() { Update(m, nil, now) })
	contracttest.Panics(t, contract.Precondition, func() { Update(m, "tick", now) })
}
