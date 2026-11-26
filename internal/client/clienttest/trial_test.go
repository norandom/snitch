package clienttest

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
)

func atClock(t time.Time) func() time.Time { return func() time.Time { return t } }

func rawAsk(t *testing.T, c *conn, req string) []byte {
	t.Helper()
	if _, err := c.Write([]byte(req + "\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	for {
		b := nextBytes(t, c)
		var env struct {
			Type string `json:"type"`
			Id   int    `json:"id"`
		}
		if err := json.Unmarshal(b, &env); err != nil {
			t.Fatalf("decode %q: %v", b, err)
		}
		if env.Id != 0 || env.Type == "error" {
			return b
		}
	}
}

func nextBytes(t *testing.T, c *conn) []byte {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	b, err := c.r.ReadBytes('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	return b
}

func decodeLine[T any](t *testing.T, b []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode %q: %v", b, err)
	}
	return v
}

func wantReplyText(t *testing.T, c *conn, req, want string) {
	t.Helper()
	rep := decodeLine[api.Reply](t, rawAsk(t, c, req))
	if !rep.Ok || rep.Text != want {
		t.Fatalf("%s -> %+v, want %q", req, rep, want)
	}
}

func wantReplyPrefix(t *testing.T, c *conn, req, prefix string) {
	t.Helper()
	rep := decodeLine[api.Reply](t, rawAsk(t, c, req))
	if !rep.Ok || !strings.HasPrefix(rep.Text, prefix) {
		t.Fatalf("%s -> %+v, want prefix %q", req, rep, prefix)
	}
}

func wantErrPrefix(t *testing.T, c *conn, req, prefix string) {
	t.Helper()
	l := c.ask(req)
	if l.Type != "error" || !strings.HasPrefix(l.Error, prefix) {
		t.Fatalf("%s -> %+v, want error prefix %q", req, l, prefix)
	}
}

func wantState(t *testing.T, c *conn, mode, trial string, kept bool, reasonPrefix string) {
	t.Helper()
	st := c.next()
	got := [5]any{st.Type, st.Mode, st.Trial, st.Kept, st.RulesChanged}
	if got != [5]any{"state", mode, trial, kept, false} || !strings.HasPrefix(st.Reason, reasonPrefix) {
		t.Fatalf("state = %+v, want mode=%q trial=%q kept=%v reason=%q", st, mode, trial, kept, reasonPrefix)
	}
}

func TestTrialVerb(t *testing.T) {
	at := time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC)
	s := Start(t, Options{Operator: uint32(os.Getuid()), Now: atClock(at), ReloadAfter: 20 * time.Millisecond})
	c := subscribed(t, s)

	want := "enforce until " + at.Add(10*time.Minute).Local().Format(time.RFC3339) +
		" (10m0s); end early: snitchd end\ntrial file: /var/lib/snitch/trial"
	wantReplyText(t, c, `{"type":"trial","id":2,"duration":"10m"}`, want)
	wantState(t, c, "enforce", "2026-10-11T12:10:00Z", false, "trial until ")

	wantErrPrefix(t, c, `{"type":"trial","id":3,"duration":"10m"}`, "a trial is already running until ")
	wantReplyPrefix(t, c, `{"type":"trial","id":4,"duration":"20m","extend":true}`, "trial extended: enforce until ")
	wantState(t, c, "enforce", "2026-10-11T12:20:00Z", false, "trial until ")
	wantErrPrefix(t, c, `{"type":"trial","id":5,"duration":"2h"}`, "trial duration 2h0m0s: must be between 1m0s and 1h0m0s")

	_ = s.Do("kill on")
	wantErrPrefix(t, c, `{"type":"trial","id":6,"duration":"10m"}`, "the kill switch is set:")
	_ = s.Do("kill off")
	_ = s.Do("learning on")
	wantErrPrefix(t, c, `{"type":"trial","id":7,"duration":"10m"}`, "the daemon is learning (-learn):")
}

func TestTrialNoRulesQuestion(t *testing.T) {
	s := Start(t, Options{Operator: uint32(os.Getuid()), ReloadAfter: 20 * time.Millisecond})
	if err := s.Do("rules none"); err != nil {
		t.Fatal(err)
	}
	c := subscribed(t, s)
	wantQ := "No rules are loaded: every connection outside the local network will be denied for 10m0s. Start the trial? [y/N]"
	if l := c.ask(`{"type":"trial","id":2,"duration":"10m"}`); l.Type != "error" || l.Error != wantQ || s.Facts().Mode != "monitor" {
		t.Fatalf("no-rules error = %+v, mode = %q", l, s.Facts().Mode)
	}
	wantReplyPrefix(t, c, `{"type":"trial","id":3,"duration":"10m","yes":true}`, "enforce until ")
	wantState(t, c, "enforce", s.Facts().Trial, false, "trial until ")
}

func TestKeepVerb(t *testing.T) {
	s := Start(t, Options{Operator: uint32(os.Getuid()), ReloadAfter: 20 * time.Millisecond})
	c := subscribed(t, s)
	wantErrPrefix(t, c, `{"type":"keep","id":2}`, "enforce can only be kept during a trial (snitchd trial starts one)")
	wantReplyPrefix(t, c, `{"type":"trial","id":3,"duration":"10m"}`, "enforce until ")
	_ = c.next()
	want := "enforce kept: /var/lib/snitch/enforce\nthe way back: rm /var/lib/snitch/enforce (or: snitchd unkeep, snitchd end, scripts/fail-open.sh)"
	wantReplyText(t, c, `{"type":"keep","id":4}`, want)
	wantState(t, c, "enforce", "", true, reasonKept)
	wantReplyPrefix(t, c, `{"type":"keep","id":5}`, "enforce is already kept: /var/lib/snitch/enforce\n")
}

func TestUnkeepVerb(t *testing.T) {
	s := Start(t, Options{Operator: uint32(os.Getuid()), ReloadAfter: 20 * time.Millisecond})
	c := subscribed(t, s)
	wantReplyText(t, c, `{"type":"unkeep","id":2}`, "nothing was kept")
	wantReplyPrefix(t, c, `{"type":"trial","id":3,"duration":"10m"}`, "enforce until ")
	_ = c.next()
	wantReplyPrefix(t, c, `{"type":"keep","id":4}`, "enforce kept:")
	_ = c.next()
	wantReplyText(t, c, `{"type":"unkeep","id":5}`, "enforce unkept: /var/lib/snitch/enforce removed (monitor within 5 s)")
	wantState(t, c, "monitor", "", false, reasonUnkept)
}

func TestEndVerb(t *testing.T) {
	s := Start(t, Options{Operator: uint32(os.Getuid()), ReloadAfter: 20 * time.Millisecond})
	c := subscribed(t, s)
	wantReplyText(t, c, `{"type":"end","id":2}`, "already monitor: no trial, nothing kept")

	wantReplyPrefix(t, c, `{"type":"trial","id":3,"duration":"10m"}`, "enforce until ")
	_ = c.next()
	wantReplyText(t, c, `{"type":"end","id":4}`, "trial ended: /var/lib/snitch/trial removed (monitor within 5 s)")
	wantState(t, c, "monitor", "", false, reasonEnded)

	wantReplyPrefix(t, c, `{"type":"trial","id":5,"duration":"10m"}`, "enforce until ")
	_ = c.next()
	wantReplyPrefix(t, c, `{"type":"keep","id":6}`, "enforce kept:")
	_ = c.next()
	wantReplyText(t, c, `{"type":"end","id":7}`, "enforce unkept: /var/lib/snitch/enforce removed (monitor within 5 s)")
	wantState(t, c, "monitor", "", false, reasonEnded)
}
