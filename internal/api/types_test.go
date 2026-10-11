package api

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"
)

// keysOf marshals v and returns the sorted top-level JSON keys.
func keysOf(t *testing.T, v any) []string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("unmarshal %s: %v", b, err)
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func wantKeys(t *testing.T, got []string, want ...string) {
	t.Helper()
	sort.Strings(want)
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("json keys\n got %v\nwant %v", got, want)
	}
}

// Req 2.6: the Python client's names where they map (design "Wire types").
func TestEventJSONNames(t *testing.T) {
	e := Event{Type: "event", Time: time.Unix(1, 0).UTC(), Program: "curl", Path: "/usr/bin/curl",
		Addr: "1.2.3.4", Port: 443, Protocol: "tcp", Verdict: "allow-rule", Hook: "connect"}
	wantKeys(t, keysOf(t, e), "type", "id", "time", "program", "path", "pid", "ppid", "comm",
		"addr", "port", "protocol", "verdict", "rule", "hook", "cookie")
	b, _ := json.Marshal(e)
	for _, frag := range []string{`"rule":null`, `"id":0`, `"time":"1970-01-01T00:00:01Z"`} {
		if !strings.Contains(string(b), frag) {
			t.Fatalf("event %s lacks %s", b, frag)
		}
	}
}

func TestEntryJSONNames(t *testing.T) {
	wantKeys(t, keysOf(t, Entry{}), "program", "path", "addr", "port", "protocol", "allowCount",
		"denyCount", "firstSeen", "lastSeen", "lastAllowed", "lastBlocked", "bytesSent", "rate", "verdict")
}

func TestRuleRefAndViewsJSONNames(t *testing.T) {
	wantKeys(t, keysOf(t, RuleRef{}), "id", "note", "source")
	wantKeys(t, keysOf(t, RuleView{}), "id", "program", "to", "protocol", "port", "verdict", "note", "source")
	wantKeys(t, keysOf(t, ProgramView{}), "name", "paths", "resolved", "executables", "source")
	wantKeys(t, keysOf(t, Observation{}), "program", "path", "addr", "protocol", "port", "count", "first", "last")
	wantKeys(t, keysOf(t, State{}), "type", "id", "mode", "trial", "kept", "rulesChanged", "reason")
	wantKeys(t, keysOf(t, Summary{Type: "summary"}), "type", "id", "since", "entries")
	wantKeys(t, keysOf(t, Dropped{Type: "dropped"}), "type", "id", "count")
}

func TestStatusJSONNames(t *testing.T) {
	wantKeys(t, keysOf(t, Status{}), "running", "pid", "version", "mode", "source", "trial", "kept",
		"kill", "learning", "rules", "rulesError", "clients", "dropped", "entries", "evictions",
		"started", "counting")
	wantKeys(t, keysOf(t, RulesSummary{}), "programs", "resolved", "executables", "rules", "file", "overlay")
}

// Req 1.7: a reply echoes the request id; an error carries the id when it was parsed.
func TestReplyAndErrorEchoId(t *testing.T) {
	b, _ := json.Marshal(Reply{Type: "reply", Id: 7, Ok: true})
	if string(b) != `{"type":"reply","id":7,"ok":true}` {
		t.Fatalf("reply: %s", b)
	}
	b, _ = json.Marshal(Error{Type: "error", Id: 9, Error: "unknown type: x"})
	if string(b) != `{"type":"error","id":9,"error":"unknown type: x"}` {
		t.Fatalf("error: %s", b)
	}
	// Payload fields stay out of a bare reply and appear with their lowerCamel names.
	wantKeys(t, keysOf(t, Reply{Type: "reply", Status: &Status{}, Window: "15m"}), "type", "id", "ok", "status", "window")
}

func TestRequestJSONNames(t *testing.T) {
	var r Request
	line := `{"type":"rule.add","id":3,"program":"curl","path":"/p","to":"1.1.1.1/32","proto":"tcp",` +
		`"port":443,"verdict":"allow","note":"n","window":"1h","events":true,"local":true,` +
		`"summary":true,"duration":"2m","extend":true}`
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		t.Fatal(err)
	}
	want := Request{Type: "rule.add", Id: 3, Program: "curl", Path: "/p", To: "1.1.1.1/32", Proto: "tcp",
		Port: 443, Verdict: "allow", Note: "n", Window: "1h", Events: true, Local: true, Summary: true,
		Duration: "2m", Extend: true}
	if r != want {
		t.Fatalf("request\n got %+v\nwant %+v", r, want)
	}
}

func TestConstants(t *testing.T) {
	if LineLimit != 64<<10 || Backlog != 1024 || WriteDeadline != 5*time.Second ||
		SummaryEvery != 2*time.Second || MaxClients != 64 {
		t.Fatalf("constants drifted from the design: %d %d %v %v %d", LineLimit, Backlog, WriteDeadline, SummaryEvery, MaxClients)
	}
}

func TestRequestYesMarshalsUnderItsName(t *testing.T) {
	b, err := json.Marshal(Request{Type: "trial", Id: 1, Duration: "10m", Yes: true})
	if err != nil || !strings.Contains(string(b), `"yes":true`) {
		t.Fatalf("got %s, %v", b, err)
	}
}
