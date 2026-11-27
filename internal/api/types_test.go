package api

import (
	"encoding/json"
	"reflect"
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
func TestEventJSONKeys(t *testing.T) {
	e := Event{Type: "event", Time: time.Unix(1, 0).UTC(), Program: "curl", Path: "/usr/bin/curl",
		Addr: "1.2.3.4", Name: "example.org", Port: 443, Protocol: "tcp", Verdict: "allow-rule", Hook: "connect"}
	wantKeys(t, keysOf(t, e), "type", "id", "time", "program", "path", "pid", "ppid", "comm",
		"addr", "name", "port", "protocol", "verdict", "rule", "hook", "cookie")
	b, _ := json.Marshal(e)
	for _, frag := range []string{`"rule":null`, `"id":0`, `"time":"1970-01-01T00:00:01Z"`} {
		if !strings.Contains(string(b), frag) {
			t.Fatalf("event %s lacks %s", b, frag)
		}
	}
}

func TestEntryJSONKeys(t *testing.T) {
	wantKeys(t, keysOf(t, Entry{Name: "example.org"}), "program", "path", "addr", "name", "port", "protocol", "allowCount",
		"denyCount", "firstSeen", "lastSeen", "lastAllowed", "lastBlocked", "bytesSent", "rate", "verdict")
}

func TestRuleRefAndViewsJSONKeys(t *testing.T) {
	wantKeys(t, keysOf(t, RuleRef{}), "id", "note", "source")
	wantKeys(t, keysOf(t, RuleView{}), "id", "program", "to", "protocol", "port", "verdict", "note", "source")
	wantKeys(t, keysOf(t, ProgramView{}), "name", "paths", "resolved", "executables", "source")
	wantKeys(t, keysOf(t, Observation{Name: "example.org"}), "program", "path", "addr", "name", "protocol", "port", "count", "first", "last")
	wantKeys(t, keysOf(t, State{}), "type", "id", "mode", "trial", "kept", "rulesChanged", "reason")
	wantKeys(t, keysOf(t, Summary{Type: "summary"}), "type", "id", "since", "entries")
	wantKeys(t, keysOf(t, Dropped{Type: "dropped"}), "type", "id", "count")
}

func TestStatusJSONKeys(t *testing.T) {
	wantKeys(t, keysOf(t, Status{DNS: &DNSStatus{}, Hook: &HookStatus{}}), "running", "pid", "version", "mode", "source", "trial", "kept",
		"kill", "learning", "rules", "rulesError", "clients", "dropped", "entries", "evictions",
		"started", "counting", "dns", "hook")
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

func TestRequestJSONKeys(t *testing.T) {
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

func TestDNSStatusJSONKeys(t *testing.T) {
	wantKeys(t, keysOf(t, DNSStatus{Reason: "disabled"}), "on", "reason", "seen", "ignored", "entries", "names", "compiled", "evictions")
	wantKeys(t, keysOf(t, DNSStatus{}), "on", "seen", "ignored", "entries", "names", "compiled", "evictions")
}

func TestOptionalNameAndDNSKeysOmitted(t *testing.T) {
	for _, v := range []any{Event{}, Entry{}, Observation{}, Status{}} {
		for _, k := range keysOf(t, v) {
			if k == "name" || k == "dns" || k == "counters" {
				t.Fatalf("%T includes empty %s", v, k)
			}
		}
	}
	for _, k := range keysOf(t, Status{}) {
		if k == "hook" {
			t.Fatalf("Status includes nil hook")
		}
	}
}

func TestObservationKeysAllowNameWithEmptyAddress(t *testing.T) {
	b, err := json.Marshal(Observation{Name: "example.org"})
	if err != nil || !strings.Contains(string(b), `"addr":""`) || !strings.Contains(string(b), `"name":"example.org"`) {
		t.Fatalf("named observation: %s, %v", b, err)
	}
}

// fullStatus sets every field a status carried before the counters object.
func fullStatus() Status {
	return Status{Running: true, Pid: 4242, Version: "v0.4.0", Mode: "monitor", Source: "trial", Trial: "2026-11-25T10:00:00Z",
		Kept: true, Kill: true, Learning: true,
		Rules: RulesSummary{Programs: 18, Resolved: 17, Executables: 21, Rules: 13, File: "/etc/snitch/rules.toml",
			Overlay: "/etc/snitch/rules.d/local.toml"},
		RulesError: "line 3: bad port", Clients: 2, Dropped: 1, Entries: 120, Evictions: 3,
		Started: "2026-11-25T09:00:00Z", Counting: true,
		DNS: &DNSStatus{On: true, Reason: "r", Seen: 10, Ignored: 2, Entries: 5, Names: 4, Compiled: 3, Evictions: 1}}
}

// statusGolden is fullStatus encoded by the type before the counters object was added.
const statusGolden = `{"running":true,"pid":4242,"version":"v0.4.0","mode":"monitor","source":"trial",` +
	`"trial":"2026-11-25T10:00:00Z","kept":true,"kill":true,"learning":true,"rules":{"programs":18,` +
	`"resolved":17,"executables":21,"rules":13,"file":"/etc/snitch/rules.toml",` +
	`"overlay":"/etc/snitch/rules.d/local.toml"},"rulesError":"line 3: bad port","clients":2,"dropped":1,` +
	`"entries":120,"evictions":3,"started":"2026-11-25T09:00:00Z","counting":true,"dns":{"on":true,` +
	`"reason":"r","seen":10,"ignored":2,"entries":5,"names":4,"compiled":3,"evictions":1}}` + "\n"

// Req 5.3: without counters a status encodes byte for byte as before, and decodes back equal.
func TestStatusWithoutCountersUnchanged(t *testing.T) {
	s := fullStatus()
	if got := string(Encode(s)); got != statusGolden {
		t.Fatalf("status encoding drifted\n got %s\nwant %s", got, statusGolden)
	}
	var back Status
	if err := json.Unmarshal([]byte(statusGolden), &back); err != nil {
		t.Fatal(err)
	}
	if back.Counters != nil || back.Hook != nil || !reflect.DeepEqual(back, s) {
		t.Fatalf("older daemon's status\n got %+v\nwant %+v", back, s)
	}
}

// Req 5.3, 5.7: the counters object round-trips; zero contracts stay, an unavailable section
// carries its reason and no maps, and the existing fields keep their bytes ahead of it.
func TestStatusWithCountersRoundTrips(t *testing.T) {
	s := fullStatus()
	s.Counters = &CountersStatus{
		Egress: ProgramCounters{Available: true,
			Counters:  map[string]uint64{"decisions": 9001, "addr_unreadable": 0, "no_exe": 2, "event_lost": 0},
			Contracts: map[string]uint64{"kill_slot": 0, "control_slot": 0, "rule_verdict": 1, "mode": 0}},
		DNS: ProgramCounters{Available: false, Reason: "tap off: disabled"},
	}
	b := Encode(s)
	var back Status
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, s) {
		t.Fatalf("round trip\n got %+v\nwant %+v", back, s)
	}
	if !strings.HasPrefix(string(b), strings.TrimSuffix(statusGolden, "}\n")+`,"counters":{`) {
		t.Fatalf("existing fields moved: %s", b)
	}
	for _, frag := range []string{`"egress":{"available":true,"counters":{`, `"addr_unreadable":0`, `"kill_slot":0`,
		`"mode":0`, `"dns":{"available":false,"reason":"tap off: disabled"}`} {
		if !strings.Contains(string(b), frag) {
			t.Fatalf("counters %s lacks %s", b, frag)
		}
	}
	wantKeys(t, keysOf(t, CountersStatus{}), "egress", "dns")
	wantKeys(t, keysOf(t, ProgramCounters{}), "available")
	wantKeys(t, keysOf(t, s.Counters.Egress), "available", "counters", "contracts")
}

// An older daemon's status line (no "counters" key) decodes with Counters nil.
func TestStatusFromOlderDaemonHasNoCounters(t *testing.T) {
	var r Reply
	line := `{"type":"reply","id":1,"ok":true,"status":{"running":true,"mode":"monitor","dns":{"on":false}}}`
	if err := json.Unmarshal([]byte(line), &r); err != nil {
		t.Fatal(err)
	}
	if r.Status == nil || r.Status.Counters != nil || r.Status.Hook != nil || !r.Status.Running {
		t.Fatalf("older status: %+v", r.Status)
	}
}

// Req 1.7, 2.1, 2.4, 2.5: the hook object round-trips for every state and preserves existing bytes ahead of it.
func TestStatusWithHookRoundTrips(t *testing.T) {
	cases := []HookStatus{
		{State: HookActive, Reason: "kernel hook active"},
		{State: HookInactive, Pending: true, Reason: "kernel hook inactive: reboot"},
		{State: HookInactive, Reason: "kernel hook inactive: boot not configured"},
		{State: HookInactive, Unsupported: true, Reason: "kernel hook unavailable"},
		{State: HookUnknown, Reason: "kernel hook not checked"},
	}
	goldenPrefix := strings.TrimSuffix(statusGolden, "}\n")
	for _, h := range cases {
		s := fullStatus()
		s.Hook = &h
		b := Encode(s)
		hb, _ := json.Marshal(h)
		want := goldenPrefix + `,"hook":` + string(hb) + "}\n"
		if string(b) != want {
			t.Fatalf("hook %+v\n got %s\nwant %s", h, b, want)
		}
		var back Status
		if err := json.Unmarshal(b, &back); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(back, s) {
			t.Fatalf("round trip %+v\n got %+v\nwant %+v", h, back, s)
		}
	}
	wantKeys(t, keysOf(t, HookStatus{}), "state", "reason")
	wantKeys(t, keysOf(t, HookStatus{Pending: true, Unsupported: true}), "state", "pending", "unsupported", "reason")
}
