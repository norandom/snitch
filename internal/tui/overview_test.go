package tui

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/clean"
	"github.com/norandom/snitch/internal/client"
	"github.com/norandom/snitch/internal/conf"
)

func assertGolden(t *testing.T, name string, got string) {
	t.Helper()
	path := filepath.Join("testdata", name+".golden")
	wantBytes, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read golden %s: %v", path, err)
	}
	want := strings.TrimSuffix(string(wantBytes), "\n")
	if got != want {
		t.Fatalf("%s mismatch:\n--- GOT ---\n%s\n--- WANT ---\n%s", name, got, want)
	}
}

func overviewModel(t *testing.T, t0 time.Time, opts Options, st api.Status, rules []api.RuleView, progs []api.ProgramView, entries []api.Entry) Model {
	t.Helper()
	m, rReq, pReq, sReq := upModel(t, t0, opts)
	m, _ = Update(m, client.Facts{Status: st}, t0)
	m, _ = Update(m, client.Answered{Token: rReq.Token, Reply: &api.Reply{Ok: true, Rules: rules}}, t0)
	m, _ = Update(m, client.Answered{Token: pReq.Token, Reply: &api.Reply{Ok: true, Programs: progs}}, t0)
	m, _ = Update(m, client.Answered{Token: sReq.Token, Reply: &api.Reply{Ok: true, Window: m.window, Entries: entries}}, t0)
	m, _ = Update(m, Tick{}, t0)
	return m
}

func baseOverviewEntries(t0 time.Time) []api.Entry {
	return []api.Entry{
		{
			Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "api.example.com",
			Port: 443, Protocol: "tcp", AllowCount: 12, BytesSent: 4096, Rate: 512,
			LastSeen: t0.Format(time.RFC3339), LastAllowed: t0.Format(time.RFC3339), Verdict: "allow-rule",
		},
		{
			Program: "curl", Path: "/usr/bin/curl", Addr: "9.9.9.9", Name: "very-long-subdomain-name.blocked.example.org",
			Port: 443, Protocol: "tcp", DenyCount: 2,
			LastSeen: t0.Add(-10 * time.Second).Format(time.RFC3339), LastBlocked: t0.Add(-10 * time.Second).Format(time.RFC3339), Verdict: "deny-rule",
		},
		{
			Program: "dig", Path: "/usr/bin/dig", Addr: "8.8.8.8", Name: "dns.google",
			Port: 53, Protocol: "udp", AllowCount: 3, BytesSent: 512,
			LastSeen: t0.Add(-2 * time.Minute).Format(time.RFC3339), LastAllowed: t0.Add(-2 * time.Minute).Format(time.RFC3339), Verdict: "allow-rule",
		},
		{
			Program: "unknown", BytesSent: 256,
			LastSeen: t0.Add(-5 * time.Minute).Format(time.RFC3339), Verdict: "allow-monitor",
		},
	}
}

func TestRenderOverviewGolden(t *testing.T) {
	t0 := feedTime()
	opts := Options{
		Conf:    conf.Default(),
		Loc:     time.UTC,
		Socket:  clean.Const("/run/snitch/snitch.sock"),
		LogTail: []clean.Safe{clean.Const("2026-11-26 11:59:00  BLOCKED curl > 1.1.1.1:443 tcp")},
	}
	st := api.Status{Running: true, Mode: "monitor", Rules: api.RulesSummary{Overlay: "/etc/snitch/rules.d/local.toml"}}
	rules := []api.RuleView{
		{Id: 1, Program: "curl", To: "api.example.com", Protocol: "tcp", Port: 443, Verdict: "allow", Note: "api traffic", Source: "/etc/snitch/rules.toml"},
		{Id: 2, Program: "curl", To: "9.9.9.9/32", Protocol: "tcp", Port: 443, Verdict: "deny", Note: "snitch tui 2026-11-26 11:59", Source: "/etc/snitch/rules.d/local.toml"},
	}
	progs := []api.ProgramView{
		{Name: "curl", Paths: []string{"/usr/bin/curl"}, Resolved: true, Executables: 1},
		{Name: "dig", Paths: []string{"/usr/bin/dig"}, Resolved: true, Executables: 1},
	}
	m := overviewModel(t, t0, opts, st, rules, progs, baseOverviewEntries(t0))
	m, _ = pressKey(m, "enter", t0.Add(time.Second))
	m, _ = pressKey(m, "down", t0.Add(2*time.Second))
	m, _ = pressKey(m, "enter", t0.Add(3*time.Second))
	m, _ = pressKey(m, "down", t0.Add(4*time.Second))
	assertGolden(t, "overview", flattenScreen(Render(m, t0)))
}

func headerTestModel(t *testing.T, t0 time.Time, st api.Status, verdict string) Model {
	t.Helper()
	opts := Options{Conf: conf.Default(), Loc: time.UTC, Socket: clean.Const("/run/snitch/snitch.sock")}
	progs := []api.ProgramView{{Name: "curl", Paths: []string{"/usr/bin/curl"}, Resolved: true, Executables: 1}}
	entries := []api.Entry{{
		Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "api.example.com",
		Port: 443, Protocol: "tcp", AllowCount: 12, BytesSent: 4096, Rate: 512,
		LastSeen: t0.Format(time.RFC3339), LastAllowed: t0.Format(time.RFC3339), Verdict: verdict,
	}}
	return overviewModel(t, t0, opts, st, nil, progs, entries)
}

func TestHeaderStatesGolden(t *testing.T) {
	t0 := feedTime()
	mTrial := headerTestModel(t, t0, api.Status{Running: true, Mode: "enforce", Trial: "2026-11-26T12:10:00Z"}, "allow-rule")
	assertGolden(t, "trial", flattenScreen(Render(mTrial, t0.Add(30*time.Second))))

	mKill := headerTestModel(t, t0, api.Status{Running: true, Mode: "enforce", Kept: true, Kill: true}, "allow-kill")
	assertGolden(t, "kill", flattenScreen(Render(mKill, t0)))

	mSearch := headerTestModel(t, t0, api.Status{Running: true, Mode: "monitor"}, "allow-rule")
	mSearch, _ = pressKey(mSearch, "/", t0.Add(time.Second))
	for i, ch := range []string{"a", "p", "i"} {
		mSearch, _ = Update(mSearch, Key{Name: ch, Text: ch, At: t0.Add(time.Duration(i+2) * time.Second)}, t0.Add(time.Duration(i+2)*time.Second))
	}
	mSearch, _ = pressKey(mSearch, "enter", t0.Add(5*time.Second))
	assertGolden(t, "search", flattenScreen(Render(mSearch, t0)))

	mStale := headerTestModel(t, t0, api.Status{Running: true, Mode: "monitor"}, "allow-rule")
	mStale, _ = Update(mStale, client.Down{Reason: "daemon stopped"}, t0.Add(time.Second))
	assertGolden(t, "stale", flattenScreen(Render(mStale, t0)))

	opts := Options{Conf: conf.Default(), Loc: time.UTC, Socket: clean.Const("/run/snitch/snitch.sock")}
	mUp, rReq, pReq, sReq := foreignUpModel(t, t0, opts)
	mUp, _ = Update(mUp, client.Facts{Status: api.Status{Running: true, Mode: "monitor"}}, t0)
	mUp, _ = Update(mUp, client.Answered{Token: rReq.Token, Reply: &api.Reply{Ok: true}}, t0)
	mUp, _ = Update(mUp, client.Answered{Token: pReq.Token, Reply: &api.Reply{Ok: true, Programs: []api.ProgramView{{Name: "curl", Paths: []string{"/usr/bin/curl"}}}}}, t0)
	mUp, _ = Update(mUp, client.Answered{Token: sReq.Token, Reply: &api.Reply{Ok: true, Window: "1h", Entries: []api.Entry{{
		Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "api.example.com",
		Port: 443, Protocol: "tcp", AllowCount: 12, BytesSent: 4096, Rate: 512,
		LastSeen: t0.Format(time.RFC3339), LastAllowed: t0.Format(time.RFC3339), Verdict: "allow-rule",
	}}}}, t0)
	mUp, _ = Update(mUp, Tick{}, t0)
	assertGolden(t, "foreign", flattenScreen(Render(mUp, t0)))
}

func foreignUpModel(t *testing.T, t0 time.Time, opts Options) (Model, Send, Send, Send) {
	t.Helper()
	m, fx := Update(New(opts), client.Up{PeerUID: 1000, PeerKnown: true}, t0)
	sends := sendsOf(fx)
	return m, mustSend(t, sends, "rules"), mustSend(t, sends, "programs"), mustSend(t, sends, "snapshot")
}

func TestHeaderStaleHeartbeat(t *testing.T) {
	t0 := feedTime()
	m := headerTestModel(t, t0, api.Status{Running: true, Mode: "enforce", Kept: true}, "allow-stale")
	m, _ = Update(m, client.EventLine{Event: api.Event{Program: "curl", Verdict: "allow-stale"}}, t0)
	head := flattenLine(Render(m, t0.Add(5*time.Second)).Lines[0])
	assertContainsAll(t, head, "ALL ALLOWED", "stale heartbeat")
	m, _ = Update(m, Tick{}, t0.Add(16*time.Second))
	headAfter := flattenLine(Render(m, t0.Add(16*time.Second)).Lines[0])
	if strings.Contains(headAfter, "ALL ALLOWED") {
		t.Fatalf("stale heartbeat persisted past 15s: %q", headAfter)
	}
}

func TestDetailInspectBeforeAndAfterGolden(t *testing.T) {
	t0 := feedTime()
	opts := Options{Conf: conf.Default(), Loc: time.UTC, Socket: clean.Const("/run/snitch/snitch.sock")}
	m, rReq, pReq, sReq := upModel(t, t0, opts)
	m, _ = Update(m, client.Facts{Status: api.Status{Running: true, Mode: "monitor"}}, t0)
	m, _ = Update(m, client.Answered{Token: rReq.Token, Reply: &api.Reply{Ok: true}}, t0)
	m, _ = Update(m, client.Answered{Token: pReq.Token, Reply: &api.Reply{Ok: true}}, t0)
	m, _ = Update(m, client.Answered{Token: sReq.Token, Reply: &api.Reply{Ok: true, Window: "1h", Entries: []api.Entry{{
		Program: "unknown", Path: "/home/user/bin/tool", Addr: "1.1.1.1",
		Port: 443, Protocol: "tcp", AllowCount: 1, BytesSent: 1024,
		LastSeen: t0.Format(time.RFC3339), LastAllowed: t0.Format(time.RFC3339), Verdict: "allow-monitor",
	}}}}, t0)
	var fx []Effect
	m, fx = Update(m, Tick{}, t0)
	assertInspects(t, fx, "/home/user/bin/tool")
	assertGolden(t, "inspect_before", flattenScreen(Render(m, t0)))

	m, _ = Update(m, Inspected{Path: "/home/user/bin/tool", Loose: true}, t0.Add(time.Second))
	assertGolden(t, "inspect_after", flattenScreen(Render(m, t0)))
}

func TestDetailInspectOncePerPathAndEmptyPath(t *testing.T) {
	t0 := feedTime()
	opts := Options{Conf: conf.Default(), Loc: time.UTC}
	entries := []api.Entry{
		{Program: "curl", Path: "/usr/bin/curl", Addr: "1.1.1.1", Name: "a.example", Port: 443, Protocol: "tcp", LastSeen: t0.Format(time.RFC3339)},
		{Program: "curl", Path: "/usr/bin/curl", Addr: "2.2.2.2", Name: "b.example", Port: 443, Protocol: "tcp", LastSeen: t0.Add(-time.Second).Format(time.RFC3339)},
		{Program: "unknown", BytesSent: 64, LastSeen: t0.Add(-2 * time.Second).Format(time.RFC3339)},
	}
	m, rReq, pReq, sReq := upModel(t, t0, opts)
	m, _ = Update(m, client.Answered{Token: rReq.Token, Reply: &api.Reply{Ok: true}}, t0)
	m, _ = Update(m, client.Answered{Token: pReq.Token, Reply: &api.Reply{Ok: true}}, t0)
	m, _ = Update(m, client.Answered{Token: sReq.Token, Reply: &api.Reply{Ok: true, Window: "1h", Entries: entries}}, t0)
	var fx []Effect
	m, fx = Update(m, Tick{}, t0)
	count := len(inspectsOf(fx))
	assertInspects(t, fx, "/usr/bin/curl")

	m, fx = pressKey(m, "enter", t0.Add(time.Second))
	count += len(inspectsOf(fx))
	keys := []string{"down", "down", "up", "up"}
	for i := range 100 {
		m, fx = pressKey(m, keys[i%len(keys)], t0.Add(time.Duration(i+2)*100*time.Millisecond))
		count += len(inspectsOf(fx))
	}
	if count != 1 {
		t.Fatalf("100 cursor moves over /usr/bin/curl emitted %d Inspect effects, want 1", count)
	}
	_, fx = pressKey(m, "end", t0.Add(20*time.Second))
	if got := inspectsOf(fx); len(got) != 0 {
		t.Fatalf("row without path emitted Inspect: %#v", got)
	}
}

func TestRenderTableWindowOnlyVisibleAndSafe(t *testing.T) {
	t0 := feedTime()
	entries := numberedEntries(20, t0)
	entries[0].Program = "curl\x1b[31m"
	entries[0].Name = "very-long-host-name-exceeding-column.example.org"
	m := overviewModel(t, t0, Options{Loc: time.UTC}, api.Status{Running: true, Mode: "monitor"}, nil, nil, entries)
	scr := flattenScreen(Render(m, t0))
	if !strings.Contains(scr, "prog-05") || strings.Contains(scr, "prog-06") {
		t.Fatalf("initial 6-row window wrong:\n%s", scr)
	}
	if strings.Contains(scr, "\x1b") {
		t.Fatalf("escape sequence leaked into screen: %q", scr)
	}
	m, _ = pressKey(m, "end", t0.Add(time.Second))
	scrEnd := flattenScreen(Render(m, t0))
	if !strings.Contains(scrEnd, "prog-19") || strings.Contains(scrEnd, "prog-13") {
		t.Fatalf("end 6-row window wrong:\n%s", scrEnd)
	}
}

func inspectsOf(fx []Effect) []Inspect {
	var out []Inspect
	for _, e := range fx {
		if in, ok := e.(Inspect); ok {
			out = append(out, in)
		}
	}
	return out
}

func assertInspects(t *testing.T, fx []Effect, wantPath string) {
	t.Helper()
	got := inspectsOf(fx)
	if len(got) != 1 || got[0].Path != wantPath {
		t.Fatalf("Inspect effects = %#v, want [%q]", got, wantPath)
	}
}

func TestDetailExtrasOverlaysAndImmutability(t *testing.T) {
	t0 := feedTime()
	rules := []api.RuleView{
		{Id: 1, Program: "wget", To: "1.1.1.1/32", Protocol: "tcp", Port: 443, Verdict: "allow", Note: "n1", Source: "a.toml"},
		{Id: 2, Program: "wget", To: "2.2.2.2/32", Protocol: "any", Verdict: "deny", Note: "n2", Source: "b.toml"},
		{Id: 3, Program: "wget", To: "3.3.3.3/32", Verdict: "deny", Note: "n3", Source: "c.toml"},
	}
	entries := []api.Entry{{Program: "wget", Path: "/usr/bin/wget", Addr: "1.1.1.1", Port: 443, Protocol: "tcp", Rate: 0.5, LastSeen: t0.Format(time.RFC3339)}}
	m := overviewModel(t, t0, Options{Loc: time.UTC}, api.Status{Running: true, Mode: "monitor", Kill: true}, rules, nil, entries)
	m, _ = Update(m, client.EventLine{Event: api.Event{Program: "wget", Verdict: "allow-stale"}}, t0)
	prev := m
	m, _ = Update(m, Inspected{Path: "/usr/bin/wget", Loose: false}, t0)
	m, _ = Update(m, Inspected{Path: "", Loose: true}, t0)
	if prev.inspected["/usr/bin/wget"] || m.inspected[""] {
		t.Fatalf("immutability or empty-path guard broken: prev=%v cur=%v", prev.inspected, m.inspected)
	}
	m, _ = pressKey(m, "/", t0.Add(time.Second))
	scr := flattenScreen(Render(m, t0.Add(time.Second)))
	assertContainsAll(t, scr, "ALL ALLOWED (kill switch, stale heartbeat)", "[undeclared]", "0.5B/s", "(+1 more)", "/_  (enter: apply, esc: clear)")
	if strings.Contains(scr, "[writable dir]") {
		t.Fatalf("Loose:false showed [writable dir]:\n%s", scr)
	}
	m, _ = pressKey(m, "esc", t0.Add(2*time.Second))
	m, _ = pressKey(m, "T", t0.Add(3*time.Second))
	assertContainsAll(t, flattenScreen(Render(m, t0.Add(3*time.Second))), "Start enforce trial")
}
