package rules_test

import (
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/rules"
)

var (
	t0   = time.Date(2026, 10, 10, 6, 0, 0, 0, time.UTC)
	curl = rules.ExeKey{Ino: 100, Dev: 8<<20 | 1}
)

func obs(path string, exe rules.ExeKey, addr string, proto rules.Proto, port uint16, at time.Time) rules.Observation {
	return rules.Observation{Path: path, Exe: exe, Addr: netip.MustParseAddr(addr), Proto: proto, Port: port, At: at}
}

func TestLearnObserveMergesRepeatsWithCountAndTimes(t *testing.T) {
	l := rules.NewLearned(nil)
	if !l.Observe(obs("/usr/bin/curl", curl, "1.1.1.1", rules.TCP, 443, t0.Add(time.Minute))) {
		t.Fatal("first observation must report a change")
	}
	if !l.Observe(obs("/usr/bin/curl", curl, "1.1.1.1", rules.TCP, 443, t0)) {
		t.Fatal("a repeat changes the count and must report a change")
	}
	l.Observe(obs("/usr/bin/curl", curl, "1.1.1.1", rules.TCP, 443, t0.Add(2*time.Minute)))
	f := l.File()
	wantPrograms := []rules.Program{{Name: "curl", Paths: []string{"/usr/bin/curl"}, ID: 1}}
	wantRules := []rules.Rule{{Program: "curl", To: netip.MustParsePrefix("1.1.1.1/32"), Proto: rules.TCP, Ports: []uint16{443},
		Verdict: rules.Allow, Count: 3, First: t0, Last: t0.Add(2 * time.Minute), ID: 1}}
	if !reflect.DeepEqual(f.Programs, wantPrograms) || !reflect.DeepEqual(f.Rules, wantRules) {
		t.Fatalf("merged file wrong:\n got %+v\nwant %+v %+v", f, wantPrograms, wantRules)
	}
}

func TestLearnDirtyIsClearedByFile(t *testing.T) {
	l := rules.NewLearned(nil)
	if l.Dirty() {
		t.Fatal("fresh state is clean")
	}
	l.Observe(obs("/usr/bin/curl", curl, "1.1.1.1", rules.TCP, 443, t0))
	if !l.Dirty() {
		t.Fatal("an observation makes the state dirty")
	}
	l.File()
	if l.Dirty() {
		t.Fatal("File() clears the dirty flag")
	}
}

func TestLearnProgramNamingRules(t *testing.T) {
	l := rules.NewLearned(nil)
	l.Observe(obs("/usr/bin/python3", rules.ExeKey{Ino: 1, Dev: 1}, "1.1.1.1", rules.TCP, 443, t0))
	l.Observe(obs("/home/mc/.local/share/uv/python/bin/python3", rules.ExeKey{Ino: 2, Dev: 1}, "1.1.1.1", rules.TCP, 443, t0))
	l.Observe(obs("", rules.ExeKey{Ino: 77, Dev: 8<<20 | 1}, "9.9.9.9", rules.UDP, 53, t0))     // exited before lookup
	l.Observe(obs("/opt/bin/any", rules.ExeKey{Ino: 3, Dev: 1}, "1.1.1.1", rules.TCP, 443, t0)) // reserved word
	named := rules.Observation{Path: "/usr/bin/curl", Exe: curl, Program: "curl-configured", Addr: netip.MustParseAddr("2001:db8::1"), Proto: rules.TCP, Port: 443, At: t0}
	l.Observe(named)
	f := l.File()
	got := map[string][]string{}
	for _, p := range f.Programs {
		got[p.Name] = p.Paths
	}
	want := map[string][]string{
		"python3":            {"/home/mc/.local/share/uv/python/bin/python3"}, // sorted by path: this one is first
		"python3-2":          {"/usr/bin/python3"},
		"unknown-77-8388609": {},
		"any-exe":            {"/opt/bin/any"},
		"curl-configured":    {"/usr/bin/curl"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("\n got %v\nwant %v", got, want)
	}
	for _, r := range f.Rules {
		if r.Program == "curl-configured" && r.To != netip.MustParsePrefix("2001:db8::1/128") {
			t.Fatalf("v6 destinations become /128, got %v", r.To)
		}
	}
}

func TestLearnFileIsDeterministicAndValid(t *testing.T) {
	l := rules.NewLearned(nil)
	l.Observe(obs("/usr/bin/curl", curl, "9.9.9.9", rules.UDP, 53, t0))
	l.Observe(obs("/usr/bin/curl", curl, "1.1.1.1", rules.TCP, 443, t0))
	l.Observe(obs("/usr/bin/git", rules.ExeKey{Ino: 300, Dev: 1}, "1.1.1.1", rules.TCP, 443, t0))
	a, b := l.File(), l.File()
	if !reflect.DeepEqual(a, b) {
		t.Fatal("File() must be deterministic")
	}
	if a.Programs[0].Name != "curl" || a.Rules[0].Program != "curl" || a.Rules[0].To.Addr().String() != "1.1.1.1" {
		t.Fatalf("want programs by name and rules by program then address, got %+v", a)
	}
	if a.Programs[0].ID != 1 || a.Rules[2].ID != 3 {
		t.Fatalf("learned files carry dense ids like parsed ones: %+v", a)
	}
}

func TestLearnSeedContinuesCounts(t *testing.T) {
	l := rules.NewLearned(nil)
	l.Observe(obs("/usr/bin/curl", curl, "1.1.1.1", rules.TCP, 443, t0))
	l.Observe(obs("/usr/bin/curl", curl, "1.1.1.1", rules.TCP, 443, t0.Add(time.Hour)))
	seed := l.File()
	again := rules.NewLearned(seed)
	if again.Dirty() {
		t.Fatal("seeding does not dirty the state")
	}
	again.Observe(obs("/usr/bin/curl", curl, "1.1.1.1", rules.TCP, 443, t0.Add(2*time.Hour)))
	r := again.File().Rules[0]
	if r.Count != 3 || !r.First.Equal(t0) || !r.Last.Equal(t0.Add(2*time.Hour)) {
		t.Fatalf("seed not continued: %+v", r)
	}
}

func TestLearnWriteFileRoundTrips(t *testing.T) {
	l := rules.NewLearned(nil)
	l.Observe(obs("/usr/bin/curl", curl, "1.1.1.1", rules.TCP, 443, t0))
	l.Observe(obs("/usr/bin/curl", curl, "2001:db8::1", rules.UDP, 53, t0.Add(time.Second)))
	l.Observe(obs("", rules.ExeKey{Ino: 77, Dev: 5}, "9.9.9.9", rules.UDP, 53, t0))
	l.Observe(obs("/tmp/odd \"quoted\" path\\x", rules.ExeKey{Ino: 8, Dev: 5}, "9.9.9.9", rules.TCP, 80, t0))
	want := l.File()
	path := filepath.Join(t.TempDir(), "learned.toml")
	if err := rules.WriteFile(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := rules.Load(path)
	if err != nil {
		t.Fatalf("the written file must load without edits: %v", err)
	}
	if !reflect.DeepEqual(strip(got), strip(want)) {
		t.Fatalf("round trip changed the model:\n got %+v\nwant %+v", strip(got), strip(want))
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil || len(entries) != 1 {
		t.Fatalf("temp file left behind: %v", entries)
	}
	src, _ := os.ReadFile(path)
	if !strings.HasPrefix(string(src), "# ") {
		t.Fatal("the file starts with a header comment")
	}
}

// strip removes what a parse legitimately changes: header lines and the source file.
func strip(f *rules.File) *rules.File {
	out := &rules.File{}
	for _, p := range f.Programs {
		p.Line, p.Source = 0, ""
		out.Programs = append(out.Programs, p)
	}
	for _, r := range f.Rules {
		r.Line, r.Source = 0, ""
		out.Rules = append(out.Rules, r)
	}
	return out
}

func TestLearnWriteFileFailsWithoutDirectory(t *testing.T) {
	err := rules.WriteFile(filepath.Join(t.TempDir(), "missing", "learned.toml"), rules.NewLearned(nil).File())
	if err == nil {
		t.Fatal("want an error")
	}
}

func TestLearnSeedContinuesUnknownAndConfiguredSubjects(t *testing.T) {
	l := rules.NewLearned(nil)
	unknown := obs("", rules.ExeKey{Ino: 77, Dev: 5}, "9.9.9.9", rules.UDP, 53, t0)
	configured := rules.Observation{Path: "/usr/bin/curl", Exe: curl, Program: "tooling", Addr: netip.MustParseAddr("1.1.1.1"), Proto: rules.TCP, Port: 443, At: t0}
	l.Observe(unknown)
	l.Observe(configured)
	again := rules.NewLearned(l.File())
	again.Observe(unknown)
	again.Observe(configured)
	f := again.File()
	if len(f.Rules) != 2 || f.Rules[0].Count != 2 || f.Rules[1].Count != 2 {
		t.Fatalf("seeded subjects did not merge with new observations: %+v", f.Rules)
	}
}

func TestLearnWriteFileReplacesTheFileAtomically(t *testing.T) {
	// a rename gives the target a new inode every time; an in-place write would keep it and
	// let a reader see a half-written file
	path := filepath.Join(t.TempDir(), "learned.toml")
	f := rules.NewLearned(nil).File()
	inode := func() uint64 {
		var st syscall.Stat_t
		if err := syscall.Stat(path, &st); err != nil {
			t.Fatal(err)
		}
		return st.Ino
	}
	if err := rules.WriteFile(path, f); err != nil {
		t.Fatal(err)
	}
	first := inode()
	if err := rules.WriteFile(path, f); err != nil {
		t.Fatal(err)
	}
	if inode() == first {
		t.Fatal("the file was rewritten in place, not replaced by rename")
	}
}

func TestLearnSeedKeepsAConfiguredNameThatLooksDerived(t *testing.T) {
	// "curl-configured" starts with the basename of /usr/bin/curl: seeding must not mistake it
	// for a collision-suffixed derived name, or the executable ends up under two names
	l := rules.NewLearned(nil)
	o := rules.Observation{Path: "/usr/bin/curl", Exe: curl, Program: "curl-configured", Addr: netip.MustParseAddr("1.1.1.1"), Proto: rules.TCP, Port: 443, At: t0}
	l.Observe(o)
	again := rules.NewLearned(l.File())
	again.Observe(o)
	f := again.File()
	if len(f.Programs) != 1 || f.Programs[0].Name != "curl-configured" || len(f.Rules) != 1 || f.Rules[0].Count != 2 {
		t.Fatalf("want one program curl-configured with count 2, got %+v %+v", f.Programs, f.Rules)
	}
}

func TestLearnUnknownPathKeepsIdentityAcrossSeed(t *testing.T) {
	l := rules.NewLearned(nil)
	l.Observe(obs("", rules.ExeKey{Ino: 77, Dev: 5}, "9.9.9.9", rules.UDP, 53, t0))
	f := l.File()
	if f.Programs[0].Note != "exe ino=77 dev=5" {
		t.Fatalf("a pathless program records its identity in the note, got %q", f.Programs[0].Note)
	}
	again := rules.NewLearned(f)
	again.Observe(obs("", rules.ExeKey{Ino: 77, Dev: 5}, "9.9.9.9", rules.UDP, 53, t0))
	if again.File().Rules[0].Count != 2 {
		t.Fatal("identity from the note did not merge")
	}
}

func TestLearnTimesAreWholeSecondsSoTheFileIsExact(t *testing.T) {
	l := rules.NewLearned(nil)
	l.Observe(obs("/usr/bin/curl", curl, "1.1.1.1", rules.TCP, 443, t0.Add(123456789*time.Nanosecond)))
	want := l.File()
	path := filepath.Join(t.TempDir(), "learned.toml")
	if err := rules.WriteFile(path, want); err != nil {
		t.Fatal(err)
	}
	got, err := rules.Load(path)
	if err != nil || !got.Rules[0].First.Equal(want.Rules[0].First) || !want.Rules[0].First.Equal(t0) {
		t.Fatalf("sub-second times must not survive into the model: %v / %v (%v)", got.Rules[0].First, want.Rules[0].First, err)
	}
}

func TestLearnSeedRecoversIdentityFromTheNameWhenTheNoteIsGone(t *testing.T) {
	l := rules.NewLearned(nil)
	l.Observe(obs("", rules.ExeKey{Ino: 77, Dev: 5}, "9.9.9.9", rules.UDP, 53, t0))
	f := l.File()
	f.Programs[0].Note = "operator wrote something else here"
	again := rules.NewLearned(f)
	again.Observe(obs("", rules.ExeKey{Ino: 77, Dev: 5}, "9.9.9.9", rules.UDP, 53, t0))
	if g := again.File(); len(g.Programs) != 1 || g.Rules[0].Count != 2 {
		t.Fatalf("identity from the name did not merge: %+v", g)
	}
}

func TestLearnOtherProtocolsRoundTripAsAny(t *testing.T) {
	// an ICMP socket (proto 1) has no spelling in the file; it must not become a duplicate of
	// its own re-seeded "any" entry on the next write
	l := rules.NewLearned(nil)
	icmp := obs("/usr/bin/ping", rules.ExeKey{Ino: 9, Dev: 1}, "1.1.1.1", rules.Proto(1), 0, t0)
	l.Observe(icmp)
	path := filepath.Join(t.TempDir(), "learned.toml")
	if err := rules.WriteFile(path, l.File()); err != nil {
		t.Fatal(err)
	}
	seed, err := rules.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	again := rules.NewLearned(seed)
	again.Observe(icmp)
	if err := rules.WriteFile(path, again.File()); err != nil {
		t.Fatal(err)
	}
	f, err := rules.Load(path)
	if err != nil || len(f.Rules) != 1 || f.Rules[0].Count != 2 || f.Rules[0].Proto != rules.AnyProto {
		t.Fatalf("want one any-proto rule with count 2, got %v, %v", f, err)
	}
}
