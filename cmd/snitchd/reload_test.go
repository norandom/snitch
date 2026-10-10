package main

import (
	"os"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/rules"
)

func snapWith(self string, extra string) *snapshot {
	f, err := rules.Parse(strings.NewReader("[[program]]\nname = \"me\"\npaths = [\""+self+"\"]\n\n[[rule]]\nprogram = \"me\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\n"+extra), "t")
	if err != nil {
		panic(err)
	}
	res, err := rules.Resolve(f, rules.OSFS(func(string) {}))
	if err != nil {
		panic(err)
	}
	return &snapshot{res: res, ent: rules.Encode(res)}
}

func newReloader(t *testing.T, path string, rec *recorder) (*reloader, *[]string) {
	t.Helper()
	logs := &[]string{}
	st := &state{}
	r := &reloader{path: path, st: st, programs: rec.ops("programs"), rules: rec.ops("rules"), load: loadRules,
		log: func(m string) { *logs = append(*logs, m) }}
	return r, logs
}

func TestReloadFullPublishesAndAppliesTheDiff(t *testing.T) {
	self, _ := os.Executable()
	path := writeRules(t, "[[program]]\nname = \"me\"\npaths = [\""+self+"\"]\n\n[[rule]]\nprogram = \"me\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\n")
	rec := &recorder{}
	r, _ := newReloader(t, path, rec)
	r.st.publish(snapWith(self, ""))
	os.WriteFile(path, []byte("[[program]]\nname = \"me\"\npaths = [\""+self+"\"]\n\n[[rule]]\nprogram = \"me\"\nto = \"2.2.2.2\"\nverdict = \"deny\"\n"), 0o644)
	if !r.reload(true) {
		t.Fatal("a valid changed file reloads")
	}
	if got := strings.Join(rec.log, ","); got != "rules put,rules del" {
		t.Fatalf("want the new rule put and the old one deleted, got %q", got)
	}
	if r.st.current().res.File.Rules[0].To.String() != "2.2.2.2/32" {
		t.Fatal("the new snapshot is not current")
	}
}

func TestReloadInvalidFileKeepsThePreviousSnapshot(t *testing.T) {
	self, _ := os.Executable()
	path := writeRules(t, "garbage = [\n")
	rec := &recorder{}
	r, logs := newReloader(t, path, rec)
	before := snapWith(self, "")
	r.st.publish(before)
	if r.reload(true) || r.st.current() != before || len(rec.log) != 0 {
		t.Fatalf("an invalid file must change nothing: current=%p before=%p ops=%v", r.st.current(), before, rec.log)
	}
	if len(*logs) != 1 || !strings.Contains((*logs)[0], "keeping the previous rules") || !strings.Contains((*logs)[0], ":1:") {
		t.Fatalf("want one log line with file:line, got %q", *logs)
	}
}

func TestReloadMapFailureKeepsThePreviousSnapshot(t *testing.T) {
	self, _ := os.Executable()
	path := writeRules(t, "[[program]]\nname = \"me\"\npaths = [\""+self+"\"]\n\n[[rule]]\nprogram = \"me\"\nto = \"3.3.3.3\"\nverdict = \"allow\"\n")
	rec := &recorder{fail: true}
	r, logs := newReloader(t, path, rec)
	before := snapWith(self, "")
	r.st.publish(before)
	if r.reload(true) || r.st.current() != before || len(*logs) != 1 {
		t.Fatalf("a failed map write must keep the old snapshot: %v", *logs)
	}
}

func TestReloadReresolvePicksUpANewExecutable(t *testing.T) {
	self, _ := os.Executable()
	dir := t.TempDir()
	path := writeRules(t, "[[program]]\nname = \"me\"\npaths = [\""+self+"\", \""+dir+"/*\"]\n\n[[rule]]\nprogram = \"me\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\n")
	rec := &recorder{}
	r, _ := newReloader(t, path, rec)
	first, err := loadRules(path, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	r.st.publish(first)
	if len(first.ent.Programs) != 1 {
		t.Fatalf("want one executable before the copy, got %d", len(first.ent.Programs))
	}
	data, _ := os.ReadFile(self)
	os.WriteFile(dir+"/copy", data, 0o755)
	if !r.reload(false) || len(r.st.current().ent.Programs) != 2 {
		t.Fatal("re-resolve must map the new executable")
	}
	if got := strings.Join(rec.log, ","); got != "programs put" {
		t.Fatalf("want exactly one programs put, got %q", got)
	}
}

func TestStampChangesWhenTheFileChanges(t *testing.T) {
	path := writeRules(t, "# a\n")
	a, ok := stampOf(path)
	if !ok {
		t.Fatal("stat failed")
	}
	os.WriteFile(path, []byte("# ab\n"), 0o644) // size changes even if mtime granularity hides the write
	b, _ := stampOf(path)
	if a == b {
		t.Fatal("a rewritten file must have a different stamp")
	}
	if _, ok := stampOf(path + ".none"); ok {
		t.Fatal("a missing file has no stamp")
	}
}

func TestReloadReresolveDoesNotRereadTheFile(t *testing.T) {
	// re-resolve looks at executables only; a changed file waits for the file watcher
	self, _ := os.Executable()
	path := writeRules(t, "[[program]]\nname = \"me\"\npaths = [\""+self+"\"]\n\n[[rule]]\nprogram = \"me\"\nto = \"1.1.1.1\"\nverdict = \"allow\"\n")
	rec := &recorder{}
	r, _ := newReloader(t, path, rec)
	first, _ := loadRules(path, func(string) {})
	r.st.publish(first)
	os.WriteFile(path, []byte("[[program]]\nname = \"me\"\npaths = [\""+self+"\"]\n\n[[rule]]\nprogram = \"me\"\nto = \"9.9.9.9\"\nverdict = \"deny\"\n"), 0o644)
	r.reload(false)
	if to := r.st.current().res.File.Rules[0].To.String(); to != "1.1.1.1/32" {
		t.Fatalf("re-resolve must keep the parsed file, got rule to %s", to)
	}
	if len(rec.log) != 0 {
		t.Fatalf("nothing changed on disk for the executables, want no map writes, got %v", rec.log)
	}
}

func TestStampSeesASizeChangeWithTheSameMtime(t *testing.T) {
	path := writeRules(t, "# a\n")
	a, _ := stampOf(path)
	os.WriteFile(path, []byte("# ab\n"), 0o644)
	os.Chtimes(path, a.mtime, a.mtime) // an editor that preserves mtime, or a coarse clock
	b, _ := stampOf(path)
	if a == b {
		t.Fatal("size must be part of the stamp")
	}
}
