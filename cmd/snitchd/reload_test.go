package main

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
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
	first, err := loadRules(path, "", func(string) {})
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
	first, _ := loadRules(path, "", func(string) {})
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

// overlayReloader watches base and overlay and ticks a fixed clock for the error's time.
func overlayReloader(t *testing.T, base, overlay string, rec *recorder) (*reloader, *[]string) {
	t.Helper()
	r, logs := newReloader(t, base, rec)
	r.overlay, r.paths = overlay, []string{base, overlay}
	r.now = func() time.Time { return time.Date(2026, 10, 11, 12, 0, 0, 0, time.UTC) }
	return r, logs
}

const goodOverlay = "[[rule]]\nprogram = \"me\"\nto = \"8.8.8.8\"\nverdict = \"allow\"\n"

// brokenOverlay publishes a merged snapshot, then breaks the overlay on disk and reloads.
func brokenOverlay(t *testing.T) (r *reloader, before *snapshot, ov string, logs *[]string) {
	t.Helper()
	base := baseFor(t)
	ov = writeOverlay(t, goodOverlay)
	r, logs = overlayReloader(t, base, ov, &recorder{})
	before, err := loadRules(base, ov, func(string) {})
	if err != nil || before.rulesErr != nil {
		t.Fatal(err, before.rulesErr)
	}
	r.st.publish(before)
	os.WriteFile(ov, []byte("garbage = [\n"), 0o644)
	if r.reload(true) {
		t.Fatal("an invalid overlay must not reload")
	}
	return r, before, ov, logs
}

// Req 5.4: an invalid overlay on disk keeps the previous rules and is reported in the facts.
func TestReloadInvalidOverlayKeepsThePreviousSnapshotAndRecordsTheError(t *testing.T) {
	r, before, ov, logs := brokenOverlay(t)
	if r.st.current() != before {
		t.Fatal("an invalid overlay must keep the previous snapshot")
	}
	at, lastErr := r.rulesError()
	if lastErr == nil || !strings.Contains(lastErr.Error(), ov) || at != r.now() {
		t.Fatalf("want the overlay error recorded at the clock's time, got %v at %v", lastErr, at)
	}
	if len(*logs) != 1 || !strings.Contains((*logs)[0], "keeping the previous rules") {
		t.Fatalf("want one log line, got %q", *logs)
	}
}

func TestReloadRepairedOverlayClearsTheError(t *testing.T) {
	r, _, ov, _ := brokenOverlay(t)
	os.WriteFile(ov, []byte(goodOverlay), 0o644)
	if !r.reload(true) {
		t.Fatal("a repaired overlay reloads")
	}
	if _, lastErr := r.rulesError(); lastErr != nil {
		t.Fatalf("a good reload clears the error, got %v", lastErr)
	}
}

func TestReloadStartupOverlayErrorIsReportedUntilAGoodFullReload(t *testing.T) {
	base, ov := baseFor(t), writeOverlay(t, "garbage = [\n")
	r, _ := overlayReloader(t, base, ov, &recorder{})
	snap, err := loadRules(base, ov, func(string) {})
	if err != nil || snap.rulesErr == nil {
		t.Fatal("the startup fallback: base only with the error on the snapshot", err)
	}
	r.st.publish(snap)
	if _, got := r.rulesError(); got != snap.rulesErr {
		t.Fatalf("the facts show the startup error, got %v", got)
	}
	if !r.reload(false) {
		t.Fatal("a re-resolve of the base succeeds")
	}
	if _, got := r.rulesError(); got != snap.rulesErr {
		t.Fatalf("a re-resolve reads no file: the overlay error stays, got %v", got)
	}
	os.WriteFile(ov, []byte(goodOverlay), 0o644)
	if !r.reload(true) {
		t.Fatal("a repaired overlay reloads")
	}
	if _, got := r.rulesError(); got != nil || len(r.st.current().res.File.Rules) != 2 {
		t.Fatalf("want no error and the merged rules, got %v, %d rules", got, len(r.st.current().res.File.Rules))
	}
}

func TestReloadBaseErrorAfterAGoodOverlayIsRecorded(t *testing.T) {
	base, ov := baseFor(t), writeOverlay(t, goodOverlay)
	r, _ := overlayReloader(t, base, ov, &recorder{})
	before, _ := loadRules(base, ov, func(string) {})
	r.st.publish(before)
	os.WriteFile(base, []byte("garbage = [\n"), 0o644)
	if r.reload(true) || r.st.current() != before {
		t.Fatal("an invalid base keeps the previous snapshot")
	}
	if _, lastErr := r.rulesError(); lastErr == nil || !strings.Contains(lastErr.Error(), base) {
		t.Fatalf("want the base error recorded, got %v", lastErr)
	}
}

// The watch stamps every path: a change to the overlay alone reloads.
func TestWatchReloadsWhenOnlyTheOverlayChanges(t *testing.T) {
	base, ov := baseFor(t), writeOverlay(t, goodOverlay)
	r, _ := overlayReloader(t, base, ov, &recorder{})
	before, _ := loadRules(base, ov, func(string) {})
	r.st.publish(before)
	r.stampAll()
	if r.pollFiles(context.Background()); r.st.current() != before {
		t.Fatal("nothing changed: no reload")
	}
	os.WriteFile(ov, []byte(goodOverlay+"\n[[rule]]\nprogram = \"me\"\nto = \"9.9.9.9\"\nverdict = \"deny\"\n"), 0o644)
	if r.pollFiles(context.Background()); r.st.current() == before || len(r.st.current().res.File.Rules) != 3 {
		t.Fatalf("a changed overlay must reload, got %d rules", len(r.st.current().res.File.Rules))
	}
	after := r.st.current()
	os.Remove(ov)
	if r.pollFiles(context.Background()); r.st.current() == after || len(r.st.current().res.File.Rules) != 1 {
		t.Fatal("a removed overlay reloads to the base alone")
	}
}

func TestWatchRequiresAPathList(t *testing.T) {
	r, _ := newReloader(t, baseFor(t), &recorder{})
	contracttest.Panics(t, contract.Precondition, func() { r.stampAll() })
}
