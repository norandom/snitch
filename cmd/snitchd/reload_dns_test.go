// Reload tests fence snapshot publication, lock order and compiled ownership.
package main

import (
	"io"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/norandom/snitch/internal/rules"
)

func TestReloadCallsAfterWithTheNewSnapshot(t *testing.T) {
	self, _ := os.Executable()
	r, _ := newReloader(t, "unused", &recorder{})
	old := snapWith(self, "")
	next := snapWith(self, goodOverlay)
	r.st.publish(old)
	r.load = func(string, string, func(string)) (*snapshot, error) { return next, nil }
	calls := 0
	r.after = func(got *snapshot) {
		calls++
		if got != next || got != r.st.current() {
			t.Fatal("hook needs published new snapshot")
		}
		if r.mu.TryLock() {
			r.mu.Unlock()
			t.Fatal("hook must hold reloader lock before tap lock")
		}
	}
	if !r.reload(true) || calls != 1 {
		t.Fatal("full reload must call hook")
	}
	r.reload(false)
	if calls != 1 {
		t.Fatal("quiet re-resolve called hook")
	}
}

func TestReloadRemovesCompiledBeforeSummary(t *testing.T) {
	f := recompileFixture()
	f.s.handle(readerRecord())
	base := writeRules(t, "")
	overlay := writeOverlay(t, "[[rule]]\nprogram = \"any\"\nto = \"example.org\"\nproto = \"tcp\"\nport = 443\nverdict = \"allow\"\n")
	r, _ := overlayReloader(t, base, overlay, &recorder{})
	old, err := loadRules(base, overlay, func(string) {})
	if err != nil {
		t.Fatal(err)
	}
	r.st.publish(old)
	os.WriteFile(overlay, nil, 0600)
	r.after = f.s.recompile
	r.compiled = func() int {
		if len(f.live) != 0 || f.dels != 1 {
			t.Fatal("summary preceded compiled deletion")
		}
		return f.s.compiledCount()
	}
	rd, wr, _ := os.Pipe()
	saved := os.Stdout
	os.Stdout = wr
	defer func() { os.Stdout = saved; rd.Close(); wr.Close() }()
	if !r.reload(true) {
		t.Fatal("reload failed")
	}
	wr.Close()
	out, _ := io.ReadAll(rd)
	if !strings.Contains(string(out), "0 rules effective") {
		t.Fatal(string(out))
	}
}

func TestReloadPassesPendingEvictor(t *testing.T) {
	r, _ := newReloader(t, "unused", &recorder{})
	old, next := newReaderFixture().snap, newReaderFixture().snap
	next.ent.Rules[rules.RuleKey{}] = rules.RuleVal{Id: 9}
	r.st.publish(old)
	r.load = func(string, string, func(string)) (*snapshot, error) { return next, nil }
	evicted, puts := false, 0
	r.onFull = func(snap *snapshot) func() bool {
		if snap != next {
			t.Fatal("evictor needs pending snapshot")
		}
		return func() bool { evicted = true; return true }
	}
	r.rules.put = func(any, any) error {
		puts++
		if !evicted {
			return syscall.ENOSPC
		}
		return nil
	}
	if !r.reload(true) || puts != 2 || !evicted {
		t.Fatalf("puts %d evicted %v", puts, evicted)
	}
}
