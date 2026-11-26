package tui

import (
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

var designKeys = []string{
	"up", "down", "pgup", "pgdown", "home", "end",
	"enter", "right", "l",
	"left", "h",
	"x", "space",
	"t", "1", "2", "3", "4", "5", "6", "7", "8", "9",
	"s", "S",
	"/", "esc",
	"e",
	"T", "K", "E", "U",
	"y",
	"q", "ctrl+c",
}

func TestKeysTableMatchesDesign(t *testing.T) {
	want := make(map[string]bool, len(designKeys))
	for _, k := range designKeys {
		want[k] = true
	}
	seen := make(map[string]bool, len(keyTable))
	for _, entry := range keyTable {
		if seen[entry.name] {
			t.Fatalf("duplicate key %q in keyTable", entry.name)
		}
		seen[entry.name] = true
		if !want[entry.name] {
			t.Fatalf("unexpected key %q in keyTable", entry.name)
		}
		if entry.handle == nil {
			t.Fatalf("key %q has nil handler", entry.name)
		}
		if fn := runtime.FuncForPC(reflect.ValueOf(entry.handle).Pointer()); fn == nil || fn.Name() == "" {
			t.Fatalf("key %q handler has no name", entry.name)
		}
	}
	for _, k := range designKeys {
		if !seen[k] {
			t.Fatalf("design key %q missing from keyTable", k)
		}
	}
}

func TestKeysActionSetAndNoInbound(t *testing.T) {
	wantAction := map[string]bool{
		"x": true, "space": true,
		"T": true, "K": true, "E": true, "U": true,
		"y": true,
	}
	for _, entry := range keyTable {
		if entry.action != wantAction[entry.name] {
			t.Fatalf("key %q action=%v, want %v", entry.name, entry.action, wantAction[entry.name])
		}
		if fn := runtime.FuncForPC(reflect.ValueOf(entry.handle).Pointer()); fn != nil {
			if strings.Contains(strings.ToLower(fn.Name()), "inbound") {
				t.Fatalf("handler %q mentions inbound connections", fn.Name())
			}
		}
	}
}

func TestKeysReachNamedHandlers(t *testing.T) {
	t0 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	for i, entry := range keyTable {
		m := New(Options{})
		m.up = true
		switch entry.where {
		case whereConfirm:
			m.confirm = &confirmState{openedAt: t0.Add(-time.Second)}
		case whereBoth:
			if entry.name == "e" {
				m.graph = true
			}
		}
		if _, ok := lookupKey(entry.name); !ok {
			t.Fatalf("lookupKey(%q) returned false", entry.name)
		}
		at := t0.Add(time.Duration(i+1) * time.Second)
		_, fx := Update(m, Key{Name: entry.name, At: at}, at)
		if entry.name == "q" || entry.name == "ctrl+c" {
			assertQuitEffect(t, entry.name, fx)
		}
	}
}

func TestQuitKeys(t *testing.T) {
	t0 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	for _, graph := range []bool{false, true} {
		for _, name := range []string{"q", "ctrl+c"} {
			m := New(Options{Egress: graph})
			_, fx := Update(m, Key{Name: name, At: t0}, t0)
			assertQuitEffect(t, name, fx)
		}
	}
}

func TestUnknownKeyDoesNothing(t *testing.T) {
	t0 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	for _, name := range []string{"z", "f1", "?", ""} {
		m := New(Options{})
		m.up = true
		next, fx := Update(m, Key{Name: name, At: t0}, t0)
		if len(fx) != 0 {
			t.Fatalf("unknown key %q emitted effects: %#v", name, fx)
		}
		if next.notice != "" || next.graph != m.graph || next.confirm != nil {
			t.Fatalf("unknown key %q mutated model state: %+v", name, next)
		}
	}
}

func TestKeysPasteOnlyInOpenSearch(t *testing.T) {
	t0 := time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	m := New(Options{})
	m.up = true
	m.confirm = &confirmState{openedAt: t0.Add(-2 * time.Second)}
	next, fx := Update(m, Paste{Text: "xyT"}, t0)
	if len(fx) != 0 || next.search != nil || next.notice != "" {
		t.Fatalf("paste during confirm modified model: %+v, fx=%#v", next, fx)
	}

	m2 := New(Options{})
	m2.up = true
	next2, fx2 := Update(m2, Paste{Text: "xyT"}, t0)
	if len(fx2) != 0 || next2.search != nil || next2.notice != "" {
		t.Fatalf("paste with closed search modified model: %+v, fx=%#v", next2, fx2)
	}

	checkPasteOpenSearch(t, t0)
}

func checkPasteOpenSearch(t *testing.T, t0 time.Time) {
	t.Helper()
	init := "ab"
	m := New(Options{})
	m.search = &init
	next, fx := Update(m, Paste{Text: "xyT\x1b[31m\n"}, t0)
	if len(fx) != 0 {
		t.Fatalf("paste in open search emitted effects: %#v", fx)
	}
	if next.search == nil || *next.search != "abxyT·[31m·" {
		t.Fatalf("paste in open search = %v, want abxyT·[31m·", next.search)
	}
	if *m.search != "ab" {
		t.Fatalf("paste mutated caller model search string: %q", *m.search)
	}
}

func assertQuitEffect(t *testing.T, keyName string, fx []Effect) {
	t.Helper()
	if len(fx) != 1 {
		t.Fatalf("%s: got %d effects (%#v), want 1 Quit", keyName, len(fx), fx)
	}
	if _, ok := fx[0].(Quit); !ok {
		t.Fatalf("%s: effect = %T, want Quit", keyName, fx[0])
	}
}
