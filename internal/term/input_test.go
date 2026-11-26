package term

import (
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"

	"github.com/norandom/snitch/internal/tui"
)

func TestTranslateKeyPress(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	cases := []struct {
		name, wantName, wantText string
		in                       tea.KeyPressMsg
		wantRep                  bool
	}{
		{"char", "q", "q", tea.KeyPressMsg{Code: 'q', Text: "q"}, false},
		{"special_up", "up", "", tea.KeyPressMsg{Code: tea.KeyUp}, false},
		{"space", "space", " ", tea.KeyPressMsg{Code: tea.KeySpace, Text: " "}, false},
		{"ctrl_c_repeat", "ctrl+c", "", tea.KeyPressMsg{Code: 'c', Mod: tea.ModCtrl, IsRepeat: true}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := translateMsg(tc.in, now)
			if !ok {
				t.Fatalf("translateMsg(%v) = false", tc.in)
			}
			k, ok := got.(tui.Key)
			if !ok || k.Name != tc.wantName || k.Text != tc.wantText || k.Repeat != tc.wantRep || !k.At.Equal(now) {
				t.Fatalf("got %+v, want Name=%q Text=%q Repeat=%v", k, tc.wantName, tc.wantText, tc.wantRep)
			}
		})
	}
}

func TestTranslatePasteAndDropsMarkers(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	got, ok := translateMsg(tea.PasteMsg{Content: "TxKyq"}, now)
	if !ok {
		t.Fatalf("PasteMsg returned ok=false")
	}
	p, ok := got.(tui.Paste)
	if !ok || p.Text != "TxKyq" {
		t.Fatalf("got %#v, want tui.Paste{Text:\"TxKyq\"}", got)
	}
	for _, marker := range []tea.Msg{tea.PasteStartMsg{}, tea.PasteEndMsg{}} {
		if got, ok := translateMsg(marker, now); ok || got != nil {
			t.Fatalf("marker %T = (%#v, %v), want (nil, false)", marker, got, ok)
		}
	}
}

func TestTranslateWindowSizeAndDropsOtherMsgs(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	got, ok := translateMsg(tea.WindowSizeMsg{Width: 100, Height: 30}, now)
	if !ok {
		t.Fatalf("WindowSizeMsg returned ok=false")
	}
	r, ok := got.(tui.Resize)
	if !ok || r.W != 100 || r.H != 30 {
		t.Fatalf("got %#v, want tui.Resize{W:100, H:30}", got)
	}
	ignored := []tea.Msg{
		tea.KeyReleaseMsg{Code: 'q', Text: "q"},
		tea.FocusMsg{},
		tea.BlurMsg{},
		tea.MouseClickMsg{},
		tea.EnvMsg{},
	}
	for _, msg := range ignored {
		if got, ok := translateMsg(msg, now); ok || got != nil {
			t.Fatalf("ignored msg %T = (%#v, %v), want (nil, false)", msg, got, ok)
		}
	}
}
