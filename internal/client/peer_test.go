package client

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
)

const documentedNoRulesQuestion = "No rules are loaded: every connection outside the local network will be denied for 10m0s. Start the trial? [y/N]"

func checkPeerUp(t *testing.T, peerFn func(net.Conn) (uint32, bool), wantUID uint32, wantKnown bool) {
	t.Helper()
	dial, p := dialPeer(t)
	var gotConn, peerGotConn net.Conn
	cfg := fast("/unused")
	cfg.Dial = func(ctx context.Context, path string) (net.Conn, error) {
		c, err := dial(ctx, path)
		gotConn = c
		return c, err
	}
	if peerFn != nil {
		cfg.Peer = func(c net.Conn) (uint32, bool) {
			peerGotConn = c
			return peerFn(c)
		}
	}
	h := start(t, cfg)
	c := p.accept()
	c.handshake(`{"type":"subscribe","id":1,"events":true,"local":false,"summary":false}`)
	up := want[Up](h)
	want[Facts](h)
	if up.PeerUID != wantUID || up.PeerKnown != wantKnown {
		t.Fatalf("Up = %#v, want PeerUID=%d PeerKnown=%v", up, wantUID, wantKnown)
	}
	if peerFn != nil && peerGotConn != gotConn {
		t.Fatalf("Peer received %v, want dialled conn %v", peerGotConn, gotConn)
	}
}

func TestPeerPassedThroughAndUnknown(t *testing.T) {
	cases := []struct {
		name      string
		peerFn    func(net.Conn) (uint32, bool)
		wantUID   uint32
		wantKnown bool
	}{
		{name: "no delegate", peerFn: nil, wantUID: 0, wantKnown: false},
		{name: "root peer", peerFn: func(net.Conn) (uint32, bool) { return 0, true }, wantUID: 0, wantKnown: true},
		{name: "other uid", peerFn: func(net.Conn) (uint32, bool) { return 1000, true }, wantUID: 1000, wantKnown: true},
		{name: "lookup failed", peerFn: func(net.Conn) (uint32, bool) { return 0, false }, wantUID: 0, wantKnown: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkPeerUp(t, tc.peerFn, tc.wantUID, tc.wantKnown)
		})
	}
}

func TestIsQuestion(t *testing.T) {
	if !IsQuestion(documentedNoRulesQuestion) {
		t.Fatalf("IsQuestion(%q) = false, want true", documentedNoRulesQuestion)
	}
	notQuestions := []string{
		"",
		refusal,
		"trial already running",
		NoAnswer,
		noSession,
		"No rules are loaded: every connection outside the local network will be denied for 10m0s. Start the trial? [y/n]",
		documentedNoRulesQuestion + " ",
		documentedNoRulesQuestion + " extra",
		"enforce until 2026-10-11T14:12:00+02:00 (10m0s)",
	}
	for _, s := range notQuestions {
		if IsQuestion(s) {
			t.Fatalf("IsQuestion(%q) = true, want false", s)
		}
	}
}

func TestAnsweredQuestionMark(t *testing.T) {
	h, c := startTable(t, true)
	cases := []struct {
		name         string
		lineFmt      string
		wantQuestion bool
		wantRole     bool
	}{
		{"no-rules question", `{"type":"error","id":%d,"error":` + `"` + documentedNoRulesQuestion + `"}`, true, false},
		{"operator refusal", `{"type":"error","id":%d,"error":"` + refusal + `"}`, false, true},
		{"other error", `{"type":"error","id":%d,"error":"trial already running"}`, false, false},
		{"reply ending with [y/N]", `{"type":"reply","id":%d,"ok":true,"text":"enforce kept [y/N]"}`, false, false},
	}
	for i, tc := range cases {
		tok := uint64(i + 1)
		h.c.Send(tok, api.Request{Type: "trial", Duration: "10m"})
		req, _ := c.readLine()
		c.sendLine(tc.lineFmt, req.Id)
		a := want[Answered](h)
		if a.Token != tok || a.Question != tc.wantQuestion || a.Role != tc.wantRole {
			t.Fatalf("%s: answer = %#v, want Question=%v Role=%v", tc.name, a, tc.wantQuestion, tc.wantRole)
		}
	}
}

func TestAnsweredQuestionFalseOnLossAndNoSession(t *testing.T) {
	h, c := startTable(t, true)
	h.c.Send(5, api.Request{Type: "keep"})
	_, _ = c.readLine()
	_ = c.Close()
	a := want[Answered](h)
	if a.Token != 5 || a.Question || a.Role || a.Err != NoAnswer {
		t.Fatalf("loss answer: %#v", a)
	}
	want[Down](h)
	time.Sleep(10 * time.Millisecond)
	h.c.Send(6, api.Request{Type: "keep"})
	a = want[Answered](h)
	if a.Token != 6 || a.Question || a.Role || a.Err != noSession {
		t.Fatalf("no-session answer: %#v", a)
	}
}
