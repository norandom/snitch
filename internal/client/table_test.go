package client

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

type tablePeer struct {
	t     *testing.T
	conns chan *tableConn
}

type tableConn struct {
	t *testing.T
	net.Conn
	r *bufio.Reader
}

func dialPeer(t *testing.T) (func(context.Context, string) (net.Conn, error), *tablePeer) {
	t.Helper()
	sock := filepath.Join(t.TempDir(), "table.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	p := &tablePeer{t: t, conns: make(chan *tableConn, 8)}
	t.Cleanup(func() { _ = l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			t.Cleanup(func() { _ = c.Close() })
			p.conns <- &tableConn{t: t, Conn: c, r: bufio.NewReader(c)}
		}
	}()
	return func(ctx context.Context, _ string) (net.Conn, error) {
		return unixDial(ctx, sock)
	}, p
}

func (p *tablePeer) accept() *tableConn {
	p.t.Helper()
	select {
	case c := <-p.conns:
		return c
	case <-time.After(wait):
		p.t.Fatal("no connection")
		return nil
	}
}

func (c *tableConn) readLine() (api.Request, string) {
	c.t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(wait))
	b, err := c.r.ReadBytes('\n')
	if err != nil {
		c.t.Fatalf("read client line: %v", err)
	}
	var req api.Request
	if err := json.Unmarshal(b, &req); err != nil {
		c.t.Fatalf("unmarshal %q: %v", b, err)
	}
	return req, string(b[:len(b)-1])
}

func (c *tableConn) sendLine(format string, args ...any) {
	c.t.Helper()
	if _, err := fmt.Fprintf(c, format+"\n", args...); err != nil {
		c.t.Fatal(err)
	}
}

func (c *tableConn) handshake(wantSub string) {
	c.t.Helper()
	_, sub := c.readLine()
	if sub != wantSub {
		c.t.Fatalf("subscribe line = %q, want %q", sub, wantSub)
	}
	st, raw := c.readLine()
	if st.Type != "status" {
		c.t.Fatalf("second line = %q, want status", raw)
	}
	c.sendLine(`{"type":"reply","id":1,"ok":true}`)
	c.sendLine(`{"type":"reply","id":%d,"ok":true,"status":{"running":true,"version":"raw","mode":"monitor"}}`, st.Id)
}

func startTable(t *testing.T, table bool) (*harness, *tableConn) {
	t.Helper()
	dial, p := dialPeer(t)
	cfg := fast("/unused")
	cfg.Dial = dial
	cfg.Table = table
	h := start(t, cfg)
	c := p.accept()
	wantSub := `{"type":"subscribe","id":1,"events":true,"local":false,"summary":false}`
	if table {
		wantSub = `{"type":"subscribe","id":1,"events":true,"local":false,"summary":true}`
	}
	c.handshake(wantSub)
	want[Up](h)
	want[Facts](h)
	return h, c
}

func TestTableOffMatchesTrayWireAndMessages(t *testing.T) {
	if (Config{}).Table {
		t.Fatal("Config.Table must default to false")
	}
	h, c := startTable(t, false)

	contracttest.Panics(t, contract.Precondition, func() {
		h.c.Send(1, api.Request{Type: "snapshot", Window: "1h"})
	})

	c.sendLine(`{"type":"summary","id":0,"since":"2026-10-11T12:00:00Z","entries":[{"program":"curl","path":"/usr/bin/curl","addr":"9.9.9.9","port":443,"protocol":"tcp","bytesSent":100,"rate":10,"verdict":"allow-monitor"}]}`)
	c.sendLine(`{"type":"dropped","id":0,"count":5}`)
	st, _ := c.readLine()
	if st.Type != "status" {
		t.Fatalf("after dropped got %q, want status refresh", st.Type)
	}
	c.sendLine(`{"type":"reply","id":%d,"ok":true,"status":{"running":true,"version":"raw","mode":"monitor"}}`, st.Id)
	want[Facts](h) // no SummaryLine and no Dropped before Facts

	h.c.Send(2, ruleAdd())
	req, _ := c.readLine()
	c.sendLine(`{"type":"reply","id":%d,"ok":true,"text":"added"}`, req.Id)
	a := want[Answered](h)
	if a.Token != 2 || a.Text != "added" || a.Reply != nil {
		t.Fatalf("off reply: %#v", a)
	}
}

func TestTableOnDeliversSummaryAndDroppedWithStatusRefresh(t *testing.T) {
	h, c := startTable(t, true)

	c.sendLine(`{"type":"summary","id":0,"since":"2026-10-11T12:00:00Z","entries":[{"program":"curl","path":"/usr/bin/curl","addr":"9.9.9.9","name":"dns.quad9.net","port":443,"protocol":"tcp","allowCount":4,"denyCount":0,"bytesSent":185344,"rate":102.4,"verdict":"allow-monitor"}]}`)
	sm := want[SummaryLine](h)
	if len(sm.Entries) != 1 || sm.Entries[0].Program != "curl" || sm.Entries[0].Name != "dns.quad9.net" || sm.Entries[0].BytesSent != 185344 {
		t.Fatalf("summary: %#v", sm)
	}

	c.sendLine(`{"type":"dropped","id":0,"count":17}`)
	if d := want[Dropped](h); d.Count != 17 {
		t.Fatalf("dropped: %#v", d)
	}
	st, _ := c.readLine()
	if st.Type != "status" {
		t.Fatalf("after dropped got %q, want status refresh", st.Type)
	}
	c.sendLine(`{"type":"reply","id":%d,"ok":true,"status":{"running":true,"version":"raw","mode":"monitor"}}`, st.Id)
	want[Facts](h)
}

func TestTableOnAllowsSnapshotReply(t *testing.T) {
	h, c := startTable(t, true)

	h.c.Send(10, api.Request{Type: "snapshot", Window: "1h"})
	req, _ := c.readLine()
	if req.Type != "snapshot" || req.Window != "1h" {
		t.Fatalf("snapshot req: %#v", req)
	}
	c.sendLine(`{"type":"reply","id":%d,"ok":true,"window":"1h","entries":[{"program":"curl","addr":"1.1.1.1","port":443,"protocol":"tcp","bytesSent":512,"verdict":"allow-monitor"},{"program":"unknown","bytesSent":64}]}`, req.Id)
	a := want[Answered](h)
	if a.Token != 10 || a.Err != "" || a.Reply == nil || a.Reply.Window != "1h" || len(a.Reply.Entries) != 2 {
		t.Fatalf("snapshot answer: %#v", a)
	}
}

func TestTableOnCarriesRulesAndProgramsReplies(t *testing.T) {
	h, c := startTable(t, true)

	h.c.Send(11, api.Request{Type: "rules"})
	req, _ := c.readLine()
	c.sendLine(`{"type":"reply","id":%d,"ok":true,"rules":[{"id":1,"program":"curl","to":"1.1.1.1/32","protocol":"tcp","port":443,"verdict":"allow","source":"/etc/snitch/rules.toml"}]}`, req.Id)
	a := want[Answered](h)
	if a.Token != 11 || a.Reply == nil || len(a.Reply.Rules) != 1 || a.Reply.Rules[0].To != "1.1.1.1/32" {
		t.Fatalf("rules answer: %#v", a)
	}

	h.c.Send(12, api.Request{Type: "programs"})
	req, _ = c.readLine()
	c.sendLine(`{"type":"reply","id":%d,"ok":true,"programs":[{"name":"curl","paths":["/usr/bin/curl"],"resolved":true,"executables":1,"source":"/etc/snitch/rules.toml"}]}`, req.Id)
	a = want[Answered](h)
	if a.Token != 12 || a.Reply == nil || len(a.Reply.Programs) != 1 || !a.Reply.Programs[0].Resolved {
		t.Fatalf("programs answer: %#v", a)
	}
}

func TestTableOnErrorAndLossLeaveReplyNilAndKeepSendGuards(t *testing.T) {
	h, c := startTable(t, true)
	for _, typ := range []string{"", "subscribe", "unsubscribe"} {
		contracttest.Panics(t, contract.Precondition, func() {
			h.c.Send(1, api.Request{Type: typ})
		})
	}

	h.c.Send(13, api.Request{Type: "snapshot", Window: "5m"})
	req, _ := c.readLine()
	c.sendLine(`{"type":"error","id":%d,"error":"unknown window 5m"}`, req.Id)
	a := want[Answered](h)
	if a.Token != 13 || a.Err != "unknown window 5m" || a.Reply != nil {
		t.Fatalf("error answer: %#v", a)
	}

	h.c.Send(14, api.Request{Type: "rules"})
	_, _ = c.readLine()
	_ = c.Close()
	a = want[Answered](h)
	if a.Token != 14 || a.Err != NoAnswer || a.Reply != nil {
		t.Fatalf("loss answer: %#v", a)
	}
}

func TestTableOnIgnoresSummaryAndDroppedBeforeUp(t *testing.T) {
	dial, p := dialPeer(t)
	cfg := fast("/unused")
	cfg.Dial = dial
	cfg.Table = true
	h := start(t, cfg)
	c := p.accept()
	_, _ = c.readLine()
	st, _ := c.readLine()
	c.sendLine(`{"type":"summary","id":0,"since":"2026-10-11T12:00:00Z","entries":[{"program":"curl"}]}`)
	c.sendLine(`{"type":"dropped","id":0,"count":4}`)
	c.sendLine(`{"type":"reply","id":1,"ok":true}`)
	c.sendLine(`{"type":"reply","id":%d,"ok":true,"status":{"running":true,"version":"raw","mode":"monitor"}}`, st.Id)
	want[Up](h)
	want[Facts](h)
}
