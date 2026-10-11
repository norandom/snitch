package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// Req 1.8: a line over the limit is an error naming the limit and the reader stays usable.
func TestLineReaderLimit(t *testing.T) {
	long := strings.Repeat("x", 65<<10)
	in := long + "\n" + `{"type":"status"}` + "\n"
	r := NewLineReader(strings.NewReader(in))
	_, err := r.ReadLine()
	if !errors.Is(err, ErrLineTooLong) || !strings.Contains(err.Error(), "65536") {
		t.Fatalf("want ErrLineTooLong naming 65536, got %v", err)
	}
	line, err := r.ReadLine()
	if err != nil || string(line) != `{"type":"status"}` {
		t.Fatalf("reader unusable after a long line: %q %v", line, err)
	}
	if _, err := r.ReadLine(); err != io.EOF {
		t.Fatalf("want EOF at the end, got %v", err)
	}
}

// The limit is inclusive: exactly limit bytes pass, one more fails.
func TestLineReaderLimitBoundary(t *testing.T) {
	for _, c := range []struct {
		n  int
		ok bool
	}{{10, true}, {11, false}} {
		r := newLineReader(strings.NewReader(strings.Repeat("a", c.n)+"\nb\n"), 10)
		line, err := r.ReadLine()
		if c.ok != (err == nil) {
			t.Fatalf("%d bytes with limit 10: ok=%v err=%v", c.n, c.ok, err)
		}
		if c.ok && len(line) != c.n {
			t.Fatalf("line truncated: %d", len(line))
		}
		if next, err := r.ReadLine(); err != nil || string(next) != "b" {
			t.Fatalf("after %d bytes the next line is %q %v", c.n, next, err)
		}
	}
}

// Chunks larger than bufio's buffer are joined; CR LF is accepted; an unterminated last line
// is still delivered.
func TestLineReaderJoinsAndTrims(t *testing.T) {
	long := strings.Repeat("y", 10000)
	r := NewLineReader(strings.NewReader(long + "\r\n" + "tail"))
	line, err := r.ReadLine()
	if err != nil || string(line) != long {
		t.Fatalf("long line: len %d err %v", len(line), err)
	}
	line, err = r.ReadLine()
	if err != nil || string(line) != "tail" {
		t.Fatalf("unterminated tail: %q %v", line, err)
	}
}

func TestEncodeOneObjectPerLine(t *testing.T) {
	b := Encode(Reply{Type: "reply", Id: 2, Ok: true, Text: "two\nlines"})
	if !bytes.HasSuffix(b, []byte("\n")) || bytes.Count(b, []byte("\n")) != 1 {
		t.Fatalf("not exactly one line: %q", b)
	}
	var back Reply
	if err := json.Unmarshal(b, &back); err != nil || back.Id != 2 || back.Text != "two\nlines" {
		t.Fatalf("round trip: %+v %v", back, err)
	}
}

func TestParseErrors(t *testing.T) {
	cases := []struct{ line, want string }{
		{`not json`, "bad json"},
		{`{"type":"status","id":"x"}`, "bad json"},
		{`{"id":4}`, "missing field: type"},
		{`{"type":"bogus","id":4}`, "unknown type: bogus"},
		{`{"type":"snapshot","id":4}`, "missing field: window"},
		{`{"type":"trial","id":4}`, "missing field: duration"},
		{`{"type":"rule.add","id":4,"to":"1.1.1.1","verdict":"allow"}`, "missing field: program or path"},
		{`{"type":"rule.add","id":4,"program":"curl","verdict":"allow"}`, "missing field: to"},
		{`{"type":"rule.add","id":4,"path":"/p","to":"1.1.1.1"}`, "missing field: verdict"},
		{`{"type":"rule.remove","id":4,"to":"1.1.1.1"}`, "missing field: program"},
		{`{"type":"rule.remove","id":4,"program":"curl"}`, "missing field: to"},
	}
	for _, c := range cases {
		_, perr := Parse([]byte(c.line))
		if perr == nil {
			t.Fatalf("%s: parsed", c.line)
		}
		if perr.Type != "error" || !strings.HasPrefix(perr.Error, c.want) {
			t.Fatalf("%s: got %+v, want %q", c.line, *perr, c.want)
		}
		if wantId := 4; strings.Contains(c.line, `"id":4`) && perr.Id != wantId {
			t.Fatalf("%s: error lost the id: %+v", c.line, *perr)
		}
	}
}

func TestParseAcceptsEveryType(t *testing.T) {
	cases := []string{
		`{"type":"status","id":1}`, `{"type":"rules"}`, `{"type":"programs"}`, `{"type":"learned"}`,
		`{"type":"snapshot","window":"15m"}`, `{"type":"subscribe"}`, `{"type":"unsubscribe"}`,
		`{"type":"trial","duration":"2m"}`, `{"type":"trial","duration":"2m","extend":true}`,
		`{"type":"keep"}`, `{"type":"unkeep"}`, `{"type":"end"}`,
		`{"type":"rule.add","program":"curl","to":"1.1.1.1/32","verdict":"allow"}`,
		`{"type":"rule.add","path":"/usr/bin/curl","to":"1.1.1.1/32","proto":"tcp","port":443,"verdict":"deny","note":"n"}`,
		`{"type":"rule.remove","program":"curl","to":"1.1.1.1/32"}`,
	}
	for _, line := range cases {
		req, perr := Parse([]byte(line))
		if perr != nil {
			t.Fatalf("%s: %+v", line, *perr)
		}
		if req.Type == "" {
			t.Fatalf("%s: type lost", line)
		}
	}
}

// Subscribe defaults (design "Subscribe options"): events and summary on, local off, unless
// given; other types keep the zero values (a snapshot subscribes to nothing).
func TestParseSubscribeDefaults(t *testing.T) {
	cases := []struct {
		line                   string
		events, summary, local bool
	}{
		{`{"type":"subscribe","id":5}`, true, true, false},
		{`{"type":"subscribe","events":false,"summary":false,"local":true}`, false, false, true},
		{`{"type":"subscribe","events":true,"summary":false}`, true, false, false},
		{`{"type":"snapshot","window":"1h"}`, false, false, false},
	}
	for _, c := range cases {
		req, perr := Parse([]byte(c.line))
		if perr != nil {
			t.Fatalf("%s: %+v", c.line, *perr)
		}
		if got := [3]bool{req.Events, req.Summary, req.Local}; got != [3]bool{c.events, c.summary, c.local} {
			t.Errorf("%s: events/summary/local %v", c.line, got)
		}
	}
}

// Every contract of codec.go and client.go trips (convention: one violation test each).
func TestCodecAndClientContracts(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { newLineReader(strings.NewReader(""), 0) })
	contracttest.Panics(t, contract.Postcondition, func() { Encode(make(chan int)) })
	contracttest.Panics(t, contract.Precondition, func() { NewClient(nil, Reader, time.Second) })
	ours, _ := net.Pipe()
	defer ours.Close()
	contracttest.Panics(t, contract.Precondition, func() { NewClient(ours, Reader, 0) })
}
