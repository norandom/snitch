// fuzz_test.go: request lines are untrusted input to a root daemon (c-hardening Req 8). The
// seeds are the request lines of examples/api.md, run as ordinary cases by `go test`;
// scripts/fuzz.sh runs the bounded mutation runs.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

// apiExamples are the request lines of examples/api.md, verbatim.
var apiExamples = []string{
	`{"type":"status","id":1}`,
	`{"type":"subscribe","id":1}`,
	`{"type": "status", "id": 1}`,
	`{"type": "rules", "id": 2}`,
	`{"type": "programs", "id": 3}`,
	`{"type": "learned", "id": 4}`,
	`{"type": "snapshot", "id": 5, "window": "15m"}`,
	`{"type": "subscribe", "id": 6, "events": true, "local": false, "summary": true}`,
	`{"type": "unsubscribe", "id": 7}`,
	`{"type":"trial","id":8,"duration":"10m"}`,
	`{"type": "trial", "id": 8, "duration": "10m", "extend": false, "yes": false}`,
	`{"type": "keep", "id": 9}`,
	`{"type": "unkeep", "id": 10}`,
	`{"type": "end", "id": 11}`,
	`{"type": "rule.add", "id": 12, "program": "curl", "to": "9.9.9.9/32", "proto": "tcp", "port": 443, "verdict": "deny", "note": "api check"}`,
	`{"type": "rule.add", "id": 12, "program": "curl", "to": "example.org", "verdict": "allow"}`,
	`{"type": "rule.remove", "id": 13, "program": "curl", "to": "9.9.9.9/32", "proto": "tcp", "port": 443}`,
	`{"type": "rule.remove", "id": 13, "program": "curl", "to": "example.org"}`,
}

// FuzzParse: a line parses to a request of a known type with the fields that type needs, or
// to an error reply with a message; never both, never a panic. A parsed request survives a
// round trip through its wire form (the subscribe flags written out, as their defaults differ
// from Go's zero values).
func FuzzParse(f *testing.F) {
	for _, s := range apiExamples {
		f.Add([]byte(s))
	}
	for _, s := range []string{"", "null", "[]", `{"type":""}`, `{"type":"x","id":-1}`,
		`{"type":"rule.add","id":"1"}`, `{"type":"subscribe","events":false,"summary":false}`,
		`{"type":"status","id":1e999}`, "{\"type\":\"status\",\"note\":\"\xff\"}"} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, line []byte) {
		req, e := Parse(line)
		if e != nil {
			checkParseError(t, req, e)
			return
		}
		if !requestTypes[req.Type] || validate(req) != nil {
			t.Fatalf("accepted an invalid request %+v", req)
		}
		again, e := Parse(wireRequest(req))
		if e != nil || !reflect.DeepEqual(again, req) {
			t.Fatalf("round trip: %+v became %+v (%v)", req, again, e)
		}
	})
}

func checkParseError(t *testing.T, req Request, e *Error) {
	t.Helper()
	if !reflect.DeepEqual(req, Request{}) {
		t.Fatalf("an error with a request: %+v %+v", req, e)
	}
	if e.Type != "error" || e.Error == "" {
		t.Fatalf("error reply without a message: %+v", e)
	}
	Encode(e) // the reply is one line (Encode's contract panics otherwise)
}

// wireRequest is the line a client sends for req, with the subscribe flags explicit.
func wireRequest(req Request) []byte {
	b, err := json.Marshal(rawRequest{Request: req, Events: &req.Events, Summary: &req.Summary})
	if err != nil {
		panic(err)
	}
	return b
}

// FuzzLineReader: for any stream and limit the reader returns exactly the lines a plain split
// on "\n" gives (one trailing "\r" trimmed, an unterminated last line kept), each at most limit
// bytes, and ErrLineTooLong for every longer line; it ends with io.EOF and never panics.
func FuzzLineReader(f *testing.F) {
	all := strings.Join(apiExamples, "\n") + "\n"
	for _, c := range []struct {
		data  string
		limit uint16
	}{
		{all, 4096}, {all, 40}, {"", 64}, {"\n\n", 64}, {"{\"type\":\"status\"}\r\n", 64},
		{strings.Repeat("a", 64) + "\nb\n", 64}, {strings.Repeat("a", 65) + "\nb\n", 64},
		{strings.Repeat("a", 64), 64}, {strings.Repeat("a", 65), 64},
		{strings.Repeat("y", 10000) + "\r\ntail", 8191},
		// the 4096th byte (bufio's buffer) is "\r" and the line goes on: too long, not cut
		{strings.Repeat("a", 4095) + "\r" + "bbbb\nc\n", 4095},
		{strings.Repeat("a", 4095) + "\r\nc\n", 4095},
	} {
		f.Add([]byte(c.data), c.limit)
	}
	f.Fuzz(func(t *testing.T, data []byte, n uint16) {
		limit := max(1, int(n)%8193) // the seeds name their limit directly
		want := splitLines(data)
		r := newLineReader(bytes.NewReader(data), limit)
		for i := 0; ; i++ {
			line, err := r.ReadLine()
			if i == len(want) {
				if err != io.EOF {
					t.Fatalf("after %d lines want io.EOF, got %q %v", i, line, err)
				}
				return
			}
			checkLine(t, i, want[i], line, err, limit)
		}
	})
}

func checkLine(t *testing.T, i int, want, line []byte, err error, limit int) {
	t.Helper()
	if len(want) > limit {
		if !errors.Is(err, ErrLineTooLong) || line != nil {
			t.Fatalf("line %d (%d bytes, limit %d): want ErrLineTooLong, got %d bytes %v",
				i, len(want), limit, len(line), err)
		}
		return
	}
	if err != nil || !bytes.Equal(line, want) {
		t.Fatalf("line %d (limit %d): want %q, got %q %v", i, limit, want, line, err)
	}
}

// splitLines is the reference: the lines of data without "\n" and one trailing "\r"; an
// empty remainder after the last "\n" is no line.
func splitLines(data []byte) [][]byte {
	parts := bytes.Split(data, []byte("\n"))
	if len(parts[len(parts)-1]) == 0 {
		parts = parts[:len(parts)-1]
	}
	for i, p := range parts {
		parts[i] = bytes.TrimSuffix(p, []byte("\r"))
	}
	return parts
}
