// codec.go: one JSON object per line in both directions. The reader bounds a line at LineLimit
// and stays usable after a long one (the rest of the line is discarded); the encoder emits
// exactly one object plus "\n"; Parse checks type, id and the fields each type needs.
package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/norandom/snitch/internal/contract"
)

// ErrLineTooLong is returned (wrapped) for a line over LineLimit; the reader then continues
// with the next line.
var ErrLineTooLong = fmt.Errorf("line longer than %d bytes", LineLimit)

// LineReader reads newline-terminated lines with an inclusive byte limit.
type LineReader struct {
	br    *bufio.Reader
	limit int
}

// NewLineReader reads lines of at most LineLimit bytes from r.
func NewLineReader(r io.Reader) *LineReader { return newLineReader(r, LineLimit) }

func newLineReader(r io.Reader, limit int) *LineReader {
	contract.Require(limit > 0, "line reader: limit must be positive")
	return &LineReader{br: bufio.NewReader(r), limit: limit}
}

// ReadLine returns the next line without its terminator. A line over the limit yields
// ErrLineTooLong after the rest of it is discarded; io.EOF ends the stream (an unterminated
// last line is still delivered).
func (r *LineReader) ReadLine() ([]byte, error) {
	var line []byte
	for {
		chunk, err := r.br.ReadSlice('\n')
		if len(line) <= r.limit { // past the limit nothing more is kept, only consumed
			line = append(line, chunk...)
		}
		if err == nil {
			break
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF && len(line) > 0 {
			break
		}
		return nil, err
	}
	line = bytes.TrimSuffix(bytes.TrimSuffix(line, []byte("\n")), []byte("\r"))
	if len(line) > r.limit {
		return nil, fmt.Errorf("%w (%d allowed)", ErrLineTooLong, r.limit)
	}
	return line, nil
}

// Encode marshals one message as a single line. Marshalling the wire types cannot fail; a
// failure is a programming error.
func Encode(msg any) []byte {
	b, err := json.Marshal(msg)
	contract.Ensure(err == nil, "encode: "+fmt.Sprint(err))
	b = append(b, '\n')
	contract.Ensure(bytes.Count(b, []byte("\n")) == 1, "encode: message spans lines")
	return b
}

// requestTypes is every type a client may send.
var requestTypes = map[string]bool{"status": true, "rules": true, "programs": true, "learned": true,
	"snapshot": true, "subscribe": true, "unsubscribe": true, "trial": true, "keep": true,
	"unkeep": true, "end": true, "rule.add": true, "rule.remove": true}

// rawRequest is Request with presence-aware subscribe flags so their defaults can be applied.
type rawRequest struct {
	Request
	Events  *bool `json:"events"`
	Summary *bool `json:"summary"`
}

// Parse decodes one request line. On failure it returns the error message to send, with the
// request id when the line was JSON (Req 1.8).
func Parse(line []byte) (Request, *Error) {
	var raw rawRequest
	if err := json.Unmarshal(line, &raw); err != nil {
		return Request{}, &Error{Type: "error", Error: "bad json: " + err.Error()}
	}
	req := raw.Request
	if req.Type == "subscribe" {
		req.Events = raw.Events == nil || *raw.Events
		req.Summary = raw.Summary == nil || *raw.Summary
	}
	fail := func(msg string) (Request, *Error) {
		return Request{}, &Error{Type: "error", Id: req.Id, Error: msg}
	}
	if req.Type == "" {
		return fail("missing field: type")
	}
	if !requestTypes[req.Type] {
		return fail("unknown type: " + req.Type)
	}
	if err := validate(req); err != nil {
		return fail(err.Error())
	}
	return req, nil
}

// validate names the first missing field a request type needs.
func validate(r Request) error {
	switch r.Type {
	case "snapshot":
		return need(r.Window != "", "window")
	case "trial":
		return need(r.Duration != "", "duration")
	case "rule.add":
		return first(need(r.Program != "" || r.Path != "", "program or path"),
			need(r.To != "", "to"), need(r.Verdict != "", "verdict"))
	case "rule.remove":
		return first(need(r.Program != "", "program"), need(r.To != "", "to"))
	}
	return nil
}

func need(present bool, field string) error {
	if present {
		return nil
	}
	return fmt.Errorf("missing field: %s", field)
}

func first(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}
