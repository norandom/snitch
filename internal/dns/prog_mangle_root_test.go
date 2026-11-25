//go:build root

// Byte-level mutators derive malformed frames from the well-formed ones answerFrame builds,
// which dnsmessage alone cannot express. Each returns a new slice and never changes its input;
// a misuse (an offset outside the frame) fails the test instead of panicking.
package dns

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// truncateAt keeps frame[:n]; n must cut something off (0 <= n < len(frame)).
func truncateAt(t testing.TB, frame []byte, n int) []byte {
	t.Helper()
	if n < 0 || n >= len(frame) {
		t.Fatalf("truncateAt %d: frame has %d bytes", n, len(frame))
		return nil
	}
	return bytes.Clone(frame[:n])
}

// setU16At writes v big-endian (network order) at frame[off:off+2].
func setU16At(t testing.TB, frame []byte, off int, v uint16) []byte {
	t.Helper()
	if off < 0 || off+2 > len(frame) {
		t.Fatalf("setU16At %d: frame has %d bytes", off, len(frame))
		return nil
	}
	out := bytes.Clone(frame)
	binary.BigEndian.PutUint16(out[off:], v)
	return out
}

// overwriteAt replaces frame[off:off+len(b)] with b; the frame keeps its length.
func overwriteAt(t testing.TB, frame []byte, off int, b []byte) []byte {
	t.Helper()
	if off < 0 || off+len(b) > len(frame) {
		t.Fatalf("overwriteAt %d+%d: frame has %d bytes", off, len(b), len(frame))
		return nil
	}
	out := bytes.Clone(frame)
	copy(out[off:], b)
	return out
}

// appendRaw adds b after the frame's last byte; the headers' length fields are not touched.
func appendRaw(t testing.TB, frame, b []byte) []byte {
	t.Helper()
	out := make([]byte, 0, len(frame)+len(b))
	return append(append(out, frame...), b...)
}

// fatalRecorder stands in for a test so a misuse can be observed without ending the caller.
type fatalRecorder struct {
	testing.TB
	failed bool
}

func (f *fatalRecorder) Helper()               {}
func (f *fatalRecorder) Fatalf(string, ...any) { f.failed = true }

// TestMangleMutators needs no kernel: it pins the mutators' results, that the input is never
// changed, and that out-of-range offsets fail the test.
func TestMangleMutators(t *testing.T) {
	in := []byte{1, 2, 3, 4}
	equalProg(t, truncateAt(t, in, 2), []byte{1, 2})
	equalProg(t, setU16At(t, in, 1, 0xABCD), []byte{1, 0xAB, 0xCD, 4})
	equalProg(t, overwriteAt(t, in, 2, []byte{9, 8}), []byte{1, 2, 9, 8})
	equalProg(t, appendRaw(t, in, []byte{5}), []byte{1, 2, 3, 4, 5})
	equalProg(t, in, []byte{1, 2, 3, 4})
	misuse := map[string]func(testing.TB) []byte{
		"truncate-whole": func(tb testing.TB) []byte { return truncateAt(tb, in, 4) },
		"truncate-neg":   func(tb testing.TB) []byte { return truncateAt(tb, in, -1) },
		"set-past-end":   func(tb testing.TB) []byte { return setU16At(tb, in, 3, 1) },
		"set-neg":        func(tb testing.TB) []byte { return setU16At(tb, in, -1, 1) },
		"overwrite-past": func(tb testing.TB) []byte { return overwriteAt(tb, in, 3, []byte{1, 2}) },
		"overwrite-neg":  func(tb testing.TB) []byte { return overwriteAt(tb, in, -1, []byte{1}) },
	}
	for name, f := range misuse {
		rec := &fatalRecorder{}
		if out := f(rec); !rec.failed || out != nil {
			t.Errorf("%s: failed=%v out=%v; want a test failure and no frame", name, rec.failed, out)
		}
	}
	equalProg(t, in, []byte{1, 2, 3, 4})
}
