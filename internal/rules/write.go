package rules

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// WriteFile writes f as a rules file Parse reads back unchanged: a temp file in the same
// directory, then rename, so a reader never sees a partial file.
func WriteFile(path string, f *File) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".learned-*.toml")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err = tmp.WriteString(format(f, time.Now().UTC())); err == nil {
		err = tmp.Chmod(0o644)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func format(f *File, now time.Time) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# snitch learned rules, written %s: what programs connected to while nothing was\n", now.Format(time.RFC3339))
	b.WriteString("# blocked. Review, then merge into the live rules file; snitchd never does that itself.\n")
	for _, p := range f.Programs {
		fmt.Fprintf(&b, "\n[[program]]\nname  = %s\npaths = [%s]\n", quote(p.Name), quoteList(p.Paths))
		if p.Note != "" {
			fmt.Fprintf(&b, "note  = %s\n", quote(p.Note))
		}
	}
	for i := range f.Rules {
		formatRule(&b, &f.Rules[i])
	}
	return b.String()
}

func formatRule(b *strings.Builder, r *Rule) {
	fmt.Fprintf(b, "\n[[rule]]\nprogram = %s\nto      = %s\n", quote(r.Program), quote(r.To.String()))
	if r.Proto != AnyProto {
		fmt.Fprintf(b, "proto   = %s\n", quote(protoName(r.Proto)))
	}
	if len(r.Ports) == 1 {
		fmt.Fprintf(b, "port    = %d\n", r.Ports[0])
	} else if len(r.Ports) > 1 {
		fmt.Fprintf(b, "port    = %s\n", quote(fmt.Sprintf("%d-%d", r.Ports[0], r.Ports[len(r.Ports)-1])))
	}
	fmt.Fprintf(b, "verdict = %s\n", quote(verdictName(r.Verdict)))
	if r.Note != "" {
		fmt.Fprintf(b, "note    = %s\n", quote(r.Note))
	}
	if r.Count > 0 {
		fmt.Fprintf(b, "count   = %d\nfirst   = %s\nlast    = %s\n", r.Count, r.First.UTC().Format(time.RFC3339), r.Last.UTC().Format(time.RFC3339))
	}
}

func verdictName(v Verdict) string {
	if v == Deny {
		return "deny"
	}
	return "allow"
}

// quote writes a TOML basic string: backslash, quote and control characters escaped with the
// escapes TOML defines (no \x), everything else verbatim.
func quote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"' || r == '\\':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, "\\u%04X", r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

func quoteList(items []string) string {
	q := make([]string, len(items))
	for i, s := range items {
		q[i] = quote(s)
	}
	return strings.Join(q, ", ")
}
