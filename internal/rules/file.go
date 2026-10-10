// Package rules is the rules file: programs named by executable paths, rules by program and
// destination. The same model is read from the operator's file and written by learning mode.
// Values are immutable after Parse; a change is a new File.
package rules

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"time"
)

// Proto is the transport a rule applies to; AnyProto matches both.
type Proto uint8

const (
	AnyProto Proto = 0
	TCP      Proto = 6
	UDP      Proto = 17
)

// Verdict is what a matching rule decides.
type Verdict uint8

const (
	Allow Verdict = 1
	Deny  Verdict = 2
)

// anyProgram is the program name that makes a rule apply to every program.
const anyProgram = "any"

// Program is one named set of executables.
type Program struct {
	Name  string
	Paths []string // absolute paths or filepath.Glob patterns
	Note  string
	ID    uint32 // 1-based declaration order; 0 is reserved (any / unknown)
	Line  int    // line of the [[program]] header
}

// Rule allows or denies one program (or any) to a destination prefix, protocol and ports.
type Rule struct {
	Program string
	To      netip.Prefix
	Proto   Proto
	Ports   []uint16 // expanded; nil = any port
	Verdict Verdict
	Note    string
	Count   uint64    // learned files only
	First   time.Time // learned files only
	Last    time.Time // learned files only
	ID      uint32    // 1-based declaration order
	Line    int       // line of the [[rule]] header
}

// File is a parsed rules file. Name is what Parse was given, for error messages.
type File struct {
	Name     string
	Programs []Program
	Rules    []Rule
}

// Error is a problem in a rules file, with the file and line it was found at.
type Error struct {
	File string
	Line int
	Msg  string
}

func (e *Error) Error() string { return fmt.Sprintf("%s:%d: %s", e.File, e.Line, e.Msg) }

// Load reads and parses the rules file at path. A missing file is reported as the os error
// (errors.Is(err, fs.ErrNotExist)), so the caller can start with no rules.
func Load(path string) (*File, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Parse(f, path)
}

// Parse decodes a rules file; name is used in error messages.
func Parse(r io.Reader, name string) (*File, error) {
	src, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	return decode(src, name)
}
