package rules

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/norandom/snitch/internal/contract"
)

// FS is what Resolve needs from the operating system, as delegates so tests inject fakes.
type FS struct {
	Glob        func(pattern string) ([]string, error)
	EvalSymlink func(path string) (string, error)
	Identity    func(path string) (ExeKey, error) // inode + kernel device of a regular file
}

// Unresolved is a program path or glob that matched no executable (the program's rules are
// still loaded; it starts matching when the file appears).
type Unresolved struct {
	Program string
	Pattern string
	Reason  string
}

// Resolved is a File plus the executable identities of its programs. Immutable once built.
type Resolved struct {
	File       *File
	Programs   map[ExeKey]uint32 // resolved executables -> program id
	Names      map[uint32]string // program id -> name
	ByID       map[uint32]*Rule  // rule id -> rule
	Unresolved []Unresolved
}

// OSFS is the real filesystem. warn is called once if mountinfo cannot give a device and the
// stat-based conversion is used instead (right on ext4/xfs, wrong on btrfs/overlayfs).
func OSFS(warn func(string)) FS {
	return FS{Glob: filepath.Glob, EvalSymlink: filepath.EvalSymlinks, Identity: identityFunc(warn)}
}

// Resolve maps every program's paths and globs to executable identities. The only error is a
// conflict: one executable declared under two programs.
func Resolve(f *File, fs FS) (*Resolved, error) {
	contract.Require(fs.Glob != nil && fs.EvalSymlink != nil && fs.Identity != nil, "Resolve needs a complete FS")
	r := &Resolved{File: f, Programs: map[ExeKey]uint32{}, Names: map[uint32]string{}, ByID: map[uint32]*Rule{}}
	for i := range f.Programs {
		p := &f.Programs[i]
		r.Names[p.ID] = p.Name
		if err := r.resolveProgram(p, fs); err != nil {
			return nil, err
		}
	}
	for i := range f.Rules {
		r.ByID[f.Rules[i].ID] = &f.Rules[i]
	}
	r.assertConsistent()
	return r, nil
}

func (r *Resolved) resolveProgram(p *Program, fs FS) error {
	if len(p.Paths) == 0 {
		r.Unresolved = append(r.Unresolved, Unresolved{Program: p.Name, Reason: "no paths"})
	}
	for _, pattern := range p.Paths {
		matches, reason := expand(pattern, fs)
		if reason != "" {
			r.Unresolved = append(r.Unresolved, Unresolved{Program: p.Name, Pattern: pattern, Reason: reason})
			continue
		}
		for _, path := range matches {
			if err := r.claim(p, path, fs); err != nil {
				return err
			}
		}
	}
	return nil
}

// expand turns a pattern into the paths it names; a literal path is used as is so that a
// missing file reports the OS error rather than "no match".
func expand(pattern string, fs FS) ([]string, string) {
	if !strings.ContainsAny(pattern, "*?[") {
		return []string{pattern}, ""
	}
	matches, err := fs.Glob(pattern)
	if err != nil {
		return nil, err.Error()
	}
	if len(matches) == 0 {
		return nil, "no match"
	}
	return matches, ""
}

// claim maps one path to p, following symlinks; a path that cannot be resolved is recorded as
// unresolved, a path already owned by another program is a conflict error.
func (r *Resolved) claim(p *Program, path string, fs FS) error {
	target, err := fs.EvalSymlink(path)
	if err == nil {
		var key ExeKey
		if key, err = fs.Identity(target); err == nil {
			return r.own(p, path, key)
		}
	}
	r.Unresolved = append(r.Unresolved, Unresolved{Program: p.Name, Pattern: path, Reason: err.Error()})
	return nil
}

func (r *Resolved) own(p *Program, path string, key ExeKey) error {
	if other, taken := r.Programs[key]; taken && other != p.ID {
		return &Error{Line: p.Line, Msg: fmt.Sprintf("executable %s is both program %q and %q", path, r.Names[other], p.Name)}
	}
	r.Programs[key] = p.ID
	return nil
}

func (r *Resolved) assertConsistent() {
	for _, id := range r.Programs {
		_, named := r.Names[id]
		contract.Invariant(id != 0 && named, "every resolved executable maps to a declared program id")
	}
	contract.Ensure(len(r.ByID) == len(r.File.Rules), "every rule is reachable by id")
}
