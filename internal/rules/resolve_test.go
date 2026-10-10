package rules_test

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/rules"
)

// fakeFS: a fixed set of files with identities and symlinks, plus glob by prefix match.
type fakeFS struct {
	files map[string]rules.ExeKey // regular files
	links map[string]string       // symlink -> target
}

func (f fakeFS) fs() rules.FS {
	return rules.FS{
		Glob: func(pattern string) ([]string, error) {
			var out []string
			for name := range f.files {
				if ok, _ := filepath.Match(pattern, name); ok {
					out = append(out, name)
				}
			}
			for name := range f.links {
				if ok, _ := filepath.Match(pattern, name); ok {
					out = append(out, name)
				}
			}
			return out, nil
		},
		EvalSymlink: func(path string) (string, error) {
			if t, ok := f.links[path]; ok {
				return t, nil
			}
			if _, ok := f.files[path]; ok {
				return path, nil
			}
			return "", fmt.Errorf("%s: no such file", path)
		},
		Identity: func(path string) (rules.ExeKey, error) {
			if k, ok := f.files[path]; ok {
				return k, nil
			}
			return rules.ExeKey{}, fmt.Errorf("%s: no such file", path)
		},
	}
}

var world = fakeFS{
	files: map[string]rules.ExeKey{
		"/usr/bin/curl":         {Ino: 100, Dev: 8<<20 | 1},
		"/opt/claude/2.1.295":   {Ino: 201, Dev: 8<<20 | 1},
		"/opt/claude/2.1.296":   {Ino: 202, Dev: 8<<20 | 1},
		"/usr/lib/git-core/git": {Ino: 300, Dev: 8<<20 | 1},
	},
	links: map[string]string{"/usr/bin/git": "/usr/lib/git-core/git"},
}

func parse(t *testing.T, src string) *rules.File {
	t.Helper()
	f, err := rules.Parse(strings.NewReader(src), "t.toml")
	if err != nil {
		t.Fatal(err)
	}
	return f
}

const programs = `
[[program]]
name  = "curl"
paths = ["/usr/bin/curl"]

[[program]]
name  = "claude"
paths = ["/opt/claude/*"]

[[program]]
name  = "git"
paths = ["/usr/bin/git"]

[[program]]
name  = "ghost"
paths = ["/usr/bin/ghost", "/opt/ghost/*"]

[[program]]
name  = "nopaths"
paths = []

[[rule]]
program = "ghost"
to = "1.1.1.1"
verdict = "allow"
`

func TestResolveMapsEveryExecutableToItsProgram(t *testing.T) {
	r, err := rules.Resolve(parse(t, programs), world.fs())
	if err != nil {
		t.Fatal(err)
	}
	want := map[rules.ExeKey]uint32{
		{Ino: 100, Dev: 8<<20 | 1}: 1, // curl
		{Ino: 201, Dev: 8<<20 | 1}: 2, // claude, two glob matches -> one program
		{Ino: 202, Dev: 8<<20 | 1}: 2,
		{Ino: 300, Dev: 8<<20 | 1}: 3, // git via the symlink's target
	}
	if fmt.Sprint(r.Programs) != fmt.Sprint(want) {
		t.Fatalf("programs:\n got %v\nwant %v", r.Programs, want)
	}
	if r.Names[2] != "claude" || r.Names[4] != "ghost" || r.ByID[1].Program != "ghost" {
		t.Fatalf("lookups wrong: names %v byid %v", r.Names, r.ByID)
	}
}

func TestResolveReportsUnresolvedAndKeepsTheirRules(t *testing.T) {
	r, err := rules.Resolve(parse(t, programs), world.fs())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, u := range r.Unresolved {
		got[u.Program+" "+u.Pattern] = u.Reason
	}
	for _, key := range []string{"ghost /usr/bin/ghost", "ghost /opt/ghost/*", "nopaths "} {
		if _, ok := got[key]; !ok {
			t.Fatalf("missing unresolved entry %q in %v", key, got)
		}
	}
	if len(r.Unresolved) != 3 || len(r.File.Rules) != 1 || r.ByID[1] == nil {
		t.Fatalf("want exactly 3 unresolved and the ghost rule kept: %v, %v", r.Unresolved, r.File.Rules)
	}
}

func TestResolveConflictNamesBothPrograms(t *testing.T) {
	src := "[[program]]\nname = \"a\"\npaths = [\"/usr/bin/curl\"]\n\n[[program]]\nname = \"b\"\npaths = [\"/usr/bin/curl\"]\n"
	_, err := rules.Resolve(parse(t, src), world.fs())
	var e *rules.Error
	if !errors.As(err, &e) || e.Line != 5 || !strings.Contains(e.Msg, "\"a\"") || !strings.Contains(e.Msg, "\"b\"") {
		t.Fatalf("want a conflict error at line 5 naming a and b, got %v", err)
	}
}

func TestResolveSamePathTwiceInOneProgramIsFine(t *testing.T) {
	src := "[[program]]\nname = \"curl\"\npaths = [\"/usr/bin/curl\", \"/usr/bin/cur*\"]\n"
	r, err := rules.Resolve(parse(t, src), world.fs())
	if err != nil || len(r.Programs) != 1 {
		t.Fatalf("want one mapping, got %v, %v", r, err)
	}
}

func TestResolveEmptyFile(t *testing.T) {
	r, err := rules.Resolve(&rules.File{}, world.fs())
	if err != nil || len(r.Programs) != 0 || len(r.Unresolved) != 0 {
		t.Fatalf("got %v, %v", r, err)
	}
}

func TestOSFSResolvesARealGlob(t *testing.T) {
	warned := 0
	fs := rules.OSFS(func(string) { warned++ })
	matches, err := fs.Glob("/usr/bin/cur*")
	if err != nil || len(matches) == 0 {
		t.Fatalf("glob: %v, %v", matches, err)
	}
	target, err := fs.EvalSymlink("/usr/bin/curl")
	if err != nil {
		t.Fatal(err)
	}
	k, err := fs.Identity(target)
	if err != nil || k.Ino == 0 || k.Dev == 0 {
		t.Fatalf("identity: %+v, %v", k, err)
	}
	if _, err := fs.Identity("/usr/bin"); err == nil {
		t.Fatal("a directory is not an executable identity")
	}
	if warned != 0 {
		t.Fatalf("no fallback warning expected on this host, got %d", warned)
	}
}
