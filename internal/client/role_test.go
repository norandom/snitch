package client

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

// fakeInfo is a stat result with the owner and mode a test wants (a test cannot own a file
// as root), the same shape as cmd/snitchd's operator tests use.
type fakeInfo struct {
	mode os.FileMode
	uid  uint32
}

func (f fakeInfo) Name() string       { return "operator" }
func (f fakeInfo) Size() int64        { return 3 }
func (f fakeInfo) Mode() os.FileMode  { return f.mode }
func (f fakeInfo) ModTime() time.Time { return time.Time{} }
func (f fakeInfo) IsDir() bool        { return f.mode.IsDir() }
func (f fakeInfo) Sys() any           { return &syscall.Stat_t{Uid: f.uid} }

// Design "Service Interface" (client.Role) and research "the role is guessed locally": the
// tray accepts exactly the operator files snitchd accepts (cmd/snitchd TestOperatorFileCases),
// so every case here carries the daemon's verdict for the user "mc" at uid 1000.
func TestRoleCases(t *testing.T) {
	root := fakeInfo{0o644, 0}
	cases := []struct {
		name    string
		uid     uint32
		content string
		info    os.FileInfo
		statErr error
		readErr error
		want    api.Role
	}{
		{"root without a file", 0, "", nil, fs.ErrNotExist, nil, api.Writer},
		{"root with a loose file", 0, "mc\n", fakeInfo{0o666, 1000}, nil, nil, api.Writer},
		{"named user", 1000, "mc\n", root, nil, nil, api.Writer},
		{"named user, spaces and no newline", 1000, "  mc\t", root, nil, nil, api.Writer},
		{"named user, trailing lines ignored", 1000, "mc\nalice\n", root, nil, nil, api.Writer},
		{"named user on the second line only", 1000, "alice\nmc\n", root, nil, nil, api.Reader},
		{"another user", 1000, "alice\n", root, nil, nil, api.Reader},
		{"group writable", 1000, "mc\n", fakeInfo{0o664, 0}, nil, nil, api.Reader},
		{"world writable", 1000, "mc\n", fakeInfo{0o666, 0}, nil, nil, api.Reader},
		{"not owned by root", 1000, "mc\n", fakeInfo{0o644, 1000}, nil, nil, api.Reader},
		{"missing file", 1000, "", nil, fs.ErrNotExist, nil, api.Reader},
		{"stat error", 1000, "mc\n", nil, errors.New("permission denied"), nil, api.Reader},
		{"read error", 1000, "mc\n", root, nil, errors.New("permission denied"), api.Reader},
		{"empty file", 1000, "", root, nil, nil, api.Reader},
		{"blank first line", 1000, " \nmc\n", root, nil, nil, api.Reader},
		{"directory", 1000, "mc\n", fakeInfo{fs.ModeDir | 0o755, 0}, nil, nil, api.Reader},
		{"symlink", 1000, "mc\n", fakeInfo{fs.ModeSymlink | 0o777, 0}, nil, nil, api.Reader},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			stat := func(string) (os.FileInfo, error) { return c.info, c.statErr }
			read := func(string) ([]byte, error) { return []byte(c.content), c.readErr }
			if got := Role(c.uid, "mc", stat, read, "/etc/snitch/operator"); got != c.want {
				t.Fatalf("role %v, want %v", got, c.want)
			}
		})
	}
}

// An empty user name never matches an empty file: the daemon's lookup of "" fails.
func TestRoleEmptyUserIsReader(t *testing.T) {
	stat := func(string) (os.FileInfo, error) { return fakeInfo{0o644, 0}, nil }
	read := func(string) ([]byte, error) { return nil, nil }
	if got := Role(1000, "", stat, read, "/etc/snitch/operator"); got != api.Reader {
		t.Fatalf("role %v, want reader", got)
	}
}

// The delegates see the path the caller passed, and the file is read only once it passed.
func TestRolePassesThePath(t *testing.T) {
	var statted, readPath string
	stat := func(p string) (os.FileInfo, error) { statted = p; return fakeInfo{0o644, 1000}, nil }
	read := func(p string) ([]byte, error) { readPath = p; return []byte("mc\n"), nil }
	if got := Role(1000, "mc", stat, read, "/x/operator"); got != api.Reader {
		t.Fatalf("role %v, want reader", got)
	}
	if statted != "/x/operator" || readPath != "" {
		t.Fatalf("stat %q, read %q", statted, readPath)
	}
}

// The real stat on a file this user owns: a reader, as the daemon ignores that file.
func TestRoleRealStatRejectsAUserOwnedFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root owns the file here")
	}
	path := filepath.Join(t.TempDir(), "operator")
	if err := os.WriteFile(path, []byte("mc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := Role(1000, "mc", os.Stat, os.ReadFile, path); got != api.Reader {
		t.Fatalf("role %v, want reader", got)
	}
}

func TestRoleContracts(t *testing.T) {
	read := os.ReadFile
	contracttest.Panics(t, contract.Precondition, func() { Role(1000, "mc", nil, read, "/x") })
	contracttest.Panics(t, contract.Precondition, func() { Role(1000, "mc", os.Stat, nil, "/x") })
	contracttest.Panics(t, contract.Precondition, func() { Role(1000, "mc", os.Stat, read, "") })
}
