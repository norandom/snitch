// role.go: the tray's guess of the role the daemon will grant this user, so a question can
// offer answers only to the operator (6.1) and none to a reader (6.9). The acceptance rules
// copy snitchd's operator file rules (cmd/snitchd operatorUID, operatorFileProblem): uid 0
// writes, and so does the user named on the first line of a regular file owned by root that
// neither group nor others can write.
//
// Fail-safe implications: none. The guess grants nothing; the daemon decides every write by
// the peer's credentials, and its refusal turns the tray into a reader. Every doubt (a file
// missing, unreadable or loose) guesses Reader, the side that cannot ask for a write.
package client

import (
	"os"
	"strings"
	"syscall"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
)

// Role guesses what the daemon will grant this user: Writer for uid 0, and for the user
// named on the first line of the operator file when that file is a regular file owned by
// root and not writable by group or others; Reader otherwise, also on any read error.
// The caller passes the user's name; the daemon looks the name up to a uid, the tray
// compares names, which agree for every account that has one name.
// stat must follow symlinks (os.Stat), as the daemon's does; the file must be readable by the user.
func Role(uid uint32, user string, stat func(string) (os.FileInfo, error),
	read func(string) ([]byte, error), path string) api.Role {
	contract.Require(stat != nil && read != nil && path != "", "client.Role: incomplete delegates")
	if uid == 0 {
		return api.Writer
	}
	info, err := stat(path)
	if err != nil || info == nil || !operatorFileAccepted(info) {
		return api.Reader
	}
	b, err := read(path)
	if err != nil {
		return api.Reader
	}
	// The daemon's parsing: the first line, trimmed; an empty name names nobody.
	name, _, _ := strings.Cut(string(b), "\n")
	name = strings.TrimSpace(name)
	if name == "" || name != user {
		return api.Reader
	}
	return api.Writer
}

// operatorFileAccepted is the daemon's operatorFileProblem == "": a regular file, owned by
// root, and no write bit for group or others, so a mode cannot promote a user.
func operatorFileAccepted(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return info.Mode().IsRegular() && ok && st.Uid == 0 && info.Mode().Perm()&0o022 == 0
}
