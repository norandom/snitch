// Package logfile opens, tails, and appends the user's snitch.log safely (requirements
// 7.1, 7.5, 13.4, 13.10). It creates missing directories as 0700 and the log file as
// 0600, refuses symbolic links and foreign ownership, narrows wider existing file modes
// to 0600, sanitises tailed lines through clean.Text, and formats appended lines with the
// local date and time.
//
// Fail-safe implications: none on kernel egress. The log file is a convenience for the
// operator; any refusal returns an error value so the TUI can report it once and continue.
package logfile

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/unix"

	"github.com/norandom/snitch/internal/clean"
)

const (
	dirMode      = 0o700
	fileMode     = 0o600
	tailCount    = 5
	maxTailBytes = 256 * 1024
	timeLayout   = "2006-01-02 15:04:05"
)

// Log holds an open append-only descriptor to the operator's log file.
type Log struct {
	mu sync.Mutex
	fd int
}

type sysOps struct {
	fstat  func(int, *unix.Stat_t) error
	fchmod func(int, uint32) error
}

func defaultOps() sysOps {
	return sysOps{
		fstat:  unix.Fstat,
		fchmod: unix.Fchmod,
	}
}

// Open ensures path's parent directory exists (0700 if created, owned by uid) and opens
// path without following symbolic links (0600 if created, owned by uid, narrower mode
// enforced via fchmod). It returns the open Log and up to the last five sanitised lines.
func Open(path string, uid uint32) (*Log, []clean.Safe, error) {
	return openWith(path, uid, defaultOps())
}

func openWith(path string, uid uint32, ops sysOps) (*Log, []clean.Safe, error) {
	dir, base, err := splitLogPath(path)
	if err != nil {
		return nil, nil, err
	}
	dirfd, err := openDir(dir, uid, ops)
	if err != nil {
		return nil, nil, err
	}
	fd, size, err := openFile(dirfd, base, path, uid, ops)
	_ = unix.Close(dirfd)
	if err != nil {
		return nil, nil, err
	}
	tail, err := readTail(fd, size)
	if err != nil {
		_ = unix.Close(fd)
		return nil, nil, err
	}
	return &Log{fd: fd}, tail, nil
}

func splitLogPath(path string) (string, string, error) {
	if path == "" || strings.HasSuffix(path, "/") {
		return "", "", fmt.Errorf("logfile: invalid path %q", path)
	}
	base := filepath.Base(path)
	if base == "" || base == "." || base == ".." || base == "/" {
		return "", "", fmt.Errorf("logfile: invalid path %q", path)
	}
	return filepath.Dir(path), base, nil
}

func openDir(dir string, uid uint32, ops sysOps) (int, error) {
	if err := os.MkdirAll(dir, dirMode); err != nil {
		return -1, fmt.Errorf("logfile: mkdir %s: %w", dir, err)
	}
	flags := unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	dirfd, err := unix.Open(dir, flags, 0)
	if err != nil {
		return -1, fmt.Errorf("logfile: open dir %s: %w", dir, err)
	}
	var st unix.Stat_t
	if err := ops.fstat(dirfd, &st); err != nil {
		_ = unix.Close(dirfd)
		return -1, fmt.Errorf("logfile: stat dir %s: %w", dir, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		_ = unix.Close(dirfd)
		return -1, fmt.Errorf("logfile: %s is not a directory", dir)
	}
	if st.Uid != uid {
		_ = unix.Close(dirfd)
		return -1, fmt.Errorf("logfile: directory %s owned by uid %d, want %d", dir, st.Uid, uid)
	}
	return dirfd, nil
}

func openFile(dirfd int, base, fullPath string, uid uint32, ops sysOps) (int, int64, error) {
	flags := unix.O_RDWR | unix.O_APPEND | unix.O_CREAT | unix.O_NOFOLLOW | unix.O_CLOEXEC | unix.O_NONBLOCK
	fd, err := unix.Openat(dirfd, base, flags, fileMode)
	if err != nil {
		return -1, 0, fmt.Errorf("logfile: open %s: %w", fullPath, err)
	}
	var st unix.Stat_t
	if err := ops.fstat(fd, &st); err != nil {
		_ = unix.Close(fd)
		return -1, 0, fmt.Errorf("logfile: stat %s: %w", fullPath, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = unix.Close(fd)
		return -1, 0, fmt.Errorf("logfile: %s is not a regular file", fullPath)
	}
	if st.Uid != uid {
		_ = unix.Close(fd)
		return -1, 0, fmt.Errorf("logfile: %s owned by uid %d, want %d", fullPath, st.Uid, uid)
	}
	if st.Mode&0o7777&^fileMode != 0 {
		if err := ops.fchmod(fd, fileMode); err != nil {
			_ = unix.Close(fd)
			return -1, 0, fmt.Errorf("logfile: chmod %s: %w", fullPath, err)
		}
	}
	return fd, st.Size, nil
}

func readTail(fd int, size int64) ([]clean.Safe, error) {
	if size <= 0 {
		return nil, nil
	}
	start := int64(0)
	if size > maxTailBytes {
		start = size - maxTailBytes
	}
	buf, err := preadRange(fd, start, int(size-start))
	if err != nil {
		return nil, fmt.Errorf("logfile: read tail: %w", err)
	}
	return extractTailLines(buf, start > 0, tailCount), nil
}

func preadRange(fd int, offset int64, length int) ([]byte, error) {
	buf := make([]byte, length)
	total := 0
	for total < length {
		n, err := unix.Pread(fd, buf[total:], offset+int64(total))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n == 0 {
			break
		}
		total += n
	}
	return buf[:total], nil
}

func extractTailLines(buf []byte, trimmedStart bool, limit int) []clean.Safe {
	if trimmedStart {
		if idx := bytes.IndexByte(buf, '\n'); idx >= 0 {
			buf = buf[idx+1:]
		}
	}
	if len(buf) == 0 {
		return nil
	}
	buf = bytes.TrimSuffix(buf, []byte{'\n'})
	raw := bytes.Split(buf, []byte{'\n'})
	if len(raw) > limit {
		raw = raw[len(raw)-limit:]
	}
	out := make([]clean.Safe, len(raw))
	for i, line := range raw {
		out[i] = clean.Text(string(bytes.TrimSuffix(line, []byte{'\r'})))
	}
	return out
}

// Append writes one sanitised line prefixed with the local date and time.
func (l *Log) Append(line clean.Safe, now time.Time) error {
	if l == nil {
		return errors.New("logfile: nil log")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fd < 0 {
		return errors.New("logfile: log is closed")
	}
	cleaned := clean.Text(string(line))
	entry := now.Local().Format(timeLayout) + "  " + string(cleaned) + "\n"
	if err := writeAll(l.fd, []byte(entry)); err != nil {
		return fmt.Errorf("logfile: append: %w", err)
	}
	return nil
}

func writeAll(fd int, data []byte) error {
	for len(data) > 0 {
		n, err := unix.Write(fd, data)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

// Close closes the underlying log file descriptor. Calling Close on nil or an already
// closed Log is a safe no-op.
func (l *Log) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.fd < 0 {
		return nil
	}
	fd := l.fd
	l.fd = -1
	return unix.Close(fd)
}
