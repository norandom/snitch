package rules

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

// ExeKey is how the kernel program identifies an executable: inode number and the
// superblock's device (kernel dev_t encoding, major << 20 | minor). Layout == bpf exe_key.
type ExeKey struct {
	Ino uint64
	Dev uint32
}

const mountinfoPath = "/proc/self/mountinfo"

// openMountinfo is the mountinfo source; an internal test swaps it to exercise the fallback.
var openMountinfo = func() (io.ReadCloser, error) { return os.Open(mountinfoPath) }

// identityFunc builds FS.Identity: statx for inode and mount id, mountinfo for the device,
// and the stat-based conversion as a fallback that warns exactly once.
func identityFunc(warn func(string)) func(string) (ExeKey, error) {
	var once sync.Once
	return func(path string) (ExeKey, error) {
		ino, mnt, stDev, err := statx(path)
		if err != nil {
			return ExeKey{}, err
		}
		dev, err := devViaMountinfo(mnt)
		if err != nil {
			once.Do(func() { warn(fmt.Sprintf("%s: %v: using the stat device, wrong on btrfs/overlayfs", path, err)) })
			dev = devFromStat(stDev)
		}
		return ExeKey{Ino: ino, Dev: dev}, nil
	}
}

// devViaMountinfo reads the device of a mount id from mountinfo; any failure is an error the
// caller may fall back from (unreadable file, malformed row, no row).
func devViaMountinfo(mnt uint64) (uint32, error) {
	f, err := openMountinfo()
	if err != nil {
		return 0, err
	}
	defer f.Close()
	dev, ok, err := devFromMountinfo(mnt, f)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, fmt.Errorf("mountinfo has no row for mount id %d", mnt)
	}
	return dev, nil
}

// devOf returns the kernel's device number for the filesystem holding path: the file's mount
// id (statx) looked up in /proc/self/mountinfo, whose major:minor column is printed from the
// superblock's s_dev. This is what i_sb->s_dev reads in the BPF program, also on btrfs
// subvolumes and overlayfs, where stat's st_dev differs.
func devOf(path string) (uint32, error) {
	_, mnt, _, err := statx(path)
	if err != nil {
		return 0, err
	}
	dev, err := devViaMountinfo(mnt)
	if err != nil {
		return 0, fmt.Errorf("%s: %w", path, err)
	}
	return dev, nil
}

// devFromMountinfo finds the row for mount id mnt and returns its device in kernel encoding.
// ok is false when no row has that id. Format: "id parent major:minor root mountpoint ...".
func devFromMountinfo(mnt uint64, r io.Reader) (dev uint32, ok bool, err error) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fields := strings.Fields(sc.Text())
		if len(fields) < 3 || fields[0] != strconv.FormatUint(mnt, 10) {
			continue
		}
		maj, min, found := strings.Cut(fields[2], ":")
		a, errA := strconv.ParseUint(maj, 10, 32)
		b, errB := strconv.ParseUint(min, 10, 32)
		if !found || errA != nil || errB != nil {
			return 0, false, fmt.Errorf("mountinfo: bad device %q for mount %d", fields[2], mnt)
		}
		return kernelDev(uint32(a), uint32(b)), true, nil
	}
	return 0, false, sc.Err()
}

// devFromStat converts a stat st_dev (glibc encoding) to the kernel's; right for ext4/xfs,
// wrong for btrfs subvolumes and overlayfs. The fallback when mountinfo has no row.
func devFromStat(stDev uint64) uint32 { return kernelDev(unix.Major(stDev), unix.Minor(stDev)) }

func kernelDev(major, minor uint32) uint32 { return major<<20 | minor }

// statx returns the inode, mount id, stat device and mode of a path (symlinks followed).
func statx(path string) (ino, mnt uint64, stDev uint64, err error) {
	var st unix.Statx_t
	err = unix.Statx(unix.AT_FDCWD, path, 0, unix.STATX_INO|unix.STATX_MNT_ID|unix.STATX_TYPE, &st)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("%s: %w", path, err)
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return 0, 0, 0, fmt.Errorf("%s: not a regular file", path)
	}
	return st.Ino, st.Mnt_id, unix.Mkdev(st.Dev_major, st.Dev_minor), nil
}
