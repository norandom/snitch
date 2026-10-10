package rules

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const mountinfoFixture = "testdata/mountinfo"

func TestDevFromMountinfoUsesTheKernelEncoding(t *testing.T) {
	src, err := os.ReadFile(mountinfoFixture)
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		mnt  uint64
		want uint32
	}{
		{31, 8<<20 | 1}, // ext4 root: major 8, minor 1 (ids 310 and 3 are decoys: exact match only)
		{3, 0<<20 | 3},
		{45, 0<<20 | 38}, // btrfs subvolume: anonymous major 0
		{52, 0<<20 | 41}, // overlay
	}
	for _, c := range cases {
		got, ok, err := devFromMountinfo(c.mnt, strings.NewReader(string(src)))
		if err != nil || !ok || got != c.want {
			t.Fatalf("mount %d: want %d, got %d ok=%v err=%v", c.mnt, c.want, got, ok, err)
		}
	}
}

func TestDevFromMountinfoUnknownMountIsNotFound(t *testing.T) {
	_, ok, err := devFromMountinfo(999, strings.NewReader("31 2 8:1 / / rw - ext4 /dev/sda1 rw\n"))
	if err != nil || ok {
		t.Fatalf("want not found without error, got ok=%v err=%v", ok, err)
	}
}

func TestDevFromMountinfoRejectsGarbage(t *testing.T) {
	_, _, err := devFromMountinfo(31, strings.NewReader("31 2 eight:one / /\n"))
	if err == nil {
		t.Fatal("want an error for a malformed major:minor")
	}
}

func TestDevFromStatConvertsGlibcToKernel(t *testing.T) {
	// glibc st_dev for 8:1 is 0x801 = 2049; the kernel's s_dev is (8 << 20) | 1
	if got := devFromStat(2049); got != 8<<20|1 {
		t.Fatalf("got %d", got)
	}
	// minor numbers above 255 are split across st_dev's bit fields; Mkdev builds that layout
	if got := devFromStat(unix.Mkdev(8, 260)); got != 8<<20|260 {
		t.Fatalf("got %d", got)
	}
}

func TestDevOfRealFileFindsItsMount(t *testing.T) {
	// the real mountinfo must contain the mount of a regular file we can stat
	dev, err := devOf(filepath.Join("testdata", "valid.toml"))
	if err != nil || dev == 0 {
		t.Fatalf("want a device for a real file, got %d, %v", dev, err)
	}
	t.Logf("device of testdata/valid.toml: %d (major %d, minor %d)", dev, dev>>20, dev&(1<<20-1))
}

func TestDevOfMissingFileFails(t *testing.T) {
	if _, err := devOf(filepath.Join(t.TempDir(), "none")); err == nil {
		t.Fatal("want an error")
	}
}
