package lsm

import (
	"bytes"
	"compress/gzip"
	"errors"
	"io/fs"
	"reflect"
	"strings"
	"testing"

	"github.com/norandom/snitch/internal/contract"
	"github.com/norandom/snitch/internal/contract/contracttest"
)

type fakeFS struct {
	files map[string][]byte
	errs  map[string]error
}

func (f fakeFS) read(path string) ([]byte, error) {
	if err, ok := f.errs[path]; ok {
		return nil, err
	}
	if b, ok := f.files[path]; ok {
		return b, nil
	}
	return nil, fs.ErrNotExist
}

func gzipMust(s string) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(s)); err != nil {
		panic(err)
	}
	if err := zw.Close(); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

type probeCase struct {
	name string
	fs   fakeFS
	want Hook
	sent string
}

var (
	cfgYes  = []byte("CONFIG_SECURITY=y\nCONFIG_BPF_LSM=y\n")
	cfgNo   = []byte("CONFIG_SECURITY=y\n# CONFIG_BPF_LSM is not set\n")
	rel734  = []byte("7.3.4-2-t2\n")
	grubYes = []byte("\tlinux\t/boot/vmlinuz-7.3.4 root=UUID=abc ro lsm=lockdown,apparmor,bpf\n")
	grubNo  = []byte("\tlinux\t/boot/vmlinuz-7.3.4 root=UUID=abc ro quiet\n")
)

var probeCases = []probeCase{
	{
		name: "active in list",
		fs:   fakeFS{files: map[string][]byte{ListPath: []byte("lockdown,capability,apparmor,bpf\n")}},
		want: Hook{State: Active},
		sent: "kernel hook active",
	},
	{
		name: "active ignores missing kernel config",
		fs:   fakeFS{files: map[string][]byte{ListPath: []byte(" lockdown , bpf \n")}},
		want: Hook{State: Active},
		sent: "kernel hook active",
	},
	{
		name: "unreadable list gives unknown",
		fs:   fakeFS{errs: map[string]error{ListPath: errors.New("open /sys/kernel/security/lsm: no such file or directory")}},
		want: Hook{State: Unknown},
		sent: "kernel hook not checked: the kernel's LSM list could not be read",
	},
	{
		name: "empty list gives inactive",
		fs:   fakeFS{files: map[string][]byte{ListPath: []byte("\n")}},
		want: Hook{State: Inactive},
		sent: "kernel hook inactive: connections are neither seen nor blocked; run as root to see whether a reboot is pending",
	},
	{
		name: "inactive pending via grub.cfg",
		fs: fakeFS{files: map[string][]byte{
			ListPath:                     []byte("lockdown,capability,apparmor\n"),
			"/proc/sys/kernel/osrelease": rel734,
			"/boot/config-7.3.4-2-t2":    cfgYes,
			"/boot/grub/grub.cfg":        grubYes,
		}},
		want: Hook{State: Inactive, Pending: true, CanTell: true},
		sent: "kernel hook inactive: reboot to activate it; until then connections are neither seen nor blocked",
	},
	{
		name: "inactive pending via grub2 linuxefi when grub.cfg lacks bpf",
		fs: fakeFS{files: map[string][]byte{
			ListPath:                     []byte("lockdown,apparmor\n"),
			"/proc/sys/kernel/osrelease": rel734,
			"/boot/config-7.3.4-2-t2":    cfgYes,
			"/boot/grub/grub.cfg":        grubNo,
			"/boot/grub2/grub.cfg":       []byte("  linuxefi /vmlinuz lsm=bpf quiet\n"),
		}},
		want: Hook{State: Inactive, Pending: true, CanTell: true},
		sent: "kernel hook inactive: reboot to activate it; until then connections are neither seen nor blocked",
	},
	{
		name: "near-miss bpfx in list and grub is not active or pending",
		fs: fakeFS{files: map[string][]byte{
			ListPath:                     []byte("lockdown,bpfx,apparmor\n"),
			"/proc/sys/kernel/osrelease": rel734,
			"/boot/config-7.3.4-2-t2":    cfgYes,
			"/boot/grub/grub.cfg":        []byte("\tlinux\t/vmlinuz lsm=lockdown,bpfx\n"),
		}},
		want: Hook{State: Inactive, Pending: false, CanTell: true},
		sent: "kernel hook inactive: bpf is not in the kernel's LSM list and the next boot is not configured for it; connections are neither seen nor blocked",
	},
	{
		name: "commented and non-linux lines in grub are ignored",
		fs: fakeFS{files: map[string][]byte{
			ListPath:                     []byte("apparmor\n"),
			"/proc/sys/kernel/osrelease": rel734,
			"/boot/config-7.3.4-2-t2":    cfgYes,
			"/boot/grub/grub.cfg":        []byte("# linux /vmlinuz lsm=bpf\nset default=lsm=bpf\n" + string(grubNo)),
		}},
		want: Hook{State: Inactive, Pending: false, CanTell: true},
		sent: "kernel hook inactive: bpf is not in the kernel's LSM list and the next boot is not configured for it; connections are neither seen nor blocked",
	},
	{
		name: "inactive grub absent gives cannot tell",
		fs: fakeFS{files: map[string][]byte{
			ListPath:                     []byte("lockdown,apparmor\n"),
			"/proc/sys/kernel/osrelease": rel734,
			"/boot/config-7.3.4-2-t2":    cfgYes,
		}},
		want: Hook{State: Inactive, Pending: false, CanTell: false},
		sent: "kernel hook inactive: connections are neither seen nor blocked; run as root to see whether a reboot is pending",
	},
	{
		name: "inactive grub permission denied gives cannot tell without OS error",
		fs: fakeFS{
			files: map[string][]byte{
				ListPath:                     []byte("lockdown,apparmor\n"),
				"/proc/sys/kernel/osrelease": rel734,
				"/boot/config-7.3.4-2-t2":    cfgYes,
			},
			errs: map[string]error{
				"/boot/grub/grub.cfg":  errors.New("open /boot/grub/grub.cfg: permission denied"),
				"/boot/grub2/grub.cfg": errors.New("open /boot/grub2/grub.cfg: no such file or directory"),
			},
		},
		want: Hook{State: Inactive, Pending: false, CanTell: false},
		sent: "kernel hook inactive: connections are neither seen nor blocked; run as root to see whether a reboot is pending",
	},
	{
		name: "unsupported from /boot/config-<release>",
		fs: fakeFS{files: map[string][]byte{
			ListPath:                     []byte("lockdown,apparmor\n"),
			"/proc/sys/kernel/osrelease": rel734,
			"/boot/config-7.3.4-2-t2":    cfgNo,
			"/boot/grub/grub.cfg":        grubYes,
		}},
		want: Hook{State: Inactive, Unsupported: true},
		sent: "kernel hook unavailable: this kernel is built without BPF LSM support, so no reboot can activate it; connections are neither seen nor blocked",
	},
	{
		name: "unsupported from /proc/config.gz fallback",
		fs: fakeFS{files: map[string][]byte{
			ListPath:              []byte("lockdown,apparmor\n"),
			"/proc/config.gz":     gzipMust(string(cfgNo)),
			"/boot/grub/grub.cfg": grubNo,
		}},
		want: Hook{State: Inactive, Unsupported: true},
		sent: "kernel hook unavailable: this kernel is built without BPF LSM support, so no reboot can activate it; connections are neither seen nor blocked",
	},
	{
		name: "supported from /proc/config.gz fallback proceeds to grub",
		fs: fakeFS{files: map[string][]byte{
			ListPath:              []byte("lockdown,apparmor\n"),
			"/proc/config.gz":     gzipMust(string(cfgYes)),
			"/boot/grub/grub.cfg": grubYes,
		}},
		want: Hook{State: Inactive, Pending: true, CanTell: true},
		sent: "kernel hook inactive: reboot to activate it; until then connections are neither seen nor blocked",
	},
	{
		name: "both kernel configs unreadable does not claim unsupported",
		fs: fakeFS{
			files: map[string][]byte{
				ListPath:              []byte("lockdown,apparmor\n"),
				"/boot/grub/grub.cfg": grubYes,
			},
			errs: map[string]error{
				"/proc/sys/kernel/osrelease": errors.New("no such file or directory"),
				"/proc/config.gz":            errors.New("no such file or directory"),
			},
		},
		want: Hook{State: Inactive, Pending: true, CanTell: true, Unsupported: false},
		sent: "kernel hook inactive: reboot to activate it; until then connections are neither seen nor blocked",
	},
	{
		name: "corrupt /proc/config.gz does not claim unsupported",
		fs: fakeFS{files: map[string][]byte{
			ListPath:              []byte("lockdown,apparmor\n"),
			"/proc/config.gz":     []byte("not-gzip"),
			"/boot/grub/grub.cfg": grubNo,
		}},
		want: Hook{State: Inactive, Pending: false, CanTell: true, Unsupported: false},
		sent: "kernel hook inactive: bpf is not in the kernel's LSM list and the next boot is not configured for it; connections are neither seen nor blocked",
	},
}

func TestProbeAndSentence(t *testing.T) {
	for _, c := range probeCases {
		t.Run(c.name, func(t *testing.T) {
			got := Probe(c.fs.read)
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("Probe() = %+v, want %+v", got, c.want)
			}
			sent := got.Sentence()
			if sent != c.sent {
				t.Fatalf("Sentence() = %q, want %q", sent, c.sent)
			}
			lower := strings.ToLower(sent)
			if strings.Contains(lower, "no such file") || strings.Contains(lower, "permission denied") {
				t.Fatalf("Sentence() leaked OS error text: %q", sent)
			}
		})
	}
}

func TestGrubQuotedArgs(t *testing.T) {
	lines := []string{
		`linux /vmlinuz "lsm=lockdown,bpf" quiet`,
		`linux /vmlinuz 'lsm=lockdown,bpf' quiet`,
		`linux /vmlinuz lsm="lockdown,bpf" quiet`,
		`linux /vmlinuz lsm='lockdown,bpf' quiet`,
	}
	for _, line := range lines {
		t.Run(line, func(t *testing.T) {
			fsys := fakeFS{files: map[string][]byte{
				ListPath:                     []byte("lockdown,apparmor\n"),
				"/proc/sys/kernel/osrelease": rel734,
				"/boot/config-7.3.4-2-t2":    cfgYes,
				"/boot/grub/grub.cfg":        []byte("\t" + line + "\n"),
			}}
			want := Hook{State: Inactive, Pending: true, CanTell: true}
			if got := Probe(fsys.read); !reflect.DeepEqual(got, want) {
				t.Fatalf("Probe() = %+v, want %+v", got, want)
			}
		})
	}
}

func TestZeroHookSentence(t *testing.T) {
	want := "kernel hook not checked: the kernel's LSM list could not be read"
	if got := (Hook{}).Sentence(); got != want {
		t.Fatalf("Sentence() = %q, want %q", got, want)
	}
}

func TestContractProbeRequiresReader(t *testing.T) {
	contracttest.Panics(t, contract.Precondition, func() { Probe(nil) })
}
