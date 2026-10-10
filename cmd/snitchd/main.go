// snitchd: egress control in the kernel (BPF LSM). Work in progress, phase 1.
//
// What runs today: both hooks attach, the daemon heartbeats the pinned control map (without
// it the program fails open), the mode comes from -mode, every decision is printed. Rules are
// not loaded yet (next step: a rules file -> programs map + LPM trie).
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"golang.org/x/sys/unix"

	snitchbpf "github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/rules"
)

const pinDir = "/sys/fs/bpf/snitch" // control + kill maps live here (kill: bpftool from a console)

var verdicts = [...]string{"allow (monitor)", "allow (rule)", "DENY (rule)", "DENY (default)",
	"allow (local net)", "allow (heartbeat stale)", "allow (kill switch)"}

func main() {
	cfg, err := parseFlagsTo(os.Args[1:], os.Stderr)
	if err != nil {
		var ue *usageError
		if errors.As(err, &ue) {
			fmt.Fprintln(os.Stderr, "snitchd:", err)
			os.Exit(ue.exitCode())
		}
		fatal("flags:", err)
	}
	mode, duration := &cfg.mode, &cfg.duration
	// rules first: a bad file is reported before anything touches the kernel
	notice := func(m string) { fmt.Fprintln(os.Stderr, "snitchd:", m) }
	snap, err := loadRules(cfg.rules, notice)
	if err != nil {
		fatal("rules:", err)
	}
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintln(os.Stderr, "memlock:", err)
	}
	if err := os.MkdirAll(pinDir, 0o700); err != nil {
		fatal("pin dir:", err)
	}
	var objs snitchbpf.SnitchObjects
	err = snitchbpf.LoadSnitchObjects(&objs, &ebpf.CollectionOptions{Maps: ebpf.MapOptions{PinPath: pinDir}})
	if err != nil {
		fatal("load:", err)
	}
	defer objs.Close()

	// mode + first heartbeat before attaching: no window where the program sees stale state
	m := uint32(0)
	if *mode == "enforce" {
		m = 1
	}
	beat := func() error {
		var ts unix.Timespec
		if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
			return err
		}
		c := snitchbpf.SnitchControlState{HeartbeatNs: uint64(ts.Nano()), Mode: m}
		return objs.Control.Put(uint32(0), &c)
	}
	if err := beat(); err != nil {
		fatal("heartbeat:", err)
	}
	var st state
	if err := apply(mapOps(objs.Programs), mapOps(objs.Rules), rules.Diff(rules.Entries{}, snap.ent)); err != nil {
		fatal("rules:", err)
	}
	st.publish(snap)
	fmt.Println(summary(snap))
	for _, p := range []*ebpf.Program{objs.SocketConnect, objs.SocketSendmsg} {
		l, err := link.AttachLSM(link.LSMOptions{Program: p})
		if err != nil {
			fatal("attach:", err)
		}
		defer l.Close()
	}
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fatal("ringbuf:", err)
	}
	defer rd.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	go func() {
		t := time.NewTicker(2 * time.Second)
		defer t.Stop()
		var end <-chan time.Time
		if *duration > 0 {
			end = time.After(*duration)
		}
		for {
			select {
			case <-t.C:
				if err := beat(); err != nil {
					fmt.Fprintln(os.Stderr, "heartbeat:", err)
				}
			case <-stop:
				rd.Close()
				return
			case <-end:
				rd.Close()
				return
			}
		}
	}()
	fmt.Printf("snitchd: mode %s, hooks lsm/socket_connect + lsm/socket_sendmsg, maps pinned in %s\n", *mode, pinDir)
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var e snitchbpf.SnitchEvent
		if err := binary.Read(bytesReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		var ip net.IP
		if e.Family == unix.AF_INET {
			ip = net.IP(e.Addr[:4])
		} else {
			ip = net.IP(e.Addr[:])
		}
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", e.Pid))
		hook := "connect"
		if e.Hook == 1 {
			hook = "sendmsg"
		}
		v := "?"
		if int(e.Verdict) < len(verdicts) {
			v = verdicts[e.Verdict]
		}
		fmt.Printf("%-23s %-8s pid %-7d %-15s proto %-2d -> %s:%d  %s\n",
			v, hook, e.Pid, cstring(e.Comm[:]), e.Proto, ip, e.Dport, filepath.Base(exe))
	}
}

func fatal(msg string, err error) {
	fmt.Fprintln(os.Stderr, msg, err)
	os.Exit(1)
}

// cstring turns a NUL-terminated C char array (int8 in Go) into a string.
func cstring(c []int8) string {
	b := make([]byte, 0, len(c))
	for _, ch := range c {
		if ch == 0 {
			break
		}
		b = append(b, byte(ch))
	}
	return string(b)
}
