package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"

	snitchbpf "github.com/norandom/snitch/internal/bpf"
)

var verdicts = [...]string{"allow (monitor)", "allow (rule)", "DENY (rule)", "DENY (default)",
	"allow (local net)", "allow (heartbeat stale)", "allow (kill switch)"}

// pump is the provisional event job (task 6.3): today's read-and-print loop. Task 6.5
// replaces it with the fixed-layout decoder and program/rule naming. It never returns nil:
// a nil return would end the whole run.
func (d *daemon) pump(ctx context.Context) error {
	go func() { <-ctx.Done(); d.rd.Close() }()
	for {
		rec, err := d.rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return ctx.Err()
		}
		if err != nil {
			continue
		}
		var e snitchbpf.SnitchEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		fmt.Println(line(&e))
	}
}

func line(e *snitchbpf.SnitchEvent) string {
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
	return fmt.Sprintf("%-23s %-8s pid %-7d %-15s proto %-2d -> %s:%d  %s",
		v, hook, e.Pid, cstring(e.Comm[:]), e.Proto, ip, e.Dport, filepath.Base(exe))
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
