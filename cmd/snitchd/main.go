// snitchd probe (phase 1): attach the LSM program, print connects for a few seconds.
package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"

	snitchbpf "github.com/norandom/snitch/internal/bpf"
)

func main() {
	if err := rlimit.RemoveMemlock(); err != nil {
		fmt.Fprintln(os.Stderr, "memlock:", err)
	}
	var objs snitchbpf.SnitchObjects
	if err := snitchbpf.LoadSnitchObjects(&objs, nil); err != nil {
		fmt.Fprintln(os.Stderr, "load:", err)
		os.Exit(1)
	}
	defer objs.Close()
	l, err := link.AttachLSM(link.LSMOptions{Program: objs.SocketConnect})
	if err != nil {
		fmt.Fprintln(os.Stderr, "attach lsm/socket_connect:", err)
		os.Exit(1)
	}
	defer l.Close()
	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		fmt.Fprintln(os.Stderr, "ringbuf:", err)
		os.Exit(1)
	}
	defer rd.Close()
	fmt.Println("attached lsm/socket_connect, observing for 12s")
	go func() { time.Sleep(12 * time.Second); rd.Close() }()
	for {
		rec, err := rd.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			continue
		}
		var e snitchbpf.SnitchEvent
		if err := binary.Read(bytes.NewReader(rec.RawSample), binary.LittleEndian, &e); err != nil {
			continue
		}
		ip := make(net.IP, 4)
		binary.LittleEndian.PutUint32(ip, e.Daddr)
		exe, _ := os.Readlink(fmt.Sprintf("/proc/%d/exe", e.Pid))
		comm := cstring(e.Comm[:])
		fmt.Printf("pid %-7d ppid %-7d %-16s ino %-9d dev %-6d proto %-2d -> %s:%d  %s\n",
			e.Pid, e.Ppid, comm, e.ExeIno, e.ExeDev, e.Proto, ip, e.Dport, exe)
	}
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
