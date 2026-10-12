package main

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf/ringbuf"

	snitchbpf "github.com/norandom/snitch/internal/bpf"
	"github.com/norandom/snitch/internal/rules"
)

// pump reads the kernel's events, names them from the current snapshot, prints them, hands
// them to the API (emit never blocks) and uncovered connections to the learning sink. It never
// returns nil: that would end the run.
func (d *daemon) pump(ctx context.Context) error {
	go func() { <-ctx.Done(); d.rd.Close() }()
	for {
		rec, err := d.rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return ctx.Err()
		}
		if err != nil || len(rec.RawSample) < eventSize {
			continue
		}
		e := decodeEvent(rec.RawSample)
		snap := d.st.current()
		// one lookup per event: the log line, the API event and the learner carry the same name
		name := d.dns.nameOf(addrOf(&e), e.Rule)
		fixed := func(netip.Addr, uint32) string { return name }
		fmt.Println(describe(&e, snap, exeOf, name))
		if d.emit != nil {
			d.emit(toEvent(&e, snap, exeOf, time.Now(), fixed))
		}
		if e.Verdict == verdictAllowMonitor && d.sink != nil {
			d.sink(observation(&e, snap, exeOf, time.Now(), name))
		}
	}
}

// exeOf is the fallback for an event without a path: the process may still be alive.
func exeOf(pid uint32) string {
	p, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return ""
	}
	return p
}

// describe is the human log line (not a contract):
//
//	DENY (default)  connect pid 4242 curl   tcp -> 9.9.9.9:443  program curl
//	allow (rule)    connect pid 4242 curl   tcp -> 1.1.1.1:443  program curl  rule #1 curl 1.1.1.1/32 tcp 443 allow
func describe(e *snitchbpf.SnitchEvent, snap *snapshot, exe func(uint32) string, names ...string) string {
	name, _ := programOf(e, snap, exe)
	dest := destination(e)
	if len(names) != 0 && names[0] != "" {
		dest += " (" + names[0] + ")"
	}
	s := fmt.Sprintf("%-23s %-8s pid %-7d %-15s %-4s -> %s  program %s",
		verdictName(e), hookName(e), e.Pid, commOf(e), protoName(e.Proto), dest, name)
	if r := ruleOf(e, snap); r != nil {
		s += "  rule " + ruleText(r)
	}
	return s
}

func destination(e *snitchbpf.SnitchEvent) string {
	return netipJoin(addrOf(e).String(), e.Dport)
}

func netipJoin(addr string, port uint16) string {
	if strings.Contains(addr, ":") {
		return fmt.Sprintf("[%s]:%d", addr, port)
	}
	return fmt.Sprintf("%s:%d", addr, port)
}

// programOf names the program: the configured name for a mapped executable, otherwise the
// path the kernel saw (or /proc as a fallback) marked unknown. known is false for the latter.
func programOf(e *snitchbpf.SnitchEvent, snap *snapshot, exe func(uint32) string) (name string, known bool) {
	if e.Program != 0 && snap != nil {
		if n, ok := snap.res.Names[e.Program]; ok {
			return n, true
		}
	}
	path := pathOf(e)
	if path == "" {
		path = exe(e.Pid)
	}
	if path == "" {
		return "unknown", false
	}
	return path + " (unknown)", false
}

func ruleOf(e *snitchbpf.SnitchEvent, snap *snapshot) *rules.Rule {
	if e.Rule == 0 || snap == nil {
		return nil
	}
	return snap.res.ByID[e.Rule]
}

// ruleText: "#1 curl 1.1.1.1/32 tcp 443 allow"
func ruleText(r *rules.Rule) string {
	port := "any"
	if len(r.Ports) == 1 {
		port = fmt.Sprint(r.Ports[0])
	} else if len(r.Ports) > 1 {
		port = fmt.Sprintf("%d-%d", r.Ports[0], r.Ports[len(r.Ports)-1])
	}
	return fmt.Sprintf("#%d %s %s %s %s %s", r.ID, r.Program, r.Dest(), protoName(uint8(r.Proto)), port, verdictWord(r.Verdict))
}

func protoName(p uint8) string {
	switch p {
	case 0:
		return "any"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	}
	return fmt.Sprintf("proto%d", p)
}

func verdictWord(v rules.Verdict) string {
	if v == rules.Deny {
		return "deny"
	}
	return "allow"
}

// observation is what the learning sink gets for an uncovered connection.
func observation(e *snitchbpf.SnitchEvent, snap *snapshot, exe func(uint32) string, at time.Time, names ...string) rules.Observation {
	o := rules.Observation{Exe: rules.ExeKey{Ino: e.ExeIno, Dev: e.ExeDev}, Addr: addrOf(e), Proto: rules.Proto(e.Proto), Port: e.Dport, At: at}
	if len(names) != 0 {
		o.Name = names[0]
	}
	o.Path = pathOf(e)
	if o.Path == "" {
		o.Path = exe(e.Pid) // one /proc lookup; programOf would repeat it
	}
	if e.Program != 0 && snap != nil {
		o.Program = snap.res.Names[e.Program]
	}
	return o
}
