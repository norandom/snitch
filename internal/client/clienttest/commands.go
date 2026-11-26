// commands.go: the stand-in's script: the fact changes with the state lines the daemon sends
// for them, the command language over them, one command per line (the tool reads them from
// stdin, tests may call Do too), and the rule sentence the daemon answers an edit with.
//
// Fail-safe implications: none. A command changes the stand-in's in-memory facts or sends a
// line to its own subscribers; a bad command is an error for the caller, never a crash.
package clienttest

import (
	"errors"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/norandom/snitch/internal/api"
	"github.com/norandom/snitch/internal/contract"
)

// ErrQuit is Do's answer to `quit`: the caller stops reading commands.
var ErrQuit = errors.New("quit")

// verdicts are the seven event verdicts of examples/api.md "event".
var verdicts = map[string]bool{"allow-local": true, "allow-rule": true, "deny-rule": true,
	"allow-monitor": true, "deny-default": true, "allow-stale": true, "allow-kill": true}

// SetMode sets the mode directly (like a daemon started with -mode); monitor also clears the
// trial and kept facts.
func (s *StandIn) SetMode(mode string) {
	contract.Require(mode == "monitor" || mode == "enforce", "clienttest: mode is monitor or enforce")
	s.announce(s.change(func(st *api.Status) {
		st.Mode = mode
		if mode == "monitor" {
			st.Trial, st.Kept = "", false
		}
	}), reasonMode, false)
}

// StartTrial enforces until now+d; the reason carries the deadline in local time, as the
// daemon's log does, the trial field in UTC.
func (s *StandIn) StartTrial(d time.Duration) {
	contract.Require(d > 0, "clienttest: a trial needs a positive duration")
	end := s.o.Now().Add(d)
	s.announce(s.change(func(st *api.Status) {
		st.Mode, st.Trial = "enforce", end.UTC().Format(time.RFC3339)
	}), "trial until "+end.Local().Format(time.RFC3339), false)
}

// endTrial is the operator's end: monitor, no trial, nothing kept.
func (s *StandIn) endTrial() {
	s.announce(s.change(func(st *api.Status) {
		st.Mode, st.Trial, st.Kept = "monitor", "", false
	}), reasonEnded, false)
}

// keep keeps enforce.
func (s *StandIn) keep() {
	s.announce(s.change(func(st *api.Status) { st.Mode, st.Kept = "enforce", true }), reasonKept, false)
}

// unkeep drops kept enforce: monitor unless a trial still runs.
func (s *StandIn) unkeep() {
	s.announce(s.change(func(st *api.Status) {
		st.Kept, st.Mode = false, "monitor"
		if st.Trial != "" {
			st.Mode = "enforce"
		}
	}), reasonUnkept, false)
}

// SetKill, setRulesError and SetLearning change the status only: the real daemon sends no
// state line for them. An empty text clears the rules error.
func (s *StandIn) SetKill(on bool) { s.change(func(st *api.Status) { st.Kill = on }) }

func (s *StandIn) SetLearning(on bool) { s.change(func(st *api.Status) { st.Learning = on }) }

func (s *StandIn) setRulesError(text string) {
	if text != "" {
		text = s.o.Now().UTC().Format(time.RFC3339) + ": " + text
	}
	s.change(func(st *api.Status) { st.RulesError = text })
}

// Refuse makes rule edits answer with an error from now on (or not).
func (s *StandIn) Refuse(on bool) { s.refuse.Store(on) }

// command runs one verb with its arguments.
type command func(s *StandIn, args []string) error

// commands is the verb table of Do.
var commands = map[string]command{
	"mode":     cmdMode,
	"trial":    cmdTrial,
	"end":      noArgs((*StandIn).endTrial),
	"keep":     noArgs((*StandIn).keep),
	"unkeep":   noArgs((*StandIn).unkeep),
	"kill":     onOff((*StandIn).SetKill),
	"learning": onOff((*StandIn).SetLearning),
	"refuse":   onOff((*StandIn).Refuse),
	"error":    cmdError,
	"event":    cmdEvent,
	"summary":  noArgs((*StandIn).FlushSummary),
	"drop":     cmdDrop,
	"rules":    cmdRules,
	"quit":     func(*StandIn, []string) error { return ErrQuit },
}

// Do runs one command line: `mode monitor|enforce`, `trial 10m`, `end`, `keep`, `unkeep`,
// `kill on|off`, `error TEXT|none`, `learning on|off`,
// `event PROGRAM PATH ADDR[=NAME] PORT PROTO VERDICT`, `summary`, `drop [COUNT]`,
// `rules none|reset`, `refuse on|off`, `quit` (ErrQuit). A blank line does nothing.
func (s *StandIn) Do(line string) error {
	f := strings.Fields(line)
	if len(f) == 0 {
		return nil
	}
	run, ok := commands[f[0]]
	if !ok {
		return fmt.Errorf("unknown command %q", f[0])
	}
	return run(s, f[1:])
}

func noArgs(fn func(*StandIn)) command {
	return func(s *StandIn, args []string) error {
		if len(args) != 0 {
			return errors.New("takes no arguments")
		}
		fn(s)
		return nil
	}
}

func onOff(fn func(*StandIn, bool)) command {
	return func(s *StandIn, args []string) error {
		if len(args) != 1 || (args[0] != "on" && args[0] != "off") {
			return errors.New("want on or off")
		}
		fn(s, args[0] == "on")
		return nil
	}
}

func cmdMode(s *StandIn, args []string) error {
	if len(args) != 1 || (args[0] != "monitor" && args[0] != "enforce") {
		return errors.New("want mode monitor or mode enforce")
	}
	s.SetMode(args[0])
	return nil
}

func cmdTrial(s *StandIn, args []string) error {
	if len(args) != 1 {
		return errors.New("want trial DURATION, e.g. trial 10m")
	}
	d, err := time.ParseDuration(args[0])
	if err != nil || d <= 0 {
		return fmt.Errorf("trial %q: want a positive duration", args[0])
	}
	s.StartTrial(d)
	return nil
}

// cmdError sets the rules error to the rest of the line; `error none` clears it.
func cmdError(s *StandIn, args []string) error {
	if len(args) == 0 {
		return errors.New("want error TEXT or error none")
	}
	text := strings.Join(args, " ")
	if text == "none" {
		text = ""
	}
	s.setRulesError(text)
	return nil
}

func cmdDrop(s *StandIn, args []string) error {
	if len(args) > 1 {
		return errors.New("want drop [COUNT]")
	}
	n := 1
	if len(args) == 1 {
		v, err := strconv.Atoi(args[0])
		if err != nil || v <= 0 {
			return fmt.Errorf("drop %q: want a positive integer", args[0])
		}
		n = v
	}
	s.Drop(n)
	return nil
}

func cmdRules(s *StandIn, args []string) error {
	if len(args) != 1 || (args[0] != "none" && args[0] != "reset") {
		return errors.New("want rules none or rules reset")
	}
	if args[0] == "none" {
		s.ClearRules()
		return nil
	}
	s.initRules(false)
	s.announce(s.Facts(), reasonReloaded, true)
	return nil
}

// cmdEvent builds an event as the pump would: comm from the path, the hook from the protocol,
// a rule reference for the two rule verdicts.
func cmdEvent(s *StandIn, args []string) error {
	if len(args) != 6 {
		return errors.New("want event PROGRAM PATH ADDR[=NAME] PORT PROTO VERDICT")
	}
	port, err := strconv.ParseUint(args[3], 10, 16)
	if err != nil {
		return fmt.Errorf("port %q: want 0 to 65535", args[3])
	}
	proto, verdict := args[4], args[5]
	if proto != "tcp" && proto != "udp" {
		return fmt.Errorf("proto %q: want tcp or udp", proto)
	}
	if !verdicts[verdict] {
		return fmt.Errorf("verdict %q: not one of the seven", verdict)
	}
	addr, name, _ := strings.Cut(args[2], "=")
	e := api.Event{Program: args[0], Path: args[1], Comm: filepath.Base(args[1]), Addr: addr,
		Name: name, Port: uint16(port), Protocol: proto, Verdict: verdict, Hook: "connect"}
	if proto == "udp" {
		e.Hook = "sendmsg"
	}
	if strings.HasSuffix(verdict, "-rule") {
		e.Rule = &api.RuleRef{Id: 1, Note: "stand-in", Source: "/etc/snitch/rules.toml"}
	}
	s.Emit(e)
	return nil
}

// Sentence is the daemon's outcome text for a rule edit (examples/api.md "rule.add").
func Sentence(req api.Request) string {
	who := req.Program
	if who == "" {
		who = filepath.Base(req.Path)
	}
	text := who + " to " + req.To
	if req.Proto != "" && req.Proto != "any" {
		text += " " + req.Proto
	}
	if req.Port != 0 {
		text += " port " + strconv.Itoa(req.Port)
	}
	if req.Type == "rule.remove" {
		return "rule removed: " + text + " (applies within 5 s)"
	}
	return "rule added: " + text + " " + req.Verdict + " (applies within 5 s)"
}
