// Package api is the daemon's local JSON-lines API: wire types, codec, roles, the per-client
// queue and (server.go) the dispatcher. It never touches BPF; the daemon converts kernel events
// into Event. Fail-safe note: nothing here can block the decision path; a client that stops
// reading loses messages (Client) and is closed, the kernel never waits for it.
package api

import "time"

// Limits of the protocol (design "Server and Client queue").
const (
	LineLimit     = 64 << 10        // longest request line in bytes, inclusive
	Backlog       = 1024            // queued messages per client before drops
	WriteDeadline = 5 * time.Second // a write slower than this closes the client
	SummaryEvery  = 2 * time.Second // summary cadence for subscribers
	MaxClients    = 64              // the 65th connection is refused
)

// Envelope: every line has type; requests carry id > 0, replies echo it, unsolicited use 0.

// Request is a client line. Fields past Id are per type (design "Wire types", request list).
type Request struct {
	Type     string `json:"type"`
	Id       int    `json:"id"`
	Window   string `json:"window,omitempty"`   // snapshot
	Events   bool   `json:"events,omitempty"`   // subscribe (default true)
	Local    bool   `json:"local,omitempty"`    // subscribe (default false)
	Summary  bool   `json:"summary,omitempty"`  // subscribe (default true)
	Duration string `json:"duration,omitempty"` // trial
	Extend   bool   `json:"extend,omitempty"`   // trial
	Yes      bool   `json:"yes,omitempty"`      // trial: start even with zero effective rules (the CLI's -y)
	Program  string `json:"program,omitempty"`  // rule.add, rule.remove
	Path     string `json:"path,omitempty"`     // rule.add
	To       string `json:"to,omitempty"`       // rule.add, rule.remove
	Proto    string `json:"proto,omitempty"`    // rule.add, rule.remove
	Port     int    `json:"port,omitempty"`     // rule.add, rule.remove
	Verdict  string `json:"verdict,omitempty"`  // rule.add
	Note     string `json:"note,omitempty"`     // rule.add
}

// Reply answers one request ("reply"); the payload fields are set per request type.
type Reply struct {
	Type     string        `json:"type"`
	Id       int           `json:"id"`
	Ok       bool          `json:"ok"`
	Text     string        `json:"text,omitempty"`
	Status   *Status       `json:"status,omitempty"`
	Rules    []RuleView    `json:"rules,omitempty"`
	Programs []ProgramView `json:"programs,omitempty"`
	Learned  []Observation `json:"learned,omitempty"`
	Learning bool          `json:"learning,omitempty"`
	Entries  []Entry       `json:"entries,omitempty"`
	Window   string        `json:"window,omitempty"`
}

// Error answers a bad or refused request ("error"); Id is 0 when the line did not parse.
type Error struct {
	Type  string `json:"type"`
	Id    int    `json:"id"`
	Error string `json:"error"`
}

// Dropped precedes the next message a client receives after drops ("dropped", id 0). Messages
// are marshalled once and shared between clients, so the count travels as its own line
// instead of a field patched into shared bytes.
type Dropped struct {
	Type  string `json:"type"`
	Id    int    `json:"id"`
	Count int    `json:"count"`
}

// Event is one kernel decision ("event", id 0). Time marshals as RFC 3339 and lets the server
// require a non-zero time. Name is the name through which a compiled rule matched,
// otherwise the most recently learned name; it is absent when unknown.
type Event struct {
	Type     string    `json:"type"`
	Id       int       `json:"id"`
	Time     time.Time `json:"time"`
	Program  string    `json:"program"`
	Path     string    `json:"path"`
	Pid      uint32    `json:"pid"`
	Ppid     uint32    `json:"ppid"`
	Comm     string    `json:"comm"`
	Addr     string    `json:"addr"`
	Name     string    `json:"name,omitempty"`
	Port     uint16    `json:"port"`
	Protocol string    `json:"protocol"` // tcp | udp
	Verdict  string    `json:"verdict"`  // allow-local | allow-rule | deny-rule | allow-monitor | deny-default | allow-stale | allow-kill
	Rule     *RuleRef  `json:"rule"`     // null unless a rule decided
	Hook     string    `json:"hook"`     // connect | sendmsg
	Cookie   uint64    `json:"cookie"`
}

// RuleRef names the rule behind a verdict.
type RuleRef struct {
	Id     int    `json:"id"`
	Note   string `json:"note"`
	Source string `json:"source"`
}

// Entry is one row of the connection table, in Summary and snapshot replies.
// Name is the name through which a compiled rule matched, otherwise the most
// recently learned name; it is absent when unknown.
type Entry struct {
	Program     string  `json:"program"`
	Path        string  `json:"path"`
	Addr        string  `json:"addr"`
	Name        string  `json:"name,omitempty"`
	Port        uint16  `json:"port"`
	Protocol    string  `json:"protocol"`
	AllowCount  uint64  `json:"allowCount"`
	DenyCount   uint64  `json:"denyCount"`
	FirstSeen   string  `json:"firstSeen"`
	LastSeen    string  `json:"lastSeen"`
	LastAllowed string  `json:"lastAllowed"`
	LastBlocked string  `json:"lastBlocked"`
	BytesSent   uint64  `json:"bytesSent"`
	Rate        float64 `json:"rate"` // bytes per second over the last 10 s
	Verdict     string  `json:"verdict"`
}

// Summary carries the entries changed since the last one ("summary", id 0).
type Summary struct {
	Type    string  `json:"type"`
	Id      int     `json:"id"`
	Since   string  `json:"since"`
	Entries []Entry `json:"entries"`
	Dropped int     `json:"dropped,omitempty"`
}

// State announces a mode, trial or rules change ("state", id 0).
type State struct {
	Type         string `json:"type"`
	Id           int    `json:"id"`
	Mode         string `json:"mode"`
	Trial        string `json:"trial"`
	Kept         bool   `json:"kept"`
	RulesChanged bool   `json:"rulesChanged"`
	Reason       string `json:"reason"`
}

// Status is the daemon's facts, the payload of a status reply.
type Status struct {
	Running    bool         `json:"running"`
	Pid        int          `json:"pid"`
	Version    string       `json:"version"`
	Mode       string       `json:"mode"`
	Source     string       `json:"source"`
	Trial      string       `json:"trial"`
	Kept       bool         `json:"kept"`
	Kill       bool         `json:"kill"`
	Learning   bool         `json:"learning"`
	Rules      RulesSummary `json:"rules"`
	RulesError string       `json:"rulesError"`
	Clients    int          `json:"clients"`
	Dropped    int          `json:"dropped"`
	Entries    int          `json:"entries"`
	Evictions  int          `json:"evictions"`
	Started    string       `json:"started"`
	Counting   bool         `json:"counting"`
	// DNS is absent only on daemons older than this version; an off tap has On false and a reason.
	DNS *DNSStatus `json:"dns,omitempty"`
}

// RulesSummary is the startup line's numbers plus the files they came from.
type RulesSummary struct {
	Programs    int    `json:"programs"`
	Resolved    int    `json:"resolved"`
	Executables int    `json:"executables"`
	Rules       int    `json:"rules"`
	File        string `json:"file"`
	Overlay     string `json:"overlay"`
}

// RuleView is one rule as the rules reply lists it.
type RuleView struct {
	Id       int    `json:"id"`
	Program  string `json:"program"`
	To       string `json:"to"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Verdict  string `json:"verdict"`
	Note     string `json:"note"`
	Source   string `json:"source"`
}

// ProgramView is one declared program with its resolution state.
type ProgramView struct {
	Name        string   `json:"name"`
	Paths       []string `json:"paths"`
	Resolved    bool     `json:"resolved"`
	Executables int      `json:"executables"`
	Source      string   `json:"source"`
}

// Observation is one learned destination (the learned reply). Name is the name
// through which a compiled rule matched, otherwise the most recently learned
// name; it is absent when unknown. A named observation may have Addr empty,
// serialized as addr:"", because learning by name does not retain an address.
type Observation struct {
	Program  string `json:"program"`
	Path     string `json:"path"`
	Addr     string `json:"addr"`
	Name     string `json:"name,omitempty"`
	Protocol string `json:"protocol"`
	Port     int    `json:"port"`
	Count    int    `json:"count"`
	First    string `json:"first"`
	Last     string `json:"last"`
}

// DNSStatus reports whether the tap is on and its lifetime counters and current sizes.
// An off tap reports On false with Reason; Ignored is the sum of rejected answers.
type DNSStatus struct {
	On        bool   `json:"on"`
	Reason    string `json:"reason,omitempty"`
	Seen      uint64 `json:"seen"`
	Ignored   uint64 `json:"ignored"`
	Entries   uint64 `json:"entries"`
	Names     uint64 `json:"names"`
	Compiled  uint64 `json:"compiled"`
	Evictions uint64 `json:"evictions"`
}
