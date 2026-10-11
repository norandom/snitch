# Requirements Document

## Project Description (Input)
daemon-api: snitchd gets a local API so the TUI, the popups and the tray can talk to the daemon
instead of Little Snitch's web UI.

- **Who**: the operator of the dev VM (today) and of fleet hosts (later), who wants the views of the
  Python client (connection overview, egress graph, alerts, rules) backed by snitchd, from a
  desktop session that does not run as root.
- **Current situation**: snitchd decides in the kernel and prints every event as a log line to the
  journal; its state (rules snapshot, mode, trial, learned observations) is reachable only through
  root-only verbs that read pinned maps and files; there is no connection table, no byte counting,
  no dedupe: a chatty program produces a journal line per connect(); the Python client `snitch`
  still speaks Little Snitch's protocol (ws://127.0.0.1:3031/stream) and Little Snitch is retired
  on the VM, so the TUI shows nothing.
- **What should change**: snitchd serves a JSON-lines API over a unix socket in its runtime
  directory, readable by the desktop user: a stream of connection events with program, destination,
  verdict and rule, deduplicated (one entry per program/destination/port/proto within a window, with
  counts); a connection table and per-socket byte counting (cgroup skb programs keyed by socket
  cookie) so an egress graph (program -> destination, bytes, rate) can be drawn; the daemon's facts
  (status, mode, trial, rules summary, learned observations) over the same socket; rule edits from
  the TUI into a local overlay file the daemon merges, and the trial verbs, for root and the
  operator's user only; nothing on the API can touch the kill switch or enter enforce outside the
  trial flow (fail-safes). The shapes are flat JSON lines carrying the fields the Python TUI
  consumes today, so the bubbletea TUI can be built against them.

Decisions taken before the requirements (research.md): flat JSON lines, not Little Snitch's tree
protocol; writes for root and the operator uid (trial verbs, rule edits), read-only for everyone
else; TUI rule edits into a local overlay file merged by the daemon; byte counting in scope with
an early feasibility gate.

## Introduction

snitchd runs as a service and decides in the kernel, but everything it knows leaves it only as
journal lines, and everything the operator can ask it needs root. The TUI, the popups and the
tray that come next all need one thing: a local channel where a desktop user can read what the
daemon sees (connections, verdicts, rules, bytes) and, as the operator, do the few things the
command line allows today (a bounded trial, an allow or deny for a program and a destination).
This feature adds that channel as a unix socket speaking one JSON object per line, adds the
state behind it (a deduplicated event stream, a connection table with byte counts), and keeps
every fail-safe: the kernel never waits for the API, and the API cannot enter enforce except
through the existing trial flow.

## Boundary Context

- **In scope**: the socket, who may connect and what each may do; the event stream and its
  dedupe; the connection table and per-connection byte counts with rates; the daemon's facts over
  the socket; the trial verbs and rule edits over the socket for authorized users; the local
  overlay rules file and its precedence; the documented wire schema with examples; tests without
  root for the protocol and a verification on the dev VM.
- **Out of scope**: the bubbletea TUI, the popups and the tray (they consume this API, next
  specs); an adapter that makes the Python client speak this API (the Python client is retired
  when the TUI reaches parity); rules by domain name (DNS tap spec); the process trace behind a
  popup beyond pid, parent pid and executable (process-trace spec); Velociraptor and OpenObserve
  export (they will read the same stream later); inbound traffic; byte counts received (egress
  only: bytes sent are counted, bytes received are reported as unknown).
- **Adjacent expectations**: the deployed service and its units (deploy-service) carry the
  socket's directory; the runtime directory's mode changes from private to traversable so the
  socket is reachable, while the status file stays private; the rules model (rule-loading) gains
  a second file with precedence but no new rule fields; the trial flow (persistent-trial) is
  reused unchanged, the API only calls what the verbs do.

## Requirements

### Requirement 1: One local channel, open to the desktop user
**Objective:** As the operator, I want a local socket the TUI can read without root, so that the
desktop tools show what the daemon sees while the daemon keeps its privileges to itself.

#### Acceptance Criteria
1. While the daemon runs, the daemon shall serve the API on one unix socket inside its runtime
   directory, and any local user shall be able to connect and read.
2. When the daemon stops or dies, the socket shall disappear with it, so that a client's connect
   fails instead of hanging and "daemon not running" is the connect error.
3. When a client connects, the daemon shall learn the client's user from the kernel's peer
   credentials and shall treat root and the configured operator user as writers and every other
   user as a reader.
4. If a reader sends a write request, the daemon shall refuse it with an error naming the request
   and the reason, and shall keep the connection open.
5. The daemon shall accept several clients at once and shall serve each independently; a client's
   disconnect shall not affect the others.
6. If a client stops reading, the daemon shall drop that client's pending messages after a bounded
   backlog, shall count the drops, shall tell the client how many were dropped on the next message
   it manages to send, and shall close the client after a bounded time without progress; at no
   time shall a slow or stuck client delay the kernel's decisions, the heartbeat or the event
   processing.
7. The API shall be one JSON object per line in both directions, each message with a type; a
   request may carry an id that its reply echoes, and unsolicited messages (events) shall be
   distinguishable from replies.
8. If a client sends a line that is not valid JSON, an unknown type, or a request with missing
   fields, the daemon shall answer with an error naming the problem and shall keep the connection
   open; a line longer than a documented limit shall be rejected the same way.
9. The daemon shall start without the API when asked to (a flag), and a failure to create the
   socket shall be logged and shall not stop the daemon from protecting the host.

### Requirement 2: The connection stream, deduplicated
**Objective:** As the operator, I want to see connections as they happen, one line per thing that
matters rather than one per packet of noise, so that the overview and the popups stay readable.

#### Acceptance Criteria
1. When a client subscribes to events, the daemon shall send every decision the kernel reports
   from that moment on, within one second of the decision, as a connection event carrying: the
   time, the program name (or unknown), the executable path, pid, parent pid and command name,
   the destination address, port and protocol, the verdict, the rule id and rule note when a
   rule decided, and whether the decision was a connect or an unconnected send.
2. The daemon shall deduplicate events: a decision with the same program, destination address,
   port, protocol and verdict as one already sent within a window shall not produce a new event
   but shall update that entry's count and last-seen time, visible in the next periodic summary
   or on request; the window shall be documented and short enough that a changed verdict (a rule
   edit, a trial start) shows within it.
3. When a client subscribes, it shall be able to exclude local-network decisions (loopback,
   RFC 1918, link-local), which are allowed in the kernel and are noise in the overview, and the
   default for a subscription shall be documented.
4. While a client is subscribed, the daemon shall send a periodic summary of what changed since
   the last one (new or updated connection entries with counts, bytes and last-seen) at a
   documented interval, so that a client can render without processing every event.
5. When a client asks for a snapshot, the daemon shall send the current connection table in full
   (every entry with its counts, first and last seen, bytes and rate), so that a client recovers
   after drops or after a restart without replaying events.
6. The event and entry shapes shall carry the field names the Python client's views use where
   they map (bytes sent, last allowed, last blocked, allow and deny counts, program path and
   name, remote address and port, protocol, verdict), so that the TUI author reads one schema.

### Requirement 3: The connection table and the egress graph
**Objective:** As the operator, I want to know which program sends how much to where, so that the
egress graph of the Python client comes back with real numbers behind it.

#### Acceptance Criteria
1. The daemon shall keep a connection table of (program, destination address, port, protocol)
   entries with: allow count, deny count, first seen, last seen, last allowed, last blocked,
   bytes sent, and a rate over a documented recent interval.
2. When a connection the kernel decided sends data, the bytes shall be attributed to that
   connection's entry, and a client reading the table or the periodic summary shall see the
   total grow within five seconds.
3. The daemon shall count bytes without ever deciding: the counting program shall allow every
   packet it sees, and a failure to install or run the counting shall be logged and shall leave
   the firewall's decisions, heartbeat and events unaffected (the table then shows bytes as
   unknown).
4. If bytes are observed for a connection the daemon did not see decided (a socket older than the
   daemon, or counted before its event arrived), the daemon shall attribute them to an "unknown
   program" entry rather than dropping them, so that totals stay honest.
5. The table shall support the time windows the Python client offers (15 minutes, 30 minutes,
   1 hour, 24 hours, 7 days): a client shall be able to ask for the entries active within a
   window with the counts and bytes of that window, and entries idle beyond the longest window
   shall be forgotten.
6. The table shall be bounded: a documented maximum number of entries, with the least recently
   seen evicted first and the eviction counted and visible in the facts, so that a port scan or a
   retry storm cannot grow the daemon without limit.
7. A feasibility gate shall come first: the counting mechanism shall be proven on the dev VM's
   kernel (the program loads and attaches, a connection's bytes appear in the table) before the
   rest of the counting work; if it fails, the spec records why and the table ships with bytes
   unknown.

### Requirement 4: The daemon's facts without root
**Objective:** As the operator, I want everything `snitchd status` knows available to the TUI, so
that the tray and the status bar need neither root nor the status file.

#### Acceptance Criteria
1. When a client asks for the status, the daemon shall answer with the same facts the status
   verb prints (running, mode and its source, trial deadline, kept, kill switch, learning, rules
   summary, version) plus the API's own counters (clients, drops, table size, evictions) and the
   daemon's start time and pid; the status file's age and the heartbeat age have no meaning
   in-process (the daemon answering is the proof of life) and are not carried.
2. When a client asks for the rules, the daemon shall list the effective rules with program, to,
   protocol, port, verdict, note, id, and the file each came from (the deployed file or the local
   overlay), in the precedence order the kernel uses.
3. When a client asks for the programs, the daemon shall list the declared programs with their
   paths, whether each resolved, and the executables mapped.
4. When a client asks for the learned observations while learning is on, the daemon shall list
   them (program or executable, destination, protocol, port, count, first and last seen) without
   touching the learned file's write cycle; when learning is off, it shall say so.
5. While a client is subscribed, when the mode, the trial state, the kept state or the rules
   change, the daemon shall send a state event within two seconds, so that the tray updates
   without polling.
6. The daemon shall answer a status request within 100 ms on the dev VM under normal load, and
   every read request shall be answerable without root on the client side.

### Requirement 5: Writes for the operator, within the fail-safes
**Objective:** As the operator at the desktop, I want to start a bounded trial and allow or deny a
program's destination from the TUI, so that the `x` key and the trial button of the Python client
come back, without a new way into enforce.

#### Acceptance Criteria
1. When a writer requests a trial, keep, unkeep or end, the daemon shall apply exactly what the
   corresponding verb does, with the same bounds (1 to 60 minutes, default 10), the same
   refusals (kill set, learning, already running without extend, nothing to keep) and the same
   boot revert, and shall answer with the same outcome text.
2. When a writer requests a rule edit (allow or deny a declared program or any program to an
   address or prefix, optionally port and protocol, with a note), the daemon shall write it to the
   local overlay rules file, and the kernel shall apply it within five seconds, visible in the
   effective rules with its source.
3. When a writer requests the removal of an overlay rule by id, the daemon shall remove it from
   the overlay file and the kernel shall stop applying it within five seconds; rules from the
   deployed file shall not be removable over the API (the answer names the file to edit).
4. The local overlay file shall use the same format as the rules file, shall take precedence over
   the deployed file for the same key, shall survive a deploy of the deployed file, and shall be
   validated like the rules file (an invalid overlay keeps the previous rules and is reported in
   the facts).
5. Every write over the API shall be logged in the journal with the requesting user, the request
   and the outcome.
6. The API shall offer no request that writes the kill switch, the control map, the trial or kept
   files directly, changes the mode outside the trial flow, or edits the deployed rules file; a
   reader's or writer's attempt at anything else shall be an error.
7. If the overlay file cannot be written (disk, permission), the daemon shall answer with the
   error and shall leave the effective rules unchanged.

### Requirement 6: Schema, tests and verification
**Objective:** As the TUI author, I want the wire schema written down with examples and proven
against the daemon, so that the TUI is built against a contract, not a reading of Go code.

#### Acceptance Criteria
1. The repository shall carry a schema document listing every message type in both directions
   with one example each, the authorization each needs, the dedupe window, the summary interval,
   the backlog limit, the line limit and the time windows.
2. The protocol shall be tested without root: parsing, authorization decisions by peer user,
   dedupe, table windows and eviction, drop accounting, and every error reply, each with a test.
3. The daemon's own tests shall prove that a blocked client never delays the event processing
   (the pump keeps consuming while a client's backlog is full).
4. A verification on the dev VM shall show, with a plain socket client as the desktop user: a
   status reply, a subscription receiving events for a probe connection within one second, bytes
   growing for a download, a rule edit refused for the reader and applied for the operator (with
   the kernel decision changing accordingly in monitor mode, visible as the verdict in the event),
   and the trial verbs refused for a non-operator user; the daemon runs throughout (the same
   pid answers before and after, and its decisions keep flowing as events).
5. The verification shall include the client-side command lines in the schema document, so that
   the next spec's author can repeat them.
