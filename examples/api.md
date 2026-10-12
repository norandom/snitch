# The snitchd API

`snitchd` listens on a unix socket, `/run/snitch/api.sock`, and speaks JSON lines: one object
per line in both directions. Any local user reads; root and the operator write. The bubbletea
TUI, the popups and the tray are built against this document, not against the Go code; the
source of truth for the shapes is `internal/api/types.go`, and `scripts/api-check.sh` proves
the document against a running daemon.

Every example below is one line on the wire. Long ones are shown wrapped for reading; the
daemon never wraps and never pretty-prints.

## Connecting

* Socket: `/run/snitch/api.sock`, mode 0666 in a 0755 directory (the unit's
  `RuntimeDirectoryMode=0755`; the status file next to it stays 0600). `-api <path>` moves it,
  `-api ""` turns the API off; the daemon runs without it when the socket cannot be created
  (one `api off:` line in the journal, the kernel side is unaffected).
* This VM's `nc` is netcat-traditional and has no `-U`, so the check script and these notes use
  python3. The snippet sends one request line (argument 1) and prints every line the daemon
  sends for N seconds (argument 2): a `status` round trip, or a subscription you watch.

```sh
python3 - '{"type":"status","id":1}' 1 <<'PY'
import socket, sys, time
req, secs = sys.argv[1], float(sys.argv[2])
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect("/run/snitch/api.sock")
s.sendall(req.encode() + b"\n")
s.settimeout(0.2)
end, buf = time.monotonic() + secs, b""
while time.monotonic() < end:
    try:
        chunk = s.recv(65536)
    except socket.timeout:
        continue
    if not chunk:
        break
    buf += chunk
    while b"\n" in buf:
        line, buf = buf.split(b"\n", 1)
        print(line.decode())
PY
```

A subscription for ten seconds: `python3 - '{"type":"subscribe","id":1}' 10 <<'PY' ... PY`
with the same body; run `curl https://9.9.9.9/` from another shell meanwhile and the event
shows up. On a host with `socat` the same thing is one line:

```sh
printf '%s\n' '{"type":"status","id":1}' | socat -t 1 - UNIX-CONNECT:/run/snitch/api.sock
printf '%s\n' '{"type":"subscribe","id":1}' | socat -t 10 - UNIX-CONNECT:/run/snitch/api.sock
```

## Envelope

Every line is one JSON object with a `type`. A request carries an `id` greater than 0; the
daemon answers every request line with exactly one `reply` or `error` carrying the same `id`.
Unsolicited lines (`event`, `summary`, `state`, `dropped`) carry `id: 0`. An `error` for a line
that was not JSON carries `id: 0` too, because there was no id to echo.

```json
{"type": "status", "id": 1}
```

```json
{"type": "reply", "id": 1, "ok": true}
```

```json
{"type": "error", "id": 1, "error": "unknown type: stats"}
```

A reply's payload fields depend on the request type (below); `ok` is always true on a reply.
Empty lists are omitted (`rules`, `programs`, `learned`, `entries`): a missing list means none.
Times are RFC 3339 in UTC (`2026-10-11T12:00:01Z`; an event's `time` may carry a fractional
second of up to nine digits, absent at whole seconds, so parse it with an RFC 3339 parser,
not a fixed format); an
unset time is `""`. The `cookie` of an event is a 64-bit unsigned integer and can exceed 2^53:
parse it as an integer, not a double.

Errors every request can get:

| `error` | when |
|---|---|
| `bad json: ...` (`id` 0) | the line did not parse |
| `line longer than 65536 bytes (65536 allowed)` (`id` 0) | the line was over the limit; the rest of it is discarded and the connection stays open |
| `missing field: type` | no `type` |
| `unknown type: <t>` | a type not in the list below |
| `missing field: <name>` | a required field of that type is absent (named in the request sections) |
| `<type>: write requires the operator` | a write from a reader (see Authorization) |
| `<type>: not available` | the daemon has no backend for the verb (a daemon started without the part the verb needs) |
| `too many clients` (`id` 0, then the connection is closed) | the 65th client |

## Authorization

The role is decided once per connection from the peer's credentials (`SO_PEERCRED`):

* **reader**: every local user. `status`, `rules`, `programs`, `learned`, `snapshot`,
  `subscribe`, `unsubscribe`.
* **writer**: uid 0, and the one user named in `/etc/snitch/operator`. Everything a reader
  has, plus `trial`, `keep`, `unkeep`, `end`, `rule.add`, `rule.remove`.

A write from a reader is refused with `<type>: write requires the operator`, for example
`trial: write requires the operator`; nothing is changed, and the refusal is journaled with the
uid like an accepted write.

`/etc/snitch/operator` holds one user name on its first line (the VM repo deploys it with the
desktop user). The daemon reads it when it starts and again when the file changes, with the
same two-second stamp as the rules file. Like a sudoers file, it must be a regular file owned
by root and not writable by group or others (0644 is right); otherwise it is ignored with one
journal line, `operator file /etc/snitch/operator ignored: mode 0664 is writable by group or
others`, and root alone writes. No file means the same. A connection keeps the role it was
given; reconnect after the file changes.

Every write, accepted or refused by its backend, leaves one journal line with the caller's uid,
the request and the outcome: `api: trial by uid 1000 {"type":"trial","id":8,"duration":"10m"}
-> ok: enforce until ...` or `-> error: ...`. A write a reader attempted is journaled too:
`api: rule.add by uid 1000 refused: write requires the operator`.

## Requests

The thirteen request types. Each shows one request and one reply.

### status

The daemon's facts, from memory (nothing waits on a file). `source` is `files` for a daemon
that follows the trial and kept files under `/var/lib/snitch` (the service) and `flag` for one
started with `-mode`, which then reports `trial: ""` and `kept: false` whatever the files say.
`trial` is the deadline of the running trial or `""`. `rulesError` is `""` or the last failed
reload as `<time>: <error>` (the error alone when the overlay was already invalid at startup).
`counting` says whether the byte counter attached. `clients`, `dropped`, `entries` and
`evictions` are the API's own counters (drops and evictions over the daemon's life).

```json
{"type": "status", "id": 1}
```

```json
{"type": "reply", "id": 1, "ok": true, "status": {
  "running": true, "pid": 1234, "version": "v0.4.0", "mode": "monitor", "source": "files",
  "trial": "", "kept": false, "kill": false, "learning": false,
  "rules": {"programs": 18, "resolved": 12, "executables": 15, "rules": 13,
            "file": "/etc/snitch/rules.toml", "overlay": "/etc/snitch/rules.d/local.toml"},
  "rulesError": "", "clients": 1, "dropped": 0, "entries": 42, "evictions": 0,
  "started": "2026-10-11T06:00:00Z", "counting": true,
  "dns": {"on": true, "seen": 120, "ignored": 2, "entries": 30,
          "names": 35, "compiled": 12, "evictions": 0}}}
```

`dns` reports the tap separately from the API counters. It is absent only on older daemons.
`on` says whether the tap is attached. Optional `reason` is `flag` (`-dns=false`) or the load or
attach error when the tap is off; with the tap on it is `no resolvers` when the resolver list is
empty or unreadable (the tap trusts no resolver and learns nothing until the file changes) or
`stats: <error>` when the counters could not be read.
`seen` counts answers seen and `ignored` rejected answers over the daemon's life; `entries`
counts cached addresses, `names` their live names, `compiled` live compiled allow entries,
and `evictions` address evictions (discarding a fifth name does not increment it).
An off tap retains address rules and reports its counters and sizes as zero:

```json
{"type": "reply", "id": 1, "ok": true, "status": {
  "running": true, "pid": 1234, "version": "v0.4.0", "mode": "monitor", "source": "files",
  "trial": "", "kept": false, "kill": false, "learning": false,
  "rules": {"programs": 18, "resolved": 12, "executables": 15, "rules": 13,
            "file": "/etc/snitch/rules.toml", "overlay": "/etc/snitch/rules.d/local.toml"},
  "rulesError": "", "clients": 1, "dropped": 0, "entries": 42, "evictions": 0,
  "started": "2026-10-11T06:00:00Z", "counting": true,
  "dns": {"on": false, "reason": "flag", "seen": 0, "ignored": 0, "entries": 0,
          "names": 0, "compiled": 0, "evictions": 0}}}
```

### rules

The effective rules in file order, base first, overlay after it, each with the file it came
from. `port` is the rule's single port, or 0 for any; a port-range rule (`port = "8000-8010"`
in the file) is reported with `port: 0` as well, since the view has one integer. `protocol` is
`tcp`, `udp` or `""` for any. `id` is dense in merged order and changes on every reload: it
names a rule in an event, never in a `rule.remove`. A name rule's `to` is the name as written
(`"github.com"`), whatever the number of addresses it currently matches.

```json
{"type": "rules", "id": 2}
```

```json
{"type": "reply", "id": 2, "ok": true, "rules": [
  {"id": 1, "program": "curl", "to": "1.1.1.1/32", "protocol": "tcp", "port": 443,
   "verdict": "allow", "note": "the enforce test's allowed address", "source": "/etc/snitch/rules.toml"},
  {"id": 2, "program": "any", "to": "203.0.113.0/24", "protocol": "", "port": 0,
   "verdict": "deny", "note": "TEST-NET-3", "source": "/etc/snitch/rules.toml"},
  {"id": 3, "program": "curl", "to": "9.9.9.9/32", "protocol": "tcp", "port": 443,
   "verdict": "deny", "note": "api check", "source": "/etc/snitch/rules.d/local.toml"}]}
```

### programs

The declared programs with their resolution state: `resolved` when at least one executable
maps to the program, `executables` how many do.

```json
{"type": "programs", "id": 3}
```

```json
{"type": "reply", "id": 3, "ok": true, "programs": [
  {"name": "curl", "paths": ["/usr/bin/curl"], "resolved": true, "executables": 1,
   "source": "/etc/snitch/rules.toml"},
  {"name": "claude", "paths": ["/home/*/.local/share/claude/versions/*"], "resolved": true,
   "executables": 2, "source": "/etc/snitch/rules.toml"}]}
```

### learned

The learned destinations of a daemon running with `-learn` (the same records `-learned` writes,
without touching its write cycle). Without learning the reply says so: `learning` is omitted
(false) and `text` is `learning is off`.

```json
{"type": "learned", "id": 4}
```

```json
{"type": "reply", "id": 4, "ok": true, "learning": true, "learned": [
  {"program": "curl", "path": "/usr/bin/curl", "addr": "9.9.9.9", "protocol": "tcp",
   "port": 443, "count": 3, "first": "2026-10-11T11:58:02Z", "last": "2026-10-11T12:00:01Z"}]}
```

```json
{"type": "reply", "id": 4, "ok": true, "text": "learning is off"}
```

A learned observation carries optional `name` too. Learning by name retains the name
instead of an address, so its always-present `addr` is `""`:

```json
{"type": "reply", "id": 4, "ok": true, "learning": true, "learned": [
  {"program": "curl", "path": "/usr/bin/curl", "addr": "", "name": "www.example.org",
   "protocol": "tcp", "port": 443, "count": 3,
   "first": "2026-10-11T11:58:02Z", "last": "2026-10-11T12:00:01Z"}]}
```

### snapshot

The connection table over a time window. `window` is required (no default): one of `15m`,
`30m`, `1h`, `24h`, `7d`; anything else is `unknown window 5m: want one of 15m, 30m, 1h, 24h,
7d`, nothing is `missing field: window`. The reply is served from a cache the summary pass
refreshes every 2 s, so a client in a request loop never holds the table's lock. Entries with
no activity in the window are left out; the counts and bytes in an entry are all-time totals,
`rate` is bytes per second over the last 10 s, `verdict` the last verdict seen.

```json
{"type": "snapshot", "id": 5, "window": "15m"}
```

```json
{"type": "reply", "id": 5, "ok": true, "window": "15m", "entries": [
  {"program": "curl", "path": "/usr/bin/curl", "addr": "1.1.1.1", "name": "www.example.org",
   "port": 443, "protocol": "tcp", "allowCount": 3, "denyCount": 0, "firstSeen": "2026-10-11T11:58:02Z",
   "lastSeen": "2026-10-11T12:00:01Z", "lastAllowed": "2026-10-11T12:00:01Z", "lastBlocked": "",
   "bytesSent": 184320, "rate": 512.5, "verdict": "allow-monitor"},
  {"program": "unknown", "path": "", "addr": "", "port": 0, "protocol": "",
   "allowCount": 0, "denyCount": 0, "firstSeen": "2026-10-11T06:00:04Z",
   "lastSeen": "2026-10-11T11:59:58Z", "lastAllowed": "", "lastBlocked": "",
   "bytesSent": 9216, "rate": 0, "verdict": ""}]}
```

Entries carry optional `name`, with the same meaning as an event; the address stays the
table key even when its name changes.

The second entry is the `unknown` bucket: bytes of sockets the daemon never saw connect
(older than the daemon, or counted before their event arrived and left unclaimed after two
sweeps). It has no path and no address, so it never collides with an unmapped executable's
entry, which carries its path.

### subscribe

Turns the unsolicited stream on for this connection. Three options, each optional: `events`
(default true: `event` lines), `local` (default false: events with verdict `allow-local`, the
local network, are filtered out unless asked for), `summary` (default true: a `summary` line
every 2 s when something changed). A second `subscribe` replaces the options. `state` lines go
to every connection with at least one option on.

```json
{"type": "subscribe", "id": 6, "events": true, "local": false, "summary": true}
```

```json
{"type": "reply", "id": 6, "ok": true}
```

### unsubscribe

Turns the stream off; the connection stays open for requests.

```json
{"type": "unsubscribe", "id": 7}
```

```json
{"type": "reply", "id": 7, "ok": true}
```

### trial, keep, unkeep, end

The four verbs of `snitchd trial | keep | unkeep | end`, through the same seam, with the same
refusals: the daemon answers with the same text the command-line verb prints, as `text` (two
lines joined with `\n` where the verb prints two). Show `text` to the user; do not parse it.

`trial` needs `duration` (Go syntax, `1m` to `1h`, the verb's default of 10 min does not apply
here); `extend` moves a running trial's deadline; `yes` is the answer to the question the
daemon asks when no rules are loaded (the error text is the question; send the request again
with `"yes": true` to confirm). The verb's refusals come back as `error`: a trial already
running, enforce already kept, the kill switch set, learning on, a daemon started with `-mode`
(`the daemon runs with -mode, it does not follow trial files`), a duration out of bounds
(`trial duration 2h0m0s: must be between 1m0s and 1h0m0s`).

```json
{"type": "trial", "id": 8, "duration": "10m", "extend": false, "yes": false}
```

```json
{"type": "reply", "id": 8, "ok": true, "text": "enforce until 2026-10-11T14:12:00+02:00 (10m0s); end early: snitchd end\ntrial file: /var/lib/snitch/trial"}
```

```json
{"type": "error", "id": 8, "error": "No rules are loaded: every connection outside the local network will be denied for 10m0s. Start the trial? [y/N]"}
```

```json
{"type": "keep", "id": 9}
```

```json
{"type": "reply", "id": 9, "ok": true, "text": "enforce kept: /var/lib/snitch/enforce\nthe way back: rm /var/lib/snitch/enforce (or: snitchd unkeep, snitchd end, scripts/fail-open.sh)"}
```

```json
{"type": "unkeep", "id": 10}
```

```json
{"type": "reply", "id": 10, "ok": true, "text": "enforce unkept: /var/lib/snitch/enforce removed (monitor within 5 s)"}
```

```json
{"type": "end", "id": 11}
```

```json
{"type": "reply", "id": 11, "ok": true, "text": "trial ended: /var/lib/snitch/trial removed (monitor within 5 s)"}
```

`keep` outside a trial is `enforce can only be kept during a trial (snitchd trial starts one)`;
`unkeep` with nothing kept and `end` with nothing to end are replies, not errors (`nothing was
kept`, `already monitor: no trial, nothing kept`). The mode change itself arrives as a `state`
line a moment later (the daemon follows the files every 2 s).

### rule.add

Writes one rule into the overlay (`/etc/snitch/rules.d/local.toml`, see The overlay). Required:
`program` or `path`, `to`, `verdict`; optional `proto` (`tcp`, `udp`, default any), `port`
(default any), `note`. `program` names a program the effective rules declare; `path` is an
executable's absolute path instead, for a program nobody declared: the overlay then declares
one named after the path's base name (a suffix on collision). A path whose executable is
already mapped to a program is refused with `executable is program curl: use that name`. The
overlay is loaded, the rule appended, the union with the base validated (an invalid result is
refused and the file untouched) and written; the daemon's reload picks it up within 2 s and
every subscriber gets a `state` line with `rulesChanged: true`. `text` is the daemon's outcome
sentence (`rule added: <program> to <to> [proto] [port N] <verdict> (applies within 5 s)`); show
it, do not parse it. A missing one answers `missing field: program or path`, `missing field: to` or
`missing field: verdict`.

```json
{"type": "rule.add", "id": 12, "program": "curl", "to": "9.9.9.9/32", "proto": "tcp", "port": 443, "verdict": "deny", "note": "api check"}
```

```json
{"type": "reply", "id": 12, "ok": true, "text": "rule added: curl to 9.9.9.9/32 tcp port 443 deny (applies within 5 s)"}
```

`to` accepts an address, prefix or domain name. A name covers its subdomains and is allow
only; the grammar and shared-address semantics are in `examples/rules.toml`. Invalid values
are refused with `to %q: not an address, prefix or domain name`; a deny by name is refused
with `to %q: a deny by name is not supported (deny stays a timed trial)` (`%q` is the quoted
value). Neither refusal changes the overlay.

```json
{"type": "rule.add", "id": 12, "program": "curl", "to": "example.org", "verdict": "allow"}
```

```json
{"type": "reply", "id": 12, "ok": true, "text": "rule added: curl to example.org allow (applies within 5 s)"}
```

### rule.remove

Removes one overlay rule by its key: `program`, `to`, and `proto` and `port` as they were
added (`proto` absent or `any` and `port` absent or 0 mean the any-proto, any-port rule).
Required: `program`, `to`. A rule that lives in the deployed file is refused with the file to
edit (`edit /etc/snitch/rules.toml`); ids are never used, they change on every reload.
`to` accepts a domain name too, with the same invalid-destination refusal as `rule.add`.

```json
{"type": "rule.remove", "id": 13, "program": "curl", "to": "9.9.9.9/32", "proto": "tcp", "port": 443}
```

```json
{"type": "reply", "id": 13, "ok": true, "text": "rule removed: curl to 9.9.9.9/32 tcp port 443 (applies within 5 s)"}
```

```json
{"type": "rule.remove", "id": 13, "program": "curl", "to": "example.org"}
```

```json
{"type": "reply", "id": 13, "ok": true, "text": "rule removed: curl to example.org (applies within 5 s)"}
```

## Unsolicited lines

All carry `id: 0` and arrive only on a subscribed connection, interleaved with replies.

### event

One kernel decision, after dedupe (below). `program` is the configured name, or `unknown` for
an executable no program claims; `path` is the executable (what the kernel wrote for unknown
programs, else one `/proc` lookup, else `""`). `rule` is the rule behind the verdict or `null`.
`hook` is `connect` (TCP connect, UDP connect) or `sendmsg` (an unconnected UDP send). `cookie`
is the socket's cookie, the key the byte counter uses.

Optional `name` on an event, entry or observation is the name through which a compiled rule
matched, else the most recently learned name for the address; it is absent for an unknown
address. Names record this host's lookups, not a particular process's lookups: events with
names are readable by every local user, like addresses. The cache starts empty at daemon start
and is not persisted; TCP 53, DoH, DoT and `/etc/hosts` do not populate it.

```json
{"type": "event", "id": 0, "time": "2026-10-11T12:00:01.123456789Z", "program": "curl", "path": "/usr/bin/curl", "pid": 4242, "ppid": 4100, "comm": "curl", "addr": "1.1.1.1", "name": "www.example.org", "port": 443, "protocol": "tcp", "verdict": "allow-monitor", "rule": null, "hook": "connect", "cookie": 18446744073709551615}
```

```json
{"type": "event", "id": 0, "time": "2026-10-11T12:00:05.5Z", "program": "unknown", "path": "/usr/bin/dig", "pid": 4250, "ppid": 4100, "comm": "dig", "addr": "2620:fe::fe", "port": 53, "protocol": "udp", "verdict": "deny-rule", "rule": {"id": 3, "note": "api check", "source": "/etc/snitch/rules.d/local.toml"}, "hook": "sendmsg", "cookie": 9007199254740993}
```

The seven verdicts:

| `verdict` | meaning | `rule` |
|---|---|---|
| `allow-local` | the destination is on the local network: allowed in the kernel program, no rule can change it (filtered out unless `local` was subscribed) | null |
| `allow-rule` | an allow rule matched | set |
| `deny-rule` | a deny rule matched; denied in monitor mode too | set |
| `allow-monitor` | no rule matched, monitor mode: allowed and reported | null |
| `deny-default` | no rule matched, enforce mode (a trial or kept enforce): denied | null |
| `allow-stale` | the daemon's heartbeat is stale: the kernel allows everything (fail-safe 3) | null |
| `allow-kill` | the kill switch is set: the kernel allows everything (fail-safe 4) | null |

### summary

Every 2 s, the table rows that changed since the last summary (the same `Entry` shape as a
snapshot); nothing changed, nothing sent. `since` is the previous summary's time. A `dropped`
field exists in the shape for a future count and is omitted today: drops travel as the
`dropped` line.

```json
{"type": "summary", "id": 0, "since": "2026-10-11T12:00:00Z", "entries": [
  {"program": "curl", "path": "/usr/bin/curl", "addr": "9.9.9.9", "port": 443, "protocol": "tcp",
   "allowCount": 4, "denyCount": 0, "firstSeen": "2026-10-11T11:58:02Z",
   "lastSeen": "2026-10-11T12:00:01Z", "lastAllowed": "2026-10-11T12:00:01Z", "lastBlocked": "",
   "bytesSent": 185344, "rate": 102.4, "verdict": "allow-monitor"}]}
```

### state

A mode, trial or rules change, to every subscribed connection. `mode` is `monitor` or
`enforce`; `trial` the deadline (RFC 3339, UTC) or `""`; `kept` whether enforce is kept;
`rulesChanged` true when the line announces a reload (`reason: "rules reloaded"`, the mode
unchanged). The reasons a mode change carries are the daemon's own log reasons: `trial until
<deadline>`, `trial ended at its deadline`, `trial ended at boot`, `trial ended by the
operator: file removed`, `enforce kept`, `enforce unkept: file removed`, `trial file
unreadable: ..., removed`. For a trial that ended, the spent file is cleared first, so the line
carries `trial: ""` and the reason names how it ended.

```json
{"type": "state", "id": 0, "mode": "enforce", "trial": "2026-10-11T12:10:00Z", "kept": false, "rulesChanged": false, "reason": "trial until 2026-10-11T14:10:00+02:00"}
```

```json
{"type": "state", "id": 0, "mode": "monitor", "trial": "", "kept": false, "rulesChanged": true, "reason": "rules reloaded"}
```

### dropped

A client that does not read fast enough loses messages instead of slowing the daemon: each
connection has a queue of 1024 messages, and what does not fit is dropped and counted. The
count arrives as its own line before the next message that is delivered, then resets. A
client that sees one should request a `snapshot` to resync.

```json
{"type": "dropped", "id": 0, "count": 17}
```

## Field names against the Python client

The Python client (`snitch` in the repository root) reads Little Snitch's web UI shapes. Where
a field maps, the API keeps the name, so the TUI's views port field for field:

| Little Snitch (Python client) | API | note |
|---|---|---|
| `statistics.bytesSent` | `bytesSent` | all-time bytes of the entry |
| `statistics.lastAllowed` | `lastAllowed` | RFC 3339 here, epoch there |
| `statistics.lastBlocked` | `lastBlocked` | RFC 3339 here |
| `statistics.deepAllowCount` | `allowCount` | |
| `statistics.deepDenyCount` | `denyCount` | |
| `primaryExecutable` | `path` | the executable; `program` is its configured name |
| `ipAddress` | `addr` | |
| `port`, `protocol` | `port`, `protocol` | `protocol` is `tcp` / `udp` |
| `statistics.bytesReceived` | none | egress only (fail-safe 1) |
| `viaExecutable` | none | the process trace comes with the popups spec |
| `remoteName` | `name` | optional; matched rule name, else the most recently learned name |

## Limits and timing

| what | value |
|---|---|
| request line | 64 KiB inclusive (65536 bytes); a longer line is an error and discarded, the connection stays |
| queue per client | 1024 messages; what does not fit is dropped and reported with a `dropped` line |
| write deadline | 5 s; a client slower than that is closed |
| clients | 64; the 65th gets `too many clients` and is closed |
| event dedupe | 10 s: the same key (program or path, address, port, protocol) with the same verdict is sent once per 10 s, counted every time; a verdict change is sent at once. The anchor is the last event sent, so a steady stream re-emits once per window |
| summary | every 2 s, only the rows that changed; the same pass refreshes the snapshot caches |
| windows | `15m`, `30m`, `1h`, `24h`, `7d`, summed from minute buckets (up to 1 h) or hour buckets (beyond); bucket-aligned: the oldest partial bucket is excluded, so `15m` covers 14 to 15 minutes of wall time and `24h` 23 to 24 hours |
| rate | bytes of the last 10 s divided by 10 |
| table | 4096 entries; one more evicts the entry seen longest ago and counts it in `evictions`; entries idle for 7 days are removed |
| cookies | a socket cookie idle for 10 min (no bytes, no event) is forgotten; its entry's totals stay |
| unknown bytes | bytes of a cookie the daemon never saw connect go to the `unknown` entry after two sweeps (4 s) |
| DNS cache | 8192 addresses x 4 names; host-wide, empty at daemon start |
| compiled name entries | 16384; file rules win capacity, compiled entries are evicted to make room |
| DNS TTL | clamped to 60 s..24 h; expired compiled entries are removed on the 2 s sweep |
| rules per exact name | 8 protocol/port combinations (`rules.NameSlots`); any-proto with a port counts twice, a port range counts per port |
| byte counting | per socket on egress, swept every 2 s; `counting: false` in `status` when the counter could not attach (bytes stay 0, everything else works) |

## The overlay

Rules written over the API go to `/etc/snitch/rules.d/local.toml` (`-overlay`; `-overlay ""`
means none). It has the rules file's format (`examples/rules.toml`), may name programs the
deployed file declares, and declares its own for executables added by `path`. The daemon
merges it over `/etc/snitch/rules.toml` on every load:

* **Precedence is per base rule, whole.** An overlay rule replaces every base rule whose
  expanded keys it touches: an any-proto overlay rule for a port removes the base's tcp and
  udp rules for that key alike, and an overlay rule for `curl -> 9.9.9.9/32` replaces a base
  rule for the same key entirely. Nothing residual is synthesised (no "base rule minus the
  overlay's part"): what you see in `rules`, with its `source`, is what the kernel has.
* **Remove by key, not by id.** `rule.remove` names `program`, `to`, `proto`, `port`; ids are
  dense in merged order and change on every reload. A rule from the deployed file is refused
  with `edit /etc/snitch/rules.toml`.
* **Port ranges** are reported with `port: 0` in `rules` (the view has one integer); the rule
  still applies to its range.
* **Invalid overlay.** At startup the daemon runs with the base alone and reports it in
  `status.rulesError`; on a reload the previous rules stay and `rulesError` is set until the
  next successful full reload. A write that would make the union invalid is refused and the
  file untouched.
* `snitchd check -rules F` validates the base alone; it does not merge the overlay.
