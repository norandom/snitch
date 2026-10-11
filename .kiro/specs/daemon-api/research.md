# Research & Design Decisions

## Discovery (2026-10-11, three parallel research passes before the requirements)

### 1. What the Python client consumes (`snitch`, repo root; Little Snitch's web protocol)

- Transport: websocket `ws://127.0.0.1:3031/stream`; server frames are JSON arrays of
  `{update: …}` objects, client frames `{action: …}`. No auth, no hello; state pushed on connect;
  reconnect after 3 s. The client opens up to four connections because tree expansion, filters
  and search are **server-side per-connection state** (overview, a hidden fully expanded
  "egress" connection, a `watch` connection filtered to denied rows, a one-shot rules connection).
- Updates: `clearConnectionRows`, `insertConnectionRows` (rows `{id, title, indentationLevel,
  isExpanded, isLeaf, isMoreItems, statistics{bytesSent, bytesReceived, lastAllowed, lastBlocked,
  deepAllowCount, deepDenyCount}}`, `afterId`), `removeConnectionRows`, `moveConnetionRows` (typo
  on the wire), `updateConnectionRows`, `updateRuleButtons` (`allowByDefault|denyByDefault|
  allowByRule|denyByRule`), `setConnectionsStatus` (filters), `globalSettings{filterDisabled}`,
  `setInspector` (`primaryExecutable, viaExecutable, remoteName{value,type}, ipAddress, port,
  protocol, isInbound, defaultAction, coveringRules, relatedRules`), `trafficEvents`
  (`{type: blocked, rowId}` per visible row on the path), `setRules`/`updateRules`.
- Actions: `toggleDisclosure`, `setConnectionsFilters` (`visiblePeriodLimit, direction, action,
  localnet, localhost`), `selectRow`, `toggleRule`, `setSearch`, `setSection rules`, `addRule`,
  `editRule`.
- Views: overview tree (process → host → address; columns rule flag, connection, last, down,
  up, ok/denied, rule), info pane, log pane, egress graph (top 10 senders, 5 destinations each,
  log bars, B/s since last refresh), popups (denied connection, process trace from /proc), keys
  `enter/left/x/space/t/1-9/s/S///e/q`, periods `15m 30m 1h 24h 7d`.
- Computed by the client: sort/rank, rates (delta of totals), egress flows (walking the hidden
  tree), dedupe of blocked events to one per connection, 10 s dedupe of log lines, popup snooze,
  `/proc` process trace. Received: tree order, windowed byte totals, counts, rule buttons.
- Identity: executable path (+ "via" launcher); rules keyed by free-text `notes`; protocol as a
  small bitmask (31 any, 6 tcp+udp, 4 udp); direction 1/2/3.
- Gaps snitchd will not replicate: inbound rows/rules, launcher ("via") attribution in rule keys,
  domain/host rules before the DNS tap, blocklists, port ranges, server-side tree state, byte
  windows before the counting exists, Little Snitch as the rule store.

### 2. The daemon today (cmd/snitchd, internal/*)

- Event pipeline: ringbuf → `decodeEvent` → `describe` → `fmt.Println`, plus the learning
  `sink` delegate for allowed events. One goroutine (`pump`), the only ringbuf reader; a fan-out
  must never block it. The `event` struct has pid, ppid, exe ino/dev, program id, addr, dport,
  family, proto, verdict (7 values), hook, comm, rule id, path[256]; no timestamp, no cookie,
  no bytes. Ringbuf 1 MiB ≈ 3200 records of burst; the kernel verdict never waits on user space.
- No connection table, counters or dedupe exist. `rules.Learned` is the only aggregation
  (write-to-file; its `File()` projection clears the dirty flag, an API read needs a side-effect
  free projection).
- Facts in memory: rules snapshot (atomic pointer), mode (atomic), trial store, version, pid,
  flags; the kill map is readable through the loaded objects. Everything `snitchd status` prints
  from pinned maps and 0700 files can be served by the daemon instead, so the TUI needs no root.
- Permissions: `/run/snitch` 0700 root (unit `RuntimeDirectoryMode=0700`, `status.writeAtomic`),
  `/var/lib/snitch` 0700, pinned maps root. No group or peer-credential model exists.
- Code shape: `daemon.go` 268/300, `ctl_verbs.go` 286, `main()` ≤ 60. `internal/api/` is the
  home named in `structure.md`; it may import `internal/{rules,status,trial,contract,jobs,bpf}`,
  never `cmd/`. Wiring in a new `cmd/snitchd/api.go`; the listener is one more `jobs.Job`.
- Event volume: no measurement; estimate single digits/s idle, 20–100 connects on a page load,
  DNS doubles it, retry storms hundreds/s. Local-net events are the quiet-mode candidate (a
  second control-flag bit).

### 3. Byte counting and the socket (verified against kernel source, this VM, cilium/ebpf v0.22)

- Socket cookie: the LSM program may call `bpf_get_socket_cookie(sock->sk)` (tracing proto,
  `bpf_get_socket_ptr_cookie`, in this kernel's BTF; merged in 5.12); `cgroup_skb/egress` calls
  `bpf_get_socket_cookie(skb)`; both use `sock_gen_cookie`, so the values match. Do not read
  `sk->sk_cookie` by hand (lazy allocation).
- Counting: `BPF_PROG_TYPE_CGROUP_SKB` at `BPF_CGROUP_INET_EGRESS` on the cgroup v2 root
  (`/sys/fs/cgroup`, pure v2 here, `bpftool feature probe` lists the type and the helpers);
  `skb->len` is L3 bytes per skb, TCP and UDP, retransmits included; the program always returns
  1 (counting only, never a verdict). `link.AttachCgroup` gives a real link on 7.2 (coexists with
  systemd's programs, detaches when the fd closes). LRU hash keyed by cookie, value
  `{bytes, pkts, last_ns}`, 65536 entries ≈ 2.6 MB worst case; user space joins cookie →
  (program, destination) from the connect event every 2 s and computes rates; unknown cookies
  are reported as "unknown program", not dropped. Limit: unconnected UDP counts per socket.
  Rejected: `sock_ops` (TCP only, no QUIC/DNS), kprobes on `*_sendmsg` (rate, symbol churn).
- Socket: `/run/snitch/api.sock` created by the daemon (not socket-activated: a dead daemon
  must mean "no API"), `RuntimeDirectoryMode=0755`, socket 0666, authorization by
  `SO_PEERCRED` (`x/sys/unix.GetsockoptUcred`, already a dependency): uid 0 and a configured
  operator uid get write verbs, everyone else read-only (Tailscale's `tailscaled.sock` model;
  Docker's group model rejected as a root-equivalent footgun). Protocol: newline-delimited JSON
  `{type, id, …}`, replies echo `id`, `subscribe` on the same connection, events `id 0`;
  per-client bounded queue (1024) with a `dropped` counter and a 5 s write deadline, never
  blocking the pump; a `snapshot` verb for recovery. Stdlib `net`, `encoding/json`, `bufio`;
  no HTTP, no new module.

### Open scope decisions (put to the operator before the requirements)

1. "Same shapes": wire-compatible with Little Snitch's tree protocol (the Python client could
   be pointed at snitchd unchanged; the daemon owns tree, expansion, search, filters; three
   connections) vs. flat JSON lines with the same fields (programs, destinations, counters,
   events; the TUI builds tree, sort, search). Recommendation: flat.
2. Writes over the API: read-only vs. root/operator uid may run the trial verbs and edit rules.
3. Where TUI rule edits (`x`) go: a local overlay file that survives deploys, or a proposals
   file the operator merges by hand into the repo's rules file.
4. Byte counting in this spec (with an early verifier check task) or a follow-up spec.

### Decisions taken by the operator (2026-10-11)
1. Flat JSON lines with the same field names; the TUI builds tree, sort and search.
2. Writes over the API for uid 0 and the configured operator uid (SO_PEERCRED): the trial verbs
   and rule edits; everyone else read-only.
3. TUI rule edits go to a local overlay file merged by the daemon (`/etc/snitch/rules.d/local.toml`
   or similar), higher precedence than the repo file, reloaded within 5 s, survives a deploy.
4. Byte counting in scope with an early feasibility task (verifier acceptance on this kernel).

---

## Gap analysis (2026-10-11)

### Requirement-to-asset map

| Req | Existing asset | Gap |
|---|---|---|
| 1.1-1.2 socket in the runtime dir, gone with the daemon | `RuntimeDirectory=snitch` 0700; `jobs.Run` ends everything when one job returns; `status.writeAtomic` creates `/run/snitch` 0700 | Missing: listener job, `RuntimeDirectoryMode=0755` (the status file stays 0600), socket 0666, unlink on close; Constraint: a hand-started daemon creates the directory itself |
| 1.3-1.4 peer credentials, reader/writer | `x/sys/unix.GetsockoptUcred` already a dependency; `-state-dir`-style flags | Missing: `-operator-uid` (or name) flag, per-connection role, refusal reply |
| 1.5-1.6 many clients, bounded backlog, drops, stuck-client close | the pump is one goroutine, `d.sink` delegate shows the fan-out shape | Missing: per-client queue + writer goroutine, drop counter, write deadline; Constraint: the pump must never block |
| 1.7-1.8 JSON lines, ids, errors, line limit | nothing (no `encoding/json` in the daemon yet) | Missing: message types, decoder with a size cap, error envelope |
| 1.9 flag to disable, soft failure | `config.check()` pattern | Missing: `-api` path flag ("" = off), log-and-continue on listen failure |
| 2.1 events within 1 s with all fields | `decodeEvent`, `describe`, `programOf`, `ruleOf`, exe path via kfunc; pid/ppid/comm in the C event | Missing: a wire event type; time stamp (user space `time.Now` at read, the C has none) |
| 2.2 dedupe window with counts | `rules.learnKey` is the same shape minus verdict/rule | Missing: dedupe table keyed (program or exe, addr, port, proto, verdict) with window, count, first/last |
| 2.3 exclude local-net | verdict `V_ALLOW_LOCAL` in events | Missing: subscription filter; Option: a kernel flag bit to stop emitting local events (quiet mode) later |
| 2.4-2.5 periodic summary, snapshot | `jobs.Every` | Missing: table delta tracking (dirty set) and full dump |
| 2.6 field names | the Python client's names (research §1) | Constraint: `bytesSent`, `lastAllowed`, `lastBlocked`, `deepAllowCount`→`allowCount`, `deepDenyCount`→`denyCount`, `primaryExecutable`→`path`, `ipAddress`→`addr`, `port`, `protocol`, verdict |
| 3.1-3.2, 3.5-3.6 connection table, windows, bounds | nothing | Missing: table (map keyed program+dst+port+proto) with per-window buckets (5 windows → ring of minute buckets up to 7 d, or exact timestamps pruned), LRU eviction with a counter |
| 3.3-3.4, 3.7 byte counting, never deciding, unknown bucket, gate | C `decide()` has `sock->sk`; kernel has `bpf_get_socket_ptr_cookie`; cgroup v2 root; `link.AttachCgroup` in cilium/ebpf | Missing: `cookie` in `struct event`, `cgroup_skb/egress` program returning 1, LRU hash cookie→{bytes,pkts,last_ns}, attach job, 2 s sweep joining cookie→entry; Unknown: verifier acceptance of the cookie helper in `lsm/socket_connect` (the gate task) |
| 4.1 status facts | `statusFacts`/`lines()` in ctl_status.go read pinned maps and files; the daemon holds the same in memory (mode atomic, store, snapshot, version, flags) except the kill map (`d.objs.Kill` readable) | Missing: a facts builder on the daemon side; Option: share one `status.Record`-like struct between the verb and the API |
| 4.2-4.3 rules and programs with source file | `Resolved.File.Rules` (ID, Line, Note), `Programs`, `Unresolved` | Missing: `Rule.Source` (file) once the overlay exists |
| 4.4 learned observations read-only | `rules.Learned` keyed by executable; `File()` clears dirty | Missing: a side-effect-free projection under the learner's mutex |
| 4.5 state events | `setMode` logs transitions; follower; reload publishes snapshots | Missing: hooks (delegates) on mode change and snapshot publish that notify the API |
| 4.6 100 ms, no root | in-memory facts | Constraint only |
| 5.1 trial verbs over the API | `runTrial/runKeep/runUnkeep/runEnd` are CLI handlers writing to `c.out`; `trialRefusal`, `liveTrial`, `followingDaemon` | Missing: a refactor seam so the verbs' decision logic is callable from the API without the CLI's flag parsing and probes (the daemon IS the following daemon: the running/following checks are trivially true in-process) |
| 5.2-5.4, 5.7 overlay file | `rules.Load/validate/Resolve/Encode/Diff`, `WriteFile`; reload job stats one path | Missing: second path, merge with precedence, `Source`, overlay write/validate; see the design research below |
| 5.5 journal line per write | `d.log` | Missing: audit line with uid |
| 5.6 no kill/control/trial-file writes | the verbs never write maps; `beat` is the only control writer | Constraint: the API's write set is exactly {trial, keep, unkeep, end, rule add, rule remove} |
| 6.1 schema document | `examples/rules.toml` style | Missing: `examples/api.md` |
| 6.2-6.3 tests without root, pump never blocked | delegates/`net.Pipe`-able design; `jobs` tests | Missing: tests |
| 6.4-6.5 VM verification | `scripts/deploy-check.sh` style; `socat`/`nc -U` available? (check `which socat nc`) | Missing: `scripts/api-check.sh` or a section in deploy-check |

### Implementation approach options

- **API package placement**: (A) everything in `cmd/snitchd` (package main): simplest wiring but daemon.go is at 268/300 and main cannot be imported by tests of other packages; (B) `internal/api` for protocol, auth, client queues, dedupe/table, with `cmd/snitchd/api.go` wiring getters and the write delegates (recommended, `structure.md` names it); (C) a separate binary: rejected, the facts live in the daemon's memory.
- **Status facts**: (A) the API builds its own facts struct; (B) one `facts` type in `internal/status` (or `internal/api`) filled by both the verb (from maps/files) and the daemon (from memory), so the nine status keys and the API's status message cannot drift (recommended).
- **Trial verbs**: (A) the API execs `snitchd trial …` as a subprocess: honest reuse but forks per request and needs root in the child (the daemon is root: fine) — simple, but output parsing; (B) refactor `ctl_verbs.go` so the decision functions take a `trialDeps` struct (store, now, boot, confirm=yes) and return `(code int, text string)`; the CLI and the API both call them (recommended; `ctl_verbs.go` is at 286 lines, the refactor moves logic into a new file).
- **Dedupe + table**: (A) two structures (dedupe map, connection table); (B) one table whose entries carry the dedupe state (last event per key within the window) (recommended: one key space, one eviction policy).
- **Windows**: (A) per-entry exact timestamps pruned (memory grows with activity); (B) per-entry minute buckets for 24 h plus hourly for 7 d (bounded, O(1) update) (recommended).
- **Byte counting join**: the cookie arrives in the connect event; the LRU map is swept every 2 s; entries whose cookie is unknown go to "unknown program" (Req 3.4).

### Complexity and risk
- Effort: L. New package, a C change with regeneration, a rules-model extension, a verbs refactor, tests, docs, VM verification.
- Risk: Medium. Fail-safes untouched by construction (the API never writes maps); the verifier acceptance of the cookie helper is the one unknown, gated first; the overlay precedence is a model change reviewed in design.

### Research needed (design)
- Overlay merge: see the dedicated analysis below (option and touch points).
- Confirm `socat`/`nc` availability on the VM for the verification script, or use a tiny Go test client (`go run ./tools/apicat`?) — decide in design.
- Per-window buckets vs exact timestamps: memory estimate for 5000 entries.

---

## Design decisions (2026-10-11)

### Overlay merge (research by a dedicated pass)
- IDs are positional and never stored; `validate` runs inside `decode`; the reloader keeps the
  previous snapshot on any load error. Chosen: **Merge at the File level** (one merged `File`,
  one `Resolved`, one `Diff`): base programs then overlay programs (same name = error), base
  rules whose expanded keys intersect an overlay rule's are dropped, overlay appended, validate
  re-runs; `Source` on programs and rules; conflict errors name the source. Rejected: merging
  `Entries` (two id namespaces, duplicated summaries) and a second kernel map layer (C change for
  a load-time decision).
- Remove-by-key (program, to, proto, port), never by id: ids renumber on every reload. Overlay
  programs reference base programs by name; an ad hoc program only for an executable no current
  program claims (the API pre-checks and names the owning program otherwise).
- Invalid overlay at startup: base only plus a reported error (an API write must not make the
  service fail on the next boot); on reload: previous snapshot kept, `rulesError` in the facts.
- `WriteFile` gains a header parameter (its learned-file header and temp prefix were specific).

### Synthesis
- Generalization: one table serves dedupe, summaries, snapshots, windows and bytes (one key
  space, one eviction); one `trialOps` seam serves the CLI and the API.
- Build vs adopt: stdlib JSON lines over a unix socket with peer credentials (Tailscale's local
  API model) instead of HTTP or a group; cgroup/skb counting on the v2 root instead of sock_ops
  (TCP only) or kprobes (rate, symbol churn); no new Go module.
- Simplification: the daemon converts kernel events, so `internal/api` has no BPF import; the
  operator is a one-line file, not a unit change; fixed-size bucket rings instead of timestamp
  lists; the counting link is not pinned (dies with the daemon like the LSM links).

### Open points carried into tasks
- The verifier's acceptance of `bpf_get_socket_cookie(sock->sk)` in `lsm/socket_connect` on
  7.2: the gate task.
- The VM repo follow-up (unit mode 0755, operator file) is outside this spec's tasks and needs
  the operator's go before the on-VM verification.

### Design validation (2026-10-11, independent reviewer): GO after three fixes
1. `trialOps` gains `following` and `yes`: a daemon run with `-mode` does not follow the files, so
   an API trial would have armed the next service start; zero rules need the explicit yes.
2. The cookie must come from the direct BTF walk `sock->sk` (trusted), not `BPF_CORE_READ` (a
   scalar the helper rejects); the byte join parks unknown cookies for two sweeps before the
   "unknown" entry and treats a lower map value as a recreated entry.
3. Snapshots are served from a cache built on the 2 s tick (no table lock on request); clients
   capped at 64; the accept loop never ends the job on an accept error.
Notes taken: an overlay rule replaces the whole base rule it touches (documented); the operator
file must be root-owned and not group/other-writable.

## Gate (task 1.1, 2026-10-11): cookie and counting accepted on kernel 7.2.6+deb14-amd64
Bounded run on this VM (service stopped for ~15 s, monitor mode, `-duration 12s`, counting
attached at the cgroup2 root `/sys/fs/cgroup`), one `curl https://1.1.1.1/`:
- The verifier accepted `bpf_get_socket_cookie(sock->sk)` in `lsm/socket_connect` (direct BTF
  walk from the trusted hook argument; no verifier message, nothing in dmesg). `bpftool prog
  show`: `1171: cgroup_skb name count_egress`, `1172: lsm name socket_connect`,
  `1173: lsm name socket_sendmsg`.
- The curl event (printed with a gate-only debug suffix, removed afterwards):
  `allow (monitor) connect pid 22488 curl tcp -> 1.1.1.1:443 program /usr/bin/curl (unknown) cookie=8197`.
- `bpftool map dump name bytes` entry for that cookie:
  `{"key": 8197, "value": {"bytes": 2584, "pkts": 13, "last_ns": 2776264138045}}`; other
  entries: cookie 1 (794536 bytes, 386 pkts: the RDP session's socket), systemd's `sd_fw_*`
  cgroup_skb programs coexist on sub-cgroups (bpf_link attach at the root, multi semantics).
- The `bytes` map is not pinned (`/sys/fs/bpf/snitch/bytes` does not exist): `MapOptions.PinPath`
  pins only the maps declared `LIBBPF_PIN_BY_NAME`.
- `struct event` grew from 328 to 336 bytes: `cookie` is the u64 at byte 72 (after `rule` and a
  4-byte pad), `path` moved from 68 to 80; `eventSize` follows the regenerated binding.
- Service restored (`systemctl is-active` → active); `deploy-check.sh` phase A tail recorded in
  the task report.
Outcome: the spec continues with counting on (`Counting = true` when the attach succeeds).

---

## Release, VM follow-up and verification on the dev VM (task 4.3, 2026-10-11, operator's standing go)

- snitch `main` pushed at 01cebeb (lint green), tag `v0.3.0` on it; release run 38145060886 green;
  assets verified: `sha256sum -c` OK, `./snitchd -version` → v0.3.0, `check` on
  /etc/snitch/rules.toml exit 0. Digest `e1303f2f31e7d62be794f051ea21d00542f84fab42124afb5222eecead98ad64`.
- VM repo 44af244 (pushed, lint incl. snitchd-rules green): unit copy with
  `RuntimeDirectoryMode=0755`, `/etc/snitch/operator` = the desktop user (root:root 0644), pins
  0.3.0. Deploy: 12 ops, 6 changed (operator file, binary, unit, boot unit enabled, running,
  restarted). After it: `/run/snitch` 0755 with `api.sock` 0666 and `status` 0600, service
  active, `snitchd -version` v0.3.0; `deploy-check.sh` phase A: 15/15,
  `state: service active mode monitor trial none kept no kill clear`.
- `scripts/api-check.sh` as the operator (mc): first run FAILed A2 only because deploy-check had
  curled 9.9.9.9 seconds before (10 s dedupe, the script explained it); second run FAILed A3
  because the first run's `rule.add` declared an ad hoc `curl` program whose events then land
  under a new key (bytes grew on the new entry): the script now sums bytes over all entries of
  the address; one further run missed B2's event once (reader now unbuffered with `python3 -u`).
  Then two clean runs: status v0.3.0, event allow-monitor within 1 s, bytes growing within 5 s,
  rule.add accepted, deny-rule event within 1 s, curl 9.9.9.9 denied with EPERM, rule.remove,
  allow-monitor again, curl connects again, pid unchanged. As `nobody`: rule.add and trial
  refused with `<type>: write requires the operator`, reads fine. Observed: the "unknown" bucket
  holds ~19 MB (sockets older than the daemon, e.g. the RDP session), as designed.
- A note for the design: an ad hoc program declared by `rule.add` stays in the overlay after
  `rule.remove` (ruleless), so later events of that executable are keyed by the program name.

---

## Feature validation (2026-10-11): GO after fixes

Mechanical: `go test -count=1 -race ./...` ok, caps ok, gofmt/vet clean, TODO grep clean (one
`XXXXXX` mktemp template), secrets grep clean; smoke: the live v0.3.0 service answered `status`
over the socket (running, counting on, 73 entries); CI 38146173147 (96ee585) and the run for
32f7534 green; VM CI 38145170683 green. `go list -deps`: internal/api imports only contract and
jobs. All 40 criteria covered; 4.1 and 6.4 amended (no status-file or heartbeat age in-process).
Boundary: no unrecorded spillover; CLI texts byte-identical; fail-safe surface untouched
(kill read-only, no control-map write, trial files only via trialOps, count_egress returns 1).

Findings fixed in 32f7534: an operator could `rule.add program=any to=0.0.0.0/0 deny`, which is
deny by default without a deadline (now refused with a pointer to `snitchd trial`); `-api` under
`-state-dir` would have opened the 0700 directory (refused); the 10 s re-resolve republished an
unchanged snapshot, so every subscriber got a `state` line every 10 s (now quiet unless the diff
is non-empty; test `TestReloadReresolveWithoutAChangeIsQuiet`); api.md's rule texts, the
spent-trial state line, and "nothing is logged" corrected; design file tree and traceability.
Note for the validators' conduct: one probe as the operator added and removed a deny for
9.9.9.9 (about 100 s, overlay byte-identical afterwards, both audit lines in the journal).
Unreleased: these fixes are on `main` after v0.3.0; tag v0.3.1 before the next VM deploy.
Cleanup candidates (not blocking): `windowNames` vs `Windows`, four proto-name mappers, three
RFC 3339 stampers; ad hoc programs from `rule.add` outlive `rule.remove` (policy for the TUI).
