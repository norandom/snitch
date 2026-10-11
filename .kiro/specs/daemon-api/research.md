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
