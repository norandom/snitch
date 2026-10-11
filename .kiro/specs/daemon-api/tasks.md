# Implementation Plan

Every task below is a self-contained brief for an implementer without conversation context.
Before a task, read `.kiro/steering/tech.md`, `.kiro/steering/fail-safes.md`, the design
sections named in the task, and the Implementation Notes of `.kiro/specs/deploy-service/tasks.md`
and `.kiro/specs/persistent-trial/tasks.md` (conventions: delegates, contracts with a violation
test each, caps via `scripts/caps.sh`, mutation evidence, verb flags before positional words,
boundaries list every fixture a change touches). `_Boundary:_` names the files a task may touch. A
Go task is done when its "Done when" command succeeds and `gofmt -l .`, `go vet ./...`,
`go test -race ./...` and `sh scripts/caps.sh` are clean. The deployed service runs on this VM:
nothing in groups 1 to 3 may stop, restart or reconfigure it except task 1.1's gate run, which
stops it for under a minute in monitor mode and starts it again (the kernel fails open meanwhile;
no mode is switched). Pushes happen only in the tasks that name them, after the no-secrets check.
Tasks that edit files in the same Go package run one at a time unless the controller accepts
the shared-package risk explicitly (1.2 and 1.3 were run together with a types.go handshake);
`(P)` tasks touch disjoint files. Bounded root runs in groups 1 to 3 (`-mode monitor -duration
5-12s`) are allowed next to the deployed service: the pinned `control` and `kill` maps are shared
with identical monitor values, double LSM decisions in monitor are harmless, a `-mode` daemon
builds no follower and writes no status or trial files; every such run passes `-overlay <temp>`
and, where it listens, `-api <temp socket>`, so it never reads a half-written overlay or clashes
with the service's socket. The counting map `bytes` and its link are not pinned (read it by name
with `bpftool map dump name bytes` while the daemon runs; bpftool lives in /usr/sbin).

- [ ] 1. The kernel side and the pure data structures
- [ ] 1.1 The socket cookie and the counting program (feasibility gate)
  - The kernel event carries the socket's cookie, taken in the decision hook from the direct
    BTF walk `sock->sk` (trusted pointer; a CO-RE read would be a scalar the helper rejects); a new counting
    program on egress adds each packet's length to a per-cookie entry in a bounded, unpinned map
    and always allows; attached by default with a soft failure logged (no new flag); the
    daemon's decoder reads the new field; the generated bindings carry the new value type
  - Gate on this VM (operator's go given for the spec): stop the service (not strictly needed,
    see the header; done for a clean journal record), run the new binary for 12 s in monitor mode,
    `curl` once, read the `bytes` map by name during the run, start the service again,
    `deploy-check.sh` phase A still passes. If the verifier rejects the
    cookie helper, record the exact message in research.md, keep the cookie field at 0, and the
    spec continues with counting off
  - Done when: `go generate ./internal/bpf/` succeeds, `go test ./cmd/snitchd -run Decode` proves
    the field is decoded, the 10 s run's log shows a curl event with a non-zero cookie and a
    `bytes` map entry for that cookie with bytes > 0 (read with bpftool), and the service is
    active afterwards
  - _Boundary: bpf/snitch.bpf.c, internal/bpf/gen.go, internal/bpf/snitch_*.go (generated),
    cmd/snitchd/decode.go, decode_test.go, cmd/snitchd/counting.go (attach only, the sweep is
    3.4), daemon.go (one line to attach), .kiro/specs/daemon-api/research.md (gate record)_
  - _Requirements: 3.3, 3.7_
- [x] 1.2 (P) The connection table, windows and byte join
  - One table keyed by program (or path), address, port and protocol: observe an event (dedupe
    within 10 s unless the verdict changed; counts, first/last seen, last allowed/blocked), add
    bytes by cookie (a cookie not yet observed parks its bytes for two sweeps, then the "unknown"
    entry; a lower map value than last time counts as a recreated entry), per-entry minute and hour rings,
    snapshot by window (15m 30m 1h 24h 7d) served from caches refreshed on the summary pass (no
    table lock on request) with rate over the last 10 s, dirty set for summaries,
    least-recently-seen eviction at a maximum with a counter, idle removal beyond 7 days
  - Contracts: size never exceeds the maximum; every cookie maps to a present entry; ring indexes
    in range; each with a violation test
  - Done when: `go test ./internal/api -run 'Table|Window|Bytes'` covers dedupe (same key within
    the window, verdict change, after the window), window sums across ring boundaries with a fake
    clock, rate, eviction and its counter, unknown bytes, cookie cleanup on eviction
  - _Boundary: internal/api/table.go, window.go, bytes.go, table_test.go, window_test.go,
    bytes_test.go_
  - _Requirements: 2.2, 2.4, 2.5, 3.1, 3.2, 3.4, 3.5, 3.6_
- [ ] 1.3 (P) Wire types, codec, roles and the client queue
  - The envelope and every message type with the design's JSON names; a line reader with the
    64 KiB limit and an encoder producing one object per line; request parsing that names the
    missing field; the role from peer credentials (root or the operator uid write, anyone else
    and unknown credentials read); a per-client bounded queue (1024) with a non-blocking send, a
    drop counter carried on the next message, and a 5 s write deadline that closes the client
  - Done when: `go test ./internal/api -run 'Codec|Role|Client'` proves the limit, bad JSON,
    unknown type, missing field, id echo, every role case, drops counted and reported, and the
    deadline closing a stuck reader (over `net.Pipe`)
  - _Boundary: internal/api/types.go, codec.go, auth.go, client.go and their tests_
  - _Requirements: 1.3, 1.6, 1.7, 1.8, 2.6_

- [ ] 2. Rules overlay and the trial seam
- [x] 2.1 (P) Merging a second rules file with precedence
  - Programs and rules know their source file; a merge of base and overlay: base programs then
    overlay programs (a same-name program is an error naming both files), base rules shadowed by
    an overlay rule's expanded keys dropped, overlay rules appended, validation re-run with dense
    ids; duplicate errors name both sources; the resolver's conflict error names the source; the
    file writer takes a header, and `WriteLearned(path, f)` keeps the learned header so the
    learner's reference in daemon.go stays untouched
  - Done when: `go test ./internal/rules -run 'Merge|Source|Write'` proves precedence for the
    same key (incl. an any-proto overlay rule removing both the tcp and the udp base rules), the
    same-name error, sources on every record, dense ids, duplicate naming both files, the header
    in the written file and a round trip; the learner's write still produces its header
  - _Boundary: internal/rules/merge.go, merge_test.go, file.go, decode.go, validate.go,
    resolve.go, write.go, write_test.go, file_test.go and learn_test.go (fixtures gain Source;
    cmd/snitchd keeps calling a learned writer by value)_
  - _Requirements: 4.2, 5.4_
- [ ] 2.2 The daemon loads base plus overlay
  - Flags: `-overlay` (default `/etc/snitch/rules.d/local.toml`) and `-api` (default
    `/run/snitch/api.sock`, empty disables; parsed and checked here, unused until the wiring
    task), with the configuration checks (overlay ≠ rules ≠ learned); the loader merges when the overlay exists, falls back to base only with a recorded
    error when the overlay is invalid at startup, and keeps the previous snapshot with a recorded
    error on a bad reload (cleared on success); the file watch takes a list of paths (rules,
    overlay, and later the operator file); the status writer and the summary unchanged
  - Done when: `go test ./cmd/snitchd -run 'Load|Reload|Config'` proves base only, base plus
    overlay, invalid overlay at startup (base effective, error recorded), invalid overlay on
    reload (previous kept, error recorded then cleared), and the flag checks; `go run` of the
    daemon with `-rules examples/rules.toml -overlay <temp> -mode monitor -duration 5s` as root
    prints the merged summary (operator present; the service keeps running, the pinned maps are
    shared: use `-duration 5s` only)
  - _Boundary: cmd/snitchd/config.go, config_test.go, state.go, state_test.go, reload.go,
    reload_test.go, daemon.go (loader call)_
  - _Depends: 2.1_
  - _Requirements: 1.9, 5.4_
- [ ] 2.3 (P) The trial seam
  - The verbs' file operations and their texts (start with bounds, extend and yes, keep, unkeep,
    end with at-boot) and the refusals that depend on the store, learning, the kill switch,
    following the files and the rule count move behind one seam the CLI handlers call; the CLI
    keeps its probes and record checks and turns its prompt into `yes`; every CLI output stays
    byte-identical
  - Done when: `go test ./cmd/snitchd -run 'Trial|Keep|Unkeep|End|Ctl'` is green without any
    change to `ctl_verbs_test.go`'s expected strings, and a new table test proves the seam's
    texts equal the CLI's for every refusal and success
  - _Boundary: cmd/snitchd/trialops.go, trialops_test.go, ctl_verbs.go_
  - _Requirements: 5.1_

- [ ] 3. The server, the wiring and the writes
- [ ] 3.1 The API server
  - Accept loop as a job; role decided once per connection; a verb table of handlers (status,
    rules, programs, learned, snapshot, subscribe, unsubscribe, trial, keep, unkeep, end,
    rule.add, rule.remove) with the write set checked before the handler; subscriptions with the
    local-net filter; a summary every 2 s of changed entries that also refreshes the snapshot
    caches; state events; `Emit` without a blocking path; at most 64 clients; an accept error
    other than the listener's close is logged and retried after 100 ms, never ending the job
  - Contracts: the constructor requires its delegates; `Emit` requires a time and is proven
    non-blocking with a full queue
  - Done when: `go test ./internal/api -run 'Server|Emit|Subscribe|Summary'` over a unix socket
    in a temp dir proves dispatch per role, every error reply, the local filter, the summary
    cadence with a fake clock, snapshot, state events, `Emit` under 1 ms with a full queue,
    `Observe` p99 under 1 ms under a hot snapshot loop, the 65th client refused, and an injected
    accept error not ending the job
  - _Boundary: internal/api/server.go, server_test.go_
  - _Depends: 1.2, 1.3_
  - _Requirements: 1.4, 1.5, 1.7, 2.3, 2.4, 2.5, 4.5, 5.6, 6.3_
- [ ] 3.2 Event conversion and the read projections
  - The pump's conversion of a kernel event to the wire event (verdict and hook names, program
    name or unknown, path, pid, ppid, comm, destination, rule reference with note and source,
    time); rule and program views from the snapshot with their source file; a side-effect-free
    projection of the learned observations (the learner's file projection clears its dirty flag;
    the new view must not)
  - Done when: `go test ./cmd/snitchd ./internal/rules -run 'Event|View|Observations'` proves
    every verdict and hook name, the rule reference, the views' sources, and that the projection
    leaves the learner's dirty flag alone (mutation: a projection that clears it fails)
  - _Boundary: cmd/snitchd/apievent.go, apievent_test.go, internal/rules/learn.go, learn_test.go
    (the projection), .kiro/specs/daemon-api/design.md (file plan: learn.go added)_
  - _Depends: 1.3, 2.2_
  - _Requirements: 2.1, 2.6, 4.2, 4.3, 4.4_
- [ ] 3.3 Operator, listener, facts, hooks and the wiring
  - The operator file read at startup and re-read on change (ignored with a log unless root-owned
    and not group/other-writable); the listener (directory 0755, stale socket removed, socket
    0666, unlinked on close, failure logged and skipped); the facts from memory (mode, trial,
    kept, kill, learning, rules counts and error, version, pid, start time, API counters,
    counting on/off; a `-mode` daemon has no follower: trial none, source flag); mode and publish
    hooks sending state events; `d.apiJobs()` returning the server job (and later the sweep) so
    daemon.go gains one job-list line and the emit field; the write delegates wired to stubs that
    answer "not available" until task 3.4 fills them
  - Done when: `go test ./cmd/snitchd -run 'Api|Facts|Operator'` proves the facts' fields in
    both modes, the operator file cases (missing, bad name, wrong owner or mode, valid), the
    listener's soft failure, and a monitor run as root with `-duration 5s -api <temp socket>
    -overlay <temp>` serves `status` to `nc -U` as the user while the service keeps running
  - _Boundary: cmd/snitchd/api.go, api_test.go, daemon.go (emit field, one job-list line),
    follow.go (hook), state.go (publish hook), events.go (emit call), reload.go (operator stamp)_
  - _Depends: 3.1, 3.2_
  - _Requirements: 1.1, 1.2, 1.9, 2.1, 4.1, 4.5, 4.6_
- [ ] 3.4 Writes over the API
  - Trial, keep, unkeep and end through the seam with the daemon's store, learning flag, kill
    reader, `following` (false for a daemon started with `-mode`: refused with the CLI's sentence)
    and the rule count (zero without `yes`: the confirm sentence as the error); rule add (program by name or an unclaimed executable's path, address or prefix,
    optional protocol and port, verdict, note) and rule remove by key into the overlay through
    load, mutate, merge-validate, write; deployed rules refused with the file to edit; one audit
    line per write with the uid; every write refused for readers
  - Done when: `go test ./cmd/snitchd -run 'ApiWrite|Overlay'` proves each verb's outcome text
    equals the CLI's, the add and remove flows on temp files incl. the claimed-executable error,
    the deployed-rule refusal, the invalid-merge refusal with the file untouched, the
    not-following and zero-rules refusals, and the audit lines
  - _Boundary: cmd/snitchd/apiwrite.go, apiwrite_test.go, api.go (the two delegate lines)_
  - _Depends: 2.1, 2.3, 3.3_
  - _Requirements: 5.1, 5.2, 5.3, 5.5, 5.6, 5.7_
- [ ] 3.5 Byte counting attached and swept
  - The cgroup v2 root found from the mounts table; the counting program attached with a link
    (not pinned) or counting switched off with one log line; a sweep every 2 s reading the
    bytes map in batches, feeding deltas by cookie to the table, forgetting cookies idle for ten
    minutes
  - Done when: `go test ./cmd/snitchd -run 'Counting|Sweep'` proves root detection from a fake
    mounts table, the delta logic against a fake map reader, the soft failure, and a monitor run
    as root with `-duration 10s` shows bytes for a curl download in a `snapshot` reply
  - _Boundary: cmd/snitchd/counting.go, counting_test.go, api.go (the sweep added to apiJobs)_
  - _Depends: 1.1, 1.2, 3.3_
  - _Requirements: 3.2, 3.3, 3.4_

- [ ] 4. Schema, verification, closing
- [ ] 4.1 (P) The schema document and the README
  - `examples/api.md`: envelope, every request with its reply, every unsolicited type, the
    field-name table against the Python client, the limits and windows, authorization, and the
    `nc -U` and python3 one-liners; README: an API paragraph and the Service paragraph gains the
    operator file and the runtime directory mode; `systemd/snitchd.service`:
    `RuntimeDirectoryMode=0755`; CLAUDE.md status
  - Done when: every type in `internal/api/types.go` appears in the document with an example that
    parses (`python3 -c json.loads` over the fenced examples), and `systemd-analyze verify` passes
    on the unit copy with its path rewritten
  - _Boundary: examples/api.md, README.md, systemd/snitchd.service, CLAUDE.md_
  - _Depends: 3.4_
  - _Requirements: 6.1, 6.5_
- [ ] 4.2 (P) The API check script
  - `scripts/api-check.sh`, run as the desktop user: status reply, subscription with a curl
    event within 1 s, bytes growing within 5 s when counting is on, rule add refused for a
    non-operator, as the operator a deny rule for curl shows the next event as deny-rule in
    monitor mode and remove restores, trial refused for a non-operator, heartbeat age in status
    ≤ 2 s throughout; PASS/FAIL per step, exit 1 on failure; shellcheck clean
  - Done when: `uvx --from shellcheck-py shellcheck scripts/api-check.sh` is clean and the script
    against a daemon without the API (today's service) fails at the connect step with a clear line
  - _Boundary: scripts/api-check.sh_
  - _Depends: 3.4_
  - _Requirements: 6.4, 6.5_
- [ ] 4.3 Release, VM follow-up and the verification on the dev VM
  - Only with the operator's go: snitch `main` pushed (no-secrets check), lint green, then tag
    `v0.3.0` (a local binary copied over the pinned one would break the as-code pin, so the
    release is the honest path; a failed verification means a second tag), release verified; in the VM repo: the unit copy with the new directory mode, an operation deploying
    `/etc/snitch/operator` with the desktop user, pins bumped to v0.3.0, deploy; then
    `scripts/api-check.sh` as the desktop user and `deploy-check.sh` phase A; results recorded;
    the design's Modified Files line and deploy-service's revalidation note updated
  - Done when: both scripts pass, the state line is monitor with no trial and nothing kept, the
    VM repo `main` is pushed and its CI green, research.md holds the record
  - _Boundary: git (push, tag), hyperland-forky-worker-vm (unit copy, tasks/snitchd.py,
    group_data/all.py), .kiro/specs/daemon-api/research.md, the dev VM_
  - _Depends: 3.5, 4.1, 4.2_
  - _Requirements: 6.4, 1.1, 1.3, 5.2_
- [ ] 4.4 Caps, contracts and CI
  - Every documented contract has a violation test; caps green; no exported identifier without a
    caller; the design's contract list names the functions and tests; both repos' CI green on
    `main`
  - Done when: every command of both `lint.yml` files passes locally and the remote runs are
    green (run ids recorded)
  - _Boundary: `*_test.go` of this spec's packages, design.md contract list_
  - _Depends: 4.3_
  - _Requirements: 6.2_

## Implementation Notes
- 2.1: `LoadOverlay`/`ParseOverlay` load an overlay whose rules name base programs (plain `Load` rejects them as undeclared); `Merge` re-validates the union so an unknown program still fails there. Overlay writer is `WriteWith(path, f, header)`; `WriteFile(path, f)` stays the learned writer (daemon.go passes it by value). Shadowing is per base rule over expanded keys (a proto overlay rule replaces an any-proto base rule whole; pinned by a test a mutant required). Fixtures comparing whole records (`file_test.go`, `learn_test.go`) gained `Source`. Later tasks: load the overlay with `LoadOverlay`, write it with `WriteWith`.
- 1.2: dedupe anchors on the last EMITTED event (a steady duplicate stream re-emits once per 10 s); windows are bucket-aligned (the bucket at now−win excluded; 15 m spans 14–15 min of wall time); `Snapshot` returns `([]Entry, error)` and is served from caches rebuilt by `Changed`, which returns every dirty row regardless of `since`; cookies idle ≥ `CookieIdle` (10 min) are expired by `Prune` (first review found the index unbounded and a whole-map invariant scan on the pump path: both fixed, Observe ≈ 6–14 µs with 200k live cookies). Sweep (3.5): call `AddBytes` per cookie delta, then `Prune(now)` once.
