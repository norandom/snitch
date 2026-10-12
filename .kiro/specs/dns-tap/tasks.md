# Implementation Plan

Every task below is a self-contained brief for an implementer without conversation context.
Before a task, read `.kiro/steering/tech.md`, `.kiro/steering/fail-safes.md`, the design
sections named in the task (`.kiro/specs/dns-tap/design.md`), the gap analysis and probe facts in
`research.md`, and the Implementation Notes of `.kiro/specs/daemon-api/tasks.md` (conventions:
delegates for OS seams, contracts with a violation test each, caps via `scripts/caps.sh`,
mutation evidence, boundaries list every fixture a change touches). `_Boundary:_` names the files
a task may touch. A Go task is done when its "Done when" command succeeds and `gofmt -l .`,
`go vet ./...`, `go test -race ./...` and `sh scripts/caps.sh` are clean. The deployed service
(v0.3.1, monitor mode) runs on this VM: nothing in groups 1 to 3 may stop, restart or
reconfigure it. Bounded root runs (`-mode monitor -duration 5-12s -overlay <temp> -api <temp
socket>`) next to the service are allowed as in the daemon-api plan: `rules`, `programs` and every
DNS map are unpinned (each daemon has its own trie; the test run's kernel inserts never reach the
service), `control` and `kill` are shared with identical monitor values, and a second pair of
`cgroup_skb` programs at the cgroup root is legal (`multi`). Root-only Go tests carry the build
tag `root`, live in `internal/dns` (never in the generated package `internal/bpf`, which the caps
exclude), and run through `scripts/dns-progtest.sh`; CI compiles them with `go vet -tags root`
but never runs them. The kernel side honours the design's fail-safe constructions in every task
that touches it: the two `SEC("cgroup_skb/...")` functions return 1 on every path, only
`verdict 1` is written, trie updates use `BPF_NOEXIST` only. Pushes happen only in the tasks that
name them, after the no-secrets check. Tasks in the same Go package run one at a time unless the
task states the handshake that makes them safe; `(P)` tasks touch disjoint files.

- [ ] 1. Kernel, names in rules, and the pure DNS package
- [x] 1.1 The DNS programs and their bindings
  - A second BPF object from the verified probe (`dnsprobe.bpf.c` in the spec directory) with
    the two changes the design requires over the probe: trie updates with `BPF_NOEXIST` (the
    probe used `BPF_ANY`; `EEXIST` counted as `exists`) and the counters map named `dns_stats`;
    the egress question recorder and the ingress answer parser with the maps of the design's
    Kernel section (`resolvers`, `domains`, `questions`, `dns_answers`, `dns_stats`, and `rules`
    declared exactly as the main object does, unpinned); the rodata switch `test_skip_question`
    (never set by the daemon); the record carries the slots the kernel inserted and is reserved
    before the RR walk (no record, no insert; a full ring buffer counts `ringbuf_full`); the
    bounds as `#define`s; a second `go:generate` line with a `-type` for every struct the Go
    side reads and no `-type` for the trie's key or value; the generated bindings committed
  - The package `internal/dns` is created here (a `doc.go` naming its purpose and the rule that
    it is pure) so the shape and load tests have a home and 1.4, 1.5 and 1.6 add files to an
    existing package
  - A Go test over the C source pins the fail-safe shape: inside the bodies of the two
    `SEC("cgroup_skb/ingress")` and `SEC("cgroup_skb/egress")` functions every `return` is
    `return 1` (helper functions and the `bpf_loop` callback may return 0); no `BPF_ANY` on the
    trie; the only verdict literal written is 1
  - Done when: `go generate ./internal/bpf/` succeeds, `go build ./...` and `go test
    ./internal/dns` are green, and as root `go test -tags root ./internal/dns -run DNSProgLoads`
    loads the object with a throwaway trie through map replacement (verifier accepts both
    programs; the instruction count is recorded in research.md)
  - _Boundary: bpf/dns.bpf.c, internal/bpf/gen.go, internal/bpf/dns_x86_bpfel.go,
    internal/bpf/dns_x86_bpfel.o, internal/dns/doc.go, internal/dns/shape_test.go,
    internal/dns/load_root_test.go, .kiro/specs/dns-tap/research.md_
  - _Requirements: 1.1, 1.2, 1.3, 1.4, 1.6, 1.8, 4.1, 4.5_
- [x] 1.2 (P) A name is a destination in the rules model
  - One name parser in the rules package (lowercase, trailing dot removed, labels of letters,
    digits and hyphens of 1 to 63 characters, no leading dot, no wildcard, at most 62 characters
    and 16 labels) with the design's error texts; a rule carries a name instead of a prefix,
    reports its destination as written, and knows whether it is a name; the decoder tries the
    prefix first then the name and refuses a deny by name with a message naming the rule; the
    validator treats program, name, protocol and port as the identity (a parent and a child name
    are two rules), prints the destination in the duplicate message, and refuses a fifth rule on
    one exact name with a message naming the domain; the merge shadows by the same identity; the
    writer round-trips a name; the encoder skips name rules so its prefix precondition holds
  - The API's rule-edit parser is untouched here (task 2.5 owns it, including the three pinned
    invalid values in its test)
  - Done when: `go test ./internal/rules -run 'Name|Dest|Validate|Merge|Write|Encode'` proves
    the grammar table (case, trailing dot, 62/16 bounds, leading dot, wildcard, 63-character
    label), the deny-by-name refusal text, the fifth-rule refusal text, parent and child as two
    rules, overlay shadowing by name, write round trip, and that `Encode` skips name rules
    (mutation: an encoder that does not skip trips the prefix contract)
  - _Boundary: internal/rules/nameparse.go, nameparse_test.go, file.go, decode.go, validate.go,
    validate_test.go, identity.go, merge.go, merge_test.go, write.go, write_test.go, encode.go,
    encode_test.go, file_test.go, decode_test.go_
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.5, 3.8, 4.5_
- [x] 1.3 Address keys for the compiler and learning by name
  - The encoder exports the key for one rule and one address (the same bits as an address rule's
    key), the rule's program id from the resolved programs, and the rule's protocol and port
    expansion, so the compiler reuses the encoder's shape instead of copying it; the learner
    records an observation under its name when it has one and writes `to = "<name>"` for it,
    seeds name rules by name, and keeps addresses for observations without a name; the name
    branches live in their own file (the learner's file is at its cap)
  - Done when: `go test ./internal/rules -run 'EncodeAddr|Expand|ProgramID|Learn'` proves the
    exported key equals the key the encoder builds for the same /32 and /128 rule, every
    protocol and port combination expands as the encoder's, an observation with a name lands in
    the learned file as a name rule once (two addresses, one name) and one without stays an
    address
  - _Depends: 1.2_
  - _Boundary: internal/rules/encode.go, encode_test.go, learn.go, learn_name.go,
    learn_name_test.go, learn_test.go_
  - _Requirements: 5.4, 4.5_
- [ ] 1.4 (P) Name keys, resolvers and the kernel's record in Go
  - The pure helpers of the DNS package that mirror the kernel: the bounds as constants, the
    suffix test between a rule's name and a learned name, the domains-map key form (leading dot,
    lowercase, zero padded), the suffix list of a name (at most 8 levels); the resolver addresses
    from a resolv.conf reader (nameserver lines only, zones dropped, de-duplicated, at most 16)
    and their map key; the decode of the kernel's answer record into a name, a TTL and
    addresses, refusing short or inconsistent records; the stats struct from the counters array
  - New files only in the package 1.1 created; no identifier shared with 1.5 (that is the
    handshake that lets 1.4 and 1.5 run side by side)
  - Done when: `go test ./internal/dns -run 'Covers|Key|Suffixes|Resolvers|Decode|Stats'`
    proves the key form against bytes the kernel would write, the suffix list cap, IPv4 and
    IPv6 resolvers with zones and duplicates, a decoded A+AAAA record, and that a truncated
    record is refused
  - _Depends: 1.1_
  - _Boundary: internal/dns/name.go, name_test.go, resolv.go, resolv_test.go, record.go,
    record_test.go_
  - _Requirements: 1.5, 3.1, 3.4_
- [x] 1.5 (P) The address-to-name cache
  - A cache from address to at most 4 names with an expiry per name: learn clamps the TTL to
    60 s..24 h, extends to the later expiry, keeps earlier names, and reports what changed;
    expire reports addresses whose names changed or vanished; names of an address most recent
    first; bounds of 8192 addresses and 4 names with eviction of the address closest to expiry,
    counted; zero value ready and empty
  - New files only in the package 1.1 created; no identifier shared with 1.4 (the handshake for
    running next to 1.4): the cache owns its bound constants (addresses, names per address),
    name.go owns the kernel's bounds; 1.6 reads both
  - Contracts: learn requires a parsed name and valid addresses (violation test); the bounds
    are never exceeded (ensure, with a test that learns 9000 addresses)
  - Done when: `go test ./internal/dns -run 'Cache|Clamp|Contract'` proves clamp both ways,
    extension keeps the later expiry and both names, expiry changes at the boundary, eviction
    order and counter, the 5th name on one address evicting the soonest, and a benchmark of
    learn and expire at 8192 addresses runs in well under the 2 s tick
  - _Depends: 1.1_
  - _Boundary: internal/dns/cache.go, cache_test.go, cache_bounds_test.go_
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6_
- [x] 1.6 The compiler and the compiled set
  - From a resolved rule set: the domains-map content (4 slots per exact name, an error beyond,
    which the validator prevents first); for one address and its live names, every key a
    covering name rule produces over its protocol and port expansion with the rule's current id,
    allow only; a compiled set that remembers key, id, name and expiry per address, diffs a
    wanted set against what it holds into puts and deletes, and subtracts the file's keys from
    both (a key the file holds is neither written nor remembered); a full recompile from a rule
    set and the cache (new ids, stale keys deleted); the name through which a rule id matched an
    address; a cap of 16384 entries
  - Contracts: no file key in puts or deletes (violation test); every put value is allow
    (invariant test)
  - Done when: `go test ./internal/dns -run 'Slots|Compute|Apply|Recompile|NameOf'` proves the
    slot layout for a name with 3 rules, expansion for any-proto and tcp-443 rules, file-key
    subtraction, a recompile after ids renumber that re-puts with the new id and deletes a key
    whose rule vanished, NameOf after recompile, and a benchmark of 50 name rules over 8192
    addresses under 50 ms
  - _Depends: 1.3, 1.4, 1.5_
  - _Boundary: internal/dns/compile.go, compile_test.go, compile_recompile_test.go_
  - _Requirements: 3.1, 4.3, 4.5, 4.7, 5.2_
- [ ] 1.7 The kernel parser under test
  - Root tests that run the ingress program on crafted datagrams (built with the test-only
    `dnsmessage` package) with the question join switched off through the rodata variable: A
    and AAAA under the asked name, a CNAME chain recording under the asked name, compression
    pointers, a truncated answer, a wrong resolver, a wrong source port, QDCOUNT 2, a name over
    the bounds, a name with no covering rule (cache record, no insert), an existing file key
    (counted, untouched), with the trie contents, the record and the counters asserted after
    each; one real-socket test with a fake resolver on 127.0.0.1:53 added to the resolvers map,
    both programs attached to a test cgroup the test creates and enters, a query and an answer,
    then the trie holds the entry and the question entry is consumed, and an answer with no
    question is ignored; the script that runs every `-tags root` test of `internal/dns` (and
    of `cmd/snitchd`, should any appear later) with `-run DNSProg`
  - Done when: `sudo scripts/dns-progtest.sh` passes on this VM and `shellcheck` is clean on the
    script; `go vet -tags root ./...` is clean; the instruction count of the probe run is
    unchanged within 10 % and recorded in research.md
  - _Depends: 1.1, 1.4_
  - _Boundary: internal/dns/prog_root_test.go, prog_frames_test.go, prog_socket_root_test.go,
    scripts/dns-progtest.sh, go.mod, go.sum (golang.org/x/net test dependency),
    .kiro/specs/dns-tap/research.md_
  - _Requirements: 1.1, 1.3, 1.4, 1.6, 1.8, 4.1, 4.5_

- [ ] 2. The daemon: attach, mirror, expire, recompile, show
- [ ] 2.1 The tap attached softly, the flag and the resolvers
  - The DNS object loaded with the daemon's trie as the shared `rules` map; the resolvers map
    filled synchronously from resolv.conf before the programs attach (so no answer can arrive
    before the resolvers are known); both programs attached at the cgroup2 root (links unpinned)
    after the LSM attach; any failure logs `dns tap off: <reason>` once and leaves the daemon as
    today; the `-dns` flag (default on) turns the tap off with the reason `flag`; a daemon state
    for the tap with its mutex, the cache, the compiled set, the map write delegates, the stats
    reader, a clock and a logger; the resolv.conf watch (a 2 s stamp of the file; on change the
    resolvers map gets the new addresses and loses the old; unreadable or empty means an emptied
    map and the status reason `no resolvers`); the jobs list gains the tap's jobs through one
    call
  - Done when: `go test ./cmd/snitchd -run 'DNS|Resolv|Config'` proves the off path for the
    flag and for a failing attach delegate (reason, log line once), the resolvers written before
    the attach delegate is called (mutation: attach first fails), the resolvers put and delete
    from a fake stamp and reader, and a bounded run as root (`-mode monitor -duration 10s
    -overlay <temp> -api <temp socket>`) logs the tap on and `bpftool map dump name resolvers`
    shows this VM's resolver during the run
  - _Depends: 1.4, 1.6_
  - _Boundary: cmd/snitchd/dns.go, dns_test.go, dnsjobs.go, dnsjobs_test.go, config.go,
    config_test.go, daemon.go (one field, the load call, one job-list line)_
  - _Requirements: 1.5, 1.7, 2.6, 4.6_
- [ ] 2.2 The reader mirrors and corrects the kernel; expiry
  - A reader job over a read delegate (the ring buffer in the daemon, a slice source in tests):
    decode, then under the tap's mutex load the current snapshot, learn, compute per address,
    apply minus the file's keys, put with the snapshot's ids, and delete every slot key the
    record says the kernel inserted that the compute does not want; read and map errors logged
    once per streak; the expiry tick (2 s) expires the cache and deletes the compiled keys of
    gone addresses minus the file's keys; when the compiled set exceeds its cap the address
    closest to expiry is evicted (cache and compiled together) and counted; the file-entry
    writer in state.go gains a variant taking an on-full delegate (ENOSPC on a file put calls
    it and retries once) while the existing writer stays a wrapper with no delegate, so its two
    callers are untouched here (2.3 wires the daemon's evictor at both call sites); the reader
    never takes the reloader's lock
  - Contract: handling a record requires a snapshot (violation test)
  - Done when: `go test ./cmd/snitchd -run 'DNSReader|Expire|ApplyFull|Evict'` proves a record
    puts the covering rule's keys with the snapshot's id, a key the file holds is neither put
    nor deleted, a recorded kernel slot for a rule the snapshot lacks is deleted, a stale id in
    the record is corrected by the put, expiry deletes within one tick, eviction at the cap, and
    the ENOSPC retry after the delegate evicted
  - _Depends: 2.1_
  - _Boundary: cmd/snitchd/dnsreader.go, dnsreader_test.go, dnsjobs.go, dnsjobs_test.go,
    dns.go (eviction), state.go, state_test.go_
  - _Requirements: 1.1, 2.3, 2.5, 4.2, 4.5, 4.7_
- [ ] 2.3 Recompile inside every reload
  - The reloader gains an after-publish hook called under its lock with the published snapshot,
    before the summary line; the tap's recompile holds its own mutex from the domains-map rewrite
    (put the new slots, delete stale names) through the full recompile of the compiled set (new
    ids, puts and deletes minus the file's keys); startup calls it once after the tap is loaded
    so the domains map is written before the first answer; the two file-entry write sites
    (startup and reload) pass the daemon's evictor as the on-full delegate; the summary line
    reports `+ N compiled` and counts a name rule once
  - Lock order pinned in a comment and a test: reloader then tap; the reader never takes the
    reloader's lock
  - Done when: `go test ./cmd/snitchd -run 'Reload|Recompile|Summary'` proves the hook receives
    the new snapshot (mutation: a hook called with the old snapshot fails), a rule removed in
    the overlay deletes its compiled keys in the same reload before the summary, a renumbering
    re-puts every compiled key with the new id, the domains map loses a removed name, both
    file-write sites call the one helper that takes the evictor (a test proves the helper retries
    once after the delegate ran; a test pins that the reloader passes the daemon's evictor), and
    the summary count is unchanged by the number of compiled addresses; every line added to
    daemon.go is one line (it stands at 290 of 300)
  - _Depends: 2.2_
  - _Boundary: cmd/snitchd/reload.go, reload_test.go, dnsjobs.go, dnsjobs_test.go, state.go,
    state_test.go, daemon.go (the hook assignment, the startup call, the evictor at the file
    write)_
  - _Requirements: 3.6, 4.3_
- [ ] 2.4 (P) Wire and status types for names and the tap
  - The API's event, table entry and observation carry an optional name; the status carries an
    optional `dns` block (on, reason, seen, ignored, entries, names, compiled, evictions); the
    table sets an entry's name from an observed event when present and copies it into views;
    the status record gains the `dns` key before `version`
  - Done when: `go test ./internal/api ./internal/status -run 'Keys|Table|Record'` proves the
    JSON key sets with `name` and `dns`, omission when empty, an entry keeping its address key
    for two names, and the record's key order
  - _Boundary: internal/api/types.go, types_test.go, table.go, table_test.go,
    internal/status/status.go, status_test.go_
  - _Requirements: 5.1, 5.3, 5.5, 5.6_
- [ ] 2.5 (P) Names in the API's rule edits
  - `rule.add` and `rule.remove` accept a name in `to` (the prefix parser first, then the rules
    package's name parser), match an existing rule by its destination, and refuse a deny by name
    with the design's text; the name branch lives in its own file (the edit file is at 272
    lines); the three pinned invalid values in the existing test (`nowhere`, `x`) move to values
    invalid under the new grammar (`bad..name`, `-x`)
  - Done when: `go test ./cmd/snitchd -run 'ApiWrite|Overlay|EditKey'` proves add by name
    writes `to = "<name>"` to the overlay, remove by name removes exactly that rule, deny by name
    is refused with the text and the overlay untouched, and an invalid name quotes the value
  - _Depends: 1.2_
  - _Boundary: cmd/snitchd/apiwrite_rules.go (the parse call), apiwrite_name.go,
    apiwrite_name_test.go, apiwrite_rules_test.go_
  - _Requirements: 3.2, 3.3_
- [ ] 2.6 Names where the operator looks (integration)
  - The tap's facts (from the counters, the cache and the compiled set) into the API status and
    the status record's `dns` field (one field in the record literal the follower writes; a
    `-mode` daemon writes no record, as today), printed by `snitchd status`; a name delegate
    (the compiled set's name for the matching rule, else the most recently learned name, else
    none) wired into the event conversion and the log line, the table observation and the
    learner's observation; the rules view shows a name rule's destination as written; the API's
    rule texts print the destination
  - Tests for the record field go to a new file (`follow_test.go` is at its cap)
  - Done when: `go test ./cmd/snitchd -run 'Facts|Event|Observation|Status|FollowDNS'` proves
    the name precedence (rule name over most recent), an unknown address without a name, the
    event rule reference pointing at the name rule, the facts in both tap states, the record
    field and the status line text, the rules view for a name rule; a bounded run as root with
    a name rule for curl in a temp overlay and `curl https://www.example.org/` shows an event
    with the name and the rule within the run
  - _Depends: 2.3, 2.4, 2.5_
  - _Boundary: cmd/snitchd/dnsfacts.go, dnsfacts_test.go, events.go, events_test.go,
    apievent.go, apievent_test.go, ctl_status.go, ctl_status_test.go, follow.go (one field),
    follow_dns_test.go, api.go (the delegate lines), daemon.go (the facts call)_
  - _Requirements: 1.7, 3.6, 5.1, 5.2, 5.3, 5.4, 5.5_

- [ ] 3. Scripts, docs, closing and the dev VM
- [ ] 3.1 (P) The check scripts gain the DNS phase
  - `scripts/api-check.sh` phase C as the operator: the status shows the tap on; a curl name
    rule added through the API (the trap removes it) and a curl to a name under it produces an
    event within 1 s with the rule and a name ending in that domain; a curl to the same host by
    its address produces an event without a name; after the rule is removed the compiled count
    in the status drops (the design substitutes the rule removal for Req 6.3's "after the entry
    expires": public TTLs exceed the 60 s floor, expiry itself is proved by the unit tests and
    the kernel tests; the script says so in a comment); `scripts/deploy-check.sh --trial` runs
    the dev tools (`gh api`, `git ls-remote`, `uv pip download`, `cargo search`, `go list -m`)
    during the 2 min trial and passes when each exits 0 and no deny event names their programs
    in the journal window; the scripts remain correct against today's service (phase C fails at
    its first step with a clear line because the status has no `dns` block)
  - Done when: `uvx --from shellcheck-py shellcheck scripts/api-check.sh scripts/deploy-check.sh`
    is clean and phase C against the running v0.3.1 service reports the missing tap and exits 1
  - _Boundary: scripts/api-check.sh, scripts/deploy-check.sh_
  - _Requirements: 6.3, 6.4_
- [ ] 3.2 (P) Documentation and the steering rewording
  - `examples/rules.toml`: a name rule with the semantics (subdomains, 8 levels, plain UDP
    answers of this host only, host-wide cache and CDN sharing, no deny by name, no Public Suffix
    List, 4 rules per name, 62 characters and 16 labels); `examples/api.md`: `name` on event,
    entry and observation, `dns` on status, `to` accepting a name in `rule.add`, the limits
    rows (cache 8192x4, compiled 16384, TTL clamp), the sentence that events with names are a
    record of the host's lookups; README: a names paragraph and the `-dns` flag; steering
    `fail-safes.md` rule 1 reworded as approved with the requirements; CLAUDE.md status and
    fail-safe 1 kept in step
  - Done when: every fenced JSON example in `examples/api.md` parses (`python3 -c json.loads`),
    `snitchd check -rules examples/rules.toml` exits 0 on the built binary, and `grep -n
    "inbound" .kiro/steering/fail-safes.md CLAUDE.md` shows the new wording in both
  - _Depends: 2.6_
  - _Boundary: examples/rules.toml, examples/api.md, README.md, .kiro/steering/fail-safes.md,
    CLAUDE.md_
  - _Requirements: 3.7, 4.6, 5.6, 6.2_
- [ ] 3.3 Release, VM rules file and the verification on the dev VM
  - Only with the operator's go: snitch `main` pushed (no-secrets check), lint green, tag
    `v0.4.0`, release verified; in the VM repo: every deferred line of `files/snitchd/rules.toml`
    becomes a name rule for its program (16 lines, 14 programs plus `any`; line 44's duplicates
    skipped), the header no longer lists domain rules as missing, `snitchd check` green in its
    CI with the new pinned version and sha256, deploy; then `scripts/api-check.sh` as the
    operator (phase C passes), `deploy-check.sh` phase A, and with the operator's explicit go
    and the serial console open `deploy-check.sh --trial` with the dev tools; results recorded
    in research.md; deploy-service's revalidation note updated
  - Done when: both scripts pass on the deployed release, the state line is monitor with no trial
    and nothing kept afterwards, the VM repo `main` is pushed with CI green, and research.md
    holds the record with run ids
  - _Depends: 2.6, 3.1, 3.2_
  - _Boundary: git (push, tag), hyperland-forky-worker-vm (files/snitchd/rules.toml,
    group_data/all.py), .kiro/specs/dns-tap/research.md,
    .kiro/specs/deploy-service/tasks.md (revalidation note), the dev VM_
  - _Requirements: 4.1, 6.1, 6.3, 6.4, 6.5_
- [ ] 3.4 Caps, contracts, design constraints and CI
  - Every contract of the design's list has a violation test or is documented as untrippable
    with its behaviour test; the design constraints verified by review are pinned where a test
    can: the decision hook is unchanged (`bpf/snitch.bpf.c` diff empty against `v0.3.1`), the
    daemon imports no resolver (`net.Resolver`, `net.LookupHost`) outside tests, and no exported
    identifier of the new package is without a caller; `lint.yml` gains `go vet -tags root
    ./...` so the root tests keep compiling; caps green; the design's file plan, contract list
    and the "no `return 0`" rule corrected to the two program functions as 1.1's shape test
    reads it; both repos' CI green on `main`
  - Done when: every command of `lint.yml` passes locally, `sh scripts/caps.sh` is green, the
    remote runs are green (run ids recorded in research.md)
  - _Depends: 3.3_
  - _Boundary: `*_test.go` of this spec's packages, minor non-test cleanups in this spec's
    packages (unexport, delete dead code), .github/workflows/lint.yml,
    .kiro/specs/dns-tap/design.md (file plan, contracts, implementation rules),
    .kiro/specs/dns-tap/research.md_
  - _Requirements: 1.2, 2.7, 4.4, 4.6_

## Implementation Notes
- 1.2: implemented by Codex, reviewed by a Claude subagent (APPROVED, four reviewer mutations caught). The controller settled the grammar's open point: a label never starts or ends with a hyphen (RFC 1123), so `-x` stays an invalid value for 2.5's pinned test. New tests went to `decode_name_test.go`, `validate_name_test.go`, `merge_name_test.go` (same package, test-only). `checkNameSlots` hard-codes 4 with a comment (rules cannot import internal/dns); 1.4 may export the constant from rules and have dns reuse it. Downstream still assumes `To` until 1.3/2.x: `learn.go:75` seeds a name rule on the zero address, `apievent.go:75` and `events.go:109` print `invalid Prefix` for a name rule. A mistyped address such as `1.2.3` parses as a name (docs task warns).
- 1.3: `EncodeAddr(r, program, addr)` returns the key with the rule's own proto and first port; the compiler overwrites `k.Proto`/`k.Port` on the returned key with each `Expand(r)` pair (as `encodeRule` does), never mutating a Rule. `ProgramID(res, name)` is 0 for `any`. A named `Observed` has a zero `Addr` by construction: `apievent.go:101` would print `invalid IP` once names reach the learner (2.6 wires `learnedView` Name). Reviewer approved on seven of its own mutations; the Codex MCP truncates long replies to their tail, so later briefs put the status block first.
- 1.1: the C file has no line cap (caps are Go-only); round 1 was rejected for squashing the probe into one-liners. Verifier: keep the `asm volatile` barrier in `read_qname` and `-mcpu=v3` on the Dns go:generate line (see research.md). The record struct is `dns_answer_record` (Go `DnsDnsAnswerRecord`); `rec.slots` carries the slots the kernel ATTEMPTED (EEXIST and failures included), the daemon subtracts file keys and re-puts anyway. A stale `questions` entry is deleted when it is refused. bpf2go also emits `DnsRuleKey`/`DnsRuleVal`; the Go side still addresses the trie with `rules.RuleKey`/`RuleVal`. Root tests: build tag `root`, `sudo go test -tags root ./internal/dns -run DNSProg`.
- 1.5: `Cache.Learn` never expires (the owner runs `Expire` on the 2 s tick) and is O(k) off the eviction path; `Evictions()` counts ADDRESS evictions only (a 5th name evicting a name is not counted): status and 1.6 use that meaning. Eviction ties and the order of `Learn`'s change slice follow map iteration order; consumers must not depend on it. Round 1 was rejected for two whole-map scans per Learn (race run 29 s); now 9-10 s, all in `TestCacheNeverExceedsBounds` (809 evictions x 8192 scan). A min-heap by latest expiry is the fallback if the gate needs to be faster.
- 1.6: `Entry{ID, Name}` carries no expiry (lifetimes belong to the cache; the daemon evicts by asking the cache for the soonest address and calling `Apply(addr, nil, file)`). The compiled set is `map[addr]map[RuleKey]Entry`; `Recompile` is ~40 ms for 50 rules x 8192 addresses on this VM (20 % under the target; pre-size `want` if it ever matters). Reviewer finding fixed by the controller: `Slots` now expands a name rule with `rules.Expand` (an any-proto rule with a port is a tcp slot and a udp slot, so kernel inserts equal `decide()`'s lookup keys) and the validator counts the same combinations per exact name (text `name %q: at most 4 rules (protocol and port combinations) per name`). A fourth test file `compile_apply_test.go` (same package). A parent and a child rule sharing (program, proto, port) on one address: the daemon's re-put decides the id.
