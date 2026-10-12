# Research & Design Decisions: dns-tap

## Summary
- **Feature**: `dns-tap`
- **Discovery Scope**: Complex Integration (a new kernel program, the rules model, the API, the deployed file)
- **Key Findings** (requirements phase, 2026-10-11, three parallel research threads):
  - Fail-safe 1 ("egress only, nothing looks at inbound traffic") collides with a DNS tap. The
    requirements scope it: the tap reads DNS answers addressed to this host's own sockets, never
    anything else inbound, and can never produce a deny (name rules are allow-only).
  - The answer-to-connect gap on this VM is as low as 291 µs (gh), 55-71 µs inside curl between
    the resolver returning and `connect()`. A user-space cache update cannot win that race; the
    compiled address rule has to be in place when the answer is delivered (Req 4.1), which points
    at parsing in BPF and writing the maps in-kernel (Calico's "Inline" mode shape).
  - The resolver on this VM is the router 10.0.0.1 over plain UDP 53 (dhcpcd-written resolv.conf,
    `hosts: files dns`, no stub, no DoH/DoT, no local listener on 53, TCP 53 works but is never
    used by dig for these names). Every observed answer is one UDP datagram, 55 to 262 bytes,
    never truncated; CNAME chains exist (files.pythonhosted.org -> fastly) and TTLs range from 25 s
    to 71841 s. The daemon classifies all of it `allow-local` (the resolver is RFC 1918), so the
    port-53 rules in the deployed file never match here.
  - The kernel (7.2.6, CONFIG_BPF_LSM, CGROUP_BPF) has `bpf_dynptr_from_skb`, `bpf_dynptr_slice`,
    `bpf_loop`, `bpf_for_each_map_elem`, `bpf_skb_load_bytes`; `cgroup_skb` is available and the
    root cgroup has no ingress program (systemd's `sd_fw_ingress` sits in per-service cgroups,
    all `multi`); the repo's `bpf/vmlinux.h` matches the live BTF for these names.
  - Prior art splits on semantics: Little Snitch scopes names per process and falls back to SNI;
    OpenSnitch keeps a host-wide `map[IP]name` forever (no TTL, no bound, last writer wins);
    Cilium/Calico compile names to CIDR sets honouring TTL with a floor, bound IPs per name,
    learn only from trusted resolvers, and either hold the answer until the datapath is ready
    (forbidden here) or accept a first-SYN miss. No firewall applies the Public Suffix List.

## Research Log

### Codebase anchors (where a name destination lands)
- **Rules model**: `Rule.To netip.Prefix` (`internal/rules/file.go:45-58`), `ParsePrefix`
  (`decode.go:134`), used by both the file decoder and the API's `parseEditKey`
  (`cmd/snitchd/apiwrite_rules.go:50`). Identity for duplicates and overlay shadowing is
  `ruleKey{program,to,proto,port}` via `expandedKeys` (`validate.go:49`, `merge.go:11`). `Encode`
  (`encode.go:44`) requires a valid prefix and writes `RuleKey`/`RuleVal{Verdict, Id}`; `Diff` is a
  pure map diff, so compiled entries fit as extra `Rules` keys. `out[k] = val` overwrites silently:
  two rules producing the same key collide (allow-only name rules make the collision harmless).
- **Kernel**: `rules` LPM trie 65536 entries NO_PREALLOC, `rule_val.id` opaque and copied to
  `event.rule`; no ingress or skb parsing exists; `count_egress` is the only `cgroup_skb` program
  (root, `multi`). Bindings via bpf2go `-type` flags in `internal/bpf/gen.go`.
- **Daemon**: `reload(full)` under `mu` computes `Diff` against the current snapshot and applies
  puts then deletes one entry at a time (`state.go:45-55`); a third trigger (cache change) has to
  go through the same lock or a parallel entry set. `publish` fires the API's `state` event
  ("rules reloaded") so a per-answer recompile must not publish.
- **API**: `Event`/`Entry` (`internal/api/types.go:73-114`) have no name field; `api.md:451` lists
  `remoteName` as "domain rules come with the DNS spec"; `Status` holds counters; table key is
  `{Program, Path, Addr, Port, Proto}` (the address stays the key, Req 5.3).
- **Learning**: `learnKey{subject, addr, proto, port}` (`learn.go:33`); `File()` writes /32 and
  /128 rules; a name needs a key branch (Req 5.4).
- **Deployed file**: 16 deferred lines (14 programs plus `any` and the waybar note), listed in the
  codebase survey with the programs' paths; the spec description said 18, corrected to 16.
- **Checks**: `scripts/api-check.sh` (python3 socket client, operator, 10 s dedupe caveat) and
  `scripts/deploy-check.sh --trial` (root, phase B trap with `snitchd end`) are the places for
  Req 6.3 and 6.4.

### Prior art (sources in the thread's list; obs = stated by the source)
- Little Snitch: domain list = "the name is in any of the domains listed", hostname list = exact;
  precedence IP > host > domain, fewer labels win; unknown name shows the bare IP and name rules
  do not match; names are learned per process (which process resolved what) with an SNI fallback
  that delays the first request (not acceptable here); its Linux help admits heuristics and table
  overflow. OpenSnitch: `dest.host` literal or regex, subdomains need `.*\.github.com`; three
  sources (nfqueue UDP answers, libc uprobes for DoH apps, resolved varlink); TTL ignored,
  unbounded map (a 12k-entry hash map once silently stopped delivering); CNAME target -> owner
  links so events show the queried name. Portmaster is the resolver itself (the opposite design).
  Cilium: `matchName` exact, `matchPattern` `*` one label; toFQDNs compiles to CIDR; "only IPs in
  intercepted DNS responses are allowed"; TTL with `--tofqdns-min-ttl`, 50 IPs per name, expired
  IPs with live connections kept; proxy holds the answer up to 100 ms. Calico: `dnsTrustedServers`,
  `dnsExtraTTL`, cache file, `Inline` eBPF mode updating ipset maps from BPF (needs `bpf_loop`).
- Threats (RFC 5452): accept only answers matching an outstanding question's id, qname and
  5-tuple, from the configured resolver; in-bailiwick records only. With allow-only name rules
  a forged answer can at worst over-allow for the named program for one lifetime (Req 4.5).
- Over-match: a CDN address serves many names; prior art accepts it and bounds it with TTL,
  per-name caps and trusted resolvers; per-process scoping is Little Snitch's answer and is out
  of scope here (host-wide cache, rules per program).

### Tools on this VM
- `gh` is static (`CGO_ENABLED=0`, pure-Go resolver reading resolv.conf, EDNS0); `cargo`, `curl`
  glibc `getaddrinfo`; cargo probes every candidate address with `connect udp :443` (RFC 6724
  source selection) then happy-eyeballs TCP; A and AAAA questions collapse into one API event
  because the key is program+addr+port+proto. Absent on the VM: strace, tcpdump, socat, bpftrace.

## Architecture Pattern Evaluation (preliminary, for the design phase)
| Option | Description | Strengths | Risks / Limitations |
|---|---|---|---|
| BPF parses answers, writes the trie in-kernel | `cgroup_skb/ingress` at the root; a `domains` map (suffix hash -> rule list) consulted per label suffix; `bpf_map_update_elem` on the LPM trie | Wins the 291 µs race; no delay to DNS | Verifier budget for name parsing (bounded loops, label compression); LPM updates from BPF; the daemon must mirror the kernel's entries for status, expiry and Diff |
| BPF parses, ring buffer to user space, daemon writes the trie | parse in BPF or Go, update from Go | Simple, all logic in Go | Loses the race: the first connect after an answer misses the name rule (gh at 291 µs) |
| Hybrid: BPF writes the trie and emits a record; the daemon owns expiry and the cache view | kernel for the hot path, Go for lifetimes and views | Matches the repo's shape (jobs, snapshots) | Two writers to one trie need an ownership rule (compiled keys tagged, e.g. by rule id range or a shadow map) |

## Design Decisions
- Deferred to the design phase: the tap point (`cgroup_skb/ingress` at the root vs per-socket),
  the in-kernel name match (suffix hash per label), how compiled entries are told apart from file
  entries in the trie, the cache bound (addresses, names per address), the question-tracking for
  Req 1.3 (query ids seen at egress by socket cookie: `count_egress` already runs there), the
  resolver list source (`/etc/resolv.conf` watch).

---

## Gap analysis (2026-10-11, after requirements approval)

### Current state
- The decision pipeline is rules file -> `Resolve` -> `Encode` -> `Diff` -> `apply` (one `Put`/`Delete`
  per entry) -> LPM trie, with a snapshot behind an atomic pointer and a reloader that serialises
  full reloads and 10 s re-resolves under one mutex. A rule has exactly one `To netip.Prefix`;
  `encodeRule` has a contract that panics on an invalid prefix (the first thing a name rule hits
  today, in `loadRules`, `reresolve` and `snitchd check`).
- Rule ids are dense 1..n per snapshot and renumbered on every reload; the kernel copies the id
  into events; `ruleOf` resolves it against the current snapshot.
- The kernel side has no ingress program; `count_egress` already runs at the cgroup2 root on
  egress with `multi`, which is the shape (attach, soft failure, `sweeper` job with delegates)
  for the two DNS programs.
- The API's `Event`/`Entry`/`Observation`/`RuleView`/`Status` have no name; the table key is the
  address; `TestEventJSONNames` and friends pin the key sets; the status file has a fixed key
  set with `version` last.
- The dev VM: router resolver over single-datagram UDP, no stub, no DoH; tools resolve per
  process (glibc, pure-Go); the answer-to-connect gap is 291 µs at the fastest.

### Feasibility (verifier probe, this VM, kernel 7.2.6; reference source `dnsprobe.bpf.c` next to this file)
- `cgroup_skb/ingress` program `dns_answer`: 26,212 processed instructions, 496 bytes of stack,
  accepted; `cgroup_skb/egress` `dns_query`: 8,308, accepted. `bpf_map_update_elem` on the LPM
  trie from cgroup_skb is accepted (inlined `trie_update_elem`). `bpf_get_socket_cookie(skb)` on
  ingress is the receiving socket's cookie (`__cgroup_bpf_run_filter_skb` swaps `skb->sk` to the
  socket the datagram is queued to): the same UDP socket sends the query and receives the
  answer, so `(cookie, dns id) -> qname` recorded at egress joins the answer to its question.
- `bpf/dns.bpf.c` as committed (task 1.1: slots in the record, `BPF_NOEXIST`, `test_skip_question`,
  5 s question age, `-mcpu=v3` on this object only): `dns_answer` 32,287 verified instructions,
  `dns_query` 8,344, both accepted on 7.2.6 (`sudo go test -tags root ./internal/dns -run
  '^TestDNSProgLoads$'`, 2026-10-12). Two verifier lessons from the first round: clang drops a
  range check it has proven and the verifier then sees `R4 invalid zero-sized read` on the
  bounded `bpf_skb_load_bytes` of the question name; an `asm volatile("" : "+r"(len))` barrier
  before the check keeps it, and `-mcpu=v3` (32-bit subregister ops) lets the verifier carry the
  bound into the helper call. bpf2go refuses a record struct named like the program, hence
  `dns_answer_record`.
- The hook runs in `sk_filter_trim_cap()` from `udp_queue_rcv_one_skb()`, per receiving socket,
  AF_INET/AF_INET6 only, `skb->data` at the network header, read-only; loopback deliveries take
  the same path (a future local stub would be seen). Return 1 on every path; 0 would drop.
- Shapes that failed: two consecutive `bpf_loop`s (884k instructions), byte-wise lowercase or
  length state machines (states do not prune), nested compile loops inline (>1M). Shape that
  works: one `bpf_loop` stepping one label or one RR per iteration, compiling each address where
  it is found; SWAR lowercase over eight u64 words; the ring-buffer record reserved before the
  walk so addresses never sit on the stack; `bpf_skb_load_bytes` (the dynptr variant verifies
  too but at exactly 512 bytes of stack).
- Domain key layout: the lowercase name with a `.` before every label, left aligned, zero padded
  to 64 bytes (`.github.com`); the suffix at label k is the same buffer from `dots[k]`, so one
  `bpf_map_lookup_elem(&domains, buf + dots[k])` serves every level without hashing.
- Bounds: names up to 62 characters and 16 labels, 8 suffix levels, 4 rule slots per exact name,
  32 answer RRs, 8 addresses per answer, 16 resolvers, 4096 outstanding questions (LRU).

### Gaps
| Need | Today | Gap |
|---|---|---|
| A name destination in `Rule` | `To netip.Prefix` only | `Name string`, `ParseName`, `Dest()`, identity in `ruleKey`, `formatRule`, `Encode` skipping names |
| Compiled address entries | file entries only, `Diff` over one set | a second entry set owned by the daemon, written first by the kernel, re-put with the snapshot's ids, deleted on expiry, recompiled on reload |
| Name match in the kernel | none | `domains` hash (64-byte key, 4 slots) rewritten on every reload |
| Answer observation | none | two cgroup_skb programs, `resolvers`, `questions`, `dns_answers` ring buffer, `dns_stats` |
| Cache | none | addr -> names + expiry, bounded 8192 x 4, evict closest expiry |
| Names on events/table/learned/status | none | `Name` fields, a `nameOf` delegate for `toEvent`, status record key |
| Resolver list | none | `/etc/resolv.conf` watch -> `resolvers` map |
| Verification | api-check, deploy-check | a DNS phase and the dev-tool trial |
| Deployed file | 16 deferred comment lines | name rules, after the release that reads them |

### Options
- **A. Extend in place**: `Name` on `Rule`, compile inside `reload`, cache inside `reloader`.
  Rejected for shape: `reload.go`/`daemon.go`/`apiwrite_rules.go` are at or near the caps, and the
  cache has its own lifecycle (per-answer updates, 2 s expiry) unrelated to file reloads.
- **B. New package `internal/dns` + new daemon files**: a pure package for the cache, the
  compiler (name rules x addresses -> trie keys with ids) and the kernel key encodings, with
  tests without root; `cmd/snitchd/dns*.go` for attach, the ring-buffer reader, the expiry tick,
  the resolver watch and the reload hook. Chosen.
- **C. User-space-only compilation** (kernel emits records, daemon writes the trie). Rejected:
  loses the first connect after an answer (291 µs vs the daemon's wakeup), which Req 4.1 forbids.
- **D. Separate BPF object** `bpf/dns.bpf.c` loaded with `MapReplacements` for `rules`, vs adding
  to `snitch.bpf.c` (316 lines). Chosen: separate object; the LSM program is untouched, the DNS
  object fails soft on its own, and the shared trie is the only coupling.

## Design decisions (synthesis)
- **Generalisation**: a "compiled entry set" owned by the daemon next to the file's entry set is
  the general shape; the DNS cache is its first producer (a later producer could be a popup's
  temporary allow). The interface is `Compiled` with `Put`/`Expire`/`Recompile`; the
  implementation stays DNS-only.
- **Build vs adopt**: no Go DNS library (the kernel parses; the daemon only receives parsed
  records); `golang.org/x/net/dns/dnsmessage` is used in tests to build answer datagrams for
  `Program.Run`; cilium/ebpf for `MapReplacements` and `BPF_PROG_TEST_RUN`.
- **Simplification**: names are allow-only, host-wide, one name per event, no persistence, no
  PSL, no TCP 53, no per-process scoping; one `bpf_loop`; the daemon never parses packets.
- **Consistency rule**: the kernel inserts with `BPF_NOEXIST` (never over a file key); the
  daemon is the authority: on every record it re-puts the keys that are not file keys with the
  current snapshot's ids, tracks them with their expiry, deletes on expiry, and recompiles all of
  them inside `reload` after `publish` (the `domains` map is rewritten first). A kernel insert
  with a stale id is corrected by the daemon's re-put of the same record.
