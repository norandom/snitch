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
