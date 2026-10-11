# Requirements Document

## Introduction
snitchd decides on addresses. The rules the Python client ran by name (github.com, pypi.org,
crates.io, docker.io, anthropic.com, ...) are comments in the deployed rules file today, marked
"deferred (DNS tap spec)". This spec gives the daemon a tap on the DNS answers that reach the
host, an address-to-name cache with lifetimes, rules that name a domain, and names on events, so
that a trial no longer cuts the dev tools and the TUI can show "gh -> api.github.com".

The daemon never resolves a name itself, never delays or alters an answer, and the kernel
decision stays an address lookup. A name rule can only make more connections allowed; nothing a
DNS answer carries can make one denied.

## Project Description (Input)
dns-tap: domain rules for snitchd through a tap on DNS answers, so the rules the Python client ran by name (github.com, pypi.org, crates.io, docker.io, anthropic.com, ...) become real rules of the daemon.

Who: the operator of the dev VM (and later fleet hosts) who wants a trial, and eventually kept enforcement, that does not cut the dev tools; today 18 rules in /etc/snitch/rules.toml are comments marked "deferred (DNS tap spec)" and the programs behind them (claude, codex, copilot, gh, git, ssh, node, uv, python, cargo, go, podman, helm, the bar's quota script) are reported in monitor mode and would be denied beyond their address rules in enforce mode.

Current situation: the daemon decides on addresses only (LPM trie keyed by program, family, proto, port, prefix); events and the API carry addresses with no name; the rules file has no way to say a domain; the Python client's rules say "domains" (a host and its subdomains) and "hosts"; the resolver on this VM is the router over plain UDP 53 (no systemd-resolved, no DoH/DoT), programs resolve through libc and the router answers with A/AAAA records and CNAME chains, TTLs of seconds to hours; nothing in the daemon observes those answers.

What should change: the daemon observes DNS answers that reach the host (without delaying or altering them, and without ever resolving anything itself) and keeps a cache from address to the names that answered to it, with their lifetime; the rules file and the API's rule edits accept a destination by name (a domain covering its subdomains) next to addresses; a name rule compiles live into address rules as answers arrive and expire, so the kernel decision stays an address lookup with no name lookup on the connect path; events, the connection table and summaries carry the name(s) an address was known by, so popups and the TUI can show "gh -> api.github.com" and the learned file can record names instead of volatile addresses; the deferred comments in the deployed rules file become rules; the fail-safes hold unchanged (a missing or stale cache can only make a name rule match less, never deny the local network, never block when the daemon is dead; the trial remains the only path to deny); the daemon says in its status how the tap is doing (answers seen, cache size, names known) and the check scripts prove it on this VM: a curl to a name under an allow rule for its program produces an event naming the rule and the name, and a 2-minute trial with the formerly deferred rules in place leaves gh, git, uv, cargo and go working.

## Boundary Context
- **In scope**: observing plain DNS answers (UDP, port 53) from the host's configured resolvers
  to programs on this host; an address-to-name cache; `to = "<domain>"` destinations in the rules
  file, the overlay and the API's rule edits, allow verdict only; live compilation of name rules
  into the kernel's address rules; the name on events, table entries, the learned file and the
  rules view; tap counters in the status; the deferred rules of the deployed file turned into
  rules; the checks on the dev VM.
- **Out of scope**: resolving names (the daemon sends no query); DNS over TCP, DoH, DoT and
  `/etc/hosts` entries (connections to such addresses have no name and fall to address rules;
  documented); deny rules by name (a forged answer must never be able to deny anything; the
  trial stays the only way to deny); per-process scoping of names (the cache is host-wide, a
  rule names the program it applies to); matching by TLS server name; persisting the cache
  across daemon restarts; the Public Suffix List (a rule for `github.io` covers every site under
  it; documented); the popups and the TUI (next spec) and Velociraptor.
- **Adjacent expectations**: `rule-loading` owns the rules model, validator and encoder, extended
  here for a name destination; `daemon-api` owns the wire format, extended by a `name` field and
  tap counters (additive; existing clients keep working); `persistent-trial` and the fail-safes
  are unchanged except that fail-safe 1 ("egress only") is scoped: the tap reads DNS answers
  addressed to this host's own sockets and nothing else inbound, and it can never produce a
  deny; `deploy-service` owns the deployed rules file and the deploy task, revalidated when the
  deferred comments become rules.

## Requirements

### Requirement 1: Observing DNS answers
**Objective:** As the operator, I want the daemon to learn which names resolved to which
addresses from the answers my programs already receive, so that name rules work without the
daemon resolving anything or standing in the resolver's path.

#### Acceptance Criteria
1. When a UDP answer from a configured resolver (an address listed in the host's resolver
   configuration, source port 53) is delivered to a socket of a program on this host, the daemon
   shall record every address record (A and AAAA) of the answer under the name that was asked.
2. The daemon shall not send any DNS query, shall not delay, drop, or modify any answer, and
   shall not change how programs resolve names.
3. If an answer arrives from an address that is not a configured resolver, or is not an answer to
   a question a local socket sent (identifier and question name differ), the daemon shall ignore
   it and count it as ignored.
4. When the answer carries a CNAME chain, the daemon shall record the addresses under the name
   that was asked, not under the chain's intermediate names.
5. When the host's resolver configuration changes, the daemon shall use the new resolver addresses
   within 10 s without a restart.
6. If an answer is truncated, arrives over TCP, or is encrypted (DoH, DoT), the daemon shall not
   learn from it and connections to its addresses shall be handled by address rules only.
7. While the tap is not available (the kernel refuses it, or it is turned off by a flag), the
   daemon shall run as before, say so in its log and status, and treat every name rule as
   matching nothing.

### Requirement 2: The address-to-name cache
**Objective:** As the operator, I want the daemon to remember names for as long as they are valid
and no longer, so that name rules match the addresses programs actually connect to without
accumulating stale addresses forever.

#### Acceptance Criteria
1. When an address record is learned, the daemon shall keep it for the record's TTL, with a floor
   of 60 s and a ceiling of 24 h, measured from the answer.
2. When the same address is learned again, the daemon shall extend its lifetime and keep every
   name it was learned under.
3. When an entry's lifetime ends, the daemon shall forget it, and a name rule shall no longer
   match that address through this entry.
4. The daemon shall bound the cache (addresses and names per address); when the bound is reached
   it shall evict the entries closest to expiry first and count the evictions.
5. The cache shall start empty at daemon start; names are learned again from new answers.
6. A cache entry's expiry shall not affect a connection that was already allowed: the decision is
   taken at connect time only.

### Requirement 3: Rules by name
**Objective:** As the operator, I want to write `to = "github.com"` in a rule, so that the rules
the Python client ran by name are expressible without listing addresses.

#### Acceptance Criteria
1. When a rule's `to` is a domain name, the rule shall match a destination whose address was
   learned under that name or any name below it (`github.com` covers `api.github.com`), with the
   same program, protocol and port constraints as an address rule.
2. The daemon shall accept a domain name in `to` in the rules file, in the overlay, and in the
   API's `rule.add` and `rule.remove`, with the verdict `allow` only.
3. If a name rule has the verdict `deny`, the daemon shall refuse the rules file (at `check` and
   at load), the overlay (base rules stay in effect, the error is reported as today) or the API
   request, with a message that names the rule and says a deny by name is not supported.
4. If `to` is neither an address, a prefix, nor a well-formed domain name (labels of letters,
   digits and hyphens, at most 253 characters, no leading dot or wildcard), the daemon shall
   refuse it with a message that quotes the value.
5. The daemon shall treat a name rule's identity (program, name, protocol, port) like an address
   rule's for duplicates in a file and for shadowing between the overlay and the base file.
6. When the rules are listed (`rules` over the API, `snitchd status`), a name rule shall show its
   name as written, and the count of effective rules shall count it once whatever the number of
   addresses it currently matches.
7. The documented rules format shall say that a name covers its subdomains, that only names seen
   in plain DNS answers of this host match, and that an address shared by many names (a CDN) is
   allowed for the program by any one of its matching name rules.

### Requirement 4: Live compilation and the fail-safes
**Objective:** As the operator, I want name rules to take effect as programs resolve names,
without a lookup on the connect path and without any new way to be locked out.

#### Acceptance Criteria
1. When an address is learned under a name that a name rule covers, the daemon shall have the
   corresponding address rule in effect for that program before the program can use the answer
   (a connect right after the answer is matched by the rule).
2. When a cache entry expires or is evicted, the daemon shall remove the address rules compiled
   from it within 10 s, unless another live entry or rule still produces them.
3. When a name rule is added, changed or removed (reload, overlay, API), the daemon shall
   recompile its address rules from the current cache within the existing reload cadence.
4. The kernel decision shall remain an address lookup: no name lookup, string comparison or wait
   happens on the connect path.
5. The daemon shall never compile a deny from a learned name: the tap and the cache can only
   add allow rules, and a forged or poisoned answer can at worst allow addresses for the program
   a name rule names, for the lifetime of the entry.
6. Fail-safes 2 to 5 shall be unchanged: the local network stays allowed in the kernel before any
   rule, a dead or wedged daemon fails open and detaches the tap with the other programs, the
   kill switch is honoured, and deny stays a timed trial; fail-safe 1 shall be scoped in the
   steering to "egress decisions only; the DNS tap reads answers to this host's own sockets and
   can never deny".
7. Compiled address rules shall count against the kernel's rule capacity; the daemon shall report
   the count and, if the capacity is reached, log it once, keep the file's rules in effect and
   skip further compiled rules (the connection is then handled as if the name were unknown).

### Requirement 5: Names where the operator looks
**Objective:** As the operator, I want events, the connection table, the learned file and the
status to carry the names behind addresses, so that popups and the TUI can show "gh ->
api.github.com" and the learned file can be edited by name.

#### Acceptance Criteria
1. When an event's destination address has a live cache entry, the event shall carry the name
   (the name most recently learned for that address) next to the address, in the API and in the
   log line; an unknown address shall carry no name.
2. When a connection was matched by a compiled rule, the event's rule reference shall name the
   name rule it came from (its id, note and source), not a per-address entry.
3. The connection table's entries and summaries shall carry the name as their events did; the
   table key shall stay the address (two names for one address are one entry).
4. While learning is on, an observation whose address has a name shall be recorded under the
   name, and the learned file shall write `to = "<name>"` for it; observations without a name
   stay addresses as today.
5. The status (`snitchd status` and the API's `status`) shall report the tap: on or off and why,
   answers seen, answers ignored, cache entries, names, compiled rules, evictions.
6. Every local user shall read names over the API as they read addresses today; the
   documentation shall say that events with names are a record of the host's lookups.

### Requirement 6: Deployment, documentation and verification on the dev VM
**Objective:** As the operator, I want the deferred rules to become real rules on this VM and
proof that a trial leaves the dev tools working.

#### Acceptance Criteria
1. The deployed rules file in the VM repo shall carry every "deferred (DNS tap spec)" line as a
   name rule (16 lines, 14 programs plus `any`), validated by `snitchd check` in the VM repo's CI,
   and the file's header shall no longer list domain rules as missing.
2. The documentation (README, `examples/rules.toml`, `examples/api.md`) shall describe name
   rules, the `name` field, the tap counters and the limits (plain UDP DNS only, host-wide cache,
   no deny by name, no Public Suffix List).
3. The check script shall prove on this VM, as the operator: the status shows the tap on, a curl
   to a name under a name rule for its program produces an event within 1 s carrying the rule and
   the name, a curl to the same host by address produces an event without a name, and the
   compiled rule disappears after the entry expires (a short-TTL name or a forced reload).
4. The trial check (`deploy-check.sh --trial`, with the operator's go and the serial console
   open) shall run `gh`, `git`, `uv`, `cargo` and `go` network commands during a 2-minute trial
   and pass when none of them is denied and the trial ends at its deadline.
5. A release shall be tagged and pinned in the VM repo, deployed, and the checks above recorded
   in the research log before the spec is validated.
