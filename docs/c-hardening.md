# c-hardening: contracts, the bindings check, fuzzing

The egress program (`bpf/snitch.bpf.c`) runs in the kernel on every `connect()` and
unconnected `sendmsg()`, and the DNS tap (`bpf/dns.bpf.c`) parses packets whose content
somebody on the path chooses. The c-hardening feature makes that code, and the daemon code
that reads what it produces, defensible to a reviewer: the compiler reports more and every
warning fails the build, the assumptions the code rests on are written down where the build
or the running system checks them, hostile DNS input is run against the tap with a stated
outcome per packet, the committed kernel objects are shown to match their source, and the
daemon's decoders of untrusted input are fuzzed. This file is the feature's documentation
record; the spec is `.kiro/specs/c-hardening/`.

One principle governs every part: **a kernel program cannot abort.** There is no exception
to throw and no process to end. So every assumption that turns out false inside a kernel
program resolves to the fail-safe outcome — allow for the egress program, pass for the tap —
and leaves a count an operator can read. Nothing in this feature denies, drops or alters
traffic as the response to a violated assumption, and nothing changes a mode or the decision
order (kill switch, heartbeat, local network, rules, mode). See CLAUDE.md, "Fail-safes".

## The contract approach at three levels (Req 9.5)

A contract here is a stated assumption plus what happens when it is false. Where it can be
checked decides what the failure looks like: a build that stops, a counter that moves while
traffic is allowed, or a daemon that exits.

### 1. Build time: the compiler refuses a broken layout

`bpf/contract.h` defines three build-time forms. Each is a C11 `_Static_assert` and emits no
instruction into the loaded program (Req 3.6):

- `CONTRACT_SIZE(type, bytes)`: `sizeof(type)` is exactly `bytes`.
- `CONTRACT_OFFSET(type, member, bytes)`: the member sits at that byte offset.
- `CONTRACT_CONST(expr, msg)`: a relation between constants holds.

What they pin:

- The size of every structure shared with the daemon (`event`, `exe_key`, `control_state`,
  `byte_count`, `rule_key`, `rule_val`, `domain_key`, `domain_slot`, `domain_val`,
  `resolver_key`, `q_key`, `q_val`, `dns_answer_record`) and the offset of every member the
  daemon reads or writes (Req 3.1).
- The relations the tap's bounded walks rely on (Req 3.3): `NAME_MAX` is a power of two and a
  multiple of 8; `STEPS_MAX` stays within the kernel's `bpf_loop` limit (1 << 23); the
  record's `slots` array has `LEVELS_MAX * SLOTS_MAX` elements; `LABELS_MAX >= LEVELS_MAX`;
  `RR_MAX >= ADDRS_MAX`.
- The counter maps: `SS_MAX` (8) and `ST_MAX` (13) equal the map sizes and the daemon's name
  tables.

The `rules` trie is shared by both programs (the tap writes allow entries into the trie the
egress program reads), so its key and value have exactly one definition: `bpf/rules_abi.h`,
included by both programs, with its own size and offset contracts and the statement that the
fixed part of the key (program, family, proto, port) is the 64 bits every `prefixlen` covers
first. A change there fails both objects (Req 3.4).

A violated build-time contract fails `go generate ./internal/bpf/` and the message names it,
for example `contract: sizeof(struct rule_val) == 8` or
`contract: STEPS_MAX <= bpf_loop limit BPF_MAX_LOOPS: ...` (Req 3.2). The daemon's side of
the same agreement is `internal/bpf/abi_test.go`: it reads each shared structure's size from
the BTF of the embedded objects and compares it with the generated Go type and the hand
mirrors in `internal/rules` and `internal/dns`; a mismatch fails `go test` and names the
structure (Req 3.5). It needs no root.

### 2. Run time in the kernel: counted, fail-open

The runtime form is `CONTRACT(cond, on_violation)`: it yields 1 when `cond` holds; otherwise
it runs `on_violation` — always a counter increment and nothing else — and yields 0. It never
returns from the enclosing function and never picks a verdict. The call site writes the
fail-open branch next to it, so the outcome is visible in review:

```c
else if (!CONTRACT(c != NULL, bump(SC_CONTROL_SLOT)))
	verdict = V_ALLOW_STALE;  // contract: control slot readable; violated -> allow as stale
```

The egress program has four contracts, checked where the value was read before this feature
(Req 4.1, 4.6, 4.7):

| Contract | Counter key | On violation | Event verdict |
|----------|-------------|--------------|---------------|
| the kill-switch slot is readable | `kill_slot` | allow | `allow-stale` |
| the control slot is readable | `control_slot` | allow (as before, now counted) | `allow-stale` |
| a found rule's verdict byte is 1 (allow) or 2 (deny) | `rule_verdict` | allow, in every mode; the rule id stays in the event | `allow-monitor` |
| the mode is 0 (monitor) or 1 (enforce) | `mode` | treated as monitor (as before, now counted) | `allow-monitor` |

One decision changed, and only on a violated contract: a rule whose verdict byte is neither
1 nor 2, met in enforce mode, used to fall through to the default deny; it now allows. A
garbage byte in a map is a defect, and a defect must not cut a connection. For every input on
which no contract is violated the decisions are the same as before (Req 9.1).

The egress program also has counters of its own (Req 4.5), in the per-CPU array
`snitch_stats` (not pinned): `decisions` (the verdict chain was reached), `addr_unreadable`
(the destination could not be read: allowed, no event), `no_exe` (no executable file:
program 0) and `event_lost` (the ring buffer was full: the verdict stands, the event is
missing).

The DNS tap has two contracts, appended after its eleven existing counters in `dns_stats`
(indices 0..10 keep their meaning and order, Req 4.8):

| Contract | Counter key | Where | On violation |
|----------|-------------|-------|--------------|
| a name has 1..`LABELS_MAX` labels and a wire length below `NAME_MAX` | `name_shape` | after `read_qname`, in the answer path and before a question is stored | the packet passes, no entry, no record |
| every label offset (`dots[k]`, k < labels) lies inside the name | `dot_range` | in the answer path, before the ring buffer reservation | the packet passes, no entry, no record |

Both sit before the first trie insert, so a violated tap contract cannot add an allow entry.
The masks that exist only to satisfy the verifier stay; the contracts make visible the case
where such a mask would have changed a value.

The operator reads all of these counters in the daemon's status (`counters`, see
`examples/api.md`, "status"). **A non-zero contract counter is a defect to report** — not a
tuning signal and not an attack indicator by itself.

### 3. The daemon: programming errors exit, input errors return

The daemon has two kinds of failure and treats them differently:

- A programming error — a violated `internal/contract` `Require`, `Ensure` or `Invariant` —
  panics with a `*contract.Violation`. The daemon logs it and exits with code 70. An exit
  closes the BPF links (they are not pinned), so the programs detach and everything is
  allowed: the daemon's contracts fail open too, by ending the process.
- Bad input is never a programming error. The decoders of kernel records (`decodeEvent` in
  `cmd/snitchd`, `dns.Decode`) reject a record whose length differs from the expected size
  with an error (Req 8.3), and `dns.DecodeContracts` rejects any number of counter values other
  than the tap's contracts; the event reader logs once per kind, counts the record as undecodable and
  continues. A malformed API line or rules file is answered
  with an error, as before.

## Compiler diagnostics (Req 1)

Both `go:generate` lines in `internal/bpf/gen.go` compile with the extended set
`-Wall -Werror -Wextra -Wshadow -Wvla -Wundef -Wpointer-arith -Wimplicit-fallthrough
-Wstrict-prototypes -Wnull-dereference -Wconversion`. Any warning fails the generation.

`vmlinux.h` is generated (a BTF dump of the kernel's types), not authored, so it is included
as `<vmlinux.h>` and found through `-isystem ../../bpf`: the compiler treats it as a system
header and reports nothing in it. The authored headers in the same directory (`contract.h`,
`rules_abi.h`) are included with quotes and stay user headers, so every warning still applies
to them (measured with clang 21.1.8, research.md).

Every fix spells out a conversion the compiler already performed, so the generated
instructions did not change. Where a warning cannot be fixed in the code, the site carries a
comment that says why:

- the casts at the `sk_protocol` and `tgid` reads and at the tap's conversion sites make the
  conversion explicit; where the bound that makes it lossless is not visible on the line, a
  comment states it (`// n < ADDRS_MAX: fits 8 bits`);
- parameters fixed by a hook or callback signature (`addrlen`, `size`, the `bpf_loop` index)
  are marked `__attribute__((unused))` with the reason in a comment;
- the two `BPF_PROG` hooks sit in one `#pragma clang diagnostic` region that ignores
  `-Wunused-parameter`, because libbpf's macro declares a `ctx` the hooks never use; the
  comment above the region says so.

The same pass resolved the four cppcheck `constVariablePointer` findings (`snitch.bpf.c`
218/219/241 and `dns.bpf.c` 356 at the time; the pointers now point to const) and the two
`knownConditionTrueFalse` reports in `dns.bpf.c` (`pkt_init` returns `void`, its two dead
error branches are gone). Their six suppressions are gone from
`bpf/cppcheck-suppressions.txt`, and every remaining suppression stands for a modelling limit
of the analyzer, not for a known defect (Req 2).

## Regenerating the bindings so the check passes (Req 7.5)

The bindings are the committed bpf2go output in `internal/bpf/` (the two `.o` objects and
their generated `.go` files). Releases ship them as committed; no release step runs a C
compiler (Req 7.7). After any change to `bpf/*.c`, `bpf/*.h` or the flags in `gen.go`:

```sh
scripts/bindings-regen.sh --docker --write   # regenerate in the pinned image, write internal/bpf/
git diff --stat internal/bpf/                # review, then commit the C and the bindings together
scripts/bindings-regen.sh --docker --check   # optional: the same comparison the pipeline makes
```

`--docker` runs the script inside the pinned image (a docker daemon the user may reach, no
sudo); the container needs network for apt and the Go module download. Exit codes: 0
identical or written, 1 stale or generation failed (the stale files are named), 2 usage, 3 the
compiler differs from the pin, 4 the environment is unavailable. `--help` prints the usage.

Why not the host toolchain: the bytes depend on clang and llvm, and whether the C compiles at
all depends on libbpf's helper declarations. The workstation's libbpf-dev 1.6.3 declares
`bpf_d_path(struct path *, ...)` and fails `snitch.bpf.c` on the const path argument under
`-Werror`; forky's 1.7.0 declares it const, matching `vmlinux.h`. Do not cast the const away
to make an older libbpf build. A plain `go generate ./internal/bpf/` is fine for a quick
compile on a host that happens to have the same versions, but only the pinned run decides.

The verdict is tied to one toolchain, named in exactly one place, the top of
`scripts/bindings-regen.sh`:

- compiler line `Debian clang version 21.1.8 (13)` (`CLANG_EXPECTED`);
- packages `clang=1:21.1.8-74 clang-21=1:21.1.8-13 llvm=1:21.1.8-74 llvm-21=1:21.1.8-13
  libbpf-dev=1:1.7.0-1` (`PACKAGES`);
- apt from snapshot.debian.org `20261123T000000Z` (`SNAPSHOT`, the state the image was built
  from, so the versions stay installable after forky moves on; `BINDINGS_SNAPSHOT` overrides
  it, empty means the image's live sources);
- the image `debian@sha256:f3671d5a279b1ae356c7318ce6cdb84c600c2063d708ee97d3cce607bebfb85a`
  (`IMAGE`), which must equal `imageBindings` in `.dagger/pins.go`.

When the pin has to move (a new clang, a libbpf the old snapshot lacks): change `IMAGE`,
`PACKAGES`, `CLANG_EXPECTED` and `SNAPSHOT` in the script and `imageBindings` in pins.go in
one commit, regenerate with `--docker --write`, review the object diff, and run the root
checks (below) on that commit — a new compiler produces new instructions, and only the
verifier on a real kernel says they load.

## The bindings check (Req 7)

`dagger call bindings` is the eighth check of the pipeline (`+check`, so `dagger check` runs
it; `lint-all` and `rugged` include it). It reads `IMAGE` from the script and refuses to run
when it differs from `imageBindings`, then runs `scripts/bindings-regen.sh --install --check`
in that image: install the pinned packages, compare `clang --version` with the pin, regenerate
on a copy of the tree, compare every file of `internal/bpf/` byte for byte. Its failures stay
distinct:

- `bindings are stale: <files>` — the C or the flags changed without regeneration, or a
  committed binding was edited by hand (Req 7.2, 7.3);
- the compiler differs from the one the verdict is tied to (Req 7.5);
- `bindings: environment unavailable` — the image or the pinned packages cannot be had; the
  check fails rather than passes (Req 7.8).

The compiler only observes: the check writes nothing back and exports nothing (Req 7.6). In
CI it is the third dispatch of the `linters` job in `.github/workflows/lint.yml`, beside
golangci and cppcheck, and like them it is skipped on `v*` tags, so the release gate stays
the committed bindings with no compiler in it. The Dagger engine caches a call by its inputs:
a second `dagger call bindings` on an unchanged tree answers from the cache in about a
second; a real run needs a changed source (CI runners start cache-cold).

## Fuzzing (Req 8)

Six fuzz targets cover the daemon's decoders of untrusted or semi-trusted input:

| Target | Package | What must hold |
|--------|---------|----------------|
| `FuzzDecodeEvent` | `./cmd/snitchd` | value or error; the event accessors do not panic on any decoded value |
| `FuzzDecode` | `./internal/dns` | value or error; a decoded record has 1-8 addresses and a valid name |
| `FuzzParse` | `./internal/api` | a request line yields a request or an error |
| `FuzzLineReader` | `./internal/api` | lines beyond the limit are rejected without unbounded buffering |
| `FuzzParse` | `./internal/rules` | a rules file parses or returns an error |
| `FuzzParseOverlay` | `./internal/rules` | base plus overlay parse and merge or return an error |

The ordinary `go test ./...` (the `go` check) runs every target's seeds as plain test cases
(Req 8.4). To fuzz for a chosen duration (Req 8.6), every target in turn:

```sh
scripts/fuzz.sh -t 60s              # every target, 60 s each
scripts/fuzz.sh -t 5m FuzzDecode    # only targets whose name contains the substring
                                    # (FuzzDecode also matches FuzzDecodeEvent)
```

or one target directly, the form the script runs (Go fuzzes one target per invocation):

```sh
go test -run '^$' -fuzz '^FuzzDecodeEvent$' -fuzztime 60s -fuzzminimizetime 5s ./cmd/snitchd/
go test -run '^$' -fuzz '^FuzzDecode$'      -fuzztime 60s -fuzzminimizetime 5s ./internal/dns/
go test -run '^$' -fuzz '^FuzzParse$'       -fuzztime 60s -fuzzminimizetime 5s ./internal/api/
go test -run '^$' -fuzz '^FuzzLineReader$'  -fuzztime 60s -fuzzminimizetime 5s ./internal/api/
go test -run '^$' -fuzz '^FuzzParse$'       -fuzztime 60s -fuzzminimizetime 5s ./internal/rules/
go test -run '^$' -fuzz '^FuzzParseOverlay$' -fuzztime 60s -fuzzminimizetime 5s ./internal/rules/
```

`-fuzztime` takes a duration or a count (`1000x`). The minimize cap (`-m`, default 5s) exists
because Go's default of 60 s lets the DNS record target spend whole runs minimizing large
inputs instead of mutating. Nothing here needs root.

When a target fails, Go writes the input to `<package>/testdata/fuzz/<Target>/` and the script
names that path. Fix the decoder, then commit that file: from then on the ordinary test suite
replays it (Req 8.5). One defect was found this way during the feature: `LineReader.ReadLine`
returned an over-long line trimmed to the limit when the buffer filled on a `\r` one byte past
it; it is fixed and its input is kept as a seed.

`dagger call fuzz --duration 30s` runs the script in the Go checks container. It is not a
check: a green fuzz run proves only that this run found nothing, so it never gates
`dagger check`, CI or a release, and it is never answered from the engine cache. A failing
input stays inside the container; rerun the named target locally to get the file.

## The hostile-input corpus (Req 6)

`internal/dns/prog_corpus*_root_test.go` (build tag `root`) runs the tap against 58 frames,
each built by the existing well-formed builder and then mutated, each with a sentence on what
it probes and what must happen. The groups: truncation (inside the Ethernet, IPv4, IPv6, UDP
and DNS headers, the question, a record header, record data), lengths (UDP, IPv4 and IPv6
lengths below or beyond the frame, IPv4 header length below 20), compression (pointers to
themselves, forward, beyond the frame, in the question; reserved label types 0x40 and 0x80),
names (a 64-byte name, 16 and 17 labels, a 63-byte label that overruns the frame), record data
(A with rdlen 3, 5, 16; AAAA with rdlen 4; rdlen beyond the frame), counts (ancount larger
than the records present and than `RR_MAX`, qdcount 0 and 2), question matching (no recorded
question, a different id, name case or content), and well-formed packets at each limit (the
longest name, the most labels, 32 records, 8 and 9 addresses, the walk-step budget).

For every entry the test asserts that the packet passes, the expected counters move, no
contract counter moves, and the exact trie content and record (none for a malformed frame).
Run it as root on any kernel with BTF (no BPF LSM needed):

```sh
sudo scripts/dns-progtest.sh                       # every DNS root test, the corpus included
sudo scripts/dns-progtest.sh -run DNSProgCorpus    # only the corpus, one result per entry
```

Without root the script refuses with `run as root`.

Some entries set `mayRefuse`: their L3 header is shorter than a full IPv4 or IPv6 header, and
newer kernels refuse such a frame in `BPF_PROG_TEST_RUN` with EINVAL before the program runs.
Either outcome is accepted, and nothing may be counted, learned or mirrored in either case.
`truncation-ipv4-ihl-beyond-frame` is the network-header case that always reaches the tap.

### Known limits

The corpus records what the tap does, including where that falls short of "a malformed
packet adds nothing". These are open and recorded here so they are not mistaken for proof:

- **Nine entries learn from a packet that is malformed in one field** (accepted in Req 6.3,
  amended 2026-11-25). A UDP length larger than the bytes present is rejected in `parse_l34`
  (`lengths-udp-beyond-frame*`, `lengths-udp-one-beyond-frame`). Four length entries — UDP
  length 20 (shorter than the message), IPv4 total length 20 or 65535, IPv6 payload length
  65535 — still learn their A record because the parser does not compare these fields with the
  frame; on a real host the kernel's IP and UDP receive paths drop or trim such
  packets before cgroup ingress, so only the test-run entry can deliver them. Two entries with
  an answer count larger than the records present learn the one real record and then stop: the
  record came from a registered resolver and was complete, and inserts made during the walk
  cannot be undone. Three `compression-owner-*` entries learn their A record because the walk
  ends an owner name at a pointer without following it and never uses the owner name. In every
  case the learned bytes are a complete A record from a resolver the operator registered, and
  the tap can only ever add allow entries (fail-safe rule 1). The UDP-length bound in `parse_l34` holds on egress too
  (the question path): the stack writes the UDP length itself, so only a raw socket can lie,
  and such a question is now not recorded.
- **15 labels.** `read_qname` reads at most 15 labels: its `LABELS_MAX` (16) turns need one for
  the closing zero. Rule names are limited to the same 15 (`rules.NameLabelsMax`, pinned to the
  tap by `TestRuleNameLabelsFitTheTap`); a rules file with a longer name is refused at load.
  The corpus pins it as `limits-15-labels-*` plus `names-16-labels` (refused).
- **The walk-step budget.** Owner names in the answer walk have no per-name label cap, so a
  run of long, legal owner names can use up `STEPS_MAX` (544 steps) before a later record is
  reached; that record is then not learned. `limits-steps-a-on-last-step` (the A record on
  step 544, learned) and `limits-steps-a-past-budget` (one label more, nothing learned) pin
  the boundary. Fewer entries, never a wrong one.

## Before a release

```sh
dagger call rugged --fuzz-duration 30s           # lint-all (the bindings check included), then fuzz
sudo scripts/root-checks.sh --at <commit to tag> # on the dev VM, as your own user through sudo
```

`rugged` is the pipeline half: every check of `lint-all`, then every fuzz target for the given
time; it stops at the first failing part and names it. It is never cached and no workflow
calls it.

`root-checks.sh` is the half the pipeline cannot run, because it loads BPF programs into the
host's kernel. `--at <rev>` tests exactly that commit in a temporary detached worktree, removed
afterwards. It builds the daemon as you, runs `scripts/dns-progtest.sh` (the corpus included),
and, only where `bpf` is in the active LSM list (the dev VM), a bounded monitor-mode run of
the built daemon for 75 s on a private socket with `scripts/api-check.sh` against it. It never
enters enforce mode (Req 9.3); if `snitchd.service` is active it is stopped for the run (the
programs detach, everything is allowed) and started again, and the kill switch value is
restored on exit. On a workstation without an active BPF LSM it runs the DNS tests only.
`scripts/enforce-test.sh` remains the operator's attended test, run only on request.

## Findings outside this feature (open)

- None from this feature. Fixed in the same follow-up (2026-11-25): CI enforces gofmt again
  (a `fmt` job in `lint.yml`; since ci-debs task 7.1, commit `6132913`, no job had dispatched it),
  and rule names are limited to the 15 labels the tap can learn.
