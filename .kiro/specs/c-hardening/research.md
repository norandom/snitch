# Research & Design Decisions — c-hardening

## Summary
- **Feature**: `c-hardening`
- **Discovery Scope**: Extension (light discovery, plus one container probe and one local
  compiler experiment because two design choices depended on measured facts)
- **Key Findings**:
  - The committed bindings rebuild **byte-identically** in a `debian:forky` container
    (Debian clang 21.1.8 (13), `go generate ./internal/bpf/`, two runs, both `.o` and all
    generated `.go` files equal to the committed ones). The drift check can therefore demand
    byte identity; no weaker form is needed.
  - The stricter warning set costs little: 7 sites without `-Wconversion`, 7 more with it,
    and `vmlinux.h` is silent once it is included as `<vmlinux.h>` through `-isystem`.
  - A new verdict value is not needed. Every runtime contract can resolve to an existing
    allow verdict, so the event ABI and the API's closed verdict list stay as they are.

## Research Log

### Do the committed bindings reproduce, and under which compiler?
- **Context**: Requirement 7 needs a verdict on "bindings match the source". Whether that can
  be byte identity depends on bpf2go and clang being deterministic.
- **Sources Consulted**: probe run 2026-11-25 on this workstation: `docker run debian:forky`,
  `apt-get install clang llvm libbpf-dev golang-go`, repository mounted read-only and copied,
  `GOTOOLCHAIN=auto go generate ./internal/bpf/` twice, `sha256sum`, `cmp` against the source
  tree.
- **Findings**:
  - `dns_x86_bpfel.o` `b17adce3…` and `snitch_x86_bpfel.o` `1b29a152…` before and after both
    runs; no generated `.go` file differs.
  - Compiler in the container: `Debian clang version 21.1.8 (13)`.
  - `imageDebian = "debian:forky"` in `.dagger/pins.go` is a rolling tag; apt packages are
    pinned by version string (`cppcheck=2.22.0-1`, `libbpf-dev=1:1.7.0-1`), not by snapshot.
- **Implications**: the check regenerates in a pinned container and compares bytes. The
  verdict is tied to one clang version; when forky moves on, the check must fail with a
  message that says "compiler moved", not "stale".
- **Workstation measured 2026-11-25** (Ubuntu clang 21.1.8 (6ubuntu1), libbpf-dev
  1:1.6.3-1ubuntu1, llvm 1:21.1.6-71): `go generate ./internal/bpf/` on a clean
  `git archive` copy **fails** for `snitch.bpf.c:270` —
  `-Wincompatible-pointer-types-discards-qualifiers` under `-Werror`. libbpf 1.6.3 declares
  `bpf_d_path(struct path *, …)`; forky's 1:1.7.0-1 declares `const struct path *`, which
  matches the committed `vmlinux.h` (`const struct path f_path`). The libbpf headers are part
  of the build's identity, not only clang: the regeneration environment for this feature is
  the forky container (task 1.1), and the drift check pins libbpf-dev as well. Do not cast
  away the const to make 1.6.3 build.

#### Regeneration procedure (task 1.1)
Measured 2026-11-25 on commit `5b8073a`, rootful `docker` used without sudo (the output
files come out owned by root; copying them works, removing the output directory needs
`docker run --user "$(id -u):$(id -g)"`). Image
`debian:forky` = `debian@sha256:f3671d5a279b1ae356c7318ce6cdb84c600c2063d708ee97d3cce607bebfb85a`.

```sh
T=$(mktemp -d); git archive HEAD | tar -x -C "$T/"; mkdir "$T.out"
docker run --rm -v "$T":/src:ro -v "$T.out":/out \
  -e GOTOOLCHAIN=auto -e GOFLAGS=-buildvcs=false -e HOME=/tmp debian:forky bash -ec '
  apt-get update -qq
  DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends \
    clang llvm libbpf-dev golang-go ca-certificates
  clang --version | head -1
  cp -a /src /tmp/w && cd /tmp/w && go generate ./internal/bpf/ && cp internal/bpf/* /out/'
for f in internal/bpf/*; do cmp "$f" "$T.out/${f##*/}"; done   # silent = identical
```

- Installed in the container: `clang` 1:21.1.8-74 → `clang-21` 1:21.1.8-13
  (`Debian clang version 21.1.8 (13)`), `llvm` 1:21.1.8-74 → `llvm-21` 1:21.1.8-13 (provides
  `llvm-strip`, which bpf2go calls), `libbpf-dev` 1:1.7.0-1, `golang-go` 2:1.27~1
  (`go1.27.4`, satisfies `go 1.26.8` in go.mod, no toolchain download), `libc6-dev` 2.43-7,
  `linux-libc-dev` 7.3.5-1.
- Result: two runs, all five files of `internal/bpf/` `cmp`-identical to the committed ones:
  `dns_x86_bpfel.o` `b17adce3fde4a1c60d20d07bd570c8fb2ed1d438a5796086f53cf1296c31f08d`,
  `snitch_x86_bpfel.o` `1b29a1521c55b65ec1911ec12ad8200275c25baec7e36213a4faa6fcc3ace22d`,
  `dns_x86_bpfel.go` `11aa0600…`, `snitch_x86_bpfel.go` `2a951de6…`, `gen.go` unchanged.
- For a maintainer regenerating after a C change: the same commands on the working tree
  (`tar -c . | tar -x -C "$T/"` instead of `git archive`), then copy `"$T.out"/*` over
  `internal/bpf/`. The host toolchain (Ubuntu libbpf 1.6.3) is not a substitute, see above.

### What does the stricter warning set report today?
- **Context**: Requirement 1; size of the fix work and whether `-Wconversion` is affordable.
- **Sources Consulted**: same probe; `clang -O2 -g -Wall <set> -target bpf -c … -o /dev/null`
  per source, once as today and once with `<vmlinux.h>` + `-isystem bpf` + `-Wconversion`.
- **Findings**:
  - `snitch.bpf.c`: `-Wunused-parameter` ×4 (lines 280, 287: `ctx` from libbpf's `BPF_PROG`,
    `addrlen`, `size`).
  - `dns.bpf.c`: `-Wsign-compare` ×2 (312, 349), `-Wunused-parameter` ×1 (377, the `bpf_loop`
    callback's index).
  - With `-Wconversion`: `snitch.bpf.c` 232 (`sk_protocol` 16 → 8 bit), 251 (`tgid` sign);
    `dns.bpf.c` 200, 247, 278, 279, 423.
  - No warning originates in `vmlinux.h` in either configuration once it is a system header.
- **Implications**: `-Wconversion` is enabled in this feature. All fixes are explicit casts
  of conversions the compiler already performs, chosen so the generated code does not change.

### Does `-isystem` exempt authored headers too?
- **Context**: Requirement 1.3 forbids exempting a file the project authors; the new
  `bpf/contract.h` and `bpf/rules_abi.h` live in the same directory as `vmlinux.h`.
- **Sources Consulted**: local experiment with clang 21.1.8: `-isystem .`, one header
  included with `<>`, one with `""`, the same lossy conversion in both, `-Wconversion`.
- **Findings**: only the quote-included header warns. A header found through the includer's
  directory is a user header even when that directory is also on the system path.
- **Implications**: `#include <vmlinux.h>` plus `-isystem ../../bpf`; authored headers are
  included with quotes. No file moves, so cppcheck's `*:bpf/vmlinux.h` rule, the CodeQL
  config and the regenerate command in CLAUDE.md stay valid.

### Where do runtime contracts fit without changing the ABI?
- **Context**: Requirements 4 and 9.1; the API's verdict strings are a closed list
  (`internal/api/types.go:87`), and `internal/ask` keys questions on them.
- **Sources Consulted**: `bpf/snitch.bpf.c:186-277`, `bpf/dns.bpf.c:262-434`,
  `cmd/snitchd/decode.go`, `internal/ask/question.go`.
- **Findings**:
  - `decide()` already allows when the control slot is missing. A rule whose verdict byte is
    neither 1 nor 2 falls through to the mode default, which is **deny** in enforce mode:
    the one place where garbage in a map can deny.
  - The DNS tap keeps the invariant "every trie insert is mirrored to user space". A contract
    detected after an insert could not retract the insert and discarding the record would
    orphan it.
  - `pkt_init` always returns 0; the two error branches cppcheck flags at 439/514 are dead.
- **Implications**: egress contracts resolve to existing allow verdicts; DNS contracts are
  all evaluated before the first insert; `pkt_init` becomes `void` and its two suppressions
  disappear.

### How are the tap's counters read today?
- **Context**: Requirements 4.8 and 5.
- **Sources Consulted**: `internal/dns/record.go:71-85`, `cmd/snitchd/dns.go:110,170-178`,
  `cmd/snitchd/dnsfacts.go`, `cmd/snitchd/api.go:88-92`.
- **Findings**: `dns_stats` is a plain array of `ST_MAX` = 11 `__u64`, read index by index;
  `dns.StatsCount = 11`; `DecodeStats` accepts 11 or more values. `api.Status` is assembled
  in one place.
- **Implications**: contract counters are appended after index 10; existing indices keep
  their meaning. A second decoder reads the tail, so `dns.Stats` and every test comparing it
  stay untouched.

### How do the root tests drive the tap?
- **Context**: Requirement 6.
- **Sources Consulted**: `internal/dns/prog_root_test.go`, `prog_frames_test.go`,
  `prog_helpers_root_test.go`, `scripts/dns-progtest.sh`.
- **Findings**: a `parserCase` table with expected `Stats`, record and exact trie content;
  frames are built with `dnsmessage` (well-formed only); the script runs
  `go test -tags root -run 'DNSProg' -v ./internal/dns ./cmd/snitchd`.
- **Implications**: the corpus is a second table in the same package, named
  `TestDNSProgCorpus` so the script picks it up unchanged. Malformed frames need byte-level
  mutation of well-formed ones, which the builder cannot express.

### Baseline (task 1.2)
Recorded 2026-11-25 on commit `c93d393`, before any change of this feature (Requirement 9.2).
The ordinary checks ran against the working tree, which carried three uncommitted files
outside this feature (`.dagger/deb.go`, `packaging/control`: maintainer-line edits;
`.kiro/handover.md`). Workstation: no BPF LSM active (`/sys/kernel/security/lsm` lacks
`bpf`), host `go1.26.10`, Dagger v0.21.12.

| Check | Command | Result |
|---|---|---|
| Analyzer | `dagger call cppcheck` | PASS (exit 0, fresh run 1m19s; zero unsuppressed findings is its only pass) |
| Pipeline `go` check | `dagger call go` (build, vet, vet `root`, vet `live`, test, caps) | PASS (exit 0; served from the engine's cache for this tree) |
| Format | `gofmt -l .` (host) | PASS (no files listed) |
| Vet | `go vet ./...`, `-tags root`, `-tags live` (host) | PASS |
| Build | `go build ./...` (host) | PASS |
| Tests | `go test -count=1 ./...` (host, fresh) | PASS (15 packages `ok`, no failures) |
| Caps gate | `scripts/caps.sh` (host) | PASS (`caps: ok (18 packages)`) |

Pending root (run by the operator, not yet recorded here): `sudo scripts/dns-progtest.sh`
(`TestDNSProgLoads`, `TestDNSProgParser`, `TestDNSProgQuery`); the bounded monitor run
`go build -o /tmp/snitchd ./cmd/snitchd && sudo /tmp/snitchd -mode monitor -duration 10s`;
`sudo scripts/api-check.sh`.

Reference counters of the tap: the expected `dns.Stats` per `TestDNSProgParser` case, literal
in `parserCases()` (`internal/dns/prog_root_test.go:23-41`); fields not named are zero
(`NoQuestion`, `UpdateFail`, `Queries`, `RingbufFull` are zero in every case). Later root
runs must reproduce these unchanged (design "Testing Strategy", 4.8, 9.2).

| Case | Expected Stats |
|---|---|
| A, AAAA, CNAME, compression, IPv6-frame | Seen 1, Parsed 1, Updates 1 |
| truncated | Seen 1, NotAnswer 1 |
| wrong-resolver | Seen 1, NotResolver 1 |
| wrong-port | all zero (not seen) |
| two-questions | Seen 1, NotAnswer 1 |
| long-name | Seen 1, NameTooLong 1 |
| no-domain | Seen 1, Parsed 1 |
| existing-file-key | Seen 1, Parsed 1, Exists 1 |
| three-slots | Seen 1, Parsed 1, Updates 3 |
| `TestDNSProgQuery` (dns_query) | Queries 1 |

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Notes |
|--------|-------------|-----------|---------------------|-------|
| Byte-identity regenerate in a pinned container | Run `go generate` on a copy, compare every file in `internal/bpf/` | Proves source ↔ object; detects hand-edited bindings; measured to work | Verdict tied to one clang build; rolling base image | Selected |
| Committed stamp of source hashes | Hash sources and bindings at generation, compare in CI without clang | No compiler in CI | Proves only that the stamp was updated; a stale object with a fresh stamp passes | Rejected: fails 7.1 in spirit, and clang is allowed as observer |
| Compile-only check | Compile with the committed flags, ignore the output | Simple | Says nothing about the committed object | Rejected: fails 7.2/7.3 |
| Pipeline function that exports regenerated bindings | `dagger call … export` writes `internal/bpf/` | Convenient on hosts without the right clang | Blurs "nothing a pipeline compiler produces is committed" | Not built; see Follow-up of the drift decision |

## Design Decisions

### Decision: one definition of the trie ABI
- **Context**: `rule_key` / `rule_val` are defined twice "byte for byte" (3.4).
- **Alternatives Considered**:
  1. Keep both, add static asserts in each file against literal sizes.
  2. Move the two structs into one header both programs include.
- **Selected Approach**: `bpf/rules_abi.h` holds the only definition and its contracts.
- **Rationale**: a divergence becomes impossible rather than detected (generalization: the
  duplicated-definition problem and the layout-contract problem are the same problem).
- **Trade-offs**: both bpf2go objects still emit their own Go type for the struct; unchanged
  from today.
- **Follow-up**: confirm cppcheck analyses the header through `-I bpf` without new findings.

### Decision: `CONTRACT(cond, counter)` yields a value, the site returns
- **Context**: 4.1, 4.2, 4.4. The LSM hook must release the exe file reference on every
  path, so a macro that returns from the function would break the verifier's reference
  tracking and hide the verdict.
- **Alternatives Considered**:
  1. `CHECK` macro that returns the fail-safe value itself.
  2. Expression macro: true when the contract holds, otherwise bumps the counter and is false.
- **Selected Approach**: option 2; the caller writes the fail-open branch.
- **Rationale**: the allow / pass value stays visible at the site and reviewable per program;
  no hidden control flow.
- **Trade-offs**: one more line per site.
- **Follow-up**: none.

### Decision: no new verdict value
- **Context**: a violated egress contract must allow and still be reported.
- **Alternatives Considered**:
  1. `V_ALLOW_CONTRACT = 7` and a new API verdict string.
  2. Map each contract to an existing allow verdict; the violation shows in the counter.
- **Selected Approach**: option 2. Unreadable kill or control slot → `V_ALLOW_STALE`; rule
  with an invalid verdict byte → `V_ALLOW_MONITOR` with the rule id kept; invalid mode →
  treated as monitor (today's behaviour), counted.
- **Rationale**: the feature's boundary excludes event and API-verdict changes; the tray's
  question logic keys on the closed list.
- **Trade-offs**: an event alone does not say "contract"; the status counters do.
- **Follow-up**: `examples/api.md` states this.

### Decision: DNS contracts only before the first insert
- **Context**: 4.2 against the tap's mirroring invariant.
- **Selected Approach**: two runtime contracts (name shape, label offsets in range), both
  evaluated between `read_qname` and the ring buffer reservation. Bounds that hold by
  construction (`slots` index, address count, `bpf_loop` step count) are build-time contracts.
- **Rationale**: a violation then implies no insert and no record, so 4.2 holds literally.
- **Trade-offs**: fewer runtime contracts than a first draft; none that cannot honour 4.2.
- **Follow-up**: the tap is close to the verifier's budget; `TestDNSProgLoads` gates each
  change.

### Decision: per-CPU counters for the egress program, the existing array for the tap
- **Context**: 4.5, 4.8; the egress program runs on every `connect()`.
- **Selected Approach**: new `snitch_stats` per-CPU array; tap contracts appended to
  `dns_stats`.
- **Rationale**: no shared cache line on the hot path; no second counter mechanism in the tap.
- **Trade-offs**: the daemon sums per-CPU values for one map and reads scalars for the other.

### Decision: keep every warning on, fix or annotate per site
- **Context**: 1.5. `-Wunused-parameter` fires on parameters fixed by the kernel's hook
  signatures and on `ctx`, which libbpf's `BPF_PROG` declares.
- **Alternatives Considered**:
  1. `-Wno-unused-parameter` in `gen.go`.
  2. `__attribute__((unused))` on authored parameters; a commented diagnostic region around
     the two `BPF_PROG` definitions for `ctx`.
- **Selected Approach**: option 2.
- **Rationale**: 1.5 allows a disabled warning only with a comment at the line.
- **Trade-offs**: two pragma regions in `snitch.bpf.c`.

### Decision: drift check environment
- **Context**: 7.4, 7.5, 7.8.
- **Selected Approach**: `debian:forky` pinned by digest, clang / llvm pinned by apt version,
  Go copied from the pinned checks image, expected `clang --version` string recorded in
  `pins.go` and compared first.
- **Rationale**: follows the existing pin pattern; three distinct failure messages
  (environment unavailable, compiler moved, bindings stale).
- **Trade-offs**: when forky drops the pinned clang, the check fails until a maintainer bumps
  the pin and regenerates. That is the intended visible failure.
- **Follow-up**: try `snapshot.debian.org` as apt source so the pin outlives forky's
  rotation; adopt it if it works inside the engine, otherwise keep the version pin. A
  local export function for hosts without the pinned clang is deliberately not built.

### Decision: decoders return errors
- **Context**: 8.2, 8.3. `decodeEvent` panics through `contract.Require` on a short record;
  `dns.Decode` accepts trailing bytes.
- **Selected Approach**: both require the exact record size and return an error; the event
  reader counts and skips. `contract.Require` stays for programming errors only.
- **Rationale**: a record from the kernel is input, not a programming error; a panic in the
  reader ends the daemon.

## Synthesis Outcomes
- **Generalization**: duplicated trie structs and layout pinning collapse into one shared
  header with contracts. Egress and tap counters share one status shape
  (`ProgramCounters`).
- **Build vs. adopt**: Go's native fuzzing (`testing.F`, `testdata/fuzz`), C11
  `_Static_assert`, bpf2go's own reproducibility, BTF from the embedded collection specs for
  the Go-side size test. Nothing new is built where these suffice; no new dependency.
- **Simplification**: no new verdict, no export function, no post-insert contracts, no
  second counter mechanism in the tap, no change to `scripts/dns-progtest.sh`.

## Risks & Mitigations
- Verifier budget of the tap — every C change is followed by the root load test; casts are
  chosen to leave the generated code unchanged; the two runtime checks sit outside `bpf_loop`.
- Rolling base image changes the compiler — digest and apt pins, expected version string,
  distinct failure message.
- Line-bound cppcheck suppressions shift when lines move — tasks update line numbers in the
  same commit (2.4); two of them disappear with `pkt_init` becoming `void`.
- Hosted CI cannot load kernel programs — root tests remain a developer / VM step and the
  design says so; CI covers compile, analysis, drift, fuzz seeds.
- Maintainer hosts with another clang build produce different bytes — the check names the
  compiler; documentation gives the regeneration environment.

## References
- `.kiro/steering/fail-safes.md` — the five rules this design is checked against.
- `.kiro/steering/tech.md` — "CI never runs clang" (line 66), to be amended (9.4).
- `.kiro/specs/ci-debs/design.md` — the check pipeline this feature extends.
- `.kiro/handover.md` — the decisions of 2026-11-25.
