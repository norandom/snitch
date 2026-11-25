# Requirements Document

## Project Description (Input)

### Who has the problem
The maintainer and the operators of hosts that run `snitchd`: the BPF C in `bpf/snitch.bpf.c`
and `bpf/dns.bpf.c` runs in the kernel on every `connect()` / `sendmsg()`, and the DNS tap
parses packets an attacker on the path can shape. Reviewers of the project need evidence that
this code is defensible, not only that it loads.

### Current situation (2026-11-25)
- Compiler flags in `internal/bpf/gen.go`: `-O2 -g -Wall -Werror -Wno-missing-declarations`
  (plus `-mcpu=v3` for the Dns object). No `-Wextra` family.
- cppcheck runs with committed suppressions; four of them (`constVariablePointer` at
  `bpf/snitch.bpf.c:218/219/241`, `bpf/dns.bpf.c:356`) are real findings whose fix was deferred.
- No `_Static_assert` anywhere: the layout of the structs shared with Go and the relations
  between the parser's constants are not pinned at compile time.
- Invariant violations at run time are counted only in `dns.bpf.c` (`ST_*`); `snitch.bpf.c`
  has no counters, so a violated assumption there is invisible.
- `scripts/dns-progtest.sh` exists as the root test for the tap; it has no malformed-packet
  corpus.
- Nothing checks that the committed bpf2go objects in `internal/bpf/` still correspond to
  the C source.
- The Go side has `recover()` in both mains and the daemon loop, and no fuzz tests.
- Decision of 2026-11-25: clang may run in CI as an observer; shipped artifacts never come
  from a CI clang.

### What should change
1. Stricter clang warnings in `internal/bpf/gen.go` (`-Wextra -Wshadow -Wvla -Wundef
   -Wpointer-arith -Wimplicit-fallthrough -Wstrict-prototypes -Wnull-dereference`;
   `-Wconversion` once `vmlinux.h` is included via `-isystem`), the bindings regenerated, the
   four deferred `constVariablePointer` findings fixed and their suppressions dropped.
2. Compile-time contracts: `_Static_assert` on `sizeof` / `offsetof` of every struct shared
   with Go and on the relations between constants.
3. Runtime contracts: a `CHECK(cond, counter)` macro that counts a violated invariant in a
   per-CPU counter and returns the fail-safe verdict (allow in the LSM hooks, pass in
   `cgroup_skb`; never deny); counters added to `snitch.bpf.c` and surfaced in the API status.
4. The verifier as dataflow evidence: a malformed-packet corpus for `scripts/dns-progtest.sh`
   (truncated headers, compression loops, over-long labels, rdlen lies, ancount beyond
   `RR_MAX`).
5. A drift check that the committed bpf2go objects correspond to the C source, with clang in
   CI as an observer only.
6. Go fuzz targets for the ring-buffer decoders, the API JSON lines and the rules TOML.

### Out of scope
- The CodeQL manual-mode lane and the deb dependency fields (ci-debs follow-ups, see
  `.kiro/handover.md`).
- Userspace hardening flags that do not apply to `-target bpf` (`-fstack-protector`,
  `_FORTIFY_SOURCE`, PIE, CFI).
- Any change to modes or to fail-safe behaviour (CLAUDE.md, "Fail-safes").

## Introduction

snitch decides about outgoing connections inside the kernel, and its DNS tap reads packets
whose content somebody else chooses. This feature makes that code defensible to a reviewer:
the compiler and the analyzer report more and are heard, the assumptions the code rests on
are written down where the build or the running system checks them, hostile DNS input is
exercised on purpose, the committed kernel objects are shown to match their source, and the
daemon's decoders are fuzzed. A kernel program cannot abort; every violated assumption
therefore resolves to the fail-safe outcome and leaves a count an operator can read.

"The kernel programs" below means the egress decision program and the DNS tap. "The
bindings" means the committed compiled objects and generated Go types in `internal/bpf/`.
"The check pipeline" means the checks the repository runs on every push and before a release.

## Boundary Context

- **In scope**: compiler diagnostics for the kernel programs; the deferred analyzer findings;
  build-time contracts on shared layouts and constants; counted, fail-open runtime contracts
  in both kernel programs and their visibility in the daemon's status; hostile-input tests
  for the DNS tap; a check that the bindings match the source; fuzz tests for the daemon's
  decoders of untrusted or semi-trusted input; the documentation and steering records that
  these changes make untrue.
- **Out of scope**: the CodeQL build-mode change and the Python client's CodeQL coverage;
  the deb's dependency fields; hardening flags for the Go binaries; new rule features, new
  hooks, new events; any change to modes, to the decision order or to a fail-safe; the tray
  and the Python client beyond staying compatible with the status reply.
- **Adjacent expectations**: the `ci-debs` check pipeline hosts the new checks and keeps its
  contract that findings are zero unsuppressed. The `daemon-api` status reply gains fields
  only additively; existing clients (the tray, the Python client, `scripts/api-check.sh`)
  keep working unchanged. Tests that need root keep running through the existing root test
  script on a developer machine or the VM; the hosted CI is not expected to load kernel
  programs. Releases still ship the committed bindings; nothing a CI compiler produces is
  ever shipped.

## Requirements

### Requirement 1: Stricter compiler diagnostics for the kernel programs
**Objective:** As the maintainer, I want the compiler to report a wider class of mistakes in
the kernel programs and to refuse a build that has any, so that suspicious code is caught
before it is committed.

#### Acceptance Criteria
1. The bindings' generation shall compile both kernel programs with the extended warning set
   named in the project description, in addition to the warnings enabled today.
2. If either kernel program produces a compiler warning under that set, the bindings'
   generation shall fail and name the warning and its source location.
3. The bindings' generation shall keep generated or third-party headers from producing
   warnings that fail the build, without exempting any file the project authors.
4. Where implicit-conversion warnings are enabled, the bindings' generation shall apply
   them to the authored kernel sources and not to generated headers.
5. When the stricter set is in force, the committed kernel sources shall compile without a
   warning and without a warning being disabled for an authored line, except where a
   comment at that line states why the warning does not apply.
6. The kernel programs shall load and pass the kernel verifier on the development kernel
   after the changes this requirement causes.

### Requirement 2: Deferred analyzer findings resolved
**Objective:** As a reviewer, I want every suppression in the analyzer's list to stand for a
modelling limit rather than for a known defect, so that the list can be trusted.

#### Acceptance Criteria
1. The kernel sources shall no longer contain the four const-correctness findings recorded
   as deferred in the suppressions list.
2. The suppressions list shall no longer contain an entry whose stated reason is a deferred
   fix.
3. When the analyzer check runs after these changes, the check pipeline shall report zero
   unsuppressed findings.
4. If a change in this feature moves a line that a line-bound suppression names, the
   suppressions list shall name the new line, and no suppression shall be widened from a
   line to a file to absorb the move.
5. The documentation shall no longer describe these four findings as open.

### Requirement 3: Build-time contracts on shared layouts and constants
**Objective:** As the maintainer, I want the build to fail when a structure shared between
the kernel programs and the daemon, or a relation between the parser's limits, changes
unintentionally, so that such a change cannot reach a running system as silent corruption.

#### Acceptance Criteria
1. The kernel sources shall state the size of every structure shared with the daemon, and
   the position of each member the daemon reads or writes, as a build-time contract.
2. If a change alters the size of a shared structure or the position of a contracted member
   without the contract being changed with it, the bindings' generation shall fail and name
   the violated contract.
3. The kernel sources shall state as build-time contracts the relations between the DNS
   tap's limits that its bounded walks rely on, including that the total number of walk
   steps stays within what the kernel permits.
4. If the trie key or value structure differs between the two kernel programs, the build of
   at least one of them shall fail.
5. If the daemon's view of a shared structure's size differs from the kernel programs' view,
   the daemon's test suite shall fail and name the structure.
6. The build-time contracts shall add no instruction to the loaded kernel programs.

### Requirement 4: Runtime contracts that fail open and are counted
**Objective:** As an operator, I want an assumption that turns out false inside the kernel
programs to result in the safe outcome and a visible count, so that a defect can neither
cut a connection nor stay hidden.

#### Acceptance Criteria
1. If a runtime contract is violated while the egress decision program handles a connection
   attempt, the egress decision program shall allow that attempt.
2. If a runtime contract is violated while the DNS tap handles a packet, the DNS tap shall
   let the packet pass unaltered and shall add no allow entry from it.
3. When a runtime contract is violated, the kernel programs shall increment a counter that
   identifies which contract was violated.
4. The kernel programs shall never deny, drop or alter traffic as the response to a violated
   runtime contract, in any mode.
5. The egress decision program shall keep counters of its own, including one per runtime
   contract it carries.
6. While the kill switch is set or the heartbeat is stale or absent, the egress decision
   program shall allow everything exactly as before this feature, whether or not a runtime
   contract holds.
7. The kernel programs shall keep the fixed decision order: kill switch, heartbeat, local
   network, rules, mode default.
8. The existing DNS tap counters shall keep their meaning and their order.

### Requirement 5: Contract counters visible to operators
**Objective:** As an operator, I want to read the contract counters from the daemon's
status, so that I can see without kernel tooling whether an assumption was ever violated.

#### Acceptance Criteria
1. When a client requests the status, the daemon shall include the egress decision program's
   counters and every runtime-contract counter of both kernel programs, each under a name
   that identifies it.
2. The daemon shall report each counter as the total since the kernel programs were loaded.
3. The status reply shall keep every field it has today with unchanged name, type and
   meaning.
4. While no runtime contract has been violated, the daemon shall report the contract
   counters as zero rather than omit them.
5. If the counters cannot be read, the daemon shall still answer the status request and
   shall mark the counters as unavailable rather than report zeros.
6. The API documentation shall describe the new counters and state that a non-zero contract
   counter indicates a defect to report.
7. Every local user who may read the status today shall be able to read the new counters.

### Requirement 6: Hostile DNS input exercised against the tap
**Objective:** As a reviewer, I want the DNS tap run against deliberately malformed packets
with stated expected outcomes, so that its handling of attacker-shaped input is evidence
and not an argument.

#### Acceptance Criteria
1. The root test suite shall run the DNS tap against a committed corpus of malformed
   packets covering at least: truncated link, network, transport and DNS headers; a
   transport length that disagrees with the packet; compression pointers that loop, point
   forward or point outside the packet; labels and names beyond the tap's limits; a record
   data length that disagrees with the record type or runs past the packet; an answer count
   larger than the records present and larger than the tap's record limit; a question count
   other than one; and an answer whose question does not match a recorded question.
2. When the DNS tap is given a corpus packet, the DNS tap shall let the packet pass.
3. When the DNS tap is given a malformed corpus packet, the DNS tap shall add no allow
   entry and shall emit no answer record for it, except where the malformed field does not
   affect the answer record the tap reads and that record is complete and came from a
   registered resolver: an IPv4 total length, an IPv6 payload length or a UDP length shorter
   than the message that disagrees with the frame; an answer count larger than the records
   present; an owner name that is a compression pointer. Each such corpus entry states the
   exception. (Amended 2026-11-25 by the user's decision; a UDP length larger than the
   packet holds is not an exception and is rejected.)
4. When the DNS tap is given a corpus packet, the root test suite shall assert the counter
   the packet is expected to increment and that no runtime-contract counter increments.
5. The corpus shall include well-formed packets at each limit (longest accepted name, most
   labels, most records, most addresses) with the allow entries they are expected to
   produce.
6. Each corpus entry shall carry a short statement of what it probes and what outcome is
   expected.
7. When the root test script is run as root on a supported kernel, the root test suite
   shall run the whole corpus and report pass or fail per entry.
8. If the root test script is run without root, the root test script shall refuse with a
   message that says so, as today.

### Requirement 7: The bindings match their source
**Objective:** As a consumer of a release, I want assurance that the committed kernel
objects were built from the committed kernel sources, so that what is reviewed is what
runs.

#### Acceptance Criteria
1. The check pipeline shall include a check that determines whether the bindings correspond
   to the kernel sources and the generation settings at the same commit.
2. If the kernel sources or the generation settings change without the bindings being
   regenerated, the check shall fail and say that the bindings are stale.
3. If the bindings are changed without a corresponding change to the kernel sources or the
   generation settings, the check shall fail.
4. When the bindings correspond to the sources, the check shall pass on every run for the
   same commit.
5. The check shall state which compiler version its verdict is tied to, and the
   documentation shall say how a maintainer regenerates the bindings so that the check
   passes.
6. The check pipeline shall use a compiler for the kernel sources only to observe and
   compare; no file a pipeline compiler produces shall be committed, packaged or released.
7. The release artifacts shall continue to be built from the committed bindings without a
   C compiler.
8. If the check cannot run because its compiler environment is unavailable, the check shall
   fail visibly rather than pass.

### Requirement 8: Fuzz tests for the daemon's decoders
**Objective:** As the maintainer, I want the daemon's decoders of kernel records, API lines
and rules files fuzzed, so that malformed input cannot crash the root daemon.

#### Acceptance Criteria
1. The daemon's test suite shall include fuzz tests for the decoding of egress event
   records, of DNS answer records, of API request lines, and of rules files including the
   operator's overlay.
2. When a fuzz test supplies arbitrary bytes, the decoder under test shall return a value or
   an error and shall not panic, hang or allocate without bound.
3. If a decoder is given a record shorter or longer than the size it expects, the decoder
   shall reject it with an error.
4. When the ordinary test suite runs, the check pipeline shall execute every fuzz test's
   committed seed inputs as regular test cases.
5. When fuzzing finds an input that fails, the failing input shall be committed as a seed so
   that the ordinary test suite reproduces it from then on.
6. The documentation shall give the command that runs each fuzz test for a chosen duration.
7. If fuzzing during this feature reveals a defect in a decoder, the defect shall be fixed
   within this feature and its input kept as a seed.

### Requirement 9: Fail-safes preserved and records kept true
**Objective:** As the operator of a host reached over RDP and SSH, I want this feature to
change nothing about when traffic is allowed, and the project's records to describe what is
now true, so that hardening cannot become a lockout and the documents stay reliable.

#### Acceptance Criteria
1. The kernel programs shall make the same allow and deny decisions as before this feature
   for every input on which no runtime contract is violated.
2. The existing bounded monitor-mode run, the root tests and the API check shall pass after
   this feature.
3. No verification step of this feature shall enter enforce mode, except the existing
   attended enforce test, which is run only when the operator asks for it.
4. The steering records shall state that a compiler may run in the check pipeline as an
   observer and that shipped artifacts never come from it, replacing the statement that the
   pipeline never runs one.
5. The documentation shall describe the contract approach: build-time contracts, runtime
   contracts that fail open and are counted, and the daemon's contracts that exit and
   thereby detach the kernel programs.
6. The handover record shall no longer list as open the points this feature closes.
