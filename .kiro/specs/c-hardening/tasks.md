# Implementation Plan

Working rules for every task (from steering): no step enters enforce mode; steps marked
"needs root" run on the developer machine or the VM and are reported as blocked, not skipped,
when root is unavailable; the bindings are regenerated and the root tests run at the closing
task of each group that changes the kernel sources (2.4, 3.5, 4.4), and again whenever a later
task changes them; line-bound analyzer suppressions are re-anchored in the same
change that moves their lines.

- [ ] 1. Foundation: a reproducible starting point
- [x] 1.1 Establish the regeneration environment and prove it reproduces the committed bindings
  - Provide an environment with the compiler version the design names, the strip tool and the
    kernel helper headers, either on the host or as the container procedure measured in
    research.md
  - Regenerate the bindings from the untouched tree
  - Done when the regenerated objects and generated types are byte-identical to the committed
    ones and the exact procedure is written down for the later documentation task
  - _Requirements: 7.5_
- [ ] 1.2 Record the passing baseline of the existing checks before any change
  - Run the analyzer check, the ordinary test suite, the root test script (needs root), a
    bounded monitor-mode run and the API check (needs root)
  - Done when each result is recorded as pass, with the tap's counters from the parser tests
    kept as the reference for later comparison
  - _Requirements: 9.2_

- [ ] 2. Stricter compiler diagnostics and the deferred analyzer findings
- [x] 2.1 Enable the extended warning set and separate generated headers from authored ones
  - Add the extended set including implicit-conversion warnings to both generation commands
  - Include the kernel type dump as a system header; keep authored headers as user headers
  - Prove with a scratch authored header, included the way authored headers are and holding
    one lossy conversion, that authored headers still fail the generation; discard it
  - Done when the generation fails and every reported warning is at an authored line (the
    fourteen sites research.md lists), none in the kernel type dump or the helper headers
  - _Requirements: 1.1, 1.2, 1.3, 1.4_
- [x] 2.2 Clear the warnings and const findings in the egress decision program
  - Make each implicit conversion explicit without changing the conversion performed
  - Mark hook parameters the kernel fixes as unused; put a commented diagnostic region around
    the hooks whose context parameter the helper macro declares
  - Make the three looked-up values the analyzer named read-only
  - Done when this program compiles without a warning under the extended set and every
    annotation carries a comment at its line
  - _Requirements: 1.5, 2.1_
- [x] 2.3 Clear the warnings and findings in the DNS tap
  - Make the sign comparisons and conversions explicit without changing the conversion
    performed; mark the loop callback's unused index
  - Make the slot value the analyzer named read-only
  - Remove the packet initializer's constant result and the two unreachable error branches
  - Done when this program compiles without a warning under the extended set
  - _Requirements: 1.5, 2.1_
- [ ] 2.4 Regenerate, shorten the suppressions list and verify nothing regressed
  - Regenerate the bindings; remove the four deferred entries and the two entries the
    unreachable branches needed; re-anchor any line-bound entry that moved, widening none
  - Run the analyzer check, the ordinary test suite and the root test script (needs root)
  - Done when the analyzer reports zero unsuppressed findings, no entry cites a deferred fix,
    the programs load, and the parser tests report the same counters as the baseline
  - _Requirements: 1.6, 2.2, 2.3, 2.4, 9.1_

- [ ] 3. Build-time contracts on shared layouts and limits
- [x] 3.1 Create the contract header
  - Provide the three build-time contract forms (size, member position, relation of
    constants) and the runtime contract expression that counts and yields false without
    leaving the enclosing function
  - Each build-time message names the type or relation it guards
  - Done when a scratch translation unit using each form compiles, and a deliberately false
    contract of each build-time form fails with a message naming its subject
  - _Requirements: 3.1, 3.2, 3.6_
- [x] 3.2 Give the trie key and value one definition shared by both programs
  - Move the two structures and their contracts into one shared header; remove both copies
  - Keep each program's type export so both generated Go types still exist
  - Done when both programs compile from the single definition and no second definition of
    either structure remains in the tree
  - _Requirements: 3.4_
- [x] 3.3 State the layout contracts for every structure shared with the daemon
  - Size, and position of every member the daemon reads or writes, for the structures of both
    programs listed in the design's contract table, with sizes taken from the compiler
  - Done when both programs compile and every structure in that table has a size contract and
    member contracts
  - _Requirements: 3.1, 3.2_
- [x] 3.4 State the relations between the DNS tap's limits
  - The relations in the design's contract table, including the walk-step bound against the
    kernel's loop limit and the slot array's element count
  - Done when the tap compiles and each relation in the table is present as a build-time
    contract
  - _Requirements: 3.3_
- [ ] 3.5 Regenerate and prove the contracts bite without adding code
  - Regenerate; compare the programs' instruction sections with those from task 2.4
  - On a scratch copy: pad one shared structure, change one member of the shared trie
    definition; observe the failures; discard the copy
  - Run the analyzer check and the root test script (needs root); if the shared header needs
    a suppression entry of a class the list already carries for the two programs, add it with
    its reason
  - Done when the instruction sections are identical to task 2.4's, the padded structure
    fails naming its contract, the changed trie member fails the build of both programs, the
    analyzer reports zero unsuppressed findings, and the root tests pass
  - _Requirements: 1.6, 2.3, 3.2, 3.4, 3.6_
- [x] 3.6 Test that the daemon's view of each shared structure equals the kernel programs' view
  - Read each shared structure's size from the type information embedded in the bindings and
    compare it with the generated Go type and with the hand-written trie mirrors; no root
  - Done when the test passes on the regenerated bindings and a deliberately wrong expected
    size fails naming the structure
  - _Requirements: 3.5_

- [ ] 4. Runtime contracts and counters in the kernel programs
- [x] 4.1 Give the egress decision program counters of its own
  - A per-CPU counter array with the fixed index order of the design; count decisions,
    unreadable destinations, missing executables and lost events where they occur today
  - State the array's size against the index list as a build-time contract
  - Done when the program compiles and the compiled object carries the counter map with the
    designed number of entries
  - _Requirements: 4.3, 4.5_
- [x] 4.2 Add the egress program's four runtime contracts with fail-open outcomes
  - Kill slot readable, control slot readable, a found rule's verdict is allow or deny, mode
    is monitor or enforce; each counts its own violation and resolves as the design's table
    states, with the allow branch written at the site
  - Leave the position and conditions of the kill switch, heartbeat and local-network checks
    exactly as they are
  - Done when the diff of the decision function shows only added allow exits and counter
    increments, the executable-file reference is released on every path, and the program
    compiles
  - _Requirements: 4.1, 4.3, 4.4, 4.6, 4.7, 9.1_
- [x] 4.3 Add the DNS tap's two runtime contracts before the first insert
  - Append the two contract counters after the existing eleven without moving any
  - Evaluate name shape and label-offset range after the question name is read and before the
    answer record is reserved; name shape also before a question is stored; a violation lets
    the packet pass
  - State the tap's counter array size against its extended index list as a build-time
    contract
  - Done when the tap compiles, the existing eleven indices are unchanged, and no path from a
    violated contract reaches an insert or a record
  - _Requirements: 3.3, 4.2, 4.3, 4.4, 4.8_
- [ ] 4.4 Regenerate and verify the kernel side
  - Regenerate; run the analyzer check, the root test script (needs root) and a bounded
    monitor-mode run (needs root)
  - Done when the analyzer reports zero unsuppressed findings, both programs pass the
    verifier, the parser tests report the same counters as the baseline, and the monitor run
    starts, reports events and ends on its own
  - _Requirements: 1.6, 2.3, 4.8, 9.2, 9.3_

- [ ] 5. Daemon and API
- [x] 5.1 (P) Make the two record decoders reject wrong-sized input instead of panicking
  - The egress event decoder and the DNS answer decoder accept only the exact record size and
    return an error otherwise; the event reader notes and skips such a record and continues
  - Done when unit tests show size minus one and size plus one are errors for both decoders
    and the reader survives an undecodable record
  - _Boundary: Record decoders_
  - _Requirements: 8.3_
- [x] 5.2 (P) Add the counters object to the status wire type
  - The additive, optional counters object with one availability-marked section per kernel
    program, as the design's API contract states
  - Done when a status without the object and one with it both round-trip, and every existing
    field serializes exactly as before
  - _Boundary: Status wire type_
  - _Requirements: 5.3, 5.7_
- [ ] 5.3 Read the kernel counters into the wire type
  - Sum the egress program's per-CPU values and name them in index order; decode the tap's
    contract tail; mark a section unavailable with a reason when its map cannot be read or the
    tap is off; report every contract name at zero when nothing was violated
  - Done when unit tests cover sums, an unreadable map (unavailable, no zeros), an off tap,
    and the full set of contract names at zero
  - _Depends: 4.4, 5.2_
  - _Requirements: 5.1, 5.2, 5.4, 5.5_
- [ ] 5.4 Integration: serve the counters in the status reply and tie the names to the maps
  - Wire the reader into the status reply for every reader of the status
  - Extend the layout test so the counter name tables must match the counter maps' sizes
  - Extend the API check to assert the counters object; run it against a bounded monitor run
    (needs root)
  - Done when a status request against the running daemon returns both sections available
    with all contract counters at zero, and the API check passes
  - _Depends: 3.6, 5.3_
  - _Requirements: 3.5, 5.1, 5.3, 5.7, 9.2_

- [ ] 6. Evidence: hostile DNS input and fuzzed decoders
- [ ] 6.1 Build the corpus harness for the DNS tap's root tests
  - A corpus entry carries its name, what it probes, the expected outcome, the frame, and the
    expected counters, record and exact trie content; byte-level mutators derive malformed
    frames from well-formed ones
  - The check asserts the packet passes, the expected counters, that no contract counter
    moved, the exact trie content and the record or its absence
  - Seed it with the truncation group so the harness is exercised end to end
  - Done when the root test script (needs root) runs the truncation entries and reports each
    by name, and still refuses without root
  - _Depends: 4.4, 5.3_
  - _Requirements: 6.2, 6.3, 6.4, 6.6, 6.7, 6.8_
- [ ] 6.2 Add the length, count and question entries to the corpus
  - Transport and network length disagreements; answer counts above the records present and
    above the tap's limit; question counts other than one; answers without a recorded or
    matching question
  - A failing expectation is a finding: fix the tap within this feature (then regenerate and
    re-run task 4.4's checks) or correct the expectation with the reason stated in the entry
  - Done when every entry of these groups passes under the root test script (needs root)
  - _Requirements: 6.1_
- [ ] 6.3 Add the compression, name-limit, record-data and at-the-limit entries to the corpus
  - Looping, forward and out-of-packet pointers; reserved label types; names and labels
    beyond the limits; record data lengths that disagree with the type or the packet
  - Well-formed packets at each limit with the allow entries they must produce
  - The same finding rule as task 6.2
  - Done when every group in the design's corpus table has its entries and all pass under the
    root test script (needs root)
  - _Requirements: 6.1, 6.5_
- [ ] 6.4 (P) Fuzz the kernel-record decoders
  - Fuzz tests for the egress event decoder with its accessors and for the DNS answer decoder,
    with seeds for a valid record and the boundary sizes
  - Run each for a bounded time; fix any defect found and keep its input as a seed
  - Done when the seeds run as ordinary cases in the test suite and a bounded fuzz run of each
    ends without a failure
  - _Boundary: Record decoders and their fuzz tests_
  - _Depends: 5.1_
  - _Requirements: 8.1, 8.2, 8.4, 8.5, 8.7_
- [ ] 6.5 (P) Fuzz the API request-line decoding
  - Fuzz tests for request parsing and for the line reader's length limit, seeded from the
    documented examples
  - Run each for a bounded time; fix any defect found and keep its input as a seed
  - Done when the seeds run as ordinary cases and a bounded fuzz run of each ends without a
    failure
  - _Boundary: API request decoding and its fuzz tests_
  - _Requirements: 8.1, 8.2, 8.4, 8.5, 8.7_
- [ ] 6.6 (P) Fuzz the rules file and overlay decoding
  - Fuzz tests for the rules file and the operator's overlay, including merging a parsed pair,
    seeded from the sample rules file
  - Run each for a bounded time; fix any defect found and keep its input as a seed
  - Done when the seeds run as ordinary cases and a bounded fuzz run of each ends without a
    failure
  - _Boundary: Rules file decoding and its fuzz tests_
  - _Requirements: 8.1, 8.2, 8.4, 8.5, 8.7_

- [ ] 7. The bindings check in the pipeline
- [ ] 7.1 (P) Pin the check's environment
  - Pin the base image by digest, the compiler and its tools by package version, and record
    the expected compiler version string; try a dated package snapshot as the source and keep
    it only if it works inside the engine
  - Done when a container built from the pins reports exactly the recorded compiler version
  - _Boundary: Bindings check_
  - _Depends: 1.1_
  - _Requirements: 7.5, 7.8_
- [ ] 7.2 Implement the bindings check
  - Regenerate on a copy inside the pinned container and compare every binding file byte for
    byte with the committed one; nothing is written back or exported
  - Three distinct failures: environment unavailable, compiler differs from the recorded
    version, bindings stale with the differing files named
  - Add it to the aggregate that runs all linters
  - Done when the check passes twice in a row on the committed tree
  - _Requirements: 7.1, 7.4, 7.6, 7.8_
- [ ] 7.3 Run the check in the workflow and prove each failure
  - Dispatch it from the linters job, which release tags skip; correct the comments that
    count the pipeline's checks
  - On scratch copies: a source change without regeneration, a flipped byte in an object, a
    wrong recorded version, an uninstallable pin; discard the copies
  - Done when each scratch case fails with its own message, the workflow file passes the
    workflow linter, and the release workflow is unchanged
  - _Requirements: 7.1, 7.2, 7.3, 7.5, 7.7, 7.8_

- [ ] 8. Records and final validation
- [ ] 8.1 Write the feature documentation and bring the affected documents up to date
  - The contract approach at its three levels; how to regenerate so the bindings check
    passes; the command that runs each fuzz test for a chosen duration
  - The counters object in the API documentation, with the statement that a non-zero contract
    counter is a defect to report; the pipeline documentation no longer lists the four
    findings as open and names the eighth check
  - Done when each of these statements can be found in the documents and no document still
    describes the four findings as open
  - _Requirements: 2.5, 5.6, 7.5, 8.6, 9.5_
- [ ] 8.2 Amend the steering records and close the handover points
  - Replace "the pipeline never runs a C compiler" with the observer rule; add the new
    headers, the check and the fuzz commands to the project instructions; remove from the
    handover the points this feature closes
  - Done when the steering states the observer rule and the handover lists none of the closed
    points
  - _Requirements: 9.4, 9.6_
- [ ] 8.3 Final validation of the whole feature
  - Run every pipeline check including the bindings check, the ordinary test suite with all
    fuzz seeds, the root test script (needs root), a bounded monitor-mode run and the API
    check (needs root)
  - Review the final diff of the decision function against the starting point: only allow
    exits and counter increments added
  - Done when every check passes, the status shows all contract counters at zero after the
    monitor run, and no step entered enforce mode
  - _Requirements: 2.3, 7.4, 9.1, 9.2, 9.3_

## Implementation Notes

- Regeneration happens only in the `debian:forky` container (research.md, "Regeneration
  procedure (task 1.1)"): the workstation's libbpf 1.6.3 fails `snitch.bpf.c:270`; forky's
  clang-21 1:21.1.8-13 + libbpf-dev 1:1.7.0-1 reproduce the committed bindings byte for byte.
  The container needs network for the Go module download.
- Root checks are batched (user decision 2026-11-25): the user runs the scratch script
  `root-checks.sh` with sudo and pastes the output. This workstation has no active BPF LSM, so
  the monitor run and api-check run on the dev VM; the DNS root tests can run here. Tasks whose
  done state needs root stay `[ ]` until the pasted output proves them.
- A plain `go generate ./internal/bpf/` stops at the first failing directive; run
  `go generate -run "Snitch " ./internal/bpf/` and `-run "Dns "` separately to see each object's
  warnings. From 2.1 until 2.4, generation at HEAD fails by design (bindings stay committed).
- Root gates are tested on detached worktrees pinned at the gate commit (scratch `gate24`, ...),
  so the operator's run proves exactly that commit while later work continues on main.
- `CONTRACT(cond, on_violation)` is a C11 conditional expression (no statement expression):
  `if (!CONTRACT(p, bump(SC_X))) { fail-open branch }`; `CONTRACT_CONST`'s msg must be a string
  literal.
- Finding from 3.4 for the corpus (6.3): the answer walk's owner-name steps have no per-name
  label cap, so a long owner name can use up `STEPS_MAX` early and later records are not walked.
  Fail-safe (fewer allow entries, never a wrong one); add a corpus entry that pins this outcome.
- `internal/bpf/abi_test.go` is an external `bpf_test` package (internal/rules and internal/dns
  import internal/bpf). For 5.4: its `sizeMismatch` message always says "bytes" (wrong for entry
  counts and array lengths) - give it a unit; `dns.addrsMax` is unexported and not covered there
  (TestMirrorKernelConstants in internal/dns covers it); `dns.StatsCount` vs `dns_stats` must move
  with task 4.3's counter tail.
- 5.1: the event reader counts undecodable records in an atomic `daemon.undecodable`; the DNS
  reader's `malformed` is still a plain uint64 touched by its one goroutine - make it atomic or
  read it under the lock if a later task serves it in the status. Ring buffer samples carry the
  exact reserved length (cilium v0.22 ringbuf/ring.go), so exact-size decoding rejects no real record.

