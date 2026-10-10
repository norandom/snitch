# Implementation Plan

Every task below is a self-contained brief for an implementer that has no conversation
context (a Codex agent over MCP, or a fresh subagent). Before starting a task, read
`.kiro/steering/tech.md`, `.kiro/steering/fail-safes.md` and the design sections named in the
task. `_Boundary:_` names the design components and the files a task may touch (design.md
"File Structure Plan"); touch nothing else. Caps (functions ≤ 40 lines, cyclomatic ≤ 10, files
≤ 300 lines), delegates over interfaces, immutable values and `internal/contract` assertions
apply to every task (design.md "Implementation Rules"). A task is done when its "Done when"
command succeeds and `gofmt -l .` and `go vet ./...` are clean. Never run enforce mode outside
task 7.3. Tasks 1.2 and 1.3 may run in parallel; all tasks in group 2 to 4 share the
`internal/rules` package, so they run one at a time.

- [ ] 1. Foundation: dependency, CI gates, contracts, jobs, kernel types
- [x] 1.1 Add the TOML dependency and the CI quality gates
  - Add `github.com/pelletier/go-toml/v2` (v2.4.x) to the module; `go mod tidy`
  - CI workflow: run the Go tests; `gocyclo -over 10` and `funlen` (40 lines) over `internal/` except `internal/bpf` (the `cmd/` tree joins the caps in task 6.3); a file-length check (≤ 300 lines, same exclusions); shellcheck over `snitch-trial` and, when the directory exists, `scripts/*.sh` (nullglob)
  - Done when: every new CI command runs green locally on the current tree and `go build ./...` still needs no clang
  - _Boundary: CI, go.mod_
  - _Requirements: 8.1, 7.8_
- [x] 1.2 (P) Code-contract helpers
  - Precondition, postcondition and invariant assertions that panic with a typed violation carrying the kind and a message; always compiled in
  - A test helper that asserts a function panics with a violation of a given kind
  - Done when: `go test ./internal/contract/...` passes with one test per helper and the file is under the caps
  - _Boundary: contract_
  - _Requirements: 8.1_
- [x] 1.3 (P) Jobs runner
  - A job is a function of a context returning an error; a runner starts all jobs, ends them all when the first returns an error or the context ends, and returns that error
  - Helpers: periodic job from a tick function, signal-driven job, deadline job (zero means never)
  - Contracts: the runner requires at least one job
  - Done when: `go test ./internal/jobs/...` proves cancellation on first error, ticker stop with the context, deadline behaviour and signal delivery
  - _Boundary: jobs_
  - _Requirements: 6.2, 4.4_
- [x] 1.4 Kernel types: rule id and gated executable path in events
  - Trie value becomes verdict plus rule id; the event gains the rule id and a 256-byte path; the control state's pad becomes flags with bit 0 "want path"
  - The path is produced only for unknown programs or when the flag is set; a failed lookup leaves it empty; the decision order and every fail-safe check stay byte-for-byte the same (show this in the diff)
  - Add the value type to the bindings generator, regenerate with clang on the dev VM, commit the output; struct names stay distinct from map names
  - Done when: `go generate ./internal/bpf/ && go build ./...` succeed, the generated Go has the new value type and the event fields, and a 10 s monitor run on the dev VM still prints events (no verifier error); field contents are verified in task 6.5
  - _Boundary: BPF additions, bindings_
  - _Requirements: 5.3, 9.9, 5.2_

- [ ] 2. Rules file model and parser
- [x] 2.1 File model and strict decode
  - Immutable model: programs (name, paths, note) and rules (program or "any", prefix or bare address, proto tcp/udp/any, port integer or "a-b" range, verdict, note, optional learned fields count/first/last); strict TOML decode that rejects unknown keys
  - Syntax errors carry file, line and reason from the decoder; a missing file surfaces as not-exist so the caller can start empty
  - Done when: `go test ./internal/rules -run Decode` loads a valid fixture into the expected model and reports the line of a syntax error and of an unknown key
  - _Boundary: File model and parser_
  - _Requirements: 1.1, 1.3, 1.5, 8.1_
- [x] 2.2 Semantic validation with line numbers and ids
  - Checks: unique program names, rules reference declared programs or "any", canonical prefixes, ports 1–65535 and ranges ≤ 256 ports, known protocols and verdicts; ids assigned 1..n in declaration order; contracts ensure ids are dense
  - Semantic errors name the table's line: take positions from a second pass with go-toml's `unstable` parser (table index → line) and keep the typed decode for the values
  - Done when: `go test ./internal/rules -run Validate` reports the expected line for each invalid case (duplicate name, undeclared program, bad prefix, port 0 and 70000, range too wide, bad proto, bad verdict) and learned fields are accepted and kept on the model
  - _Boundary: File model and parser_
  - _Requirements: 1.4, 9.8_
- [x] 2.3 Documented example rules file
  - An example with curl, the session tooling glob, apt, an any-program deny, and comments explaining precedence and every field; used as a parser fixture
  - Done when: the example loads in the parser test with the expected program and rule counts
  - _Boundary: examples, file_test.go_
  - _Requirements: 1.1, 1.5_

- [ ] 3. Resolving programs to the kernel's executable identity
- [x] 3.1 Device identity from mountinfo
  - Compute a file's inode and the superblock device the kernel reports: mount id via statx, major:minor from the mountinfo row for that mount, encoded as the kernel does (major shifted by 20, or'ed with minor)
  - Fallback to the stat device's major/minor with a one-time warning when mountinfo is unreadable or has no row
  - Done when: `go test ./internal/rules -run Dev` passes against a sample mountinfo fixture (ext4 and a btrfs-style row) and the fallback case; the live comparison with a kernel event is task 7.2's pre-check
  - _Boundary: Resolver_
  - _Requirements: 2.2, 8.2_
- [x] 3.2 Resolve every program's paths and globs
  - Glob, symlink and identity access injected as function values so tests use fakes; several matches map to one program; non-regular files skipped
  - Unresolved paths or globs reported by program name while the program's rules stay loaded; one executable in two programs is a configuration error naming both
  - Output includes id→name and id→rule lookups for the event printer; contracts ensure no executable maps to two ids
  - Done when: `go test ./internal/rules -run Resolve` covers globs, symlinks, missing paths, conflicts and the lookups
  - _Boundary: Resolver_
  - _Requirements: 2.1, 2.3, 2.4, 2.5, 2.6_

- [ ] 4. Encoding rules for the kernel maps
- [x] 4.1 Encode resolved rules into map entries
  - One entry per rule and port: prefix length = 64 + address bits, family 2 or 10, v4 address in the first four bytes, program id or 0 for any, proto 0/6/17, port host order or 0; value carries verdict and rule id using the generated kernel types from 1.4
  - Contracts: prefix length ≥ 64, address bytes beyond the prefix are zero
  - Done when: `go test ./internal/rules -run Encode` checks the documented keys for v4 /32, v4 /0, v6 /48, any-program, port range expansion and the value layout, and shows the precedence tiers produce distinct keys
  - _Boundary: Encoder_
  - _Depends: 1.4, 3.2_
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 8.3_
- [x] 4.2 Diff two entry sets into puts and deletes
  - New and changed entries become puts, removed entries deletes, for programs and rules alike; identical inputs give an empty change set (contract)
  - Done when: `go test ./internal/rules -run Diff` passes including the empty-old (first load) case
  - _Boundary: Encoder_
  - _Requirements: 4.1, 4.3_

- [ ] 5. Learning aggregation
- [x] 5.1 (P) Aggregate observations and write them as a rules file
  - Observations (executable path or kernel identity, configured program name if any, address, proto, port, time) merge by key with count, first and last seen; dirty flag for the writer
  - Projection to the file model: one program per executable (basename, "-2" suffix on collision, "unknown-<ino>-<dev>" with empty paths when the path is unknown), one allow rule per destination/proto/port with the learned fields
  - Atomic write (temp file + rename) with a header comment; seeding from an existing file continues the counts
  - Parallel to group 4 only if the implementer works in `learn.go`/`learn_test.go` alone; the package must compile at hand-over
  - Done when: `go test ./internal/rules -run Learn` proves merge, naming, seeding, and that the written file parses back to identical entries
  - _Boundary: Learned_
  - _Depends: 2.2, 3.2_
  - _Requirements: 9.3, 9.4, 9.6, 9.8_

- [ ] 6. Daemon wiring (integration)
- [ ] 6.1 Flags and startup checks
  - Flags for the rules file (default `/etc/snitch/rules.toml`) and the learning file (default `/var/lib/snitch/learned.toml` when given without a value); enforce without a duration and learning together with enforce are refused before any kernel load, exit code 2 with the reason
  - Done when: `snitchd -mode enforce` exits 2 with a message, `snitchd -mode enforce -learn` exits 2 with "learning never denies", and `-h` lists the new flags
  - _Boundary: main.go (flags and checks only)_
  - _Requirements: 1.2, 6.1, 9.2, 9.5_
- [ ] 6.2 Snapshot state, map apply and summary
  - Load, resolve and encode before the kernel objects are loaded; apply puts then deletes to the two maps; publish an immutable snapshot through an atomic pointer only after a successful apply; contracts guard publish-after-apply
  - Missing rules file starts empty with a notice; invalid file exits 1 with file:line:reason; summary line after apply: programs declared/resolved/unresolved (names), executables mapped, rules effective
  - Done when: a monitor run with the example file prints the summary, a bad file exits 1 with the line, a missing file prints the notice, and the `kill` map value is unchanged across a start/stop (bpftool before and after)
  - _Boundary: state.go, main.go (startup sequence)_
  - _Depends: 1.2, 2.2, 3.2, 4.2_
  - _Requirements: 1.3, 1.4, 2.3, 3.1, 3.6, 6.4_
- [ ] 6.3 Assemble the daemon from jobs
  - The entry point parses flags, runs the startup sequence, builds the job list and runs it under one context: heartbeat (timestamp, mode and the flags word from startup config), deadline, stop signals, and a provisional pump job holding today's ring-buffer read-and-print loop moved unchanged into its own file (6.5 replaces it); later tasks add their jobs to this list only
  - A contract violation anywhere is logged with a stack and exits 70; the `cmd/` tree joins the caps in CI
  - Done when: `main()` is ≤ 60 lines, the daemon exits on its deadline and on SIGTERM with no snitch programs attached (`bpftool prog show`), heartbeat still beats every 2 s (control map timestamp advances), and the caps tooling is green for `cmd/`
  - _Boundary: main.go, events.go (provisional pump), CI caps scope_
  - _Depends: 1.3, 6.2_
  - _Requirements: 6.2, 6.3, 6.1_
- [ ] 6.4 Reload jobs
  - File watch job (2 s stat of mtime/size/inode) does a full reload; re-resolve job (10 s) refreshes executables only; SIGHUP does a full reload; each publishes a new snapshot only after a successful apply and prints the summary
  - Failures (parse, conflict, map error) are logged with file:line:reason and keep the previous snapshot
  - Done when: in a monitor run, editing the file changes the summary within 5 s, breaking it logs the error while rules stay effective, copying an executable into a globbed directory is matched within 10 s, and SIGHUP reloads at once
  - _Boundary: reload.go, main.go (job list entry only)_
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5_
- [ ] 6.5 Event pump with program and rule names
  - Fixed-layout decode of ring buffer records (length contract, no reflection) replaces the reflective reader; the old reader helper file is removed
  - Program name from the snapshot; unknown programs show the kernel-provided path or the `/proc` link, marked unknown; verdicts by rule show `#id program prefix proto port verdict`; observations are handed to a sink delegate (a no-op until 6.6)
  - Done when: a monitor run with the example file shows `program curl` and `rule #n …` for an allowed address, `allow (monitor)` without rule for another, and a path plus `unknown` for a program not in the file; a short-lived program not in the file (a copy of curl under /tmp) still shows its path
  - _Boundary: events.go, decode.go, main.go (job list entry only); deletes reader.go_
  - _Depends: 1.4, 6.3_
  - _Requirements: 5.1, 5.2, 5.3, 9.9_
- [ ] 6.6 Learning sink and writer job
  - Events decided as "allow (monitor)" become observations through the sink; the writer job saves every 60 s when dirty and once more at shutdown; an existing learned file seeds the state (invalid seed exits 1); the startup config sets the want-path flag while learning
  - Done when: a 60 s `-learn` monitor run with no rules writes a file that then loads with `-rules` and turns the same connections into `allow (rule)` events
  - _Boundary: learn.go, main.go (sink, job list entry and the learning startup config)_
  - _Depends: 5.1, 6.5_
  - _Requirements: 9.1, 9.4, 9.5, 9.6, 9.7_

- [ ] 7. Validation
- [ ] 7.1 Monitor-mode integration pass on the dev VM
  - Run the acceptance checks of tasks 6.2–6.6 end to end from a clean start with the example file and record the observed lines in the spec's research log; include one explicit deny rule and show it denies in monitor mode
  - Done when: every check has a recorded observation and no contract violation or verifier error occurred
  - _Requirements: 3.5, 4.1, 4.3, 5.1, 5.3, 9.1_
- [ ] 7.2 Enforce test script
  - Root script: options for duration, allowed address, denied address, local probe, daemon binary, `-y`, and `--check-only`; generates a temp rules file (curl → allowed address/32 tcp 443; session tooling glob → anywhere)
  - Phase 1 (always, monitor mode, no confirmation needed): identity pre-check, an event for a curl run shows `program curl` (this is the live proof that the resolver's device equals the kernel's); stop here with `--check-only` or when the confirmation is declined
  - Phase 2 (after confirmation or `-y`): steps allowed curl ok with allow-by-rule logged, other public address EPERM with default-deny logged, local probe ok, kill switch on → ok, off → EPERM, SIGSTOP → ok within 16 s, SIGCONT → EPERM within 3 s; IP literals only
  - Trap on exit: resume and stop the daemon, clear the kill switch, write mode monitor into control, print mode/kill/attached-programs facts; exit code = failed steps
  - Done when: `shellcheck scripts/enforce-test.sh` is clean and `--check-only` passes on the dev VM without entering enforce
  - _Boundary: scripts/enforce-test.sh_
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8, 8.2_
- [ ] 7.3 Run the enforce test on the dev VM
  - Only with the operator's explicit go in the session and the hypervisor console open; duration ≤ 120 s; the operator confirms the RDP session stayed up
  - Done when: all steps pass, the trap prints mode monitor / kill clear / zero attached programs, and the output is recorded in the research log
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 6.2, 6.3_
- [ ] 7.4 Caps and contract coverage audit
  - Every documented contract in design.md "Code contracts" has a test asserting its violation; caps tooling and file-length check green for `cmd/` and `internal/`; no exported identifier without a caller in another package
  - Done when: the CI workflow passes on the branch
  - _Requirements: 8.1, 8.3_

## Implementation Notes
- 1.1: `funlen`'s standalone command has no line-limit flag, so the function and file caps are enforced by the in-repo `tools/caps` (go/ast, tests included in scope); gocyclo v0.6.0 does complexity. `scripts/caps.sh` is the single entry point for CI and developers. Do not run `go mod tidy` before task 2.1 imports go-toml, it would drop the require.
- 1.3: `jobs.Run` ends when the FIRST job returns, nil included (that is how `After` ends a run). Consequences: the event pump (6.5) must never return nil by accident (today's loop returns on `ringbuf.ErrClosed`), or the daemon exits early; other jobs' errors are discarded, so the learned-file writer (6.6) must log its own shutdown write failure. `Every` does not tick before the first period: main writes the first heartbeat before `Run` (design order heartbeat → apply → attach → Run).
- 1.4: `bpf_d_path` needs a trusted pointer; a walk `task->mm->exe_file` is untrusted (verifier: "R1 type=scalar"). The program acquires the exe with the kfuncs `bpf_get_task_exe_file` / `bpf_put_file` (Linux ≥ 6.12, a new runtime prerequisite; dev kernel is 7.2). The event's `path` bytes after the NUL are uninitialised ring-buffer memory: the Go decoder (6.5) must stop at the first NUL. `flags` stays 0 until the daemon sets WANT_PATH (6.6).
- 2.1: every error names its `[[program]]`/`[[rule]]` header line via a second pass with go-toml's `unstable` parser (document order matches the decoded slices); the inline form `program = [{...}]` is rejected with an error, not supported. Value conversion (prefix, proto, ports ≤ 256, verdict, no zoned addresses) lives in `decode.go`; `validate.go` (2.2) does names, references and ids.
- 2.2: decision for 4.1: a rule with ports and proto any is encoded as TCP and UDP entries per port (the kernel never probes (proto 0, port); a bare (0, port) key would be a silent dead rule). `paths = []` stays legal: learned files use it for executables whose path was unknown; 3.2 reports such a program as unresolved.
- 3.1/3.2: `rules.DevOf` gives the kernel's device (ext4 root here: 8388609 where stat says 2049). The mountinfo source is the unexported `openMountinfo` variable, swapped by internal tests; those tests must stay serial (no `t.Parallel`). `OSFS(warn)` takes the warning sink as a delegate. Literal paths skip Glob so a missing file reports the OS error; a program with no paths is reported as unresolved "no paths".
- 4.1/4.2: two rules that encode to the same key (same program, prefix, proto, port after the any-proto expansion) are rejected by the validator naming both lines; `Encode` itself has no error path and would otherwise keep the later rule silently. `Diff` puts changed values (never delete+put); "identical → empty" is pinned by a test, not a runtime contract.
- 5.1: learned entries are keyed by the executable (path, else ExeKey), never by the program name; a configured name is a display preference. A pathless program carries its identity in its `note` ("exe ino=N dev=N", with the `unknown-<ino>-<dev>` name as fallback). Observation times are truncated to seconds (what the file carries). Residual: a configured name shaped exactly `<base>-<digits>` reads back as derived and reverts to `<base>` on the next write. A configured program with several executables is written as one program per executable (`tooling`, `tooling-2`); the operator merges. For 6.6: `Dirty()` + `File()` + `WriteFile`; `File()` clears dirty.
