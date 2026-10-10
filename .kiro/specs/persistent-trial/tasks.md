# Implementation Plan

Every task below is a self-contained brief for an implementer without conversation context.
Before a task, read `.kiro/steering/tech.md`, `.kiro/steering/fail-safes.md`, the design
sections named in the task, and the Implementation Notes of `.kiro/specs/rule-loading/tasks.md`
(the conventions this spec continues: jobs, delegates, contracts with a violation test each,
caps via `scripts/caps.sh`, mutation evidence for tests). `_Boundary:_` names the files a task
may touch. A task is done when its "Done when" command succeeds and `gofmt -l .`, `go vet
./...`, `go test -race ./...` and `sh scripts/caps.sh` are clean. Nothing in groups 1 to 5 may
put this VM into enforce mode: the trial flow is observed only in task 6.2, after the operator's
go. Tasks in one package run one at a time.

- [ ] 1. Trial logic, pure and file-backed
- [x] 1.1 The mode decision and its bounds
  - A mode decision from (now, boot id, state, learning): with learning the decision is always monitor and the files are logged as ignored; otherwise kept wins; no trial is monitor; a trial from another boot ends at boot; a passed deadline or a trial older than the maximum ends at its deadline; otherwise enforce until the deadline; a malformed trial file counts as none and is cleared. Each decision carries the log reason and whether the trial file is spent
  - Bounds: durations from 1 to 60 minutes, default 10; the boot id read through a delegate
  - Contracts: the decision requires a non-zero time and a boot id; a spent trial is only reported when a trial or a problem exists
  - Done when: `go test ./internal/trial -run 'Decide|Bounds|Boot'` covers every row of the design's decision table, the clock-jump cap, the bound edges (59 s, 1 min, 60 min, 61 min) and the contracts
  - _Boundary: internal/trial/trial.go, trial_test.go_
  - _Requirements: 2.2, 3.1, 3.2, 3.5, 4.1, 4.2, 5.3, 8.4_
- [x] 1.2 The two files
  - A store over a directory with read, start trial, keep (writes the kept marker and removes the trial), clear trial, clear kept; file access through delegates so tests use memory; atomic writes; the plain key=value formats from the design
  - Read reports malformed files as problems rather than errors, so the daemon can log and clear them; missing files are simply absent
  - Done when: `go test ./internal/trial -run Store` proves round trips of both files, problems for malformed contents, keep removing the trial, clears on absent files, and that a rewrite replaces the file (new inode)
  - _Boundary: internal/trial/store.go, store_test.go_
  - _Requirements: 2.1, 3.3, 3.4, 5.1, 5.4, 6.1_

- [ ] 2. Status record
- [x] 2.1 (P) The daemon's facts for the command line
  - A record (pid, mode, source, learning, trial deadline, kept, rules file, rules numbers, written time) written atomically as key=value lines and read back; a missing file is a distinct error
  - Done when: `go test ./internal/status` proves the round trip and the missing-file error
  - _Boundary: internal/status/status.go, status_test.go_
  - _Requirements: 2.4, 2.7, 7.1, 7.2_

- [ ] 3. The daemon follows the files
- [ ] 3.1 Mode source, atomic mode, mode-change log
  - The daemon's mode becomes an atomic read by the heartbeat; a source "flag" when `-mode` was given, "files" otherwise; a single mode-change function that logs `mode: <monitor|enforce> (<reason>)`; flags for the state directory and the status file path with the design's defaults; the state directory created when missing
  - At startup with source "files", the decision runs once before the first heartbeat, so a kept enforce starts enforcing and a trial from another boot is cleared before anything is attached. Learning never denies: with `-learn` the decision is always monitor and a kept or trial file is logged as ignored
  - Done when: `go test ./cmd/snitchd -run 'Source|SetMode|Startup'` proves source detection from the flags, the log line on a change and silence without one, the startup decision with a fake store (kept → enforce before attach; foreign-boot trial → cleared, monitor; kept + learning → monitor, logged as ignored); a monitor run of the real daemon without `-mode` and with `-state-dir` and `-status` on an empty temp dir still prints the rules summary and events
  - _Boundary: cmd/snitchd/daemon.go, config.go, config_test.go, daemon_test.go_
  - _Depends: 1.1, 1.2_
  - _Requirements: 1.4, 3.3, 3.6, 4.2, 5.3_
- [ ] 3.2 Follow job and status writer
  - A follow job on the 2 s tick: read the store, decide, apply the mode on a change (log once per transition, repeated identical decisions silent), clear a spent trial; the "ended by the operator" reason when the file vanished while enforcing; a status writer on the same tick building the record from the snapshot summary, mode, source, learning and store state
  - Both jobs join the job list only when the source is "files"; the status file's directory is created (0700) when missing, so a hand-started daemon works without systemd
  - Done when: `go test ./cmd/snitchd -run 'Follow|StatusWriter|JobList'` with a fake clock and store proves: trial start → one enforce log, silent repeats, deadline → one monitor log and the trial cleared, file removed by hand → "ended by the operator", kept → enforce, kept while learning → monitor (the learning flag is passed on every tick, not only at startup), malformed → cleared and logged, and that the job list built for source "flag" contains neither job; a real monitor run without `-mode` (`-state-dir` and `-status` on temp paths) writes the status file every 2 s and, given a trial file with a foreign boot id written by hand, logs "trial ended at boot", stays in monitor and removes the file
  - _Boundary: cmd/snitchd/follow.go, follow_test.go, daemon.go (job list entry only)_
  - _Depends: 2.1, 3.1_
  - _Requirements: 1.4, 3.1, 3.2, 3.4, 3.5, 4.1, 5.4, 7.1_

- [ ] 4. The command line
- [ ] 4.1 Verb dispatch and the pinned-map readers
  - A first argument that is a verb runs the command line instead of the daemon, `main()` stays within its cap; shared verb flags `-state-dir` and `-status` (the same defaults as the daemon) so the test script can point the verbs at temp paths; readers for the pinned control map (heartbeat age on the monotonic clock, mode, flags) and the kill map; absent maps read as "not running, kill clear"; root required with a clear message
  - Done when: `go test ./cmd/snitchd -run 'Verb|Pinned'` proves the dispatch with a stub verb, the shared flags, and the absent-map behaviour with fakes; `snitchd -h` still exits 0 and a bare word that is not a verb exits 2 (never treated as a daemon argument)
  - _Boundary: cmd/snitchd/main.go, ctl.go (dispatch and shared flags only), ctl_maps.go, ctl_test.go_
  - _Depends: 2.1_
  - _Requirements: 7.3, 7.4_
- [ ] 4.2 trial, keep, unkeep, end
  - `trial [-extend] [-y] [duration]` with every refusal from the requirements (kill set, learning, not running or source flag, kept, running trial without extend) and the zero-rules confirmation; prints the deadline and the way out. `keep` only during a running trial, prints the file and the command that removes it. `unkeep`. `end [-at-boot]` removing the trial (and the kept marker unless at boot), reporting "already monitor" on nothing, exit 0; never touching the kill switch
  - Readers injected (control state, kill, status record, store) so every message is tested without root
  - Done when: `go test ./cmd/snitchd -run 'Trial|Keep|Unkeep|End'` covers each refusal text and exit code, extend within the bound, keep's rm command in the output, end on nothing; `grep -n kill cmd/snitchd/ctl*.go` shows reads only
  - _Boundary: cmd/snitchd/ctl.go, ctl_test.go_
  - _Depends: 1.2, 2.1, 4.1_
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 5.1, 5.2, 5.5, 5.6, 6.1, 6.2, 6.3_
- [ ] 4.3 status
  - `status` printing running (heartbeat age within 15 s), mode, trial deadline and remaining, kept, heartbeat age, kill switch, rules summary and learning from the status file; degrades to files and kill when the daemon is down; exit 1 when down
  - Done when: `go test ./cmd/snitchd -run Status` covers running and down outputs and exit codes; on this VM, as root with no daemon, `snitchd status` prints "not running" and exits 1 within one second; during a hand-started monitor run (no `-mode`, `-state-dir` and `-status` on temp paths, the same paths given to the verb) it shows every field and exits 0
  - _Boundary: cmd/snitchd/ctl.go (status verb), ctl_test.go; runs after 4.2 (same files)_
  - _Depends: 2.1, 4.2_
  - _Requirements: 7.1, 7.2, 7.3, 7.4_

- [ ] 5. Service units
- [ ] 5.1 The two unit files
  - `systemd/snitchd.service` (root, default rules file, no mode flag, restart on failure, state and runtime directories) and `systemd/snitchd-trial-boot.service` (oneshot before the service, runs the boot-time end); neither is installed or enabled by this spec; the README's install section lists them as "not enabled here, deployed by the VM repo" and says the older `snitch-trial*` units belong to the Little Snitch client, not to snitchd
  - Done when: `systemd-analyze verify` passes on copies of both units whose `ExecStart` is rewritten to the built binary's path (`/usr/local/sbin/snitchd` does not exist on this VM), and the README section is in place (6.1 extends it later)
  - _Boundary: systemd/snitchd.service, systemd/snitchd-trial-boot.service, README.md (install section)_
  - _Requirements: 1.1, 1.2, 1.3, 1.5, 4.3, 8.3_

- [ ] 6. Validation
- [ ] 6.1 Trial phase in the enforce test
  - Phase 3 after the same confirmation: daemon run without `-mode` (duration as ceiling, state dir and status file on temp paths): trial 2 m → EPERM within 5 s; restart the daemon → still EPERM; end → ok; trial 1 m → ok within 65 s and "ended at its deadline" logged; foreign-boot trial file → monitor and "ended at boot"; trial 2 m then `snitchd end -at-boot` → trial file gone and monitor within 5 s (the running daemon logs "ended by the operator"; do not grep for "at boot" here); trial + keep → trial file gone, still EPERM; unkeep → ok; kill switch and SIGSTOP steps as in phase 2; status exit 0 while running and 1 after stop; the trap also runs `end`
  - Done when: `shellcheck scripts/enforce-test.sh` clean and `sudo scripts/enforce-test.sh --check-only` still passes (phase 3 is not entered); README (the section 5.1 started) and CLAUDE.md status describe the trial commands
  - _Boundary: scripts/enforce-test.sh, README.md (trial commands, after 5.1), CLAUDE.md_
  - _Depends: 3.2, 4.3_
  - _Requirements: 8.1, 8.2_
- [ ] 6.2 Run the trial phase on the dev VM
  - Only with the operator's explicit go in the session and the serial console open; the operator confirms the RDP session stayed up
  - Done when: every phase-3 step passes, the trap prints mode monitor, kill 0, no attached programs, no trial and no kept file, and the transcript is in the research log
  - _Requirements: 8.1, 8.2, 3.1, 3.2, 3.3, 4.1, 5.1, 5.4, 6.1_
- [ ] 6.3 Caps, contracts and CI
  - Every documented contract of this spec has a violation test; caps green for the new packages; no exported identifier without a caller in another package; the design's contract list matches the code
  - Done when: every command of `.github/workflows/lint.yml` passes locally (the remote run follows the operator's push, recorded as pending until then)
  - _Boundary: `*_test.go` of this spec's packages, design.md contract list_
  - _Depends: 3.2, 4.3_
  - _Requirements: 8.4_

## Implementation Notes
- 1.1: `trial.Decide` follows the decision table (a trial is over when now ≥ End or now − Start > MaxTrial; exactly MaxTrial is still active); reasons are the log lines later tasks grep for, "enforce kept" is a prefix when a broken trial file is also present. Implementers: end the status report with the dash form `- STATUS:` exactly as the template shows.
- 1.2: `Store` has no Stat delegate (presence comes from ReadFile's ErrNotExist); `OSStore.WriteFile` creates the state dir 0700; `TrialPath()`/`KeptPath()` exist for the CLI's rm hint. For 3.2: a malformed `enforce` file reads as Kept=false plus a Problem naming `KeptPath()`, and `Decide` only carries ClearTrial, so the follow job must also remove a kept file named in a Problem (else it logs every tick). For 4.2: the CLI must check the state dir exists before writing (the store would create it). For 5.1: set `StateDirectoryMode=0700` in the unit (systemd's default is 0755 and MkdirAll leaves an existing dir alone).
- 2.1: `status.Write` creates `/run/snitch` 0700 when missing; `Read` keeps fs.ErrNotExist for the missing-file case ("daemon not running"); `Written` is carried to the second. `parseKV`/`writeAtomic` are duplicated from `internal/trial/store.go` (a shared `internal/kvfile` helper is a later cleanup, outside this spec).
