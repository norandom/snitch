# Gap Analysis: persistent-trial

Date: 2026-10-10. Requirements approved (8 requirements, 39 criteria). Builds on the completed
`rule-loading` spec (daemon as jobs, snapshot state, bounded enforce, fail-safes in the C).

## 1. Current State

| Asset | Where | What it gives this feature |
|---|---|---|
| Mode is a daemon field written with every heartbeat | `cmd/snitchd/daemon.go` (`d.mode`, `beat()` → `control_state.mode`) | Switching mode at runtime is one field change plus the next 2 s heartbeat; the kernel reads `mode` on every decision. No C change needed. |
| Startup checks | `cmd/snitchd/config.go` (`check`: enforce needs `-duration`, learn excludes enforce) | The bounded run stays; the service runs with no `-mode` flag, which becomes "follow the files". |
| Jobs runner, `Every` | `internal/jobs` | A "trial watcher" job on the 2 s tick fits the existing shape (like `watchFile`). |
| Pinned maps `control` and `kill` | `/sys/fs/bpf/snitch/{control,kill}`; cilium `ebpf.LoadPinnedMap` | The status and trial commands can read heartbeat age, mode and kill switch without the daemon's cooperation. |
| Old trial shape | `snitch-trial` + `systemd/snitch-trial{,-boot}.service`, `.timer` | Deadline as a file, a boot unit that ends an open trial before the daemon, `--keep` as the explicit step. The requirements copy this shape. |
| Enforce test | `scripts/enforce-test.sh` (phases, trap, EPERM detector) | The trial phase extends it. |
| Console recovery | `scripts/fail-open.sh` | Unchanged; `end` must not touch the kill switch (Req 6.3). |
| Learned-file writer pattern | `internal/rules/write.go` (temp + rename) | The same atomic write for the deadline, keep and status files. |
| Logging | stdout/stderr | Under systemd both land in the journal; "log with reason" is a print. |

Conventions: logic in `internal/<domain>` with delegates (clock, file system) so it tests
without root; the daemon stays wiring; contracts; caps.

Verified on the VM: `/proc/sys/kernel/random/boot_id` exists (a per-boot UUID); systemd's
`StateDirectory=`/`RuntimeDirectory=` create `/var/lib/<name>` and `/run/<name>`.

## 2. Requirement → Asset Map

| Req | Need | Status |
|---|---|---|
| 1.1–1.3 service unit | `systemd/snitchd.service`: root, default rules, no mode flag, `Restart=on-failure`, `StateDirectory=snitch`, `RuntimeDirectory=snitch` | **Missing** (file only) |
| 1.4 mode-change log | one line per change with reason | Missing, trivial |
| 1.5 kill switch across restarts | pinned map | exists |
| 2.x trial command | a control CLI: write deadline file; checks: kill switch (pinned map), learning + "daemon follows files" + rules count (needs daemon state → status file), daemon running (heartbeat age), bounds, extend | **Missing**: CLI surface + a status file the daemon writes |
| 3.1–3.5 daemon follows the file | a job on the 2 s tick: read trial/keep files → decide mode → set `d.mode` (next heartbeat writes it) → log on change; remove the deadline when passed; malformed → remove + log | **Missing**; design: pure `decide()` in `internal/trial` |
| 3.3 restart keeps the trial | file persists; daemon reads it at startup | follows from 3.1 |
| 3.6 bounded run ignores files | when `-mode` is given, the watcher job is not started | trivial |
| 4.x boot ends a trial | distinguish boot from restart (boot id in the file) and/or `ExecStartPre` / oneshot unit that removes it | **Missing**; options below |
| 5.x keep / unkeep | keep file; keep only while a trial runs; boot with keep → enforce; unkeep → monitor ≤ 5 s | Missing; same watcher |
| 6.x end | remove both files | Missing, trivial |
| 7.x status | daemon running (heartbeat age), mode (control map), files, kill switch (pinned map), rules summary + learning flag (status file written by the daemon) | **Missing**: status file + CLI |
| 8.1 test phase | extend `scripts/enforce-test.sh` with a trial phase (bounded daemon run WITHOUT `-mode`, following files) | Missing |
| 8.3 unit not enabled here | nothing to do; VM repo later | — |
| 8.4 tests without root | `internal/trial` with a clock delegate and a file-system delegate | Missing |

Complexity: a small state machine over two files and a clock, a CLI with four verbs, one unit
file, one status file. No external integration, no C change.

## 3. Implementation Approach Options

### A. Everything in `cmd/snitchd`
Subcommands and the watcher as more daemon files; files read with `os` directly.
- ✅ Fewest packages. ❌ The mode decision (the part that must be right) would be hard to test
  without root and without time control; contradicts steering.

### B. `internal/trial` package + daemon wiring + subcommands in `snitchd` (recommended)
`internal/trial`: `State` (files: deadline + boot id, kept), `Read/Write/Clear` through a
small FS delegate, `Decide(now, bootID, state, flags) (Mode, Reason)` pure, bounds and
refusals as pure functions. Daemon: a `follow` job on the 2 s tick that calls `Decide` and
flips `d.mode` + logs; a `status` writer on the same tick. CLI: `snitchd trial|keep|unkeep|
end|status` as subcommands (first non-flag argument), implemented in `cmd/snitchd/ctl.go`
against pinned maps + files.
- ✅ Decision logic fully tested with a fake clock and fake boot id; the daemon stays wiring;
  no third binary (the TUI is the second one).
- ❌ Subcommand parsing beside the existing flags (small).

### C. B with a separate `snitchctl` binary
- ✅ Clear separation. ❌ A third binary to build, ship and pin; steering says two.

### Sub-decisions

**Boot detection (Req 4)**
- B1 Boot id in the deadline file: the daemon treats a deadline from another boot as "ended at
  boot" (removes it, logs). Self-contained, testable, no unit dependency; a restart in the same
  boot keeps the trial (Req 3.3).
- B2 `ExecStartPre=` in the unit removing the deadline: ends it also when the daemon never
  starts (Req 4.3 literally), but cannot tell a restart from a boot (`Restart=` re-runs
  ExecStartPre), so it alone breaks Req 3.3.
- B3 A separate oneshot unit `snitchd-trial-boot.service` (`Before=snitchd.service`, runs once
  per boot): satisfies 4.3 and 3.3, one more unit.
- Recommendation: B1 as the mechanism the daemon relies on, plus B3 as belt and braces (one
  tiny unit, the shape of the old `snitch-trial-boot`). Both do the same thing; either alone
  ends the trial at boot.

**Daemon state for the CLI (Req 2.4, 2.7, 7.1)**
- S1 Status file `/run/snitch/status` written atomically every heartbeat: mode, flags (learning,
  follows files or flag mode), rules summary numbers, pid. tmpfs, gone after a boot.
- S2 The unix socket API (future spec). Not available yet.
- Recommendation S1; the API spec later replaces the reader, not the writer's facts.

**Daemon running? (Req 2.6, 7.1–7.3)**
- Heartbeat age from the pinned `control` map ≤ 15 s = running (the kernel's own definition);
  also works for a hand-started daemon. `systemctl is-active` only for the service.

**Deadline time base**
- Wall clock in the file (operators read it); the daemon compares with `time.Now()`. A clock
  jump backwards could extend a trial: cap the effective trial at 60 min after the recorded
  start, so a jump can never give more than the bound.

**Deadline file format**
- Two lines `deadline=<RFC3339>` `boot=<uuid>` (plus `started=`), or reuse TOML via go-toml.
  Plain lines parse with the standard library and are readable from a console. Recommendation:
  plain `key=value` lines.

## 4. Effort and Risk

| Area | Effort | Risk | Why |
|---|---|---|---|
| `internal/trial` state + decide + tests | S | Low | pure logic with delegates |
| Daemon follow job + status writer | S | Medium | the one place that can leave enforce on; mitigated by the kernel fail-safes and tests |
| CLI subcommands | S–M | Low | argument parsing, pinned-map reads, messages |
| Unit files | S | Low | |
| Test script trial phase + VM run | S | High (operational) | as before: trap, serial console, explicit go |

Overall M (3–4 days), Medium.

## 5. Recommendations for the Design Phase

- Option B; boot detection B1 + B3; status file S1; running = heartbeat age; plain-lines files.
- Mode as a small type with three sources: flag (bounded run), trial, kept; `Decide` returns the
  mode and a reason string that is the log line.
- Files under `/var/lib/snitch/` (`trial`, `enforce`) and `/run/snitch/status`; the keep
  command prints the `rm` command for the way back (Req 5.5).
- Research to carry forward: (1) cilium `LoadPinnedMap` + `Lookup` for a non-daemon reader of
  `control`/`kill` (root), and whether `bpftool` stays the console fallback; (2) subcommand +
  flags layout in Go's `flag` package (verb first, then flags); (3) whether `Restart=on-failure`
  should also cover clean exits (`Restart=always`) given a deadline run exits 0.

---

# Design Discovery (2026-10-10, light: extension of the daemon)

## Findings
- `d.mode` is written into the control map on every heartbeat; runtime switching = an atomic
  field plus ≤ 2 s. No kernel change.
- `ebpf.LoadPinnedMap(path, nil)` + `Map.Lookup` read `control`/`kill` from any root process;
  heartbeat age needs `CLOCK_MONOTONIC` (the clock `beat()` uses).
- `/proc/sys/kernel/random/boot_id` gives a per-boot UUID; recording it in the trial file lets
  the daemon tell a restart (same id → trial continues, Req 3.3) from a reboot (different id →
  ended at boot, Req 4.1) without a unit's help; the oneshot unit is belt and braces for 4.3.
- systemd `StateDirectory=`/`RuntimeDirectory=` create `/var/lib/snitch` and `/run/snitch`.
- `Restart=on-failure`: the service has no `-duration`, so it never exits 0 by itself; stop via
  systemd is clean. `always` would also restart after a deliberate `systemctl stop`-less exit;
  not wanted.

## Decisions
- Option B (`internal/trial` + daemon wiring + subcommands on `snitchd`), boot detection B1+B3,
  status file S1, running = heartbeat age ≤ 15 s, plain `key=value` files.
- Synthesis: one `Decide` function is the whole policy (generalization: kept, trial, boot,
  clock cap, malformed are rows of one table); no interfaces, delegates for clock/files/apply;
  status is a file now, the API later reads the same facts (simplification: no socket yet).
- Build vs adopt: standard library only; no new module.

## Risks
- The follow job is the one place that can turn enforce on at runtime: covered by unit tests
  with a fake clock, the transition log, the kernel fail-safes, and the trial phase on the VM.
- A kept enforce surviving boot is deliberate (Req 5.3); the way back is a file and
  `fail-open.sh`, both documented by the `keep` command's own output.
