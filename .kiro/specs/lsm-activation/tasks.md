# Implementation Plan

Every task below is a self-contained brief for an implementer without conversation context.
Before a task, read `.kiro/steering/tech.md`, `.kiro/steering/fail-safes.md`, the design
sections named in the task (`.kiro/specs/lsm-activation/design.md`) and `research.md` in the
same directory (it lists file and line anchors and the tests that pin exact bytes).
Conventions as in the earlier specs: delegates (function values) for OS seams, contracts with a
violation test each, caps via `scripts/caps.sh` (functions at most 40 lines, files at most 300,
cyclomatic at most 10, test files included). `_Boundary:_` names the files a task may touch. A
Go task is done when its "Done when" command succeeds and `gofmt -l` and `go vet` are clean
for the packages it touches and `sh scripts/caps.sh` is clean; the whole-tree gate
(`go test -race ./...`) runs at the joins named in 4.4 and 7.1, because `(P)` tasks share one
working tree. Several touched files sit within a few lines of the 300-line cap (`daemon.go`
296, `overview.go` 297, `icons.go` 294, `ctl_status_test.go` 283): each call site there costs
one line and the logic goes into the new files the design names.

Rules for this spec: nothing under `bpf/`, `internal/bpf`, `internal/rules`, `internal/dns`,
`internal/trial` or `internal/status` is edited; the status file format stays byte-identical.
Existing golden files and exact-bytes tests are not edited to make them pass, except where a
task names the edit (the status key set in 1.2, the state lists in 4.3, the status
verb's key list in 2.3). No task needs root, loads a kernel program, runs `update-grub` on the
development host, edits `/etc/default/grub*` there, or reboots anything: boot-loader behaviour
is proven with fixture files and a stub. Only 7.2 touches a real host, and the operator runs
it. Pushes, tags and releases are not part of any task (5.3 uses a local throwaway tag and
deletes it). Wording is fixed by the design's "Sentences" list; tests compare it exactly.
Tasks in the same Go package run one at a time; `(P)` tasks touch disjoint files.

- [x] 1. Foundation: the probe and the wire fact
- [x] 1.1 (P) The kernel hook probe
  - A package that answers, from an injected file reader, whether `bpf` is in the kernel's
    active LSM list (active, inactive, unknown) and, when inactive, whether a generated GRUB
    configuration already carries it (pending) or could not be read (cannot tell)
  - One fixed sentence per outcome, exactly as the design lists them; no operating-system
    error text ever appears in a sentence
  - Also whether the running kernel is built with BPF LSM at all (its build configuration
    under `/boot`, falling back to `/proc/config.gz`; unreadable means not claimed), so a
    kernel without support is reported as unsupported rather than "reboot to activate"
  - Tests: unsupported from either configuration source and not claimed when both are
    unreadable; list with and without `bpf`, a near-miss token (`bpfx`), whitespace, unreadable
    list, GRUB configuration with `lsm=...,bpf`, with `lsm=` lacking `bpf`, absent, permission
    denied; a nil reader violates a contract
  - Done when: `go test -race ./internal/lsm` is green and no sentence contains `no such file`
  - _Boundary: internal/lsm/lsm.go, internal/lsm/lsm_test.go_
  - _Requirements: 1.1, 1.2, 1.7_
- [x] 1.2 (P) The hook fact in the status type
  - The status gains an optional hook object (state, pending, unsupported, reason) as its last member,
    omitted when absent, with the three state words as constants
  - The status without a hook stays byte-identical to the existing golden; with a hook the
    bytes are the existing ones followed by the hook member; the key-set test names the new key
  - Done when: `go test -race ./internal/api` is green, including a round trip of each state
    and the unchanged golden
  - _Boundary: internal/api/types.go, internal/api/types_test.go_
  - _Requirements: 2.1, 2.4, 2.5, 1.7_

- [x] 2. The daemon reports and refuses
- [x] 2.1 Probe at start, log, and serve the fact
  - The daemon probes after attaching, logs the sentence as one line before its existing start
    line (which stays unchanged), keeps the probe cached and re-probes when older than 30 s,
    and puts the fact into every status it serves; `daemon.go` gains one struct field and one
    call, everything else lives in `hook.go`
  - Inactive or unknown changes nothing else: the daemon keeps running, the mode, the maps,
    the heartbeat and the kill switch are untouched
  - Done when: `go test -race ./cmd/snitchd -run 'Hook|Facts|Startup'` is green: a daemon
    built with a fake reader serves each of the three states, the start-line test still passes
    unedited, a test shows the mode and kill values equal before and after an inactive probe,
    and a test shows a recorded trial and a kept enforce byte-identical in the store after a
    start with the hook inactive
  - _Boundary: cmd/snitchd/hook.go, cmd/snitchd/hook_test.go, cmd/snitchd/daemon.go, cmd/snitchd/api.go_
  - _Depends: 1.1, 1.2_
  - _Requirements: 1.3, 1.4, 1.5, 1.6, 2.1, 3.3_
- [x] 2.2 Refuse a trial or a keep while the hook is inactive
  - The shared trial operations consult the hook before any other check or write: `start` and
    `keep` answer `refused: ` plus the sentence when inactive; `end` and `unkeep` never ask
  - Wired for both doors: the API handlers use the daemon's cached probe, the command-line
    verbs a new `hook` delegate in `ctl`'s dependencies (production: the real probe); every
    existing fixture of the trial operations and of those dependencies, including the
    nil-delegate contract test, gets a probe answering active, so no test reads the real `/sys`
    (this workstation has `bpf` inactive and would otherwise refuse every existing trial test)
  - Done when: `go test -race ./cmd/snitchd -run 'Trial|Keep|Refus'` is green: refusal over
    the API and the CLI in the inactive state with no file written under the store, acceptance
    in active and unknown, `end` and `unkeep` working in all three
  - _Boundary: cmd/snitchd/trialops.go, cmd/snitchd/apiwrite.go, cmd/snitchd/ctl.go, cmd/snitchd/ctl_verbs.go, cmd/snitchd/hook_refusal_test.go, cmd/snitchd/trialops_test.go, cmd/snitchd/ctl_verbs_test.go, cmd/snitchd/contracts_trial_test.go, cmd/snitchd/ctl_status_test.go_
  - _Depends: 2.1_
  - _Requirements: 3.1, 3.2, 3.4_
- [x] 2.3 The `hook:` line of `snitchd status`
  - One line after `kill:` in every state carrying the sentence of the `hook` delegate that 2.2
    added; without root the inactive sentence is the "run as root" variant; the usage text names the key; the exit code logic
    is untouched
  - Done when: `go test -race ./cmd/snitchd -run Status` is green with the key list extended,
    and a test shows exit 0 for a running daemon in the inactive state
  - _Boundary: cmd/snitchd/ctl_status.go, cmd/snitchd/ctl_status_test.go, cmd/snitchd/ctl_status_hook_test.go_
  - _Depends: 2.2_
  - _Requirements: 2.2, 2.3_

- [x] 3. The fake daemon can report a hook state
  - `SetHook(*api.HookStatus)` and a stdin command `hook active|inactive|pending|unknown|none`
    (`pending` = inactive with pending, `none` = not reported) on the stand-in;
    the default stays "not reported", so every existing client test and host check is unchanged
  - Done when: `go test -race ./internal/client/...` is green and a connected test client
    receives the changed fact after the command
  - _Boundary: internal/client/clienttest/hook.go, internal/client/clienttest/hook_test.go, internal/client/clienttest/commands.go_
  - _Depends: 1.2_
  - _Requirements: 8.3_

- [x] 4. Every client surface warns
- [x] 4.1 The status-bar verb
  - Inactive gives class `down` and the sanitised reason as the tooltip's first line; unknown
    and not reported print what they print today; always one line, exit 0
  - Done when: `go test -race ./internal/verbs ./cmd/snitch -run 'Bar|Status'` is green with
    cases for inactive, unknown, not reported, and inactive while enforce is recorded
  - _Boundary: internal/verbs/bar.go, internal/verbs/bar_hook_test.go, cmd/snitch/oneshot_hook_test.go_
  - _Depends: 1.2, 3; not (P): its gate builds `./cmd/snitch`, which compiles the packages 4.2 and 4.3 edit_
  - _Requirements: 5.1, 5.2, 5.3, 3.3_
- [x] 4.2 (P) The terminal UI
  - A `NO KERNEL HOOK` tag directly after ` snitch |` in the header (the leading ` snitch |`
    becomes its own span inside the existing `Sprintf` line of the header, no net lines, the
    existing goldens unchanged as text), and the bottom line
    carrying the warning (pending or not configured) or the shorter unknown notice whenever no
    confirmation, search or notice occupies it; both in the overview and the graph; fixed
    wording only, the constants of the design (each at most 78 columns); one call per site in
    `overview.go`, the logic in `hook.go`
  - The warning goes away on the next status that says active; every key keeps working
  - Done when: `go test -race ./internal/tui` is green with new goldens rendered at exactly
    80x20 for inactive, inactive-pending, unknown, and inactive with a kept enforce (tag and
    line complete at 80 columns), every existing golden byte-identical, and a test that a later
    active status removes the tag and the line
  - _Boundary: internal/tui/hook.go, internal/tui/hook_test.go, internal/tui/overview.go, internal/tui/graph.go, internal/tui/testdata/blind*.golden, internal/tui/testdata/hook_unknown.golden_
  - _Depends: 1.2_
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 3.3_
- [x] 4.3 (P) The tray's seventh state and its icon (integration of `internal/tray` and `internal/sni`)
  - `kernel hook inactive` ranks after "daemon not running" and before "kill switch set",
    needs attention, is named by the tooltip and the first menu row, adds a row saying reboot
    pending, boot not configured, or kernel lacks BPF LSM, and notifies once on entry; nothing new is written or
    switched by the tray
  - In the same task, because inserting the state shifts every later state's value and the
    icon package's out-of-range contract test depends on the count: a drawn pixmap for the new
    state (outline with one red horizontal bar extending past it) in its own file so
    `icons.go` stays under the cap, the icon dispatch, and the state and name lists of the
    icon tests; both PNG sizes written into `docs/` by the existing helper test
  - Done when: `go test -race ./internal/tray ./internal/sni` is green: seven states, order and
    attention asserted, both row texts, exactly one note on entering the state, the state
    with a kept enforce recorded still showing the hook state, the new pixmap distinct from the
    six others at 22 and 44 px with its halo, the out-of-range contract test still failing on
    an eighth value; and `docs/tray-blind-22.png`, `docs/tray-blind-44.png` exist
  - _Boundary: internal/tray/hook.go, internal/tray/hook_test.go, internal/tray/model.go, internal/tray/view.go, internal/tray/facts.go, internal/tray/notes.go, internal/tray/model_test.go, internal/sni/icons_blind.go, internal/sni/icons_blind_test.go, internal/sni/icons.go, internal/sni/icons_test.go, docs/tray-blind-22.png, docs/tray-blind-44.png_
  - _Depends: 1.2_
  - _Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 3.3, 1.7_
- [x] 4.4 The inactive state in the two host-check scripts, and the first whole-tree gate
  - One step each in the tray check and the TUI check that drives the stand-in to inactive
    (stdin command `hook pending`) and asserts the tray's title, status and tooltip and the
    screen's tag and bottom line
  - Done when: `dagger call shellcheck` is clean;
    `go build -o /tmp/snitch ./cmd/snitch && go build -o /tmp/fakedaemon ./tools/fakedaemon &&
    dbus-run-session -- bash scripts/tray-check.sh --bin /tmp/snitch --fake /tmp/fakedaemon --headless`
    passes with the new step counted; `scripts/tui-check.sh -api <socket>` against
    `/tmp/fakedaemon -api <socket>` passes with the new step counted; and `go test -race ./...`
    is green
  - _Boundary: scripts/tray-check.sh, scripts/tui-check.sh_
  - _Depends: 3, 4.1, 4.2, 4.3_
  - _Requirements: 8.3_

- [x] 5. The package configures the next boot
- [x] 5.1 The helper and the drop-in
  - A POSIX shell helper that prints one kernel parameter or nothing for the five cases of the
    design's table, with `--explain` for the human sentence, file overrides for tests, output
    validated against `^[a-z0-9_,]+$`, exit 0 always; a GRUB drop-in that appends the helper's
    output when the helper is executable and does nothing otherwise
  - `--explain` and `--manual` per the design (the manual line starts with the fixed prefix
    `snitch: add to the kernel command line: `); the admin case recognises `lsm=` at the start
    of the GRUB variables and after whitespace, and says "already in your lsm=" when the admin's
    list holds `bpf`; the character check applies to the list; without `-l`, a root that is not
    PID 1's root (or an unreadable `/proc/1/root`) yields no parameter, while `--explain` and
    `--manual` always print their line
  - The pipeline's shellcheck check also globs `packaging/*.sh` (one line in `.dagger/checks.go`)
  - A Go test runs the helper with fixture files for all five cases, both admin variants, a
    list with a forbidden character, and the explain and manual wording, and sources the
    drop-in with and without a helper present, and the guard tripping on an unreadable
    `/proc/1/root`
  - Done when: `go test -race ./internal/lsm -run Helper` is green and `dagger call shellcheck`
    is clean with `packaging/lsm-cmdline.sh` in its list
  - _Boundary: packaging/lsm-cmdline.sh, packaging/grub-snitch-lsm.cfg, internal/lsm/helper_test.go, .dagger/checks.go_
  - _Depends: 1.1_
  - Before emitting anything, the helper checks every installed kernel under the boot
    directory: each `vmlinuz-<v>` needs a readable `config-<v>` with `CONFIG_BPF_LSM=y`;
    otherwise, or with no kernel found, it emits nothing and `--explain` names the first kernel
    and the reason. Tests cover all supported, one kernel without the option, one without a
    configuration file, and an empty boot directory (`-k` points at fixtures)
  - _Requirements: 7.1, 7.2, 7.3, 7.4, 7.5, 7.12_
- [x] 5.2 The maintainer scripts and the deb tree
  - `postinst` (configure): regenerate through `update-grub` when it and `/boot/grub` exist,
    report a failure in one line without failing, then print the helper's explanation; without
    GRUB print the parameter to add by hand; `postrm` (remove, purge): regenerate when
    possible, never fail. Neither enables a unit, writes the operator file, or touches rules
  - The deb tree ships the drop-in (declared conffile), the helper (0755 under `/usr/lib/snitch`)
    and both scripts; the control description says the package configures GRUB
  - Every absolute path in both scripts carries the `${DPKG_ROOT:-}` prefix (dpkg's own
    variable, empty on a normal install)
  - Done when: `dagger call shellcheck` is green, and a Go test in `internal/lsm` runs both
    scripts with `DPKG_ROOT` set to a temporary tree and a stub `update-grub` first on PATH:
    called once on configure and on remove, a failing stub still exits 0, the tree without
    `boot/grub` prints the manual line
  - _Boundary: packaging/postinst.sh, packaging/postrm.sh, packaging/conffiles, packaging/control, .dagger/deb.go, internal/lsm/scripts_test.go_
  - _Depends: 5.1_
  - _Requirements: 7.6, 7.7, 7.8, 7.9, 7.10_
- [x] 5.3 The smoke proves it on both distributions
  - Group 2's payload list grows to the eleven files; a new group 9 "boot setting" checks the
    laid files and modes, the no-GRUB message of the install, the stub-driven configure and
    its failing variant, the helper's table inside the container, removal (helper gone,
    drop-in inert), purge (drop-in gone), and that neither unit is enabled at any point;
    lintian becomes group 10 at the unchanged threshold, with an override added only if a
    tag at error level appears and is justified in the overrides file
  - Group 5's journal check still passes with the new log line
  - The group asserts that `DPKG_ROOT` is unset or empty in the real install
  - Done when: with all earlier tasks committed (the smoke builds from a clean tree; group 8
    runs 4.4's new tray-check step), on a local throwaway tag, `dagger call smoke` is green for
    both distributions; the tag is deleted afterwards and never pushed
  - _Boundary: .dagger/smoke.go, packaging/lintian-overrides_
  - _Depends: 2.1, 4.4, 5.2_
  - _Requirements: 7.11, 8.4_

- [ ] 6. Documentation and the host check script
- [ ] 6.1 (P) The reference documents
  - The API document describes the hook member with one example per state; the daemon
    document gains the `hook:` line, the start log line and the trial refusal; the terminal UI
    document the tag, the bottom line and the `down` class; the tray document the seventh
    state with its icon, rank, row and note
  - Done when: every state word, sentence and key in these documents matches the code
    (`grep` for each design sentence finds it in code and document alike)
  - _Boundary: examples/api.md, docs/daemon.md, docs/tui.md, docs/tray.md_
  - _Depends: 2.2, 2.3, 4.1, 4.2, 4.3_
  - _Requirements: 2.6, 8.2_
- [ ] 6.2 (P) The user and package documents
  - The README says the package configures GRUB hosts, that a reboot is needed after the first
    install, how to check, and what to do on other boot loaders; the package document replaces
    "nothing runs on install" with the new promise, lists the eleven payload files and the
    scripts, and records the conffile behaviour on removal and the image-build limit (a
    container that is its own PID namespace reads its own kernel's list); development, CLAUDE.md, the
    steering files and the roadmap item for chandali are brought in line
  - Done when: no document still claims the package has no maintainer scripts
    (`grep -rn "no maintainer scripts\|no .postinst" docs README.md` finds only the changed,
    historical-marked sentence), and every relative link resolves
  - _Boundary: README.md, docs/ci-debs.md, docs/development.md, CLAUDE.md, .kiro/steering/product.md, .kiro/steering/tech.md, .kiro/steering/structure.md, .kiro/steering/roadmap.md_
  - _Depends: 5.2_
  - _Requirements: 8.1, 8.2_
- [ ] 6.3 (P) A read-only host check
  - A script that prints the active LSM list, whether the running command line carries
    `lsm=`, whether the drop-in and helper are installed, what the helper would emit (called
    with explicit `-l /sys/kernel/security/lsm -c /proc/cmdline`, so the PID-1 guard does not
    blank it for an ordinary user), and the
    daemon's reported hook state; no sudo inside, changes nothing, exit 0 when active and 1
    otherwise
  - Done when: `dagger call shellcheck` is clean and the script runs on the
    development host as an ordinary user and reports the inactive state
  - _Boundary: scripts/lsm-check.sh_
  - _Depends: 2.1, 5.1_
  - _Requirements: 8.5_

- [ ] 7. Close-out
- [ ] 7.1 The whole tree is clean
  - Full test, vet, format, caps, the import and request pins of the user binary, and the
    pipeline's lint functions
  - Done when: `gofmt -l .` prints nothing, `go vet ./...`, `go test -race ./...`,
    `sh scripts/caps.sh` and `dagger call lint-all` are green
  - _Depends: 2.2, 2.3, 4.4, 5.3, 6.1, 6.2, 6.3_
  - _Requirements: 8.3_
- [ ] 7.2 The check on chandali, run by the operator
  - The operator installs the built package, runs the host check (inactive, reboot pending,
    every surface warning), reboots, and runs it again (active; the overview shows programs
    with destinations). No agent uses root; the outputs are pasted into the task notes
  - Done when: the pasted second run shows the hook active and a status whose egress decision
    counter is above zero
  - _Depends: 7.1_
  - _Requirements: 8.5_

## Implementation Notes
- Task 2.1: `cmd/snitchd/apifacts_test.go` (`TestFactsOfAFlagDaemon`) was added to Task 2.1's boundary to assert `got.Hook != nil && got.Hook.State != "" && got.Hook.Reason != ""` and clear `got.Hook = nil` alongside `got.DNS` and `got.Counters` before struct equality comparison (matching commits `2f68e338` and `90bfeb11`). Also `hookCache` uses field name `clock` because `now()` is a method.
- Task 2.2: `cmd/snitchd/apiwrite_test.go` (`apiDaemonOf`) was added to Task 2.2's boundary so API trial tests inject an in-memory `hookCache` reader answering `lsm.Active` instead of reading host `/sys/kernel/security/lsm`.
