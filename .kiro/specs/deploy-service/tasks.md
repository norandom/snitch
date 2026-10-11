# Implementation Plan

Every task below is a self-contained brief for an implementer without conversation context.
Before a task, read `.kiro/steering/tech.md`, `.kiro/steering/fail-safes.md`, the design
sections named in the task, and the Implementation Notes of `.kiro/specs/persistent-trial/tasks.md`
(the conventions this spec continues: delegates, contracts with a violation test each, caps via
`scripts/caps.sh`, mutation evidence for tests, verb flags before positional words). Two
repositories: snitch (`/home/mc/Source/snitch`) and the VM repo
(`/home/mc/Source/hyperland-forky-worker-vm`, pyinfra 3.10.0, run with
`TARGET_HOSTS=@local TARGET_USER=mc uv run pyinfra -y inventory.py tasks/<task>.py`, `--dry` to
prepare only; pushing that repo deploys nothing, the deploy is always a local run). `_Boundary:_`
names the files a task may touch. A Go task is done when its "Done when" command succeeds and
`gofmt -l .`, `go vet ./...`, `go test -race ./...` and `sh scripts/caps.sh` are clean; a VM-repo
task when `uvx ruff check` and the repo's lint commands are clean. Nothing in groups 1 to 3
changes this VM: every deploy, the reboot and the trial happen only in group 4, each after the
operator's explicit go in the session, with the serial console open. Pushes (snitch `main`, the
tag, the VM repo) happen only in the tasks that name them, after the no-secrets check of the
diff. Tasks that edit files in the same Go package run one at a time. The spec counts as
validated with task 4.5 (the learning run) still open: it needs a working day of monitor mode.

- [x] 1. The binary says what it is and checks what it loads
- [x] 1.1 The version in the binary
  - One version variable, "dev" unless set at link time; `-version` prints it and exits 0
    before the configuration check, so `-version` alone is valid; the startup journal line
    carries it (`snitchd <version>: mode …`)
  - Contract: the version is never empty where printed (a link with an empty value trips it);
    the print goes through a small helper so the contract has a test
  - Done when: `go test ./cmd/snitchd -run Version` proves the flag's output and exit, the
    startup line, and the contract; a build with `-ldflags "-X main.version=v9.9.9"` prints
    `v9.9.9` for `-version`
  - _Boundary: cmd/snitchd/version.go, config.go, config_test.go, daemon.go, daemon_test.go_
  - _Requirements: 1.2_
- [x] 1.2 The version in the status record and in `snitchd status`
  - The status record gains a `version` key, last after `written`, written by the daemon's
    status writer from the version variable and required on read like every other key; the
    `status` verb prints a ninth line `version:` from the record, or the "unknown (no status
    record)" form the other lines use; the persistent-trial design's status-record section gets
    one sentence recording the thirteenth key
  - Done when: `go test ./internal/status ./cmd/snitchd -run 'Status|Version'` proves the body
    with the key, the round trip, the missing-key error naming `version`, the newline
    precondition, and the status line in both forms
  - _Boundary: internal/status/status.go, status_test.go, cmd/snitchd/follow.go, follow_test.go
    (the writer's record fixture), ctl_status.go, ctl_status_test.go,
    .kiro/specs/persistent-trial/design.md (one sentence)_
  - _Depends: 1.1_
  - _Requirements: 1.2_
- [x] 1.3 The `check` verb
  - A verb that loads a rules file the way the daemon does (parse, validate, resolve through
    the OS seams) without root or BPF: exit 0 with the daemon's summary line plus one
    `unresolved:` line per pattern without a match; exit 1 with the parser's or resolver's
    `file:line: reason` on stderr, a missing file included; exit 2 on a bad flag; `-rules`
    defaults to the service's path; the shared verb flags are accepted and ignored
  - The verb table gains a per-verb root requirement; dispatch refuses non-root only for the
    verbs that need it, every existing verb still refuses
  - Contract: an empty rules path is a precondition violation
  - Done when: `go test ./cmd/snitchd -run 'Check|Dispatch'` proves every exit code and message
    with temp files and a fake euid, and a binary built from this tree runs
    `check -rules examples/rules.toml` as a normal user with exit 0 and the summary
  - _Boundary: cmd/snitchd/ctl.go, ctl_test.go, ctl_check.go, ctl_check_test.go,
    contracts_trial_test.go (skip the root-less verb in the every-verb loop)_
  - _Requirements: 3.1_

- [ ] 2. A release to pin
- [x] 2.1 The release workflow
  - The lint workflow becomes callable from another workflow (its jobs unchanged); a release
    workflow on `v*` tags runs it first, then builds the static amd64 binary with the version
    linked in, asserts `-version` equals the tag, writes the sha256 file in the form
    `sha256sum -c` reads, and publishes `snitchd`, `snitchd.sha256` and the Python client's two
    files as assets: upload with replace when the release exists, create with generated notes
    and tag verification otherwise; only the publish job has write permission; nothing is
    published when any earlier job fails
  - README: a Release paragraph (tag → checks → assets, `-version`); the Service paragraph
    points at the VM repo's task for deployment
  - Done when: actionlint passes on both workflows; the build command from the workflow, run
    locally with a fake tag, yields a statically linked binary (`file` says so) that prints the
    tag; `sha256sum -c` accepts the generated file
  - _Boundary: .github/workflows/release.yml, .github/workflows/lint.yml, README.md (Release
    and Service paragraphs)_
  - _Requirements: 1.1, 1.3, 1.4, 4.1_
- [ ] 2.2 Tag v0.2.0 and verify the release
  - Only after the operator's go (a tag push publishes a release): commit group 1 and 2.1 if
    not yet committed, check the diff for secrets, push `main`, wait for lint to be green, then
    tag that commit `v0.2.0` and push the tag; watch the release workflow
  - Done when: the workflow is green, the downloaded `snitchd` matches `snitchd.sha256`,
    `./snitchd -version` prints `v0.2.0`, `./snitchd check -rules examples/rules.toml` exits 0,
    and the digest is recorded in research.md for the VM pin
  - _Boundary: git (push of main, the tag), .kiro/specs/deploy-service/research.md (digest)_
  - _Depends: 1.2, 1.3, 2.1_
  - _Requirements: 1.1, 1.2, 1.3_

- [ ] 3. Deployed by the VM repo
- [x] 3.1 (P) The rules file for this VM
  - `files/snitchd/rules.toml` per the design's content contract: a header naming the source,
    the deferred list and the session warning; a program for every Python rule's executable
    with globs kept and `~` as `/home/*`; the Anthropic address rules for any program and for
    Claude Code; the any-destination rules for hypr-rdp, DNS, DHCP broadcast, time sync and
    apt; one deferred comment block per program with domain rules; the local-network rows as
    comments; no curl; every rule with a note saying where it came from
  - Done when: a snitchd built from group 1 says `check -rules files/snitchd/rules.toml` exit 0
    reporting 18 programs and 13 rules (the design's content contract: any 2, claude 2,
    hypr-rdp 2, DNS 2, DHCP 1, timesyncd 2, apt 2), with the not-yet-installed tools as the
    expected unresolved patterns, and every row of research.md's inventory is either a rule, a
    declared program, or a deferred or local-network comment (checklist in the report)
  - _Boundary: hyperland-forky-worker-vm/files/snitchd/rules.toml_
  - _Depends: 1.3_
  - _Requirements: 3.1, 3.2, 3.3, 3.4, 3.6_
- [ ] 3.2 The snitchd task
  - Group data: the enabled switch, version and sha256 pins (the values from 2.2), the learn
    switch, in a commented block after the serial console; the task after `services` in the
    deploy order; copies of both unit files with the one-line header; the task's operations in
    the design's order and with its gates: rules directory and file always; binary download
    with checksum before install (mismatch names the seen and expected digest, nothing
    replaced), units, learning drop-in or its absence, boot-revert unit enabled but never
    started, service enabled and running, restart as a separate step gated at execution time
    on any of binary, units or drop-in having changed (one lambda over `any`, a list of `_if`
    callables means all), the off branch stopping and disabling both units and leaving every
    file
  - Done when: ruff is clean; `--dry` prepares every operation without error against this VM
    (nothing executed); `grep -nE 'snitchd[^#]*(-mode|-duration)' tasks/snitchd.py` and
    `grep -n '/sys/fs/bpf' tasks/snitchd.py` find nothing
  - _Boundary: hyperland-forky-worker-vm/tasks/snitchd.py, group_data/all.py, deploy.py,
    files/snitchd/snitchd.service, files/snitchd/snitchd-trial-boot.service_
  - _Depends: 2.2, 3.1_
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 3.5_
- [ ] 3.3 The VM README
  - The task-table row; a section with the switch, the pins and how to bump them, the rules
    file and the deferred list, the learning run, the trial commands with the serial console and
    the kill switch as the way back and the restart remedy for a version mismatch, off, and the
    kept-enforce download caveat; the "once it ships" line rewritten to say snitchd watches
    egress from boot in monitor mode and how it is switched
  - Done when: the section and the row exist and name every value and command the task uses
    (a checklist against 3.2 in the report)
  - _Boundary: hyperland-forky-worker-vm/README.md_
  - _Depends: 3.2_
  - _Requirements: 4.2, 4.3, 5.6_
- [ ] 3.4 The rules file checked in the VM repo's CI
  - A lint job that reads the pins from the group data, downloads the pinned release binary,
    verifies its checksum, runs the `check` verb on the rules file, and fails on a command line
    in the task carrying a mode or duration flag or on any mention of the BPF path; a pin-check
    tuple so the daily pin run reports a newer snitch release
  - Done when: on a pushed branch of the VM repo, `gh workflow run lint.yml --ref <branch>`
    is green, and a second run on the same branch with a deliberately broken rules file is red
    at the new job (reverted before the merge in 4.2; both run ids in the report);
    `python3 tools/pin-check.py` lists snitchd
  - _Boundary: hyperland-forky-worker-vm/.github/workflows/lint.yml, tools/pin-check.py,
    files/snitchd/rules.toml (temporary break, reverted on the branch), git (a branch of the
    VM repo, no merge)_
  - _Depends: 2.2, 3.1, 3.2_
  - _Requirements: 3.1, 2.7_

- [ ] 4. Verified on the dev VM
- [ ] 4.1 (P) The deploy check script
  - `scripts/deploy-check.sh`: root; phase A always (service active, both units enabled,
    version line equal to the binary's `-version` first with the restart remedy on mismatch,
    status exit 0 with monitor, no trial, nothing kept, kill clear; the startup and rules
    summary lines in this boot's journal; `apt-get update` → a journal event attributed to the
    apt rule; curl to the deny address → a monitor event for curl; journal checks after a
    cursor taken before each probe); phase B behind `--trial` and a [y/N] prompt with a trap
    running `snitchd end` (trial 2 m → enforce in status, EPERM for the deny address, local
    probe and apt still fine, monitor again by the deadline, start and end lines in the
    journal); a final `state:` line in both phases; never writes under the state or runtime
    directories except through the verbs, never touches the kill map or restarts the service
  - README: the Trial paragraph names the script for a deployed host
  - Done when: `shellcheck scripts/deploy-check.sh` is clean, `sudo scripts/deploy-check.sh`
    on this VM (no service installed yet) fails at the first step with a clear line and exit 1,
    and `-h` prints the usage
  - _Boundary: scripts/deploy-check.sh, README.md (Trial paragraph, after 2.1)_
  - _Depends: 1.2, 2.1_
  - _Requirements: 4.1, 5.1, 5.2, 5.4, 5.5, 5.6_
- [ ] 4.2 First deploy on the dev VM
  - Only after the operator's go: deploy the task with the switch on; phase A of the check;
    a second deploy executes zero operations; a comment edit in the rules file deploys and the
    journal shows a new summary within 5 s with no restart; a copy of the installed binary
    with one byte appended moved over `/usr/local/sbin/snitchd` as root (new inode, so no
    ETXTBSY; its checksum differs) and a deploy re-install it and restart the service,
    `snitchd status` exits 0 within 5 s; switch off, deploy: inactive, disabled, files present;
    switch on, deploy: active again without a download; then the VM repo's group 3 changes are
    merged to `main` and pushed with the switch on
  - Done when: every step above is recorded in research.md with its command and outcome, and
    phase A passes
  - _Boundary: .kiro/specs/deploy-service/research.md, hyperland-forky-worker-vm (merge and
    push of 3.1 to 3.4), the dev VM_
  - _Depends: 3.3, 3.4, 4.1_
  - _Requirements: 2.2, 2.4, 2.5, 2.6, 2.8, 5.1, 5.2_
- [ ] 4.3 Reboot and the two-minute trial
  - Only after the operator's go, serial console open, RDP drops once: reboot; phase A again
    (active, monitor, no trial recorded); then `deploy-check.sh --trial`; the operator confirms
    the RDP session stayed up through the trial
  - Done when: both runs pass, the final state line (active, monitor, no trial, nothing kept,
    kill clear) is in research.md, and CLAUDE.md's status says snitchd is deployed and how
  - _Boundary: .kiro/specs/deploy-service/research.md, CLAUDE.md, the dev VM_
  - _Depends: 4.2_
  - _Requirements: 5.3, 5.4, 5.5_
- [ ] 4.4 Caps, contracts and CI
  - Every documented contract of this spec has a violation test; caps green; no exported
    identifier without a caller; the design's contract list matches the code; then snitch
    `main` is pushed after the no-secrets check of the diff (the VM repo was pushed in 4.2), and
    both repos' lint workflows are green on `main`
  - Done when: every command of both `lint.yml` files passes locally, and the remote runs are
    green (recorded with their run ids)
  - _Boundary: `*_test.go` of this spec's packages, design.md contract list, git (push of
    snitch main)_
  - _Depends: 1.2, 1.3, 3.4, 4.2_
  - _Requirements: 1.4_
- [ ] 4.5 The learning run
  - A later session, after at least one working day of the service in monitor mode: learn
    switch on, deploy (the service restarts with the learning flags; the trial verb refuses
    meanwhile); after a working day read `/var/lib/snitch/learned.toml` and review it with the
    operator; the learned file itself is never deployed. Merging the wanted rules into the
    repo's rules file and switching learning off are the follow-up commit, outside this task
  - Done when: the learned file exists and the review (what is wanted, what is not) is in
    research.md
  - _Boundary: hyperland-forky-worker-vm/group_data/all.py (the learn switch),
    .kiro/specs/deploy-service/research.md, the dev VM_
  - _Depends: 4.3_
  - _Requirements: 3.5_

## Implementation Notes
- 1.1: `-version` returns `errVersion`, which wraps `flag.ErrHelp`, so main's silent exit-0 branch handles it without touching main.go; the print goes through the package-level `stdout io.Writer` seam (swapped in tests, no `t.Parallel` in the package); `startupLine(version, mode, source)` and `mustVersion` (the single Ensure) are the helpers 1.2 should reuse. An empty linked version panics before `run`'s recover (raw exit 2, not 70): harmless, nothing attached yet.
- 1.2: `version` is the thirteenth, last status key; `versionLine` follows `rulesLine`'s shape (`recErr != nil` → unknown). The task boundary missed `follow_test.go`, whose writer fixture compares the whole record: boundaries of tasks that add a record field must list every fixture building that record (`grep -rn 'status.Record{' cmd/snitchd`). Implementers: a one-line fix outside the boundary is a NEEDS_CONTEXT, handled by the parent, as here.
- 1.3: `check` calls `rules.Load`/`Resolve`/`Encode` directly (no stat-then-load window; a missing file is exit 1 `<path>: does not exist`); errors print as `snitchd check: <path>:<line>: <reason>`; the unresolved line is `unresolved: <program> <pattern> (<reason>)`, one per pattern (3.1 and the deploy check read that shape). The every-verb contract test skips root-less verbs (`check` uses no probes or trial delegates): a verb that needs none of them is marked `root: false` and gets its own contract tests.
- 3.1: 18 programs, 13 rules, 15 map entries (the two proto-less DNS rules expand to tcp+udp); on this VM only the Go toolchain glob is unresolved (the tools are installed here). B3 (Anthropic domains for any program) was missing from research.md's inventory and is covered as a deferred comment under `claude`; research.md fixed.
- 2.1: the publish step is an explicit if/else on `gh release view` (a failed upload no longer falls through into `create`); `go build -o dist/snitchd` creates `dist/`; the reviewer ran shellcheck over the `run:` blocks via `uvx --from shellcheck-py shellcheck`, which also works locally for later shell tasks.
