# Research & Design Decisions

## Gap analysis (2026-10-11)

### Scope of the analysis

Two repositories. In snitch: the release workflow, two small daemon additions the deployment
needs (`-version`, a root-less rules check), README. In hyperland-forky-worker-vm (pyinfra
3.10.0, Python 3.11, one deploy as root via sudo): a `snitchd` task, pins, the rules file, the
unit files, README, pin checker, CI check of the rules file. Then the verified first deploy on
this VM, with one reboot and a two-minute trial.

### What exists

**snitch**
- `systemd/snitchd.service` (ExecStart `/usr/local/sbin/snitchd -rules /etc/snitch/rules.toml`,
  StateDirectory/RuntimeDirectory `snitch` 0700) and `systemd/snitchd-trial-boot.service`
  (`snitchd end -at-boot`): exactly what the task installs. Nothing to change.
- `CGO_ENABLED=0 go build ./cmd/snitchd` gives a statically linked ELF of 6.9 MB with the Go
  toolchain alone (the BPF object and bindings are committed). Verified locally.
- `.github/workflows/lint.yml`: four jobs (ruff on the Python client, go build/vet/test + caps,
  shellcheck, actionlint) on push and PR. No release workflow. Release `v0.1.0` exists, made by
  hand, with the Python client's `snitch` and `snitch-trial` as assets.
- No `-version` flag (`cmd/snitchd/config.go` has `-rules -learn -learned -mode -state-dir
  -status -duration`). No way to parse a rules file without root: `rules.Load` is only reached
  through `run`, which loads the BPF objects. `scripts/enforce-test.sh --check-only` runs the
  daemon as root.
- Rules model (`internal/rules`): `[[program]]` name/paths (filepath.Glob, no `**`, no `~`)/note;
  `[[rule]]` program (declared name or `any`)/to (CIDR or address, mandatory, no keyword for
  "any" or "local")/proto (optional)/port (optional, int or `"a-b"` up to 256 ports)/verdict/
  note. "Any destination" is two rules, `0.0.0.0/0` and `::/0`. One executable belongs to one
  program (symlinks resolved to the inode), so apt's `http` and `https` methods are one program.
  The local network is allowed in the BPF program (RFC 1918, 169.254/16, loopback, fc00::/7,
  fe80::/10); `255.255.255.255` is not in that list.
- `scripts/enforce-test.sh` probes `1.1.1.1` (allowed by a generated curl rule, tcp 443) and
  `9.9.9.9` (denied); `examples/rules.toml` documents the same 1.1.1.1 rule.
- `snitchd status` prints eight stable keys (persistent-trial design); the status record has
  twelve keys, none for a version.

**hyperland-forky-worker-vm** (HEAD 9e7bf65, 2026-10-11, "retire Little Snitch and the snitch
0.1 client")
- No snitch pins, tasks or units remain. `group_data/all.py` keeps `serial_console = True`
  ("the way back when the network is gone, e.g. an egress firewall that denies too much").
  Pins are `<tool>_version` + `<tool>_sha256`, a pin of `None` means "do not install".
- Root binary + system unit pattern: `tasks/away.py` (`files.put` to `/usr/local/sbin` with
  `_sudo=True`, unit text inline via `StringIO` headed `# Managed by debian-hypr`, then
  `systemd.service(running=True, enabled=True, restarted=unit.changed,
  daemon_reload=unit.changed)`). Release-binary download with checksum and a stamp file:
  `tasks/apps.py:179-196` (`server.shell`, `curl -fsSL`, `echo "<sha>  <file>" | sha256sum -c`,
  stamp under `/usr/local/share/debian-hypr/<name>.sha256`). The repo never uses
  `files.download`.
- Switch pattern: `tasks/tuning.py:43-48`, one `server.shell` whose name and command depend on
  the boolean (`systemctl enable --now` / `disable --now ... || true`).
- Static files in `files/<area>/`, templates in `templates/<area>/*.j2`. Tasks run in the order
  of `deploy.py`; one task alone: `uv run pyinfra inventory.py tasks/<task>.py`.
- CI: `lint.yml` (shellcheck by shebang, ruff, luacheck, actionlint), `pins.yml` runs
  `tools/pin-check.py` daily; a new pin needs a tuple in `pins()` (`tools/pin-check.py:55-61`,
  tag prefix "v"). No pyinfra dry run in CI.
- README: lines 169-170 already quote snitchd's kill switch under "Serial console"; lines
  411-412 say snitchd "replaces it once it ships". The task table has no snitchd row.

### Requirement-to-asset map

| Req | Existing asset | Gap |
|---|---|---|
| 1.1 static amd64 build, assets binary + sha256 | static build verified; `go-version-file: go.mod` works in lint.yml | Missing: `release.yml` on `v*` tags, `permissions: contents: write`, upload |
| 1.2 `-version` | none | Missing: `var version = "dev"` set by `-ldflags -X`, `-version` flag, version in the startup journal line; Unknown: whether `snitchd status` gets a ninth line (changes the "eight stable keys") |
| 1.3 nothing on failure | GitHub Actions job dependencies | Constraint: upload only in a job that `needs:` the checks and the build |
| 1.4 same checks as lint | lint.yml steps | Option: make lint.yml `workflow_call`-able and `uses:` it from release.yml, or duplicate the four jobs (drift) |
| 2.1 pins + switch | pin naming style, `serial_console` block | Missing: `snitchd_enabled`, `snitchd_version`, `snitchd_sha256`; pin-check tuple |
| 2.2 download, verify, install, units, rules, enable | `apps.py` release_tools pattern; `away.py` unit pattern | Missing: `tasks/snitchd.py`; Unknown: units copied into the VM repo or fetched from the release (see options) |
| 2.3 checksum mismatch fails before replacing, names the checksum seen | `sha256sum -c` pattern says only "FAILED" | Missing: print `sha256sum "$t/snitchd"` before `exit 1` |
| 2.4 new version → restart, back within 5 s | `systemd.service(restarted=op.changed)`; daemon start is well under 1 s | Constraint: the download op must expose `did_change` (stamp file comparison inside `server.shell` does: pyinfra 3 reports a shell op as changed whenever it runs; so a version guard `_if` is needed, or the stamp read as a fact) |
| 2.5 off keeps files | `tuning.py` switch | Missing: off branch `systemctl disable --now snitchd.service snitchd-trial-boot.service` |
| 2.6 rules change → reload without restart | daemon's 2 s file stat reload; summary line | Missing: `files.put` of the rules file with no restart tied to it |
| 2.7 never mode/duration/kill/trial/kept | units carry no `-mode` | Constraint: the task must not add a drop-in with flags; the learning switch (3.5) must not break this |
| 2.8 idempotent | `files.put` and `systemd.service` are; `server.shell` is not | Constraint: guard the shell op with a fact or `_if` so a no-change run reports no changes |
| 3.1 rules file in the VM repo, checked in CI | none | Missing: `files/snitchd/rules.toml`; Missing: a root-less check command (`snitchd check -rules F` or `-check`) and a VM CI job that downloads the pinned binary, verifies its sha and runs the check |
| 3.2 translate address/range/local rules | inventory below | Constraint: 2 address rows (Anthropic ranges, for any program and for Claude Code), 3 local rows need no rule (BPF allows local), 8 "any destination" rows need `0.0.0.0/0` + `::/0` pairs; Req 3.2 wording amended to include them |
| 3.3 domain rules as deferred comments | 18 domain rows | Missing: comment block per program |
| 3.4 Claude Code to Anthropic ranges, warning | `160.79.104.0/23`, `2607:6bc0::/48`; program paths `/home/*/.local/share/claude/versions/*` | Missing: the rule and the comment |
| 3.5 learning run after a working day | `-learn -learned` flags; follower ignores files while learning | Unknown: how to turn learning on for the service (drop-in via a `snitchd_learn` switch, or a hand run with the service stopped) |
| 3.6 curl stays out | Python client has no curl rule; `examples/rules.toml` declares curl for the test only | Constraint: no curl program in the deployed file; the test script generates its own rule in a temp file |
| 4.1 snitch README | README has Service/Trial paragraphs | Missing: Release paragraph, pointer to the VM repo |
| 4.2 VM README task description | README structure with a task table | Missing: snitchd row and section |
| 4.3 "once it ships" line | lines 411-412 | Missing: rewrite |
| 5.1-5.6 verification | enforce-test.sh (temp state dir, generated rules) does not cover a deployed service | Missing: a checklist script or a documented manual sequence; Unknown: whether to add a phase to enforce-test.sh (it must not touch `/var/lib/snitch` of the live service) or write `scripts/deploy-check.sh` |

### The rules inventory (from the Python client, `snitch` L611-662)

All rules are `allow`. The Python model has launcher ("via") distinctions and directions; the
daemon has neither (egress only, keyed by executable), so those collapse.

| Class | Rows | Translation |
|---|---|---|
| ADDRESS | B4 any program → Anthropic ranges; D2 Claude Code → Anthropic ranges | direct: `to = "160.79.104.0/23"` and `"2607:6bc0::/48"` per program |
| LOCAL | B1 local network any program; D19 helm → cluster; D20 kubectl/k9s/ktop → cluster | no rule: the BPF program allows the local network. The programs can still be declared with a comment so the learned file names them |
| ANY DESTINATION | B2 hypr-rdp (never block); B5 DNS port 53 any program; B6 DHCP udp 67-68; B7 systemd-timesyncd udp 123; B8/B9/D9 apt methods http+https | `to = "0.0.0.0/0"` + `"::/0"` with the port/proto; DHCP: add `255.255.255.255/32` udp 67 for any program (broadcast is not local in the BPF list; discover goes over AF_PACKET anyway, renewals are unicast to the RFC 1918 server) |
| DOMAIN | B3 any program → anthropic.com, claude.ai, claude.com; D1 Claude Code, D3/D4 Codex, D5 Copilot, D6 gh, D7 git-remote-http(s), D8 ssh, D10 node/npm, D11 uv, D12/D13 pip, D14 cargo, D15/D16 go, D17 podman, D18 helm, D21/D22 bar quota (codex, hypr-agent-quota) | deferred: one comment block per program naming the domains, "deferred to the DNS tap spec". The programs themselves can be declared (paths) so events carry their names in monitor mode and the learned file groups by them |

Program path globs (`claude/versions/*`, `vendor/*/bin/codex`, `releases/*/bin/codex`,
`python3.*`, `uv/python/*/bin/python3*`, `go-*/bin/go`, `toolchain@*/bin/go`) are supported by
the daemon (`filepath.Glob`); `~` becomes `/home/*`. Zero matches is "unresolved", not an error.

Left out on purpose: curl, wget, a bare python as a downloader (the Python client never allowed
them; pip's interpreter rule is scoped to pypi, a domain rule, so deferred).

### Implementation approach options

**Release (Req 1)**
- A. `release.yml` with its own copy of the four check jobs, then `build` (static, ldflags
  version), then `publish` (`gh release create "$TAG" snitchd snitchd.sha256 --generate-notes`
  or upload to an existing release). Simple, drifts from lint.yml.
- B. Add `workflow_call` to lint.yml's `on:`, have release.yml `uses: ./.github/workflows/lint.yml`
  as its first job and `needs:` it. One source of truth for the checks. Recommended.
- Tag scheme: the repo has `v0.1.0` holding the Python client. Keep one `v*` scheme for the repo
  (the next tag is `v0.2.0`), the workflow attaches snitchd + sha256; the Python files can be
  attached by the same workflow (they are plain files in the repo) so a release stays complete.
  The VM pin uses tag prefix "v", as pin-check expects.

**Units into the host (Req 2.2)**
- A. Copy the two unit files into the VM repo (`files/snitchd/*.service`, `files.put`), header
  "Managed by debian-hypr, copy of snitch/systemd/". Matches `away.py`; the VM repo owns what it
  installs; drift risk small (units are stable) and visible by diff. Recommended.
- B. Ship the units as release assets and download them with their checksums. Three pins
  instead of one, more shell; the sha of the binary would no longer be the single pin.
- C. One tarball asset (binary + units), one sha256. Clean single pin, but Req 1.1 says the
  binary and its sha256 are the assets; pin-check and the download shell get a tar step.

**Root-less rules check (Req 3.1)**
- A. A `check` verb (`snitchd check -rules F`): parse + validate, print the summary, exit 1 on
  error; no root, no BPF. Fits the verb table from persistent-trial (`ctl.go`); `rules.Load` is
  already the pure part. VM CI job: read the pins from `group_data/all.py`, download the pinned
  binary, verify the sha, run the verb on `files/snitchd/rules.toml`. Recommended.
- B. A Go test in the snitch repo that reads the VM repo's file: cross-repo path, breaks in CI.
- C. Validate with a Python TOML load in the VM repo's CI: catches syntax only, not references,
  duplicate keys or port bounds.

**Learning run (Req 3.5)**
- A. `snitchd_learn = False` switch in group data; when true the task writes a drop-in
  `/etc/systemd/system/snitchd.service.d/learn.conf` with `ExecStart=` reset and the same line
  plus `-learn -learned /var/lib/snitch/learned.toml`, and restarts; when false it removes the
  drop-in. Learning never denies (follower ignores the files), so Req 2.7 holds: no mode, no
  duration. Recommended: a switch, a deploy, a day, a deploy back.
- B. Hand run: stop the service, run the binary with `-learn` from a shell for a day. Fragile
  (a reboot or a closed shell ends it) and leaves the trial-boot unit meaningless meanwhile.

**Verification (Req 5)**
- A. `scripts/deploy-check.sh` in snitch: a read-only checklist against the live service
  (systemctl is-active/is-enabled, `snitchd status` exit 0 and mode, curl 1.1.1.1 then grep the
  journal for the rule, a monitor event), with the trial steps behind their own [y/N] prompt and
  a trap running `snitchd end`. The reboot is a manual step between two invocations. Reuses the
  enforce test's helpers but never touches `/var/lib/snitch` except through the verbs.
- B. Extend `scripts/enforce-test.sh` with a phase 4: its temp state dir and generated rules
  are built for a hand-started daemon; mixing in the live service makes the trap wrong.
- Recommended: A.

### Complexity and risk

- Effort: M. Two repos, five deliverables each small, plus an operator-paced verification over
  at least two sessions (deploy + reboot, and the learning day).
- Risk: Medium. The deploy touches the host that carries the operator's session: every step
  runs in monitor mode until the operator's go, the serial console exists, and the trial is two
  minutes with the boot revert installed first. The reboot drops RDP once by design.

### Recommendations for the design

1. Release: option B (reusable lint workflow) + binary and `.sha256` assets; version via
   ldflags; the Python client's files attached too.
2. Daemon additions, both deployment-revealed and small: `-version` (also in the startup
   journal line and as a ninth `snitchd status` line `version:`), and a `check` verb.
3. VM task `tasks/snitchd.py` after `services` in `deploy.py`: pins + switch + `snitchd_learn`;
   download guarded by a fact so a second run reports no change; units copied into
   `files/snitchd/`; rules at `files/snitchd/rules.toml`; off branch leaves files.
4. Rules file: declared programs for every Python rule (so events are named), address rules
   for Anthropic, any-destination rules for hypr-rdp, DNS, DHCP broadcast, timesyncd, apt;
   domain rules as deferred comment blocks; no curl.
5. `scripts/deploy-check.sh` for Req 5, run twice around the reboot.

### Research needed (design phase)

- pyinfra 3.10: does `server.shell` report `changed` on every run, and what is the idiom for a
  conditional op (`_if=` with a `host.get_fact(File/Sha256File, ...)`)? Confirm `Sha256File`
  fact exists (`pyinfra.facts.files.Sha256File`) to make the download idempotent without a stamp.
- GitHub release creation from a workflow: `gh release create` needs `permissions: contents:
  write`; confirm `--generate-notes` behaviour when the release already exists (`gh release
  upload --clobber` as the fallback).
- Whether `snitchd status` gaining a `version:` line needs a persistent-trial design note (the
  "eight stable keys" statement) — yes, record it as a deviation there.
- DHCP on this VM: which client (systemd-networkd or dhclient) and whether it sends UDP to
  255.255.255.255 from a connected or unconnected socket (decides whether the broadcast rule is
  needed at all; harmless if present).

### Requirements amendments made during the analysis

- 2.1 and 4.3: the VM repo retired its `snitch_*` pins and Little Snitch text on 2026-10-11
  (commit 9e7bf65); the criteria now name the current state.
- 3.2: "address, address range or local network" extended with "any destination" so the
  hypr-rdp, DNS, DHCP, time sync and apt rules are in scope as `0.0.0.0/0` + `::/0` pairs.

---

## Design decisions (2026-10-11, light discovery for an extension)

### Verified during discovery
- pyinfra 3.10.0 (installed source): `Sha256File` fact returns None for a missing file;
  `server.shell` is always a change, gated with `_if=callable`; `files.put` changes only when
  content or mode differ (path or StringIO); `systemd.service(service, running, restarted,
  enabled, daemon_reload)` names confirmed; `files.download(sha256sum=)` exists but the repo's
  idiom is `server.shell` + `sha256sum`, kept for consistency.
- gh: `gh release create <tag> <files> --generate-notes --verify-tag`; creating a release that
  exists fails with "a release with the same tag name already exists", so the publish step
  tries `gh release view` first and falls back to `gh release upload --clobber`.
- `actions/setup-go@v5` with `go-version-file` reads the `go` directive (`go 1.26.8`) and
  installs that patch version.
- DHCP on the VM is dhcpcd (raw socket for discover, unicast renewals); the broadcast rule is
  harmless insurance, not a known need.
- A `[[program]]` without rules validates (no "unused" check), so programs with only deferred
  rules are declared for event names.

### Synthesis
- Generalization: "a verb that needs no root" is the only new axis in the CLI; one `root bool`
  on the verb table covers it (and the future TUI/API verbs).
- Build vs adopt: the reusable lint workflow (`workflow_call`) instead of duplicated jobs;
  `gh` instead of a third-party release action; pyinfra's own facts instead of a stamp file.
- Simplification: the units are copied into the VM repo (one header line) rather than
  downloaded and pinned separately; one pin (the binary's sha256). No new Go package: the
  `check` verb reuses `rules.Load/Resolve` and the daemon's `summary`. The deploy check is a
  separate script, not a fourth phase of the enforce test, because the two have different
  state-directory contracts.

### Decisions
- Tag scheme stays `v*` for the whole repo; the next release is `v0.2.0`; the Python client's
  files ride along as assets.
- `-version` prints the tag exactly; the release job asserts it.
- The status record gains a thirteenth key `version` (last); persistent-trial's design gets a
  one-line deviation note.
- The deploy never starts the boot oneshot (it would end a live trial): `enabled=True,
  running=False`.
- Learning is a switch (`snitchd_learn`) that writes a drop-in; the trial verb refuses while
  learning, so the switch cannot deny.
- Requirement 5.2 amended: the rule probe is `apt-get update` (curl has no rule by 3.6).

### Boundary impacts
- The rules file content is owned by this spec but lives in the VM repo; the DNS tap spec will
  rewrite its deferred comments into rules (revalidation trigger recorded).
- The VM's CI depends on a published snitch release; until `v0.2.0` exists the job cannot pass,
  so the VM-repo tasks come after the release task in the plan.

### Design validation (2026-10-11, independent reviewer): GO with one fix
- pyinfra: `OperationMeta.did_change()` raises before execution and `.changed` of a
  `server.shell` is always true at parse time (`_if` is only consulted while executing), so a
  `restarted=` bool computed from it would restart the daemon on every deploy. Fixed: a
  separate `systemctl restart` shell op gated with `_if=[op.did_change, ...]` callables.
- The 2.7 CI grep anchored on a command line so comments may explain the rule.
- Version skew: the strict status record makes an un-restarted old daemon read as "not
  following"; the deploy check compares versions first and names the restart as the remedy.
- Verified by the reviewer in pyinfra's source: `running=False` on an inactive oneshot is a
  no-op; `enable` and `daemon-reload` start nothing.

---

## Release v0.2.0 (task 2.2, 2026-10-11)

- Tag `v0.2.0` on commit 86a26ea (groups 1 and 2.1), pushed after lint run 38133518047 was
  green on `main`. Release workflow run 38133561179: jobs checks/{actionlint,shellcheck,ruff,go}
  and release all success.
- Assets: `snitchd` (4690082 bytes), `snitchd.sha256`, `snitch`, `snitch-trial`.
- Verified locally from the download: `sha256sum -c snitchd.sha256` → OK; `./snitchd -version`
  → `v0.2.0`; statically linked ELF x86-64; `./snitchd check -rules examples/rules.toml` → exit 0
  (3 programs, 6 rules).
- **Pin for the VM repo**: `snitchd_version = "0.2.0"`,
  `snitchd_sha256 = "a51cf6d6c27e1af9de2487f0613cee1f0ef061e020a99e1065feb669dc45d291"`.

### Unit fix found by the 3.2 review (2026-10-11)
`Wants=snitchd-trial-boot.service` in `snitchd.service` meant every `systemctl restart
snitchd.service` (the deploy's op 7b on a version bump) started the oneshot, which runs
`snitchd end -at-boot` and removes an open trial file: fail-safe direction, but against the
design's "the restart does not touch the trial file" and Req 2.7. Fixed by dropping `Wants=`
(keeping `After=`) in snitch/systemd and the VM copy; persistent-trial's design records the
deviation. 4.2 checks `journalctl -u snitchd-trial-boot -b` after the restart step: the oneshot
must have run once this boot only.

## VM repo CI (task 3.4, 2026-10-11)
- Branch `snitchd` at b7af2bc (3.1-3.4 plus the unit fix): lint run 38134552778 green, the new
  `snitchd-rules` job downloaded the v0.2.0 asset, verified the digest and ran `check` on
  files/snitchd/rules.toml (18 programs, 13 rules).
- Throwaway commit with a rule for an undeclared program: run 38134607285 red at
  `snitchd-rules` with `files/snitchd/rules.toml:238: rule for undeclared program "undeclared"`;
  the branch was reset to b7af2bc afterwards. The merge to `main` is task 4.2's step.

---

## First deploy on the dev VM (task 4.2, 2026-10-11, operator's go given)

| Step | Command / change | Outcome |
|---|---|---|
| pre-check | clean VM tree at b7af2bc, `snitchd_enabled = True`, serial getty active, kill map 0, nothing installed | ok |
| deploy | `uv run pyinfra -y inventory.py tasks/snitchd.py` | 9 ops, 8 success, 1 no change (drop-in absent); the restart op fired once on the first install |
| phase A | `sudo scripts/deploy-check.sh` | 15/15 PASS; `state: service active mode monitor trial none kept no kill clear`; oneshot journal empty this boot |
| path | `sudo snitchd status` → command not found: sudo's `secure_path` is `/usr/sbin:/usr/bin:/sbin:/bin`, the user's PATH lacks `/usr/local/sbin` | deploy-revealed: the task now links `/usr/sbin/snitchd` and `/usr/local/bin/snitchd` to the binary (commit in the VM repo); `sudo snitchd status` exit 0, `snitchd -version` as the user prints v0.2.0 |
| idempotent (2.8) | second deploy | 11 ops, 11 no change (9/9 before the links were added) |
| reload (2.6) | comment appended to files/snitchd/rules.toml, deploy | `snitchd rules` changed, restart op no change, new `rules:` summary in the journal within 5 s, `ExecMainStartTimestamp` unchanged; reverted and deployed again |
| version bump (2.4) | modified copy moved over `/usr/local/sbin/snitchd`, deploy | install op re-ran (digest back to a51cf6d6…), restart op ran, new PID, `snitchd status` exit 0 after 3 s including the deploy; oneshot journal still empty (the `Wants=` fix holds) |
| off (2.5) | `snitchd_enabled = False`, deploy | 3 ops: off op ran; service inactive, both units disabled; binary, rules, units, links present; `/var/lib/snitch` empty; second off run 3/3 no change |
| on | `snitchd_enabled = True`, deploy | 11 ops: boot unit enabled, service running; install op no change (no download); active, both enabled |
| merge (4.2) | VM repo `main` pushed, branch `snitchd` deleted | see the run id in tasks.md |

## Trial on the deployed service (task 4.3, part 1, 2026-10-11, serial console open)

`echo y | sudo scripts/deploy-check.sh --trial -l 10.0.0.1:53`: phase A 15/15, phase B 9/9
(T1 trial 2m accepted and enforce within 5 s; T2 curl 9.9.9.9 EPERM, local probe ok, apt ok;
T3 journal `mode: enforce (trial until`; T4 monitor within 130 s, `trial ended at its deadline`,
curl connects again). Trap: `snitchd end (no trial left)`. Final line:
`state: service active mode monitor trial none kept no kill clear`. The operator's RDP session
and this Claude Code session (Anthropic ranges allowed by rule) stayed up.

Order change: the trial ran before the reboot because a reboot ends the Claude Code session
on this VM; the reboot and the post-reboot phase A are the operator's next step (part 2).

## Reboot (task 4.3, part 2, 2026-10-11)

Operator reboot at 13:44:28 (RDP dropped once and came back). `journalctl -u snitchd-trial-boot -b`:
the oneshot ran once at 13:44:32, `already monitor: no trial, nothing kept`, then
`snitchd v0.2.0: mode monitor (files)` from the daemon. `sudo scripts/deploy-check.sh` after the
reboot: 15/15, `state: service active mode monitor trial none kept no kill clear` (Req 5.3, 5.5).

## Push state (task 4.4)
- snitch `main`: lint run 38136576321 success 5271e17 (run id, conclusion, sha).
- VM repo `main`: lint run 38136203738 success eea9699, snitchd-rules job included.

## Checksum mismatch exercised (validation, 2026-10-11)
Wrong pin `snitchd_sha256 = "0000000000…"` on the deployed host, one deploy: the install op ran
(digest differs), printed `snitchd v0.2.0: sha256 a51cf6d6…5d291, expected 0000000000…5d291`
and failed; pyinfra stopped for the host; binary digest and the daemon's PID unchanged, service
active; pin restored (Req 2.3).

## Feature validation (2026-10-11): GO
Mechanical: `go test -count=1 -race ./...` ok, caps ok, no TODO/secret markers in either repo's
feature files, live smoke on the deployed service (active, `snitchd status` exit 0 at v0.2.0,
`check` on /etc/snitch/rules.toml exit 0), shellcheck and actionlint clean. Two independent
cross-task reviews (coverage + boundary; design alignment + integration): 27/27 criteria
covered (3.5 deferred to task 4.5 by the plan), no Critical or Warning findings; nine Notes, all
documentation alignments, fixed in f29b79b, 8644e2f and VM 173ecef; the checksum-mismatch branch
was exercised on the host (above). Open: task 4.5, the learning run after a working day.

## Revalidation by daemon-api (2026-10-11)
daemon-api changed two things this spec deployed: `snitchd.service` now has
`RuntimeDirectoryMode=0755` (the status file stays 0600; the API socket needs a traversable
directory) and the task deploys `/etc/snitch/operator`. Both landed in the VM repo at 44af244
(lint incl. snitchd-rules green) and were deployed with pins v0.3.0; `deploy-check.sh` phase A
passed 15/15 afterwards.
