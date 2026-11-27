# Research & Design Decisions: lsm-activation

## Summary
- **Feature**: `lsm-activation`
- **Discovery Scope**: Extension (integration-focused; one codebase map by a search agent,
  kernel and packaging behaviour from prior knowledge and the host's own files)
- **Key Findings**:
  - The API status has an exact-bytes golden and a prefix test that require every new field
    to be `omitempty` and to come after `counters`; a nil pointer is the natural "not
    reported", which also keeps the fake daemon's zero value silent.
  - `trialOps` (`cmd/snitchd/trialops.go`) is shared by the API handlers and the CLI verbs, so
    one refusal there covers both doors.
  - `/boot/grub/grub.cfg` is mode 0600 on Ubuntu; only root (the daemon) can tell "reboot
    pending". `/sys/kernel/security/lsm` is world-readable.
  - Files under `/etc` in a hand-assembled deb must be declared conffiles (lintian error
    otherwise), and conffiles survive `remove`. A drop-in that only calls a helper under
    `/usr/lib` is inert once the helper is gone, which makes `remove` behave correctly.

## Research Log

### Why the hooks are silent
- **Context**: v1.1.0 on chandali (Ubuntu resolute, kernel 7.3.4): attach succeeds,
  `decisions` stays 0.
- **Findings**: `CONFIG_BPF_LSM=y`, `CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor"`,
  no `lsm=` on the command line; the active list is
  `lockdown,capability,landlock,yama,apparmor,ima,evm`. `link.AttachLSM` succeeds regardless:
  the trampoline attaches, the LSM framework just never calls a `bpf` LSM that was not
  initialised at boot. The cgroup programs (byte counting, DNS tap) do run, hence the one
  `unknown` row with bytes.
- **Implications**: attach success proves nothing; the list is the only reliable signal, and
  it only changes at boot.

### The `lsm=` parameter
- **Findings**: `lsm=` replaces the build-time order for the mutable LSMs. Names of
  first/last-ordered LSMs (`capability`, `ima`, `evm`) in the list are accepted and have no
  effect, so the active list can be passed back verbatim with `,bpf` appended. With `lsm=`
  set, the legacy `security=` parameter is ignored.
- **Implications**: "current list + bpf" is safe and needs no per-distro table. The setting
  is recomputed on every `update-grub` from the running kernel, so it follows the host.

### Existing code (agent map, 2026-11-27)
- `internal/api/types.go` `Status` (:142-165), tests `types_test.go` :68, :153, :161, :193.
- Daemon: `startup` daemon.go:67-100 (33 body lines of 40), `facts()` api.go:87-99,
  `startupLine` version.go:27 (exact-string test daemon_test.go:174), `ctl_status.go`
  `lines()` :188 with the optional `dns` line as the pattern, `trialops.go` `start` :46 and
  `keep` :106.
- Tray: `internal/tray/model.go` states :23-54, `view.go` `conditions` :57, `factRows` :137,
  `notes.go` rules-error notes as the pattern; `internal/sni/icons.go` 294 lines (cap 300),
  `Pixmaps` contract bound to `tray.Gone..tray.Monitor`.
- TUI: `overviewHeader` overview.go:51 (297 lines), `overviewBottom` :218, goldens in
  `internal/tui/testdata/`; bar: `internal/verbs/bar.go` `barClass` :52, `buildTooltip` :79.
- Fakes: `clienttest.StandIn` `change(fn)` :248, command map commands.go:92.
- Deb: `.dagger/deb.go` `debTreeScript` :28-107; smoke groups in `.dagger/smoke.go`; group 5
  fails on "no such file" in the daemon's journal; shellcheck globs `scripts/*.sh` only
  (`.dagger/checks.go:103`); `dagger call deb|smoke` need a tagged, clean commit.
- Caps: 40-line functions, 300-line files, tests included; several touched files are within
  six lines of the cap.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks | Notes |
|--------|-------------|-----------|-------|-------|
| Probe by attach result | trust `AttachLSM` | no new code | proven wrong on chandali | rejected |
| Probe by a self-test connect | daemon connects and waits for its own event | proves the whole path | a daemon that makes connections; timing | rejected: the list is sufficient |
| Read the active LSM list | `/sys/kernel/security/lsm` contains `bpf` | exact, cheap, root-less | securityfs absent in containers | chosen; absent means `unknown` |
| Static drop-in with a fixed list | `lsm=landlock,...,bpf` | trivial | drops or reorders a host's LSMs | rejected (Req 7.2) |
| Drop-in computing from the running kernel | helper prints `lsm=<active>,bpf` | host-correct | needs a helper script | chosen |
| Edit `/etc/default/grub` in postinst | sed the admin's file | none | edits a conffile of another package | rejected |

## Design Decisions

### Decision: one small package `internal/lsm`, used by the daemon only
- **Selected**: pure functions over an injected `func(string) ([]byte, error)` reader, as
  `trial.BootID` does. Clients never read `/sys`; they display the daemon's status.
- **Rationale**: one probe, one wording, testable without root.

### Decision: `hook` is an optional object after `counters`
- **Selected**: `Hook *HookStatus \`json:"hook,omitempty"\`` as the last field.
- **Rationale**: keeps the golden and prefix tests true; nil is "not reported" for an older
  daemon and for the fake daemon by default (Req 2.4, 2.5).

### Decision: `snitchd status` probes for itself
- **Alternatives**: a new key in the strict status file (`onlyKeys`, version-last test).
- **Selected**: the verb calls `lsm.Probe(os.ReadFile)`; the status file is unchanged.
- **Trade-off**: run without root it cannot read `grub.cfg`; the line then says so.

### Decision: the refusal lives in `trialOps`
- **Selected**: `trialOps.hook func() lsm.Hook`; `start` and `keep` refuse on `Inactive`.

### Decision: drop-in (conffile) + helper + two maintainer scripts
- **Selected**: `/etc/default/grub.d/snitch-lsm.cfg` calls `/usr/lib/snitch/lsm-cmdline`;
  `postinst configure` and `postrm remove|purge` run `update-grub` when it exists. Precedent:
  kdump-tools ships a grub.d drop-in and regenerates in its maintainer scripts.
- **Follow-up**: lintian's verdict on the scripts is observed in the smoke (threshold: error).

### Synthesis
- **Generalization**: TUI, bar, tray and CLI all render the same three facts (state, pending,
  reason); the reason sentence is produced once in `internal/lsm` and carried in the status.
- **Build vs adopt**: no library needed; `update-grub` and grub.d are the platform mechanism.
- **Simplification**: no status-file change, no new API message, no state line (the hook
  state cannot change while the daemon runs; only `pending` can, and a cached re-probe
  covers it); the tray's "ask no questions while inactive" was dropped from the requirements
  because no events exist in that state.

### Decision: probe kernel support before touching the boot configuration (operator, 2026-11-27)
- **Context**: "the kernel config needs to probe that the feature is available before; invalid
  options can suck". `lsm=` lands on every boot entry `grub-mkconfig` writes, including older
  and fallback kernels.
- **Selected**: the helper emits a parameter only when every `/boot/vmlinuz-<v>` has a
  readable `/boot/config-<v>` with `CONFIG_BPF_LSM=y`; anything else (missing, unreadable,
  option off, no kernel) emits nothing and the explanation names the kernel. The daemon reads
  the running kernel's configuration (`/boot/config-<release>`, then `/proc/config.gz`) and
  reports `unsupported` so no surface asks for a reboot that cannot help.
- **Observed on chandali**: three installed kernels (7.0.0-44-generic, 7.3.4-2-t2,
  7.3.4-3-t2), all `CONFIG_BPF_LSM=y`, configs 0644; no `/proc/config.gz`.
- **Trade-off**: a host with one stale kernel lacking the option gets no automatic setting
  until that kernel is removed; the printed reason says which one.

## Risks & Mitigations
- A wrong `lsm=` could disable an LSM: the list is the kernel's own active list, verbatim;
  the helper adds nothing when it cannot read it; recovery entries do not get the parameter.
- securityfs absent or the host's list visible inside the smoke container: wording never
  contains a raw OS error; group 5's "no such file" guard stays green.
- `update-grub` failing in postinst must not fail the install: the scripts never propagate
  its status.
- File and function caps: new code goes into new files; `icons.go`, `overview.go`,
  `feed.go`, `daemon.go` get minimal edits.

## References
- `docs/ci-debs.md` (the package's promises), `.kiro/steering/fail-safes.md`,
  `examples/api.md` (status), `.kiro/steering/roadmap.md` (the chandali item).
