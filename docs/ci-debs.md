# ci-debs: one pipeline, two doors, one deb

The ci-debs feature put the whole pipeline into the Dagger module at the repo
root: one function per check, build, packaging and smoke phase, every tool in a
pinned container (`.dagger/`, the registry in `pins.go`). The workflows only
dispatch, so CI and an operator's `dagger call` run the same functions with the
same passing criteria — a green run means the same thing behind both doors.
This file is the feature's one documentation record: what the package ships
and promises, what the smoke proves and can never prove, what CodeQL covers
and what it cannot, which parts belong to other owners, how to reproduce
everything locally, and the deficits the feature carries today. Each section
cites the requirements it discharges (`.kiro/specs/ci-debs/`, same directory).

## The deb (R4.1–R4.6)

One distro-agnostic package, assembled exactly once per release: both contract
distros build the binaries, the proof compares them checksum-for-checksum, and
the pinned `debian:forky` builder (`dpkg-deb` 1.23.11) packs the forky pair
(R4.1, R5.1). The version is the release tag with its leading `v` stripped
(`v0.5.0` → `0.5.0`); the artifacts are `snitch_<version>_amd64.deb` plus its
bare-filename `.sha256` (the form `sha256sum -c` reads). At the time of writing
the `-Znone` build is 9,871,552 bytes — the payload plus ar/tar structure, and
the same commit and epoch rebuild to the same size (the reproducibility
properties are below, in Local reproduction).

Payload (11 shipped files under `/` plus `DEBIAN/`; every mode explicit, every file root-owned):

| path in package | source | mode | notes |
|---|---|---|---|
| `/usr/local/sbin/snitchd` | the built daemon | 0755 | the frozen unit contract: both shipped units name this exact path in `ExecStart` (R4.2) |
| `/usr/bin/snitch` | the built client binary | 0755 | a PATH directory, so `snitch` (TUI, `status`, `default`, `tray`) and the desktop entry's `Exec=` resolve for every user (R4.4) |
| `/usr/lib/snitch/lsm-cmdline` | `packaging/lsm-cmdline.sh` | 0755 | POSIX `sh` helper computing `lsm=<list>,bpf` from active LSMs and kernel configs |
| `/usr/lib/systemd/system/snitchd.service` | repo unit, byte-identical | 0644 | enabled at boot by `postinst` (fresh install or from `< 1.2.0`), never started by it |
| `/usr/lib/systemd/system/snitchd-trial-boot.service` | repo unit, byte-identical | 0644 | enabled at boot by `postinst` (fresh install or from `< 1.2.0`), never started by it |
| `/usr/share/applications/snitch-tray.desktop` | repo desktop entry | 0644 | the autostart entry the desktop session resolves |
| `/etc/default/grub.d/snitch-lsm.cfg` | `packaging/grub-snitch-lsm.cfg` | 0644 | GRUB drop-in (declared conffile); invokes `lsm-cmdline` when executable |
| `/etc/snitch/rules.toml` | `examples/rules.toml`, byte-identical | 0644 | the sample: a declared conffile, validated by `snitchd check` before packing |
| `/usr/share/doc/snitch/copyright` | `LICENSE` | 0644 | the license, where policy puts it |
| `/usr/share/doc/snitch/changelog.Debian.gz` | generated (version + epoch date) | 0644 | `gzip -9n`, `LC_ALL=C` — a function of the commit alone |
| `/usr/share/lintian/overrides/snitch` | `packaging/lintian-overrides` | 0644 | the package's policy-deviation review record (see below) |
| `DEBIAN/control` | `packaging/control` + injected Version and Installed-Size | 0644 | no `Depends`; `Recommends` bpftool and a session bus, `Suggests` the KDE side (R4.5) |
| `DEBIAN/conffiles` | `packaging/conffiles` | 0644 | lists `/etc/default/grub.d/snitch-lsm.cfg` and `/etc/snitch/rules.toml` |
| `DEBIAN/postinst` | `packaging/postinst.sh` | 0755 | `configure`: runs `update-grub` when present and prints next-boot status or manual `lsm=` line; enables both units at boot (fresh install or from `< 1.2.0`); restarts `snitchd.service` if it is running |
| `DEBIAN/prerm` | `packaging/prerm.sh` | 0755 | `remove`: stops `snitchd.service` and disables both units; never fails |
| `DEBIAN/postrm` | `packaging/postrm.sh` | 0755 | `remove`/`purge`: runs `update-grub` when present; never fails |
| `DEBIAN/md5sums` | generated, `LC_ALL=C` sorted | 0644 | dpkg's own verification form |

`/usr/local/sbin` is deliberate: both shipped units and every host deployed by
the pyinfra flow already run snitchd from that exact path, so moving to
`/usr/sbin` would break existing hosts at upgrade — the lintian overrides below
record the same justification. The units ship the repo's bytes unchanged
(the deploy-service spec owns their semantics).

Maintainer scripts (amended in `lsm-activation`, operator decision 2026-11-27,
replacing the historical unpack-only rule): **the package runs `update-grub` on
configure and on removal, enables `snitchd.service` with
`snitchd-trial-boot.service` at boot on a fresh install (or from a version
before 1.2.0), restarts a running `snitchd.service` on upgrade, stops and
disables both on removal (amended 2026-11-28), and nothing else**. It never
starts a stopped unit on install, never creates `/etc/snitch/operator`, and never alters rules beyond
dpkg's conffile handling of `/etc/snitch/rules.toml`. Enablement stays the
operator's or pyinfra's step (R4.3): the deployment runs
`systemctl enable --now snitchd-trial-boot.service snitchd.service`, never
the package (deploy-service owns that, see Adjacency).

Semantics of the sample (`/etc/snitch/rules.toml`, R4.3 and R4.6):

- **Fresh install** (no file at the path): dpkg lays the shipped sample. The
  smoke's group 2 proves it — `dpkg -i` alone reaches `install ok installed`
  with zero dependencies, and every payload file, the sample included, lands
  byte-equal to the deb's own member.
- **Install over an authored file** (the deployed-host case: pyinfra authored
  rules before the package existed — the first-install-over-unregistered case):
  `dpkg -i --force-confdef --force-confold` keeps the authored file
  byte-for-byte and parks the shipped copy beside it. The suffix reality, caught
  by the smoke instead of assumed: dpkg writes `rules.toml.dpkg-dist`, not
  `.dpkg-new` — `.dpkg-new` belongs to the upgrade-over-registered-conffile
  case, and here dpkg has no previous version to offer (probed on the builder's
  own dpkg 1.23.11; the design's first guess was wrong and group 1's assertion
  refused it). The smoke proves all three parts: the authored sha survives, the
  parked copy is byte-equal to the deb's member, and the authored file is not
  the sample.
- **Upgrades** (dpkg has registered the conffile): plain conffile semantics
  govern — an unchanged sample lands without questions, a changed sample over a
  locally modified file is decided by dpkg's force flags, and dpkg never
  destroys authored content silently. Neither maintainer script touches rules,
  so that stays entirely dpkg's.

Next-boot configuration (`lsm-activation`):

- **Drop-in and helper** (`/etc/default/grub.d/snitch-lsm.cfg` and
  `/usr/lib/snitch/lsm-cmdline`): when `grub-mkconfig` sources the drop-in and
  `/usr/lib/snitch/lsm-cmdline` is executable, the helper reads
  `/sys/kernel/security/lsm`, `/proc/cmdline`, and `GRUB_CMDLINE_LINUX*`. Before
  emitting anything, it verifies every installed `/boot/vmlinuz-*` has a readable
  `/boot/config-*` with `CONFIG_BPF_LSM=y` (otherwise it emits nothing and
  `--explain` names the first unsupported or unreadable kernel). It preserves all
  active LSMs (such as AppArmor), leaves any administrator-set `lsm=` alone, emits
  nothing when `bpf` is already active without `lsm=` on the running command line,
  and validates the list against `^[a-z0-9_,]+$`.
- **`DEBIAN/postinst` (`configure`) and `DEBIAN/postrm` (`remove`, `purge`)**:
  every absolute path carries the `${DPKG_ROOT:-}` prefix (empty on a normal
  install). On `configure`, if `update-grub` is on `PATH` and
  `${DPKG_ROOT:-}/boot/grub` exists, `postinst` runs `update-grub` (reporting a
  failure in one line without failing the install) and prints
  `lsm-cmdline --explain` (stating a reboot is needed when it configured the next
  boot). Without GRUB or `update-grub`, `postinst` prints `lsm-cmdline --manual`
  (`snitch: add to the kernel command line: lsm=<list>,bpf`). Then, under a
  booted systemd (`${DPKG_ROOT:-}/run/systemd/system`), it runs
  `systemctl daemon-reload` and, only if `snitchd.service` is active,
  `systemctl try-restart snitchd.service`, printing one line either way; it
  exits `0`.
  On `remove` and `purge`, `postrm` runs `update-grub` when present with
  `${DPKG_ROOT:-}/boot/grub`, ignoring its exit status.
- **Conffile survival and inertness on removal**: on `dpkg -r snitch`, dpkg
  removes `/usr/lib/snitch/lsm-cmdline` before running `postrm remove`; the
  surviving conffile `/etc/default/grub.d/snitch-lsm.cfg` checks
  `[ -x /usr/lib/snitch/lsm-cmdline ]` and does nothing, so `update-grub`
  restores the kernel's default LSM list. On `dpkg -P snitch`, dpkg removes the
  conffile too before running `postrm purge`.
- **Image-build / PID-namespace limit**: without `-l`, `lsm-cmdline` compares
  `/` against `/proc/1/root` and emits nothing when they differ or `/proc/1/root`
  is unreadable, so a `chroot` image build with a bind-mounted `/sys` never bakes
  the build host's LSM list into an image. A container running in its own PID
  namespace still sees its own `/` at `/proc/1/root` and therefore still reads
  its own kernel's LSM list; this is a known limit of the PID-1 check.

Never shipped, on purpose: the operator file `/etc/snitch/operator`
(`scripts/setup.sh` owns it, deploy-service deploys it) and any base
configuration of `/etc/snitch` beyond the sample.

No runtime `Depends` (R4.5): both binaries are static (`CGO_ENABLED=0`,
`-trimpath`), so the control file declares no scripting runtime, no libc and no
desktop environment, and the installation needs nothing but the archive. What
the package uses at run time is declared softly (amended 2026-11-25):
`Recommends: bpftool, default-dbus-session-bus | dbus-session-bus` (the kill
switch is a `bpftool` command; the tray talks to the session bus) and
`Suggests: plasma-workspace, breeze-icon-theme` (the tray's host and the icon
its notifications name). Suggests, not Recommends, for the KDE side: apt
installs Recommends by default, and a headless host must not pull Plasma in.
`dpkg -i` ignores both fields, so the smoke's zero-dependency install stands.
The names were checked with `apt-cache` in forky and 26.04 (the session bus is
virtual; `dbus-user-session` provides it in both).

## The distro stratagem: what the smoke proves (R5.3, R5.4)

The proof chain: both distros build the binaries from the sha-pinned
go1.26.8 tarball (`GOTOOLCHAIN=local`), run the plain test suite, assert
`-version`; the proof compares the two sha256 lists and exits non-zero naming
the first mismatch (R5.1, R5.2); the deb is assembled once from the forky pair
and then smoked in each distro's own userspace. The mechanism: a Dagger engine
container cannot run systemd (probes in `research.md`), so the smoke drives
the host's docker daemon through its socket — the same door on the GHA runner
and on a docker-ce workstation. The driver container holds only the pinned
static docker CLI (a transport, never a build tool), the deb under test and
the assertion scripts; the privileged sibling containers it boots under the
host daemon are the actual per-distro smoke containers, systemd as PID 1.

The ten assertion groups (each named in the log; any failure exits non-zero
naming its group):

1. conffile-keep over the authored rules — the install-over-authored semantics
   above, proved inside the distro (R4.3, R4.6).
2. fresh install — after a purge reset, install, configure, payload
   byte-equality (all 11 files), executable bits, `DPKG_ROOT` empty (R4.3).
3. unit verify — `systemd-analyze verify` on both shipped units at their
   installed paths, the distro's own systemd judging.
4. trial-boot start — see the expected state below.
5. daemon journal signature — see the expected state below.
6. installed-path check — `snitchd check -rules /etc/snitch/rules.toml`
   exits 0 on the installed sample (the tolerated `unresolved:` lines for
   programs the container lacks are the daemon's own mapped-not-enforced
   state).
7. tray -version from PATH — the installed `snitch` resolves and answers the
   linked version (R4.4).
8. tray headless — the installed tray binary against the pipeline-built
   fakedaemon on a private session bus, driven by `scripts/tray-check.sh
   --headless` with its `--bin`/`--fake` flags; registration, initial state,
   hook inactive warning, clean exit under SIGTERM ("as far as a headless
   container allows").
9. boot setting — drop-in and helper modes, captured no-GRUB install message,
   the helper's decision table with fixture files, stub-driven `postinst
   configure` (both working and failing `update-grub` exit 0), `dpkg -r`
   (helper removed, drop-in survives and is inert, stub called), `dpkg -P`
   (drop-in removed), both systemd units enabled after install and disabled after remove and purge.
10. lintian — see below; it runs in the driver, which is the distro, not in
    the sibling.

Two expected states are defined, and both are assertion content, not hopes
(R5.3):

- `snitchd-trial-boot.service` **fully completes headless**: the oneshot needs
  no kernel objects, so `Result=success` with `ExecMainStatus=0` is the only
  accepted outcome.
- `snitchd.service` **starts and dies at the kernel step, with the signature
  in the journal**: the daemon resolves its binary and its rules (the smoke
  also requires the mode-decision line to have printed — the rules parsed
  before the kernel step), then fails at the pinned-maps load. The signature is
  deterministic on every host, because the sibling boots with a tmpfs over
  `/sys/fs/bpf`: bpffs is where eBPF pins must live, so the pin fails the same
  way everywhere. The journal must carry the pin-dir/load/attach failure
  signature — recorded from a real run:
  `snitchd: load: assign values: field SocketConnect: program socket_connect:
  map kill: pin map to /sys/fs/bpf/snitch/kill: /sys/fs/bpf/snitch/kill is not
  a bpf filesystem` — and must contain **no missing-file error**: a missing
  `ExecStart` binary or absent rules file would be a packaging error, not a
  kernel limitation, and fails the group by name.

The tmpfs is also the safety property: the smoke can never attach a host-global
BPF LSM, on any host — not on a workstation whose kernel lists `bpf` in its
LSM chain (it never reaches the attach step; the pin fails first), and not on
a GHA runner, whose kernels exclude `bpf` from the boot-time LSM list entirely
(actions/runner-images#14783) — and the two doors see the identical signature.

The socket trust posture is the mechanism's cost and must be said plainly: a
mounted `docker.sock` is host-root-equivalent inside the smoke driver. Inside
CI that is the same trust posture the runner already has (it owns dockerd);
locally, run the smoke only against a runtime you control — never against a
daemon shared with anything you do not trust.

The sibling-leak caveat: the driver removes its sibling in an EXIT trap so a
privileged container never outlives the run, but a hard engine death mid-run
kills the driver before the trap fires, and the sibling stays on the host
daemon until someone removes it (`docker rm -f snitch-smoke-…`). Later runs
self-heal — every run names its sibling uniquely (`$$`-`$RANDOM`), so a
leaked container never breaks the next smoke.

Lintian (R5.4): the committed threshold is `--profile debian --display-info
--show-overrides --color never --fail-on error` — an error-class tag fails the
smoke, warnings and info print for the record. Each distro's own lintian
(forky 2.144, ubuntu 26.04's 2.129; installed by name on purpose — the
distro's own implementation is the input under test) judges the one published
deb. The below-threshold policy tags, recorded per R5.4 (this generation of
lintian; re-record on a tool bump):

- `W: file-in-unusual-dir` — `usr/local/sbin/snitchd` (the frozen path, above)
- `W: no-manual-page` — `usr/bin/snitch` (no manual ships today; lintian
  reports the PATH-directory binary — the unusual-dir tag already covers what
  sits under `/usr/local/sbin`)
- `I: desktop-entry-lacks-keywords-entry` — `snitch-tray.desktop`
- `I: systemd-service-file-missing-documentation-key` — `snitchd.service`,
  `snitchd-trial-boot.service`
- (a recorded deviation from expectations: the research-predicted
  hardening-no-relro/hardening-no-pie tags do not appear on either distro's
  lintian for these stripped static Go binaries)

The shipped in-package overrides (`/usr/share/lintian/overrides/snitch`,
`packaging/lintian-overrides` in the repo, each with its written
justification) and their reasons in one line:

- `statically-linked-binary` ×2 (`snitchd`, `snitch`) — static by design
  (`CGO_ENABLED=0`, `-trimpath`); a shared build would contradict the
  package's own no-Depends metadata (R4.5).
- `dir-in-usr-local` and `file-in-usr-local` — the frozen
  `usr/local/sbin/snitchd` contract; moving the binary would break every
  deployed host at upgrade. These are the two tags lintian 2.117 split the old
  combined `dir-or-file-in-usr-local` into; the first draft's override named
  the pre-split tag and lintian rejected it as `alien-tag` — an override
  naming a tag lintian does not know is itself an error, the triage's first
  real catch.
- `uses-no-compression-for-control-tarball` and
  `uses-no-compression-for-data-tarball` — the `-Znone` determinism pin (see
  Local reproduction): removing compression from the build removes the
  compressor from the artifact's byte identity.

## CodeQL (R3.1–R3.4)

CodeQL runs as its own workflow (`codeql.yml`), never inside the module and
never referenced by the release chain. Suite: `security-extended`, per-language
categories, push to main plus PRs plus a weekly Monday run that re-analyzes main
between pushes.

Coverage realities (R3.2):

- **Go is traced**: `build-mode: manual` — `init` arms the trace observer and
  the workflow's explicit `go build ./...` (after `setup-go` from go.mod) is
  the traced build, the same command the pipeline's own go check runs, so the
  database covers what CI actually builds.
- **The BPF C is traced** (since 2026-11-25, user decision; it was `build-mode: none`
  before): `build-mode: manual`, and the traced build is an observation compile of both
  programs with the runner's clang and libbpf headers, output to `/dev/null` — the compiler
  observes, nothing it produces is kept; the committed bindings, checked byte for byte by the
  pipeline's bindings check, are what ships. The flags are `internal/bpf/gen.go`'s without
  `-Werror` (the runner's libbpf 1.3 declares `bpf_d_path` without the const forky's 1.7 has;
  that warning must not stop the observation). Traced extraction replaces none-mode's inferred
  compilation units and its macro-accuracy caveat, which mattered most for `dns.bpf.c`, the
  parser of attacker-shaped DNS answers. cppcheck stays the line-level layer.
- *(History)* Until `tui` retired the legacy frontend, a third `python` lane
  scanned a pre-scan copy of that script; `codeql.yml` now scans `go` and `c-cpp`.

The findings-review expectation (R3.3, R3.4): findings never gate anything —
they surface in code scanning for human review; the release does not reference
this workflow, so a finding cannot hold a release hostage. Infrastructure and
extraction errors are the opposite: they fail the job visibly (`codeql.yml`
carries no `continue-on-error` anywhere; the analyze action's own semantics
draw exactly this line).

## Adjacency: what this feature does not own (R6.4)

- The deploy-service pyinfra flow owns `/etc/snitch` and the deployed rules:
  it authors the real rules file, deploys the binary and units, creates the
  operator file and enables the units. The deb never contradicts it — the
  sample is only the fresh-install start, and the conffile mechanism keeps the
  authored file (proof: the smoke's group 1).
- `scripts/setup.sh` owns the operator file (`/etc/snitch/operator`); the
  package never ships or touches it.
- The VM repository pins the tag and the sha256 of the `snitchd` asset and
  carries a copy of the two unit files, marked as copies of these. The deb
  ships byte-identical units and a byte-identical binary, so a host installed
  from the package and a host installed by pyinfra run the same code at the
  same paths.
- Base configuration remains the deployment's: `/etc/snitch/operator` stays
  uncreated and rules stay the sample. Since 2026-11-28 the package enables
  both units at boot on a fresh install, restarts a running daemon on upgrade
  and stops and disables both on removal, besides running `update-grub`; the
  deployment's own `systemctl enable --now` stays harmless (idempotent).
- Consuming repos update their pins deliberately on each release; this
  feature's side of that contract is stable asset names and byte-stable
  construction (following `tui`, six assets publish: the four Go binary/sha256
  assets plus the deb pair).

## Local reproduction (R7.1–R7.3)

Prerequisites: a checkout, a container runtime with a rootful daemon socket,
and the Dagger CLI — nothing else. No host Go, no linters, no dpkg tooling, no
CodeQL; every toolchain lives in the module's pinned containers. The CLI:

```sh
curl -fsSL https://dl.dagger.io/dagger/install.sh | DAGGER_VERSION=0.21.12 sh
```

The runtime: docker-ce is the door today (`/var/run/docker.sock`); during
implementation the engine was also verified over rootless podman 5.7, but
docker-ce/rootful is the supported path — and the deb smoke needs the host
daemon anyway (the smoke drives it through the socket, identically in CI and
locally).

The command set, from the repo root (a throwaway tag such as v0.0.0-cidev
satisfies the tag guard; never push it, delete it after):

```sh
dagger call lint-all                                                        # every check, all PASS banners
dagger call release-build --version=vX.Y.Z --output=dist                    # the Go release artifacts
dagger call deb --version=vX.Y.Z --output=dist-deb                          # the deb + its sha256
dagger call smoke --distro=UBUNTU_2604 --version=vX.Y.Z --docker-socket=/var/run/docker.sock
dagger call smoke --distro=DEBIAN_FORKY --version=vX.Y.Z --docker-socket=/var/run/docker.sock
dagger call deb-release --version=vX.Y.Z --docker-socket=/var/run/docker.sock --output=dist-deb   # the release lane in one call
dagger check                                                               # the seven-check gate
```

`dagger check` runs the seven functions marked `+check`: fmt, go, shellcheck
(covering both `scripts/*.sh` and `packaging/*.sh`), actionlint, golangci,
cppcheck and — added by c-hardening — bindings,
which regenerates `internal/bpf/` with the pinned clang in a pinned forky
image and fails when the committed bindings differ from their source (the
compiler only observes; nothing it produces is committed or shipped; see
`docs/c-hardening.md`). `lint-all` runs the same seven, the first four
through `lint-core`.

The build functions enforce, not assume, the two determinism guards: a clean
tree (`git status --porcelain` empty) and `version` being a tag on HEAD — a
refusal names the guard and builds nothing. Exports land only where `--output`
points (CI's `dist`/`dist-deb` lane names below mirror the workflow's); locally
pick a target outside the tree or under the gitignored `dist/` — an untracked
export inside the tree is dirt, and the guards refuse the next run before it
starts.

Why the artifacts are reproducible — every byte-varying input is pinned:

- `SOURCE_DATE_EPOCH` is the HEAD commit's committer time, read from the
  checkout at assembly (the same number in both doors for the same commit) and
  set exactly, with a post-assembly `touch -h -d @$SDE` over the whole tree —
  exporting the variable alone is not enough, it clamps newer mtimes but
  preserves older ones.
- the builder is pinned `debian:forky` with `dpkg-deb` 1.23.11 (member
  ordering and ar headers have been dpkg's deterministic path since 1.18.x);
  the deb is assembled once, in forky, never per distro.
- `-Znone` via `--uniform-compression`: no compression step exists in the
  build at all, so no compressor version can enter the artifact's bytes (the
  two distros carry different liblzma builds; a compressed deb would depend on
  which distro packed it).
- explicit `install -m` modes under `umask 022` (dpkg-deb normalizes neither);
  `--root-owner-group` so the builder's uid/gid cannot leak.
- `LC_ALL=C` for the changelog date and the md5sums sort; `gzip -9n` for the
  changelog (no stored name, no stored timestamp); `Installed-Size` summed
  from content bytes, never block counts.
- the toolchain is the sha256-pinned `go1.26.8.linux-amd64.tar.gz` with
  `GOTOOLCHAIN=local` (the distros' apt Go series diverge; the proof would be
  meaningless over two toolchains).
- the VCS stamp is preserved (`-buildvcs` default): the binaries' bytes bind
  to the commit. Combined with the guards, same commit + same tag means the
  same bytes — the clean-room rebuild (engine destroyed, cold caches) proved
  it: identical deb sha256 twice.

Parity in one line: for the same release tag, `release-build`'s `snitchd` and
`snitch-linux-amd64` are byte-identical to the deb's shipped binaries, and the deb
packs that same pair — all six published assets are reproducible by construction (R6.1, R7.1).

## CI specifics

- The workflows carry no pipeline logic: each job checks out and dispatches
  (dagger-for-github@v8.4.1, `version: 0.21.12`, `verb: call`); the engine
  boots on the runner's own dockerd, once per job, ephemeral. `release-build`
  and the deb lane run as parallel artifact jobs behind the checks gate, and
  the publish job needs both artifact sets before it touches the release
  (R1.1, R6.2).
- The linters job (golangci, cppcheck and the c-hardening bindings check,
  one engine for the three steps) skips
  `refs/tags/v*`, so a release is gated exactly on the checks that gated it
  before the feature (R6.2). The skip's basis is workflow_call semantics: a
  called workflow receives the caller's event payload, so `github.ref` inside
  lint.yml is the release's tag ref on a tag push — the condition holds there
  exactly as it does on lint's own runs (GitHub's events-that-trigger docs).
- `GH_TOKEN` exists only in the publish job (`contents: write` only there);
  no pipeline function receives a secret, and no engine holds credentials.
- Publish is all-or-nothing: one existence loop over the six asset paths
  (`snitchd`, `snitchd.sha256`, `snitch-linux-amd64`, `snitch-linux-amd64.sha256`,
  and the deb pair) prints `missing asset: <path>` and exits 1 before any `gh` runs, then one `gh` step
  (`upload --clobber` over an existing release, `create --verify-tag
  --generate-notes` otherwise) — a reader-side pin never observes a partial
  release (R6.3).
- The release chain never references CodeQL (R3.4); codeql.yml is a separate
  workflow with its own minimal token permissions.

## Honesty records

- **The formerly deferred cppcheck findings are fixed (c-hardening)**: this
  feature shipped with four `constVariablePointer` findings recorded as
  deferred — real const-correctness improvements at `bpf/snitch.bpf.c:218`,
  `:219`, `:241` and `bpf/dns.bpf.c:356` — because fixing the C needed a
  regeneration of the committed bindings under clang. The c-hardening feature
  fixed all four (the pointers now point to const) and the two
  `knownConditionTrueFalse` reports in `dns.bpf.c` (`pkt_init` returns `void`,
  its dead error branches are gone), regenerated the bindings in the pinned
  forky image (`scripts/bindings-regen.sh`) and dropped the six suppressions.
  Every line left in `bpf/cppcheck-suppressions.txt` now stands for a
  modelling limit, not a known defect, and the cppcheck check reports zero
  unsuppressed findings. None of the four is open. See `docs/c-hardening.md`.
- **actionlint runs unpinned on purpose**: the workflow it mirrors
  (`uvx --from actionlint-py actionlint -color`) never pinned the package, and
  parity with the workflow wins over inventing a pin the workflow does not
  have. At run time inside the pinned uv image the spec resolves to
  actionlint-py 1.7.12.25, wrapping actionlint 1.7.12; the pinned uv image
  itself (0.13.9) is what freezes the environment between runs. A drift in
  what the unpinned spec resolves is a real, accepted drift — the day it
  pinches, pin both doors in one diff.
- **Where the linter configs live, and their reviewability**: the Go layer's
  strictness is the committed `.golangci.yaml` alone (v2.15.0 schema: the
  `standard` set plus `copyloopvar` and `misspell`; the bpf2go bindings
  excluded as generated; three scoped exclusion rules, each with its written
  reason; reporting caps removed so a zero-findings gate sees every finding).
  The C layer's strictness is the invocation in `.dagger/linters.go` plus
  `bpf/cppcheck-suppressions.txt`, every suppression line carrying its reason.
  Nothing is implicit on any host (R2.4), and loosening anything is a
  reviewable diff to a committed file (R2.3) — there is no local override to
  discover.
- **Records tied to a tool generation**: the deb's `ci-debs` baseline size
  (9,871,552 bytes before `lsm-activation`), the lintian below-threshold list
  and the override tag names are records of lintian 2.144/2.129 and dpkg-deb
  1.23.11 as installed today; re-triage and re-record when those move (the
  alien-tag lesson above is what a rename looks like when it is not expected).
