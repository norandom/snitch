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

Payload (every mode explicit, every file root-owned, `DEBIAN/` as listed):

| path in package | source | mode | notes |
|---|---|---|---|
| `/usr/local/sbin/snitchd` | the built daemon | 0755 | the frozen unit contract: both shipped units name this exact path in `ExecStart` (R4.2) |
| `/usr/bin/snitch` | the built tray binary | 0755 | a PATH directory, so `snitch tray` and the desktop entry's `Exec=` resolve for every user (R4.4) |
| `/usr/lib/systemd/system/snitchd.service` | repo unit, byte-identical | 0644 | unpacked by dpkg, never enabled by the package |
| `/usr/lib/systemd/system/snitchd-trial-boot.service` | repo unit, byte-identical | 0644 | unpacked by dpkg, never enabled by the package |
| `/usr/share/applications/snitch-tray.desktop` | repo desktop entry | 0644 | the autostart entry the desktop session resolves |
| `/etc/snitch/rules.toml` | `examples/rules.toml`, byte-identical | 0644 | the sample: a declared conffile, validated by `snitchd check` before packing |
| `/usr/share/doc/snitch/copyright` | `LICENSE` | 0644 | the license, where policy puts it |
| `/usr/share/doc/snitch/changelog.Debian.gz` | generated (version + epoch date) | 0644 | `gzip -9n`, `LC_ALL=C` — a function of the commit alone |
| `/usr/share/lintian/overrides/snitch` | `packaging/lintian-overrides` | 0644 | the package's policy-deviation review record (see below) |
| `DEBIAN/control` | `packaging/control` + injected Version and Installed-Size | 0644 | declares no runtime `Depends` at all (R4.5) |
| `DEBIAN/conffiles` | `packaging/conffiles` | 0644 | lists exactly `/etc/snitch/rules.toml` |
| `DEBIAN/md5sums` | generated, `LC_ALL=C` sorted | 0644 | dpkg's own verification form |

`/usr/local/sbin` is deliberate: both shipped units and every host deployed by
the pyinfra flow already run snitchd from that exact path, so moving to
`/usr/sbin` would break existing hosts at upgrade — the lintian overrides below
record the same justification. The units ship the repo's bytes unchanged
(the deploy-service spec owns their semantics), and the package carries no
maintainer scripts at all (no `postinst`/`prerm`): nothing runs on install
beyond dpkg's own unpacking, so unpacked-never-enabled is a structural
property, not a promise. Enablement stays the operator's or pyinfra's step
(R4.3): the deployment runs
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
  destroys authored content silently. The package's no-maintainer-scripts rule
  keeps that entirely dpkg's.

Never shipped, on purpose: the operator file `/etc/snitch/operator`
(`scripts/setup.sh` owns it, deploy-service deploys it), any base
configuration of `/etc/snitch` beyond the sample, and the legacy Little-Snitch
client era units — `snitch-trial*.service`, `snitch-trial.timer`,
`snitch-watch.service` belong to the Python client, not to snitchd's package.

No runtime `Depends` (R4.5): both binaries are static (`CGO_ENABLED=0`,
`-trimpath`), so the control file declares no scripting runtime, no libc and no
desktop environment; D-Bus is provided by the desktop session at runtime, and
the installation needs nothing but the archive.

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

The nine assertion groups (each named in the log; any failure exits non-zero
naming its group):

1. conffile-keep over the authored rules — the install-over-authored semantics
   above, proved inside the distro (R4.3, R4.6).
2. fresh install — after a purge reset, install, configure, payload
   byte-equality, executable bits (R4.3).
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
   clean exit under SIGTERM ("as far as a headless container allows").
9. lintian — see below; it runs in the driver, which is the distro, not in
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
- **The BPF C is analyzed with `build-mode: none`**: it infers compilation
  units without ever running a compiler. That keeps CI clang-free (the bpf2go
  bindings are committed), with the recorded caveat that none-mode is
  macro-accurate only up to its inference — a macro-heavy tree like `vmlinux.h`
  can leave inferred units that a real compile would not produce. Macro-scale
  bugs may therefore hide from this lane; it is accepted, recorded, and the C
  code keeps the cppcheck layer as its line-level analyzer.
- **The extension-less Python client is NOT extracted** — a deliberate,
  documented limitation. Its shebang is
  `#!/usr/bin/env -S uv run --quiet --script`, which does not match the
  extractor's script pattern (the `env -S` form is invisible to it), and no
  extractor override exists for a file the extractor classifies as nothing.
  Ruff keeps covering the file on the lint side (pinned 0.16.10), and the
  python matrix column keeps the suite pointed at the day the file moves to a
  matched form.

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
- Enablement and base configuration remain the deployment's: unpacked, never
  enabled is the package's whole motion; everything else is a deploy step.
- Consuming repos update their pins deliberately on each release; this
  feature's side of that contract is stable asset names and byte-stable
  construction (the six frozen names are untouched, the deb pair joins them).

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
dagger call lint-all                                                        # every check, nine PASS banners
dagger call release-build --version=vX.Y.Z --output=dist                    # the four existing artifacts
dagger call deb --version=vX.Y.Z --output=dist-deb                          # the deb + its sha256
dagger call smoke --distro=UBUNTU_2604 --version=vX.Y.Z --docker-socket=/var/run/docker.sock
dagger call smoke --distro=DEBIAN_FORKY --version=vX.Y.Z --docker-socket=/var/run/docker.sock
dagger call deb-release --version=vX.Y.Z --docker-socket=/var/run/docker.sock --output=dist-deb   # the release lane in one call
dagger check                                                               # the seven-check gate
```

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
`snitch-linux-amd64` are byte-identical to today's pre-module workflow build
of the same commit, and the deb packs that same pair — the eight assets are
the same bytes by construction (R6.1, R7.1).

## CI specifics

- The workflows carry no pipeline logic: each job checks out and dispatches
  (dagger-for-github@v8.4.1, `version: 0.21.12`, `verb: call`); the engine
  boots on the runner's own dockerd, once per job, ephemeral. `release-build`
  and the deb lane run as parallel artifact jobs behind the checks gate, and
  the publish job needs both artifact sets before it touches the release
  (R1.1, R6.2).
- The linters job (golangci + cppcheck, one engine for both steps) skips
  `refs/tags/v*`, so a release is gated exactly on the checks that gated it
  before the feature (R6.2). The skip's basis is workflow_call semantics: a
  called workflow receives the caller's event payload, so `github.ref` inside
  lint.yml is the release's tag ref on a tag push — the condition holds there
  exactly as it does on lint's own runs (GitHub's events-that-trigger docs).
- `GH_TOKEN` exists only in the publish job (`contents: write` only there);
  no pipeline function receives a secret, and no engine holds credentials.
- Publish is all-or-nothing: one existence loop over the eight asset paths
  (six frozen names in their order, then the deb pair) prints `missing asset:
  <path>` and exits 1 before any `gh` runs, then one `gh` step
  (`upload --clobber` over an existing release, `create --verify-tag
  --generate-notes` otherwise) — a reader-side pin never observes a partial
  release (R6.3).
- The release chain never references CodeQL (R3.4); codeql.yml is a separate
  workflow with its own minimal token permissions.

## Honesty records

- **Deferred cppcheck improvements, deliberately recorded as deferred**: four
  `constVariablePointer` findings are real const-correctness improvements —
  `bpf/snitch.bpf.c:218`, `:219`, `:241` and `bpf/dns.bpf.c:356`. Fixing them
  edits `bpf/*.c`, and the committed bpf2go bindings regenerate only under
  clang (`internal/bpf`'s go:generate), which neither CI nor the packaging
  workstation runs — fixing the C without regenerating the bindings would ship
  a stale pair. Each line is suppressed standing alone (with this reason) in
  `bpf/cppcheck-suppressions.txt`, so any *new* finding of the class stays
  visible at its own site. Fix them the day a bindings-regen host has clang.
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
- **Records tied to a tool generation**: the deb's size (9,871,552 bytes), the
  lintian below-threshold list and the override tag names are records of
  lintian 2.144/2.129 and dpkg-deb 1.23.11 as installed today; re-triage and
  re-record when those move (the alien-tag lesson above is what a rename
  looks like when it is not expected).
