# Research & Design Decisions

## Summary
- **Feature**: `ci-debs` — Daggerized pipeline + linter layer + CodeQL + one reproducible distro-agnostic deb
- **Discovery Scope**: Complex Integration (full discovery: web research ×4 agents + hands-on container probes ×7)
- **Key Findings**:
  - Dagger v0.21.12 (Go SDK, `.dagger/` module) + `dagger/dagger-for-github@v8.4.1` is the current stable "one
    pipeline, two doors" mechanism; `dagger check`/`dagger call` names each check and exits non-zero on failure.
  - The deb is **hand-rolled `dpkg-deb`** (no debhelper): SOURCE_DATE_EPOCH + `--root-owner-group` + `-Znone`
    + pre-touched tree + explicit modes = **empirically byte-identical** across rebuilds (probed in both distros).
  - dpkg conffile semantics are the R4.3/R4.6 mechanism: **without an explicit `DEBIAN/conffiles` dpkg silently
    overwrites authored `/etc` files; with it, dpkg keeps operator-authored content** (probed; lintian enforces).
  - GHA-hosted runners **cannot run BPF LSM** (officially refused, fixed at boot) — the deb smoke asserts
    environment-limited expected states, honestly defined; `snitchd-trial-boot.service` runs fully headless.
  - cppcheck 2.22 analyses the BPF C (incl. `vmlinux.h`) in ~20 s with `-D__has_*(x)=0` predefines + libbpf
    headers; committed suppressions keep authored-file findings as the gate (probed, with real findings surfaced).
  - CodeQL: Go via traced `go build` (security-extended); C via `build-mode: none` (GA since Oct 2025) — CI never
    runs clang; the extension-less Python client is **not extractable** (shebang regex, probed source) → documented
    limitation exactly as R3.2 anticipates.

## Research Log

### Local environment and ground truth (hands-on probes, 2026-11-24)
- **Context**: every local-execution premise of the design had to be real, not assumed.
- **Probes**: image pulls; runtime identity; dpkg mechanics in both distros; systemd in-container; cppcheck on
  the real BPF sources; dpkg conffile behaviors; tray-check harness shape.
- **Findings**:
  - The workstation's `docker` is **podman 5.7.0 (rootless)** behind `/usr/bin/docker` (shim; explains the
    previously noted `docker info` version-parse quirk). `dagger` CLI is not installed yet. 16-core amd64 host,
    kernel 7.3.4-3-t2-resolute; active LSM list **has no `bpf`** (`lockdown,capability,landlock,yama,apparmor,ima,evm`).
  - `ubuntu:26.04` = dpkg-deb 1.23.7, `debian:forky` = dpkg-deb 1.23.11; both support `--root-owner-group`,
    `--uniform-compression`, `--threads-max`. Neither stock image ships `/sbin/init`/systemd.
  - **Reproducibility probe (in-container, both distros)**: `SOURCE_DATE_EPOCH` pinned +
    `dpkg-deb --root-owner-group --uniform-compression --build` with drastically varied file/dir mtimes →
    **identical sha256 both builds**; different SDE → different hash. Mechanism confirmed; clamp-vs-set nuance
    below (older mtimes are *clamped*, not set).
  - apt candidates: forky systemd 262.2-1, lintian 2.144.0, cppcheck 2.22.0-1, golang-go 2:1.27~1;
    ubuntu 26.04 systemd 259.9, lintian 2.129.0ubuntu2.2, cppcheck 2.19.0-3, golang-go 2:1.26~1.
    **Go/lintian/cppcheck versions diverge between distros** → pin centrally, never per-distro-apt.
  - **systemd-in-container probe** (forky + `podman --systemd=always`, rootless): systemd boots as PID 1,
    `is-system-running` → running, units start, journald works. CI (real docker): use
    `--privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock` + `-v /sys/fs/cgroup` + `policy-rc.d` exit 0.
    Oneshot units assert via `Result=success`/`ExecMainStatus=0`, not `is-active` (shows inactive when done).
  - **cppcheck probe** (forky + apt cppcheck 2.22.0 + libbpf-dev):
    1. Bare run dies in 1 s: `vmlinux.h:17: #if __has_attribute(bpf_fastcall)` — unevaluable macro → syntaxError.
    2. With `-D__has_attribute(x)=0 -D__has_builtin(x)=0 -D__has_feature(x)=0 -D__has_extension(x)=0`: parses
       vmlinux.h fine; next blocker was wrong include path for `<bpf/bpf_helpers.h>` (needs plain `-I /usr/include`).
    3. Fixed: **snitch.bpf.c 20 s / dns.bpf.c 22 s**, full analysis output. Findings: `returnDanglingLifetime`
       on `bpf_map_lookup_elem` results (cppcheck cannot model the kfunc — the pointer is map memory, not stack:
       false-positive class to suppress per-idiom), 211× `intToPointerCast` from
       `/usr/include/bpf/bpf_helper_defs.h` (libbpf helper shim — suppress by file), `knownConditionTrueFalse`,
       `unusedStructMember`, `constVariablePointer` in our sources (triage: fix or suppress with reason).
       Rationale for the layer confirmed: it surfaces real candidate findings immediately.
  - **dpkg conffile probe** (forky container, real `dpkg -i`):
    - No `DEBIAN/conffiles` → `/etc/snitch/rules.toml` **not a conffile** (dpkg-query prints none) → fresh install
      over a pyinfra-authored file **silently overwrites it** (R4.3 deal-breaker; also upgrade overwrites local edits).
    - With `DEBIAN/conffiles` listing it → fresh install over an authored file: dpkg keeps the authored version
      (interactive prompt default keep; noninteractive `--force-confdef --force-confold` keeps silently;
      shipped copy parked as `.dpkg-new`), upgrades preserve local modifications. Confirms lintian's error tag
      `file-in-etc-not-marked-as-conffile` points at the mandatory mechanism.
  - **File modes are not normalized** by dpkg-deb (umask leaks into data.tar — probed elsewhere by research):
    the tree assembly must set modes explicitly (and `umask 022`).
  - `scripts/tray-check.sh` already exercises the tray headlessly (phase A: repo `tools/fakedaemon` on a private
    socket, session-bus registration/tooltip/notification asserts via `busctl`) — the in-container tray smoke
    (R5.3 "as far as a headless container allows") reuses this pattern against the installed binary.

### Dagger — pipeline architecture (web research, official docs as of 2026-11-24)
- **Sources**: docs.dagger.io/0.21 (quickstarts, module extension, CI integrations, checks, CLI, container
  runtimes), github.com/dagger/dagger releases, github.com/dagger/dagger-for-github (action.yml + releases),
  pkg.go.dev/dagger.io/dagger@v0.21.12.
- **Findings**:
  - Stable: **v0.21.12** (Go SDK `dagger.io/dagger@v0.21.12`). Dagger 1.0 is in beta with breaking renames
    (`dagger call`→`dagger api call`, `dagger develop`→`dagger generate`, `dagger.json` split); design against
    stable v0.21.x only. Module layout: `dagger.json` at repo root, source in `.dagger/` (own `go.mod`; generated
    `dagger.gen.go` committed; the app's `go.mod` gains **zero** dependencies).
  - **`dagger/dagger-for-github@v8.4.1`** (latest): inputs `verb`+`call`+`workdir`+`version`; recommended thin
    dispatcher (`verb: call`, `call: "<function> --source=."`, `version: "0.21.12"` pinned). The old caching
    actions (`dagger/engine-cache`, `dagger/generate-action-module-cache`) are **deleted**; engine is ephemeral
    per job — accepted (runner dockerd still caches image layers).
  - Checks: functions annotated `+check` join `dagger check`; the CLI lists each check with pass/fail and exits
    non-zero on failure (= R1.3's naming/exit contract). Directory inputs via `+defaultPath`; exports via
    `--output=`; `WithExec` `Expect: SUCCESS|FAILURE|ANY`; `Directory.WithTimestamps(int)` exists for mtime
    normalization; `WithMountedCache` for Go module caches; the engine runs as a privileged sibling container
    on the runner's dockerd (nested-container pitfalls none on ubuntu-latest; Dagger's own CI dogfoods this).
  - 1.0-beta churn (renames, manifest split) is deliberately avoided; migration later touches only workflow
    strings, not the design.

### Linter layer (web research + hands-on probes)
- **Sources**: golangci-lint releases/docs/FAQ/Dockerfile (official), hub.docker.com API, cppcheck cmdline help
  (2.22.0 `cli/cmdlineparser.cpp`), lintian(1) — see References.
- **Findings**:
  - **The committed configuration IS the contract** (R2.3): golangci `.golangci.yaml`; cppcheck = flags in the
    committed invocation + committed suppressions file; any loosening is a reviewable diff. Triage when findings
    exist: a) real defect → fix code; b) BPF-idiom false positive → committed, commented suppression; c)
    third-party header noise → file-level suppression. With today's code the committed recipe must **pass**
    (triaging is an implementation task; zero findings at configured strictness is the acceptance criterion).
  - golangci-lint **v2.15.0** (latest, built against Go 1.27): config `version: "2"`, `linters.default:
    standard` (errcheck, govet, ineffassign, staticcheck, unused); **v2 path exclusions are regexps, not
    globs** (`^internal/bpf/.*_bpfel\.go$`; the bpf2go `// Code generated` headers are also auto-excluded under
    `generated: strict`); `run.timeout` defaulted 0 (disabled) — set it; findings → exit 1. Official image
    `golangci/golangci-lint:v2.15.0(-alpine)` (pin digest; built FROM golang:1.27 with GOTOOLCHAIN auto).
  - **cppcheck 2.22.0** (latest; forky apt ships exactly this): probe-backed recipe above; flags
    `--std=c11 --platform=unix64 --check-level=normal --enable=warning,style,performance,portability
    --inline-suppr --error-exitcode=1` + `-I bpf -I /usr/include` + the four `-D__has_*(x)=0` predefines +
    committed suppressions list (`*:bpf/vmlinux.h` + libbpf shim + per-idiom entries). vmlinux.h is
    self-contained BTF types — no extra `-D` needed for `__u*`/etc. ~20 s/file, 1–3 GB RAM worst case.
  - No official cppcheck image; **apt-exact-version pin in a debian:forky container**
    (`cppcheck=2.22.0-1 libbpf-dev=…`) — an apt move becomes a visible pipeline failure, which is the reviewable
    moment (R2.3 spirit). No derived multi-tool image needed: the linter layer runs once per pipeline, not per
    distro (distro containers exist for build/deb/smoke parity).
  - House caps stay where they are (`scripts/caps.sh`; golangci runs no funlen/gocyclo): one check, one owner.

### CodeQL (web research, official + extractor source)
- **Sources**: github/codeql-action releases/action.yml/CHANGELOG, docs.github.com (workflow-configuration-options,
  build-options-for-compiled-languages, query suites, troubleshooting), starter-workflows codeql.yml,
  codeql GitHub extractor sources (python/extractor/semmle/traverser.py, modules.py), actions/runner-images#14783.
- **Findings**:
  - Action: **`github/codeql-action@v4`** (v4.39.5 today; CLI 2.27.6). Recommended: **matrix of 3 jobs**
    (`fail-fast: false`), `category: /language:<lang>`, `queries: security-extended` (correct current suite
    label; go 1.26 supported since CLI ~2.24).
  - Failure semantics match R3.3/R3.4 as-designed: `analyze` exits non-zero on infra/extraction errors; findings
    never fail the job (architectural); do **not** set `continue-on-error`. Code scanning review is the surface.
  - **Go**: `build-mode: manual` + explicit `go build ./...` after `init` (autobuild would first sniff
    make/build.sh — avoid the ambiguity; Tracee precedent). `setup-go` with `go-version-file: go.mod` before init.
  - **C (BPF)**: **`build-mode: none`** — GA since CLI 2.23.3 (Oct 2025): infers compilation units from
    extensions and include paths by inspecting the codebase; `vmlinux.h` sits next to the source so include
    resolution works; paths config applies. Honors the house rule that **CI never runs clang**. Documented
    caveat: none-mode accuracy can drop with atypical macros (BPF kfunc/macro density) → R3.2 limitation note.
    (Tracee precedent: manual clang-traced BPF builds — heavier machinery, deliberately not chosen.)
  - **Python**: the extractor takes `.py` files **or** extension-less files whose first 100 bytes match
    `#! *(/usr|/bin|/local)*/?(env)? *python`. Our client shebang is `#!/usr/bin/env -S uv run --quiet --script`
    → **no match** → not extracted; no config/extractor override exists for non-matching extension-less files.
    → documented limitation (R3.2's own escape hatch); ruff keeps covering the file; renaming is not taken
    (the root `snitch` name is owned until TUI parity).
  - Scheduling: push (main) + PR + weekly; separate workflow; **never** in the release chain (R6.2).

### Reproducible deb, lintian, systemd-in-docker, toolchain (web research + probes)
- **Sources**: reproducible-builds.org/docs (source-date-epoch, timestamps), dpkg-deb(1)/deb-conffiles(5) via
  manpages.debian.org + dpkg 1.23 sources, lintian(1) 2.144.0, docs.docker.com, actions/runner-images#14783,
  go.dev/doc/toolchain, Debian policy 5.1/9.1.2/12.7, packages/trackers for versions.
- **Findings**:
  - **dpkg-deb recipe** (the exact committed recipe): SOURCE_DATE_EPOCH = **commit timestamp of HEAD**
    (`git log -1 --pretty=%ct`; deterministic in CI and locally for the same commit — R7.1/R7.2); shared-tree
    build with explicit `install -m` modes + `umask 022` (modes are NOT normalized by dpkg-deb);
    `find pkg -exec touch -h -d "@$SDE" {} +` (SDE **clamps** newer mtimes but preserves older ones — set
    exactly); `dpkg-deb --root-owner-group --uniform-compression -Znone --build`. Ordering is deterministic
    since dpkg 1.18.5 (qsort by strcmp); ar headers fixed by dpkg (1.18.11). **`-Znone`** because default xz
    compresses in-process with liblzma **5.8.4 (forky) vs 5.8.3 (26.04)** → realistic byte divergence;
    gzip attacks the tie-break — `-Znone`.
  - **One builder for the deb**: binaries are built in BOTH distros and checksum-compared (R5.1), but **the deb
    is assembled once, in debian:forky** (dpkg-deb 1.23.11 = the pinned, documented reproducibility property of
    R7.2; avoids dpkg-deb version skew becoming an untracked variable). Ubuntu's container installs the deb.
  - **Conffiles**: `deb-conffiles(5)`: conffiles are **only what `DEBIAN/conffiles` lists** (dpkg never
    auto-treats /etc files — that memory belongs to debhelper, which we don't use). Ship
    `/etc/snitch/rules.toml` as a declared conffile; the shipped sample derives from the repo's documented
    example (examples/rules.toml), tuned so `snitchd check -rules` passes; `scripts/setup.sh`'s operator file
    NEVER ships. Automation drives `dpkg -i --force-confdef --force-confold`. postst-create-if-missing is the
    rejected alternative (it re-implements dpkg's state machine and marks the file "modified").
  - **lintian**: run in BOTH distro containers with `--profile debian` (ubuntu defaults otherwise), committed
    threshold `--fail-on error` (default; warnings/info/pedantic emitted to the log and recorded in the
    feature documentation — R5.4's "below-threshold policy tags"). Expected error tags are **handled, not
    overridden implicitly**: `no-copyright-file` (ship `/usr/share/doc/snitch/copyright`), `description-too-short`
    (control), `debian-changelog-file-missing` (ship deterministic `changelog.Debian.gz`, `gzip -9n`),
    `file-in-etc-not-marked-as-conffile` (list the conffile). Legit justified deviations ship an overrides file
    (`/usr/share/lintian/overrides/snitch`, comments): `statically-linked-binary` (static-by-design),
    `dir-or-file-in-usr-local` (units' frozen `ExecStart=/usr/local/sbin/snitchd` contract). Known warnings to
    document, not fix: `no-manual-page`, `hardening-no-relro/-pie` (stripped static binaries; GOCSPGo static).
  - **systemd-in-docker**: smoke containers `apt-get install systemd systemd-sysv dbus` + `policy-rc.d` exit 0 +
    `ENV container=docker`; run `--privileged --cgroupns=host --tmpfs /run --tmpfs /run/lock -v /sys/fs/cgroup`;
    locally podman `--systemd=always` works (probed). Units ship to `/usr/lib/systemd/system` (policy-correct);
    the deb does NOT enable units (enablement stays the operator's/pyinfra's step, matching the documented
    "enabled next to, never Wants=" ownership contract).
  - **BPF LSM in CI: officially impossible** — hosted runner kernel 6.17-azure has `CONFIG_BPF_LSM=y` but the
    boot-time LSM list excludes `bpf` (actions/runner-images#14783, closed not-planned 2026-10-16); LSMs are
    fixed at boot; a privileged container cannot help. Therefore the smoke never asserts full snitchd attach:
    `snitchd.service` expected state = **the headless limitation signature** (journal shows the daemon's
    pin-dir/load/attach failure — i.e. binary, config and units all resolved — and never a missing-file error),
    while `snitchd-trial-boot.service` (oneshot, no kernel objects) **fully completes** in-container, and
    `snitchd check -rules /etc/snitch/rules.toml` (exit 0) proves the shipped sample parses. (Note: even where
    runners DO have `bpf` active, a container-attached BPF LSM hook is host-global; the smoke deliberately does
    not cross that line.)
  - **Go toolchain**: apt diverges (26.04 → go1.26.x, forky → go1.27.x) → the build containers get the **pinned
    official tarball go1.26.8** (go.mod's floor, = what today's `setup-go go-version-file: go.mod` installs),
    sha256-pinned from go.dev/dl, `GOTOOLCHAIN=local`. Byte-parity with today's assets additionally requires
    preserving the **VCS stamp**: today `go build -buildvcs=auto` stamps revision/time/modified from the checkout
    (GHA checkout includes `.git`), so the build functions receive the source **including `.git`** and assert a
    **clean tree** (`git status --porcelain`) + version param consistency with HEAD's tag, making the stamp
    deterministic in CI and locally. Build flags otherwise unchanged from release.yml (see Decisions).
  - GHA runner disk: 5 thin-dispatch jobs = 5 ephemeral dagger engines (each pulls golang-class images; runner
    dockerd caches layers). Accepted cost, noted for optimization later (composite dispatch) without violating
    R6.2's split.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Notes |
|--------|-------------|-----------|---------------------|-------|
| Pipeline-as-code (Dagger module, one door) | All checks + artifact phases as module functions; workflows only dispatch | Exactly R1; local parity is structural, not aspirational | Engine boot cost per job; rootless-podman local caveat | **Selected** |
| Keep GHA-YAML logic, add jobs | golangci/cppcheck/codeql/deb jobs in YAML | No new runtime | Checks cannot run locally (R1 fails); YAML grows pipeline logic again | Rejected — R1 is the point |
| Dagger Cloud Checks (app-run) | GitHub App runs checks on managed engines | Zero workflow files | External dependency, cloud-coupled; checks ≠ release artifacts pipeline | Deferred — revisit later |
| debhelper/debuild packaging | `debian/` tree + debhelper suite | Policy-conventional | Pulls changelog/maintainer-script machinery the repo doesn't own; heavier reproducibility story | Rejected for hand-rolled dpkg-deb |
| fpm | Generic packager abstraction | One command | Extra opaque layer (ruby tree), weaker conffile control | Rejected |
| QEMU-in-CI BPF tests | Nested VM for real attach in CI | Full kernel coverage in CI | Large new machinery; out of scope for a packaging spec | Deferred (future spec candidate) |

## Design Decisions

### Decision: `084e8746` — one Dagger module (v0.21.x stable), workflows as thin dispatchers
- **Context**: R1 demands one pipeline callable from CI and from the operator's machine with identical passing
  criteria. **Alternatives**: YAML status quo (rejected — no local door); Dagger 1.0-beta (rejected — beta
  churn for CI-critical infrastructure); Cloud Checks (deferred).
- **Selected**: Go SDK module at `.dagger/` (committed bindings; zero app-module imports), dispatched by
  `dagger/dagger-for-github@v8.4.1` (`version: "0.21.12"` pinned). Per-check functions + composite functions.
- **Rationale / Trade-offs**: matching upstream stable; `dagger check`/`call` exit semantics directly implement
  R1.3; engine-ephemeral-per-job accepted.
- **Follow-up (resolved empirically in task 1)**: the workstation's rootless podman 5.7.0 **does** boot the
  v0.21.12 engine (the docs' rootless warning is stale); the local door is verified working. Upstream's
  rootful-podman/docker note stays documented as the supported path, and rootless `--privileged` smoke
  semantics get real verification in task 6.

### Decision: `d0d88f59` — check function granularity mirrors today's checks; composites for ergonomics
- **Context**: R1.4 freezes the existing check set; R6.2 keeps new linters out of the release gate only.
- **Selected**: functions = `fmt`, `go-checks` (gofmt+build+vet×3+test+caps — one container, today's sequence),
  `shellcheck`, `ruff`, `actionlint`, `linters` (golangci+cppcheck), composites `lint-core` (the five existing),
  `lint-all`. Same commands, same pins (ruff@0.16.10, actionlint-py, gocyclo@v0.6.0, tools/caps).
- **Rationale**: today's four lint.yml jobs keep their names/shape (thin dispatch each); the new `linters` job
  is skipped on `refs/tags/v*` → release gate = existing checks only (R6.2), push/PR gate = full set (R2).

### Decision: `c9cfa6f1` — CodeQL as a separate workflow, never in the release chain
- **Context**: R3 (dataflow scanning) vs R6.2 (findings/review cannot gate releases).
- **Selected**: `.github/workflows/codeql.yml`, matrix `go|c-cpp|python`, `fail-fast: false`, go=`manual`
  (`go build ./...` after setup-go from go.mod), c-cpp + python = `build-mode: none`, all `security-extended`,
  categories `/language:*`; push(main)+PR+weekly.
- **Rationale**: official pattern; failure semantics natively match R3.3/R3.4. Python client extraction is
  impossible (shebang regex) → **documented limitation**; BPF C covered via none-mode with a documented
  macro-accuracy caveat (R3.2's recording requirement).

### Decision: `50b894e6` — hand-rolled dpkg-deb with the verified reproducibility recipe
- **Context**: R4/R5/R7 need one distro-agnostic, byte-identical, idempotent-semantics package without
  adopting a packaging suite.
- **Alternatives**: debhelper (machinery overkill), fpm (opaque), raw `ar`+`tar` (reimplements dpkg).
- **Selected**: assemble the tree in-module (explicit modes, `umask 022`), SDE = HEAD commit time, exact-touch,
  `dpkg-deb --root-owner-group --uniform-compression -Znone`; **build the deb once, in debian:forky**
  (pinned dpkg-deb 1.23.11 as the R7.2 documented property); binaries built in BOTH distros from the
  go1.26.8 sha-pinned tarball (`GOTOOLCHAIN=local`), checksum-compared (R5.1); version = tag stripped of the
  leading `v` (debian-native); VCS stamp preserved (source incl. `.git`, clean-tree assertion, tag==version
  assertion) for byte-parity with today's asset construction (R6.1).
- **Rationale**: every property probed or source-verified; zero new maintainers' machinery for a two-binary
  static package.
- **Trade-offs**: `-Znone` (larger deb ~tens of MB) buys cross-distro/compressor determinism (liblzma skew).

### Decision: `2a91a44b` — conffile-listed sample rules; operator's realm never ships
- **Context**: R4.3/R4.6 (never clobber authored config; upgrades preserved) vs reality (dpkg silently
  overwrites non-conffiles — probed).
- **Alternatives**: postinst create-if-missing (rejected — reimplements dpkg's state machine); no /etc file
  (rejected — R4.3 requires a fresh install to start).
- **Selected**: `DEBIAN/conffiles` lists `/etc/snitch/rules.toml`; content = the repo's documented sample
  (examples/rules.toml, tuned if needed for `snitchd check`); installs driven `--force-confdef
  --force-confold` in automation; `snitchd-trial-boot` and unit files ship; `snitch` (tray) at `/usr/bin`
  (PATH, desktop entry compatibility), `snitchd` at `/usr/local/sbin` (frozen unit contract), units at
  `/usr/lib/systemd/system`, desktop entry at `/usr/share/applications`, license/copyright + deterministic
  changelog + md5sums; lintian overrides shipped for static-bin + /usr/local with justification comments.
- **Rationale**: dpkg's own conffile state machine is the reviewed, tested mechanism (policy §5.1).

### Decision: `f5c1a3c6` — honest, environment-limited smoke assertions
- **Context**: R5.3 "verify the services reach their expected state" vs BPF LSM being boot-fixed and absent on
  GHA runners (official), absent on this workstation, host-global if actually attached.
- **Selected**: per-distro smoke = dpkg install (conffile-keep assertion over a pre-authored rules.toml),
  `systemd-analyze verify` on shipped units, `snitchd-trial-boot.service` start → `Result=success`,
  `snitchd.service` start → assert journal carries the BPF-limitation signature and no missing-binary/config
  error, `snitchd check -rules /etc/snitch/rules.toml` → 0, `snitch -version` from PATH, tray-vs-fakedaemon
  headless exercise (private bus, tray-check phase-A pattern), lintian both distros `--profile debian`,
  `--fail-on error`.
- **Rationale**: every asserted state is reachable and meaningful regardless of runner kernel; the packaging
  contract is what the smoke proves (paths/units/config resolve), the kernel limitation is documented (R3.2/R5.4
  documentation duties).

### Decision: `bb1c26aa` — release chain: unchanged gate for existing assets, new phases converge at one atomic publish
- **Context**: disambiguating R6.2+R6.3 (see design.md's flow): the six existing assets' construction stays
  gated exactly as today (existing checks via workflow-call, no new-phase dependencies); distro-proof/deb
  phases join the chain producing their artifacts; **one publish job** (contents: write) needs : both artifact
  sets and publishes **all 8 assets atomically** (existence loop + `--clobber` pattern, extended by
  `snitch_<version>_amd64.deb` + `.sha256`) — "nothing is published when an earlier job fails" (R6.2 clause 2).
- **Selected**: release.yml = checks → [release-build job ∥ distro-proof+deb+smoke job] → publish (8 assets).
  The linter job's tag-skip lives in lint.yml; CodeQL is not referenced by release.yml at all.

### Synthesis records (lenses applied)
- **Generalization**: every check = function(`*dagger.Directory`, `…`) `error`; distro = a string parameter to
  the shared build function (ubuntu:26.04 / debian:forky); artifact sets = `*dagger.Directory` exports.
- **Build vs Adopt**: dagger engine, dpkg conffile state machine, lintian, systemd-in-container, tray-check
  harness, tools' own configs — all adopted; built: only the ~deterministic tree assembly and the pipeline
  functions themselves (thin by design).
- **Simplification**: linter layer runs once (no distro matrix); deb assembled once (no cross-distro deb
  compare); no derived multi-tool images; CodeQL outside dagger; publish remains a workflow step (token stays
  in the runner, asset loop unchanged); composites used instead of workflow gymnastics

## Risks & Mitigations
- **Dagger engine vs rootless podman (local door)** — RESOLVED empirically in task 1: engine v0.21.12 boots
  over rootless podman 5.7.0; residual risk moved to task 6 (privileged/systemd smoke containers under
  rootless podman get real verification there).
- **golangci/staticcheck findings on existing code** — triage task with explicit fix-or-configure acceptance (R2.1).
- **cppcheck triage set (probe-observed)** — same pattern; suppressions file only with written reasons.
- **VCS stamp parity edge cases** — clean-tree + tag assertions in the build function make mismatches loud.
- **apt version drift for cppcheck/systemd in distro containers** — exact-version pins where possible; drift
  fails visibly rather than silently.
- **5 ephemeral engines per lint run (GHA)** — accepted; composite-dispatch is a pure optimization for later.
- **CodeQL matrix label naming (`cpp` vs `c-cpp`) and config-file details** — verify against action inputs during
  implementation; treated as a task-level verification, not a design unknown.
- **`.deb` size with `-Znone`** — accepted (~30 MB vs ~10 MB) for determinism.
- **`snitch` has been resting on the untagged namespace** — the deb ships `/usr/bin/snitch` (Go tray binary);
  on VMs where the client was installed at `~/.local/bin`, PATH order resolves the user's first — documented.

## References
- Dagger docs (0.21): https://docs.dagger.io/0.21/ ; module schema: https://docs.dagger.io/reference/dagger.schema.json ;
  action: https://github.com/dagger/dagger-for-github ; releases: https://github.com/dagger/dagger/releases/tag/v0.21.12
- golangci-lint: https://golangci-lint.run/docs/configuration/file/ ; https://github.com/golangci/golangci-lint/releases/tag/v2.15.0
- cppcheck: https://github.com/cppcheck-opensource/cppcheck/releases/tag/2.22.0 ; https://tracker.debian.org/pkg/cppcheck
- CodeQL: https://docs.github.com/en/code-security/reference/code-scanning/workflow-configuration-options ;
  build-mode none GA: https://github.blog/changelog/2025-10-14-codeql-scanning-rust-and-c-c-without-builds-is-now-generally-available/ ;
  python extractor sources: https://github.com/github/codeql/blob/main/python/extractor/semmle/python/modules.py ;
  action: https://github.com/github/codeql-action/releases ; starter: https://github.com/actions/starter-workflows/blob/main/code-scanning/codeql.yml
- Reproducibility: https://reproducible-builds.org/docs/source-date-epoch/ ; https://reproducible-builds.org/docs/archives/ ;
  dpkg-deb(1): https://manpages.debian.org/testing/dpkg/dpkg-deb.1.en.html ; deb-conffiles(5) + policy §5.1:
  https://www.debian.org/doc/debian-policy/ap-pkg-conffiles.html
- GHA runner kernel/BPF LSM: https://github.com/actions/runner-images/issues/14783
- Go toolchain: https://go.dev/doc/toolchain ; https://go.dev/dl/
- Local probe logs (this session): dpkg SDE/clamp/conffile/systemd/cppcheck probes summarized above —
  artifacts retained in session history, dates 2026-11-24.
