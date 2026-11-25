# Handover — c-hardening implemented, ci-debs follow-ups open (2026-11-25)

Status (2026-11-25, evening): everything is pushed; `main` = `origin/main`. The first live
runs are green: lint.yml (fmt, go, shellcheck, ruff, actionlint, linters incl. the bindings
check) and codeql.yml (go and c-cpp traced, python via the pre-scan copy, 0 open alerts). The
repository's CodeQL *default setup* was switched off (user decision) because it blocked
codeql.yml's uploads; its `actions` lane is no longer scanned. Still pending: the c-hardening
root gates (below) and the deb lane's first CI run, which happens on the first `v*` tag.

## Decisions on record (2026-11-25)

- **The compiler may run in CI as an observer**; artifacts never come from it. Landed as the
  bindings check and written into `.kiro/steering/tech.md` ("The compiler as observer").
- **deb dependencies: Suggests-only for KDE, one package** (no `snitch-tray` split). Topic (b).

## Dependabot (new, undecided)

13 alerts, all in `.dagger/go.mod` (the CI pipeline module, never shipped): grpc (3 high, 1
medium), x/net and otel packages. Dependabot PR #1 bumps six of them and fails every lint job,
most likely because Dagger's generated SDK pins those versions. Options: bump the Dagger engine
and SDK (`dagger develop` on a newer engine), or dismiss the alerts as pipeline-only.

## c-hardening: root gates not yet run

Run on the dev VM (BPF LSM active), as your user through sudo, and paste the output:

```sh
sudo scripts/root-checks.sh --at <HEAD>
```

It proves 1.2, 2.4, 3.5, 4.4, 5.4, 6.1–6.3 and the root half of 8.3 (DNS root tests with the
58-frame corpus, a 75 s bounded monitor run, `scripts/api-check.sh` incl. the `counters`
object at zero). Those tasks stay `[ ]` until the output proves them. Never enforce mode.

## c-hardening: decided 2026-11-25 (task group 9)

- **Req 6.3**: the tap now rejects a UDP length larger than the packet (task 9.1, root run
  pending); Req 6.3 is amended to name the nine remaining exceptions (`docs/c-hardening.md`
  "Known limits").
- **15 labels**: rule names are limited to 15 labels (task 9.2, done).
- **gofmt in CI**: a `fmt` job in lint.yml (task 9.3, done).
- **Fuzz leftovers**: survivor check and boundary seeds in the rules fuzzer, exact-length
  `DecodeContracts` (task 9.4, done). Still optional: the `internal/dns` reader's `malformed`
  counter is a plain uint64 (atomic if ever served).

## Topic (a) leftovers: PIE (ci-debs follow-up)

1. Done 2026-11-25: CodeQL c-cpp is traced (`build-mode: manual`, an observation compile with
   the runner's clang and libbpf 1.3, flags without `-Werror`, output to `/dev/null`) and the
   python lane extracts the client through the pre-scan copy `snitch-client.py`. Extraction
   only proves on the first live run after push.
2. Undecided: `-buildmode=pie` for the two Go binaries (static non-PIE today); small gain,
   changes the release shas.

## Topic (b): deb dependencies (done 2026-11-25)

`packaging/control`: `Recommends: bpftool, default-dbus-session-bus | dbus-session-bus`,
`Suggests: plasma-workspace, breeze-icon-theme`, no `Depends`; names checked with `apt-cache`
in forky and 26.04; R4.5 amended; `docs/ci-debs.md` updated. The deb's sha256 changed. The
maintainer line was corrected earlier (`9c3f5e0`).

## Pending verification (happens only after push)

- First live `lint.yml` run: the four dispatch jobs plus the tag-skipped `linters` job, now
  with the `bindings` dispatch (cache-cold on runners: apt from snapshot.debian.org + regen).
- First live `codeql.yml` run: go and c-cpp traced, python through the pre-scan copy.
- The deb lane's first CI run (~2.5–3 min warm, both distro smokes included).

## Release-day runbook

Release note for the next tag (c-hardening 9.2): rule names now have at most 15 labels. A
16-label name in `/etc/snitch/rules.toml` makes snitchd refuse to start (fail-open: nothing
attached); in the overlay `local.toml` it makes the whole overlay skipped at startup. Before
upgrading, run `snitchd check -rules /etc/snitch/rules.toml` and check `local.toml`. (The VM's
deployed rules have their domain rules commented out; no current exposure.)

Before tagging: `dagger call rugged --fuzz-duration 30s`, then
`sudo scripts/root-checks.sh --at <commit to tag>` on the dev VM. Push a `vX.Y.Z` tag →
`release.yml`: `checks` (lint.yml via workflow_call; linters, incl. the bindings check,
self-skip on tags) → `release-build` ∥ `deb` lanes → `publish` (eight-file existence loop,
then the unchanged `gh` pattern; `contents: write` only there). SOURCE_DATE_EPOCH = the tag
commit's committer time. After publish: the VM repo deliberately re-pins `snitchd`'s sha256
and may add the deb pin; unit copies in the VM repo are marked copies of this repo's.

## Small leftovers (deliberate)

- Stray literal tab in `.dagger/smoke.go:141` inside the smoke driver script — cosmetic;
  tidy in the first commit after a push.
- `.dagger/go.mod` toolchain floor is Go 1.27.4 (SDK-set, one step above the app's 1.26.8);
  first module `go vet` in a fresh container needs `GOTOOLCHAIN=auto` to download it.
- `actionlint` runs unpinned via `actionlint-py` (resolves v1.7.12 at run time); pinning it
  is a deliberate future decision.
- The workstation runtime is docker-ce 29.10.1; the module's smoke needs the
  `--docker-socket` endpoint (path may differ elsewhere; `docs/ci-debs.md` records it).
  `scripts/bindings-regen.sh --docker` uses the same daemon, no sudo.
- Workstation toolchain: clang 21.1.8 but libbpf-dev 1.6.3, so host `go generate` fails
  `snitch.bpf.c`; regenerate with `scripts/bindings-regen.sh --docker --write`.
