# Handover — c-hardening implemented, ci-debs follow-ups open (2026-11-25)

Status: spec `c-hardening` is implemented through task 8.2 (details in
`.kiro/specs/c-hardening/` and `docs/c-hardening.md`); the root-only proof of 1.2, 2.4, 3.5,
4.4, 5.4 and 6.1–6.3 and the final validation (8.3) are pending, so those tasks stay open.
**58 commits ahead of `origin/main` after the 8.2 commit, nothing pushed** (ci-debs and c-hardening together). The ci-debs artifact shas recorded at
`f48f7ee` are stale (the Maintainer correction and the regenerated bindings moved them);
release shas settle per the tag commit.

## Decisions on record (2026-11-25)

- **The compiler may run in CI as an observer**; artifacts never come from it. Landed as the
  bindings check and written into `.kiro/steering/tech.md` ("The compiler as observer").
- **deb dependencies: Suggests-only for KDE, one package** (no `snitch-tray` split). Topic (b).

## c-hardening: root gates not yet run

Run on the dev VM (BPF LSM active), as your user through sudo, and paste the output:

```sh
sudo scripts/root-checks.sh --at <HEAD>
```

It proves 1.2, 2.4, 3.5, 4.4, 5.4, 6.1–6.3 and the root half of 8.3 (DNS root tests with the
58-frame corpus, a 75 s bounded monitor run, `scripts/api-check.sh` incl. the `counters`
object at zero). Those tasks stay `[ ]` until the output proves them. Never enforce mode.

## c-hardening: open for the user's decision

- **Ten Req 6.3 deviations**: corpus entries where the tap learns from a packet malformed in
  one field (five length entries, two ancount-surplus, three `compression-owner-*`). Fail-safe
  rule 1 holds. Accept as documented, or harden (`uh.len <= skb->len - off` in `parse_l34`
  turns the UDP-length entry into a reject). See `docs/c-hardening.md` "Known limits".
- **15 vs 16 labels**: `read_qname` reads at most 15 labels, `rules.ParseName` and
  `examples/rules.toml` accept 16, so a 16-label domain rule is never learned. Fix either side
  (ParseName refuses > 15, or the loop runs `LABELS_MAX + 1` turns; re-check the limit
  contracts and the verifier budget).
- **CI does not enforce gofmt** (pre-existing, since ci-debs 7.1 / `6132913`): no lint.yml job
  dispatches `fmt`. Add a `call: fmt` dispatch or fold it into the go job.
- Optional: 6.6 review suggestions (survivor check in the overlay fuzz, explicit boundary
  seeds); `internal/dns` reader's `malformed` counter is a plain uint64 (atomic if ever served).

## Topic (a) leftovers: CodeQL lanes, PIE (ci-debs follow-up)

1. CodeQL `c-cpp` → `build-mode: manual` (install `clang libbpf-dev` in the codeql job; the
   tracer watches `clang -target bpf -c bpf/{snitch,dns}.bpf.c -o /dev/null`, observation
   only; the bindings check's pinned image is the natural toolchain) and the Python lane's
   pre-scan copy (`cp snitch snitch-client.py` before `init`, same bytes, noted in the
   config). Today: go manual / c-cpp none / python none. Records: `docs/ci-debs.md` CodeQL
   section, the ci-debs design/research decision `c9cfa6f1`. Expected yield is modest (stock
   C queries model libc sinks BPF code lacks). Extraction only proves after push.
2. Undecided: `-buildmode=pie` for the two Go binaries (static non-PIE today); small gain,
   changes the release shas.

## Topic (b): deb dependencies (decided: Suggests-only, not implemented)

`packaging/control` declares no relationship fields (ci-debs R4.5: static binaries). Target:

- `Recommends: bpftool` (the kill switch, fail-safe 4) and the session D-Bus for `snitch tray`.
- `Suggests:` `plasma-workspace` (StatusNotifierWatcher, notifications), `breeze-icon-theme`
  (cosmetic). Not Recommends: a headless host must not pull Plasma.
- No `Depends`; Linux >= 6.12 with BPF LSM stays in the Description.
- Verify first with `apt-cache` in the smoke containers on both contract distros (forky,
  26.04): `bpftool`, `default-dbus-session-bus | dbus-session-bus`, `plasma-workspace`,
  `breeze-icon-theme`.
- Records that change with it: R4.5 in `.kiro/specs/ci-debs/requirements.md`, the "declares
  no runtime dependency" sentence in the control Description, the `statically-linked-binary`
  comment in `packaging/lintian-overrides`, `docs/ci-debs.md`. The deb's sha256 changes.
- Done: `Maintainer: Marius Ciepluch <wishinet@…>` in `packaging/control` and the changelog
  line in `.dagger/deb.go` (committed with `9c3f5e0`).

## Pending verification (happens only after push)

- First live `lint.yml` run: the four dispatch jobs plus the tag-skipped `linters` job, now
  with the `bindings` dispatch (cache-cold on runners: apt from snapshot.debian.org + regen).
- First live `codeql.yml` run (current form above, or the upgraded lanes if item (a)1 lands).
- The deb lane's first CI run (~2.5–3 min warm, both distro smokes included).

## Release-day runbook

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
