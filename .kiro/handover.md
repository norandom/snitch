# Handover — ci-debs, open points (2026-11-25)

Status: the feature is implemented and locally validated end-to-end (tasks 1–9 done; every
acceptance criterion carries executable evidence; details in `.kiro/specs/ci-debs/`, the
closing checkpoint of session `snitch-1795453519489`, and durable observations #24–#35).
HEAD `f48f7ee`, tree clean, **23 commits ahead of `origin/main`, nothing pushed**.
Final artifact shas at `f48f7ee`: `snitchd` `65d69227…`, `snitch-linux-amd64` `249d0f87…`,
`snitch_0.0.0-cidev_amd64.deb` `bfe27eca…` (9,871,552 bytes, `-Znone`).

## Open decision: CodeQL coverage of C/C++ and the Python client (user critique, pending go)

The user judged the shipped CodeQL coverage backwards for this codebase: the BPF C
(`dns.bpf.c` parses attacker-controlled packets in the kernel) runs in the *weakest* mode
(`build-mode: none`, inferred, macro-accuracy caveat) and the extension-less Python client is
not extracted at all. Proposed revision (design decision `c9cfa6f1` reopens; R3.2 moves from
"documented limitation" to full coverage):

1. `c-cpp` lane → `build-mode: manual`: install `clang libbpf-dev` in the codeql job, tracer
   watches `clang -target bpf -c bpf/snitch.bpf.c -o /dev/null` (and `dns.bpf.c`) —
   observation only, output to `/dev/null`, the committed `.o` and all build lanes stay
   clang-free (Tracee precedent: manual-traced BPF builds).
2. Python lane → pre-scan copy: `cp snitch snitch-client.py` before `init` (same bytes, `.py`
   extension so the extractor takes it), noted in the config; real taint coverage for the
   client until the Go TUI retires it.
3. Records to update: `docs/ci-debs.md` CodeQL section, design.md/research.md decision, and
   a one-line tech.md amendment ("CI never runs clang — except the CodeQL tracer's
   `-o /dev/null` observation build; artifacts never come from clang") unless the user
   overrules the letter verbally instead.
4. Locally verifiable: the clang observation compile in a container. CodeQL's actual
   extraction still only proves after push.
5. Scope: small workflow diff + docs/steering updates; `feat(ci-debs)` follow-up commits.

## Deferred C fixes (real, admitted, not hidden)

Four `constVariablePointer` suppressions cppcheck called right: `bpf/snitch.bpf.c:218/219/241`
and `bpf/dns.bpf.c:356`. Fix plan is *not* workstation-side: editing `.bpf.c` requires
regenerating the committed bpf2go bindings, which needs clang (the dev VM per CLAUDE.md).
Do them there: fix the four lines, `go generate ./internal/bpf/`, commit, then drop the four
suppression lines from `bpf/cppcheck-suppressions.txt` and the honesty-records entry in
`docs/ci-debs.md`. Also present by-referral: `knownConditionTrueFalse` at `dns.bpf.c:439/514`
(mismodel judgement — revisit when the deferred pass happens).

## Pending verification (happens only after push)

- First live `lint.yml` run: the four dispatch jobs + the tag-skipped `linters` job
  (workflow_call ref-inheritance verified against docs; runner-side engine boot untested).
- First live `codeql.yml` run: current form = go manual / c-cpp none / python none; if the
  open decision lands, the upgraded manual + copy lanes instead.
- The deb lane's first CI run (~2.5–3 min warm, both distro smokes included).

## Release-day runbook

Push a `vX.Y.Z` tag → `release.yml`: `checks` (lint.yml via workflow_call; linters self-skip
on tags) → `release-build` ∥ `deb` lanes → `publish` (eight-file existence loop, then the
unchanged `gh` pattern; `contents: write` only there). SOURCE_DATE_EPOCH = the tag commit's
committer time; the deb and its sha256 settle per that commit exactly as the task-9 battery
demonstrated. After publish: the VM repo deliberately re-pins `snitchd`'s sha256 and may add
the deb pin; unit copies in the VM repo are marked copies of this repo's.

## Small leftovers (deliberate)

- Stray literal tab in `.dagger/smoke.go:141` inside the smoke driver script — cosmetic;
  left because fixing it moves HEAD and invalidates the shas settled at `f48f7ee`. First
  commit after a push is a fine time to tidy.
- `.dagger/go.mod` toolchain floor is Go 1.27.4 (SDK-set, one step above the app's 1.26.8);
  first module `go vet` in a fresh container needs `GOTOOLCHAIN=auto` to download it.
- `actionlint` runs unpinned via `actionlint-py` for parity with the pre-feature workflow
  (resolves actionlint v1.7.12 at run time); pinning it is a deliberate future decision.
- The runtime on this workstation moved mid-feature (rootless podman 5.7 → docker-ce 29.10.1);
  the module's smoke needs the `--docker-socket` endpoint — on other machines the path may
  differ (`docs/ci-debs.md` records the prerequisite).
