# rugged: the pre-release suite, and why half of it cannot run in CI

Situation: before a `v*` tag, the repo wants one command that proves the tree is releasable.
Complication: the proof has two halves, and only one of them fits in a hosted runner.
Question: what do you run, where, and what does each half actually prove?
Answer: `dagger call rugged --fuzz-duration 30s` for everything the pipeline can do, and
`sudo scripts/root-checks.sh --at <commit>` on a real Linux host with the `bpf` LSM active
for the part that loads kernel programs. Run both, in that order, then tag.

## What rugged is

`rugged` is one Dagger call that runs two things back to back and stops at the first
failure, naming it:

1. `lint-all` — every pipeline check: fmt, go, shellcheck, actionlint, golangci,
   cppcheck, and the bindings check. The bindings check regenerates `internal/bpf/` with
   the pinned clang in the pinned forky image and compares byte for byte with the committed
   objects. The compiler only observes: nothing it produces is committed or shipped
   (see `docs/c-hardening.md`, "The bindings check").
2. `fuzz` — `scripts/fuzz.sh -t <duration>` over all six fuzz targets:
   `FuzzDecodeEvent` and the egress decoders (`cmd/snitchd`), `FuzzDecode` (`internal/dns`),
   `FuzzParse` + `FuzzLineReader` (`internal/api`), `FuzzParse` + `FuzzParseOverlay`
   (`internal/rules`). The ordinary `go test ./...` already runs each target's seeds as
   plain tests; rugged adds the mutation run.

```sh
dagger call rugged --fuzz-duration 30s
```

Neither part is gated in a workflow: no job calls `rugged` or `fuzz`, and the release chain
does not depend on them. They are the operator's pre-tag command, run on demand. A run is
never answered from the engine cache, so a green rugged always means "this tree, just now".

## What the pipeline cannot prove, and root-checks.sh

The daemon's decisions happen in BPF programs loaded into the host kernel. A hosted CI
runner is an unprivileged container: no `bpf` in the LSM list, no CAP_BPF, so
`BPF_PROG_TEST_RUN`, cgroup attach, and the monitor run are impossible there. That is why
the root half is a script the operator runs, by design:

```sh
stat -c %a /tmp                              # must be 1777; the script refuses otherwise
sudo scripts/root-checks.sh --at <commit to tag>
```

`--at <rev>` checks out exactly that commit in a temporary detached worktree and removes
it afterwards, so the run proves the commit you are about to tag while work continues on
main. The script, and nothing else:

1. builds the daemon as your own user (not root),
2. runs the DNS tap root tests (`scripts/dns-progtest.sh`): both programs load and pass the
   verifier, and the hostile-input corpus (58 entries, each with a stated expected outcome)
   passes,
3. only where `bpf` is in the active LSM list (a dev VM, not a workstation): a bounded
   75 s monitor-mode run of the built daemon on a private socket under `/run/snitch-check`,
   with `scripts/api-check.sh` run against it as your user, including the `counters`
   assertion (both sections available, every contract counter zero).

It never enters enforce mode. If `snitchd.service` is active it is stopped for the run and
started again afterwards; the kill switch value found at the start is restored on exit.
On a host without an active BPF LSM it runs only the DNS tests. Exit 0 means every step
that ran passed.

`scripts/enforce-test.sh` stays the attended operator test, run only on explicit request;
nothing in the release path runs it.

## The release sequence

```sh
dagger call rugged --fuzz-duration 30s           # pipeline half, on any machine with the engine
sudo scripts/root-checks.sh --at <commit>        # kernel half, on the dev VM
 git tag vX.Y.Z && git push origin vX.Y.Z        # then release.yml: checks, release-build + deb, publish
```

Push the tag only after both halves are green on the exact commit the tag points at.
