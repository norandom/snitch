# Handover — c-hardening fully validated (2026-11-26)

State: everything is pushed, `main` = `origin/main`, working tree clean. CI on `f149560` is
green (lint.yml: fmt, go, shellcheck, ruff, actionlint, linters incl. the bindings check;
codeql.yml: go, c-cpp, python). CodeQL *default setup* is off (user decision 2026-11-25: it
blocked codeql.yml's uploads; the `actions` lane is no longer scanned).

## Next steps, in order

1. **c-hardening is complete**: the last open item, task 1.2 (baseline record), was run on the
   dev VM 2026-11-26: `sudo scripts/root-checks.sh --at c1ca575`, rc=0 — both programs load,
   parser/query/socket-join tests pass with the committed (unchanged) expectations, the 75 s
   monitor run ended on its own, api-check 0 failed steps. Recorded in
   `.kiro/specs/c-hardening/tasks.md` (Implementation Notes); tasks 1.2 and group headers 1 and 8
   ticked. `/kiro-validate-impl c-hardening` was re-run: every task [x], full suite + fuzz +
   lint/codeql green on f1b1642 → GO.
2. **Dependabot PR #3** (otel 1.44 -> 1.47 in `.dagger/`, opened 2026-11-25 18:13) fails
   every lint job, like #1 and #2 before it. Close it, and either dismiss the 8 otel alerts
   (4 medium, 4 low) as "tolerable risk: telemetry exporters of the CI-only pipeline module" or
   wait for a Dagger release. Reason: engine v0.21.12 (the newest; Dagger's `main` too)
   rewrites `.dagger/go.mod`'s `replace` lines to otel/log v0.16.0, and otel 1.47 with log
   v0.16 does not compile. A `dependabot.yml` ignore for `go.opentelemetry.io/*` in
   `/.dagger` would stop the reopening. User decision.
3. **Open decisions**: `-buildmode=pie` for the two Go binaries (static non-PIE today; small
   gain, changes the release shas); pinning `actionlint` (unpinned via `actionlint-py`).
4. **First `v*` tag**: the deb lane's first CI run happens there (see the runbook below).

## Done in c-hardening (spec `.kiro/specs/c-hardening/`, record `docs/c-hardening.md`)

Root gates passed 2026-11-26: `sudo scripts/root-checks.sh --at 8300add` on the VM, rc=0:
both programs load (dns_query 9420, dns_answer 62785 verified instructions), 58/58 corpus
entries (three short-L3 entries refused by the test run with EINVAL, accepted as `mayRefuse`),
parser/query/socket-join tests, a 75 s monitor run ending on its own, api-check 0 failed steps,
`counters` present with every contract counter 0, monitor mode throughout. Closed: 2.4, 3.5,
4.4, 5.4, 6.1–6.3, 8.3, 9.1 (everything except 1.2 and the group headers 1 and 8).

The first VM run (`--at f990624`) failed and found two defects, fixed in `8300add`:

- Six truncation entries predated 9.1's UDP-length check (a cut frame keeps the full UDP
  length and is rejected before `ST_SEEN`). DNS-header cuts now expect nothing counted; the
  question/record cuts shrink the UDP length (`cutDatagram`) so they still reach the parsers.
- `snitchd -api <path>` chmods the socket's directory to 0755; the script used `/tmp`, so the
  run turned the VM's `/tmp` into 0755 (fixed on the VM with `chmod 1777 /tmp`). The daemon now
  refuses a sticky or world-writable directory (`api off:`, mode untouched;
  `TestApiListenerRefusesSharedDir`, `examples/api.md`); `scripts/root-checks.sh` uses
  `/run/snitch-check/` and refuses to start when `/tmp` is not 1777. The deployed service is
  unaffected (`/run/snitch`, `RuntimeDirectory`).

Decisions on record (2026-11-25):

- **The compiler may run in CI as an observer**; artifacts never come from it (the bindings
  check; `.kiro/steering/tech.md`, "The compiler as observer").
- **deb dependencies: Suggests-only for KDE, one package** (no `snitch-tray` split):
  `packaging/control` has `Recommends: bpftool, default-dbus-session-bus | dbus-session-bus`,
  `Suggests: plasma-workspace, breeze-icon-theme`, no `Depends`; ci-debs R4.5 amended.
- **Req 6.3** amended: the tap rejects a UDP length beyond the packet (9.1); the nine
  remaining one-field exceptions are listed in `docs/c-hardening.md` "Known limits".
- **15 labels** max for rule names (9.2), **gofmt** job in lint.yml (9.3), fuzz leftovers
  (9.4). Still optional: the `internal/dns` reader's `malformed` counter is a plain uint64
  (make it atomic if it is ever served).
- **CodeQL**: c-cpp traced (`build-mode: manual`, an observation compile with the runner's
  clang and libbpf, no `-Werror`, output to `/dev/null`), python via the pre-scan copy
  `snitch-client.py`; 0 open code-scanning alerts.

Dependabot: grpc (1.79.3 -> 1.83.2, all high) and `golang.org/x/net` 0.60.0 fixed in
`.dagger/go.mod` (`3ef4f14`, `f15d84b`); only the 8 otel alerts above remain.

## Release-day runbook

Release note for the next tag (c-hardening 9.2): rule names now have at most 15 labels. A
16-label name in `/etc/snitch/rules.toml` makes snitchd refuse to start (fail-open: nothing
attached); in the overlay `local.toml` it makes the whole overlay skipped at startup. Before
upgrading, run `snitchd check -rules /etc/snitch/rules.toml` and check `local.toml`. (The VM's
deployed rules have their domain rules commented out; no current exposure.) Also note: an
`-api` path inside a shared directory such as `/tmp` is now refused.

Before tagging: `dagger call rugged --fuzz-duration 30s`, then
`sudo scripts/root-checks.sh --at <commit to tag>` on the dev VM. Push a `vX.Y.Z` tag →
`release.yml`: `checks` (lint.yml via workflow_call; linters, incl. the bindings check,
self-skip on tags) → `release-build` ∥ `deb` lanes → `publish` (eight-file existence loop,
then the unchanged `gh` pattern; `contents: write` only there). SOURCE_DATE_EPOCH = the tag
commit's committer time. The deb lane's first CI run (~2.5–3 min warm, both distro smokes)
happens here. After publish: the VM repo deliberately re-pins `snitchd`'s sha256 and may add
the deb pin; unit copies in the VM repo are marked copies of this repo's.

## Working notes

- Root checks are batched: the agent has no sudo; the user runs `scripts/root-checks.sh` and
  pastes the output. The workstation has no BPF LSM (DNS root tests run there, LSM checks only
  on the VM).
- Workstation: clang 21.1.8 but libbpf-dev 1.6.3, so host `go generate` fails `snitch.bpf.c`;
  regenerate with `scripts/bindings-regen.sh --docker --write` (docker-ce 29.10.1, no sudo).
  `shellcheck` is not on the host PATH: `dagger call lint-all` runs it (~3 min).
- `.dagger/go.mod` toolchain floor is Go 1.27.4 (SDK-set); a fresh container's first module
  `go vet` needs `GOTOOLCHAIN=auto`.
- The module's smoke needs the `--docker-socket` endpoint (`docs/ci-debs.md`).
- Cosmetic: a stray literal tab in `.dagger/smoke.go:141` inside the smoke driver script.
