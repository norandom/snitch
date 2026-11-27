# Development: build, check, release

For people changing snitch. Users start at the [README](../README.md).

## Build from source

Go only; the BPF objects are committed under `internal/bpf/`, so `go build` needs no clang.

```sh
go build -o /tmp/snitchd ./cmd/snitchd      # the daemon
go build -o /tmp/snitch ./cmd/snitch        # the user binary (TUI, status, default, tray)
/tmp/snitch -version                        # `dev` for a plain go build
```

Try the daemon without installing anything (monitor mode, bounded):

```sh
sudo /tmp/snitchd -mode monitor -duration 10s
```

More ways to run it by hand, including learning mode, are in [daemon.md](daemon.md).

## Layout

| Path | What |
|---|---|
| `bpf/` | the kernel programs: `snitch.bpf.c` (egress decisions), `dns.bpf.c` (the DNS tap), `contract.h`, `rules_abi.h`, `vmlinux.h` |
| `internal/bpf/` | bpf2go output, committed |
| `cmd/snitchd/` | the daemon |
| `cmd/snitch/` | the user binary |
| `internal/` | Go packages; `lsm` probes the kernel hook (stdlib + `internal/contract`), `term` isolates Bubble Tea and Lip Gloss, `sni` isolates the session D-Bus |
| `systemd/`, `desktop/`, `packaging/` | the units, the tray's autostart entry, the deb's control files, GRUB drop-in, `lsm-cmdline` helper and maintainer scripts |
| `scripts/` | checks and console helpers |
| `.dagger/` | the pipeline: one function per check, build, packaging and smoke phase |

After editing the C, the headers or the cflags in `internal/bpf/gen.go`, regenerate the
bindings in the pinned image: `scripts/bindings-regen.sh --docker --write`. See
[c-hardening.md](c-hardening.md) for the contracts, the bindings check, fuzzing and the
hostile DNS corpus.

## Checks

```sh
gofmt -l . && go vet ./...                  # the quick ones
scripts/fuzz.sh -t 60s                      # fuzz targets, no root
dagger call bindings                        # committed bindings match their source, byte for byte
```

CI (`.github/workflows/lint.yml`) runs fmt, go, shellcheck (`scripts/*.sh` and `packaging/*.sh`), actionlint, golangci, cppcheck
and the bindings check on every push. The workflows only dispatch into the Dagger module, so
CI and a local `dagger call` run the same functions; see [ci-debs.md](ci-debs.md) for the
pipeline, the deb and local reproduction.

Checks against a running daemon:

| Script | Checks |
|---|---|
| `scripts/api-check.sh` | the API document against the running service, as the desktop user |
| `scripts/tui-check.sh` | the TUI and the user verbs |
| `scripts/tray-check.sh` | the tray |
| `sudo scripts/deploy-check.sh [--trial]` | a deployed service, read-only; `--trial` adds a prompted two-minute trial |
| `sudo scripts/enforce-test.sh` | the enforce flow, bounded, reset in a trap |
| `sudo scripts/dns-progtest.sh` | the DNS tap's root tests |

Anything that enforces can cut a remote session. Run those on a machine with a console open,
and keep [`scripts/fail-open.sh`](../scripts/fail-open.sh) at hand.

## Release

Before tagging, run the two-door suite ([rugged.md](rugged.md)):
`dagger call rugged --fuzz-duration 30s` (every lint check incl. the bindings check, then a
fuzz run of every target), then `sudo scripts/root-checks.sh --at <commit>` on a host with
the `bpf` LSM, which loads the kernel programs and runs the hostile-input corpus and a
bounded monitor run. A tag `vX.Y.Z` runs the lint checks (`.github/workflows/lint.yml`, the
same jobs as on every push) and then the release lanes (`.github/workflows/release.yml`): the
static amd64 builds (position-independent, `-buildmode=pie`) with the tag linked in, plus the
deb. A failing check publishes nothing. Six assets are published in one step:
`snitchd`, `snitchd.sha256` (the form `sha256sum -c` reads), the user binary
`snitch-linux-amd64` and its `snitch-linux-amd64.sha256`,
and the deb `snitch_<version>_amd64.deb` with its `snitch_<version>_amd64.deb.sha256`.
`snitchd -version` prints the tag (`dev` for a plain `go build`), and `snitchd status` shows
it. The [hyperland-forky-worker-vm](https://github.com/norandom/hyperland-forky-worker-vm)
repo pins the version and the sha256 of the `snitchd` asset (see
[daemon.md](daemon.md#service)).

## Further reading

- [c-hardening.md](c-hardening.md): compiler diagnostics, contracts, fuzzing, the bindings check
- [ci-debs.md](ci-debs.md): the Dagger pipeline, the deb, CodeQL
- [rugged.md](rugged.md): the pre-release suite
- [parity.md](parity.md): the Go client against the retired Python client, item by item
- [`examples/api.md`](../examples/api.md): the daemon's API schema
