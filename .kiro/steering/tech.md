# Technology Stack

## Architecture

Two binaries, one Go module, one BPF program:

```
 snitch (TUI, user)  ──unix socket, JSON lines──▶  snitchd (root, Go)
                                                      │ cilium/ebpf: load, pin, heartbeat,
                                                      │ fill rule maps, read events
                                                      ▼
                                           bpf/snitch.bpf.c (BPF LSM)
                                lsm/socket_connect, lsm/socket_sendmsg
                     maps: programs (hash), rules (LPM trie), control, kill (pinned), events (ringbuf)
```

The kernel program decides alone: it needs no daemon round trip per connection. The daemon
owns configuration (rules file → maps), the heartbeat, and the event stream. The TUI is a
client of the daemon and never touches BPF. Decision order in the kernel is fixed: kill switch
→ heartbeat → local network → rules (program-specific before any-program; exact proto+port,
proto, any) → mode default (monitor allows and reports, enforce denies and reports).

The user-side binary `cmd/snitch` serves the Bubble Tea TUI (`overview` default, `egress`),
one-shot `status` and `default` verbs, `-version`, and the 7-state KDE `tray` (`internal/sni`
imports `internal/tray`; `internal/term` isolates `charm.land/bubbletea/v2` and
`charm.land/lipgloss/v2` over pure `internal/tui` + `internal/table` + `internal/clean`; shared
`internal/client` and `internal/ask` import only `internal/api` wire types). `cmd/snitchd`
imports `internal/lsm` (stdlib + `internal/contract` only) to probe the kernel hook;
`cmd/snitch` reads `api.Status.Hook` instead. Alert popups (`watch`, `ask`) and process
tracing return with `popups-trace`.

## Core Technologies

- **Language**: Go (version pinned in `go.mod`, currently 1.26) for both binaries; C for the
  BPF program (CO-RE, `vmlinux.h` from the running kernel's BTF).
- **Kernel interface**: BPF LSM hooks via `github.com/cilium/ebpf` (programs attached with
  `link.AttachLSM`, maps pinned under `/sys/fs/bpf/snitch`). Requires a kernel with
  `CONFIG_BPF_LSM` and `bpf` in the active LSM list; developed on Debian forky, kernel 7.2.
- **TUI & tray**: Bubble Tea v2 + Lip Gloss v2 isolated in `internal/term`, plus `snitch` verbs
  (`overview`, `egress`, `status`, `default`, `tray`, `-version`; see `docs/tui.md`). Interactive
  popups (`watch`, `ask`) and process trace return with `popups-trace`.
- **Packaging**: static Go binaries; GitHub releases pinned by sha256 by the consuming repo;
  `.deb` package (`packaging/`) shipping systemd units (enabled at boot on fresh install, never started by it), GRUB
  drop-in + `lsm-cmdline` helper, and `postinst`/`postrm` (running `update-grub` on configure
  and removal, restarting a running snitchd on upgrade) and `prerm` (stop + disable on remove); Nix flake (`buildGoModule`) later. systemd units in `systemd/`.

## Key Libraries

- `cilium/ebpf` (+ `bpf2go` as a Go tool dependency): the only BPF library. The generated
  bindings and the compiled `.o` are committed so `go build` works without clang.
- `golang.org/x/sys/unix`: clock, stat, socket constants. Avoid cgo.
- `github.com/godbus/dbus/v5` (v5.2.4): the tray's session bus, in `internal/sni` only
  (StatusNotifierItem, dbusmenu, notifications). BSD-2-Clause, pure Go, no cgo, so the static
  release builds are unaffected — `release.yml` builds `snitch-linux-amd64` from `cmd/snitch`
  with the same flags as `snitchd`.

## Development Standards

### Correctness over cleverness
The BPF program is small on purpose: fixed-size keys, bounded loops, one `decide()` shared by
both hooks. New kernel-side logic must keep the verifier happy on the committed kernel and
must not add a path that can deny local traffic or deny when the daemon is gone.

### Type and ABI discipline
C structs shared with Go are exported through BTF (`-type` flags in `internal/bpf/gen.go` plus
a `const struct x *unused __attribute__((unused));`). A struct must not share its name with a
map. Every struct shared with Go carries size and offset contracts (`bpf/contract.h`); the
`rules` trie key and value have one definition, `bpf/rules_abi.h`, included by both programs.
Changing a struct means regenerating with `scripts/bindings-regen.sh --docker --write` and
committing the output with the C.

### The compiler as observer
The pipeline may run a C compiler only as an observer: the bindings check (`dagger call
bindings`, in lint.yml's `linters` job, skipped on tags) regenerates on a copy inside the
pinned image and compares byte for byte, writing nothing back. Artifacts never come from a
pipeline compiler; releases ship the committed bindings. The toolchain pin lives at the top of
`scripts/bindings-regen.sh` (`IMAGE`, `PACKAGES`, `CLANG_EXPECTED`, `SNAPSHOT`), and `IMAGE`
must equal `imageBindings` in `.dagger/pins.go`. Details: `docs/c-hardening.md`.

### Kernel-side contracts
Build-time contracts (`CONTRACT_SIZE` / `CONTRACT_OFFSET` / `CONTRACT_CONST`) cost no
instructions. A runtime `CONTRACT(cond, counter)` counts a violation and the call site writes
the fail-open branch (allow in the LSM hooks, pass in the DNS tap), never deny. The counters
are in the API status (`counters`); a non-zero contract counter is a defect.

### Code quality
`gofmt -l .` clean, `go vet ./...` clean; shell (`scripts/*.sh` and `packaging/*.sh`) with shellcheck; workflows with actionlint. CI is
`.github/workflows/lint.yml`. Comments explain why, in plain sentences; file headers state
what the file does and its fail-safe implications.

### Code shape (binding, enforced in CI where a tool exists)
- Caps: functions ≤ 40 lines and cyclomatic complexity ≤ 10 (`tools/caps`, `gocyclo`; `scripts/caps.sh` runs both), files
  ≤ 300 lines (generated bindings excluded), `main()` ≤ 60 lines.
- Delegates over interfaces: inject varying behaviour as function values (`FS{Glob, Identity}`,
  `Clock func() time.Time`, `Sink func(Observation)`, `jobs.Job`). An interface needs two real
  implementations. Values are immutable after construction; change = new value.
- Concurrency as jobs: every long-running loop is a `jobs.Job` (`func(ctx) error`) run under
  one `jobs.Run`; shared state is an `atomic.Pointer` to an immutable snapshot.
- Code contracts: `internal/contract` `Require` / `Ensure` / `Invariant` panic with
  `*Violation` on programming errors (always compiled in). Operator errors return `error`.
  A violation exits the daemon, which detaches the kernel programs: contracts fail open.
- Tasks are written as self-contained briefs so an external implementer agent can take one at
  a time without conversation context.

### Testing
- Unit tests for pure Go (rule parsing, path → inode/dev resolution, dev number conversion
  `(major << 20) | minor`, event decoding). `internal/bpf/abi_test.go` ties the Go types to
  the BTF sizes in the bindings.
- Fuzz targets for every decoder of untrusted input (ring-buffer records, API request lines,
  rules file and overlay); their seeds and kept failing inputs run in `go test ./...`.
- The DNS tap's hostile-input corpus runs as root (`sudo scripts/dns-progtest.sh`, BTF
  enough, no BPF LSM). The root gates are one batch: `sudo scripts/root-checks.sh --at <rev>`
  (DNS root tests; on the dev VM also a bounded monitor run with `scripts/api-check.sh`).
- Kernel behaviour is tested on the VM with a bounded run (`-duration`) and a shell trap that
  resets mode and kill switch. Enforce tests follow the script in `CLAUDE.md` (allow curl →
  one prefix, expect EPERM elsewhere, kill switch on/off, SIGSTOP the daemon → fail open after
  15 s). Never leave an enforce run unattended or without the revert.

## Development Environment

### Required Tools
Go (see `go.mod`), `bpftool` (kill switch, BTF dump), root on the VM for attaching. For
regenerating the BPF objects: docker (the pinned image brings clang 21.1.8, llvm, libbpf-dev
1.7). A host `go generate ./internal/bpf/` needs the same versions; libbpf 1.6.3 (Ubuntu)
fails `snitch.bpf.c`. The pipeline checks need `dagger`.

### Common Commands
```bash
# code-shape caps (CI runs the same script)
scripts/caps.sh

# build + bounded monitor run
go build -o /tmp/snitchd ./cmd/snitchd && sudo /tmp/snitchd -mode monitor -duration 10s
# the user binary (builds static `snitch`; or output to `/tmp/snitch` to keep repo root clean)
go build -o /tmp/snitch ./cmd/snitch && /tmp/snitch -version
# regenerate bindings after editing bpf/*.c, bpf/*.h or gen.go (pinned image), then check
scripts/bindings-regen.sh --docker --write
scripts/bindings-regen.sh --docker --check
# fuzz every target for a chosen time (no root)
scripts/fuzz.sh -t 60s
# before a release: every pipeline check + fuzz, then the root batch on the dev VM
dagger call rugged --fuzz-duration 30s
sudo scripts/root-checks.sh --at <commit to tag>
# new kernel: refresh CO-RE types
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
# lint
gofmt -l . && go vet ./...
# kill switch (root, no network needed)
bpftool map update pinned /sys/fs/bpf/snitch/kill key 0 0 0 0 value 1 0 0 0   # on
bpftool map update pinned /sys/fs/bpf/snitch/kill key 0 0 0 0 value 0 0 0 0   # off
```
Build caches are cleaned after work (`go clean -cache -modcache` when done with a session);
the VM's disk is for the user's development.

## Key Technical Decisions

- **Go, not V or Python**: V has no eBPF ecosystem; Python cannot ship a root daemon with an
  in-kernel decision path. Go + cilium/ebpf is the mature option.
- **BPF LSM, not netfilter/nfqueue or a proxy**: the verdict needs the calling program, which
  only the LSM hook at `connect()` has for free (`current->mm->exe_file`).
- **Programs keyed by inode + device**, not path: paths are what the rules file says, the
  daemon resolves them (globs for versioned installs) at load and on change. Unknown program
  = id 0, matched by any-program rules only.
- **Maps pinned, links not**: `control` and `kill` survive a daemon restart (the kill switch
  must), but a dead daemon detaches the programs, so nothing enforces without a heartbeat.
- **Deny only as a trial**: enforce mode is entered with a deadline and a boot-time revert
  (shape: `/var/lib/snitch` deadline + `systemd/snitchd-trial-boot.service` running
  `snitchd end -at-boot`). The lockout of 2026-10-09 is why.
- **Domain rules via a DNS tap, not synchronous resolution**: a BPF tap on DNS answers feeds
  an IP → name cache; rules by name are compiled to prefixes live.
- **Enrichment stays outside the hot path**: Velociraptor supplies the process graph and
  OpenObserve the fleet view (Sankey); the kernel program never waits on either.

---
_Document standards and patterns, not every dependency_
_updated 2026-11-25 (c-hardening): the compiler-as-observer rule replaces "CI never runs clang"_
