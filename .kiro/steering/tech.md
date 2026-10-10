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

## Core Technologies

- **Language**: Go (version pinned in `go.mod`, currently 1.26) for both binaries; C for the
  BPF program (CO-RE, `vmlinux.h` from the running kernel's BTF).
- **Kernel interface**: BPF LSM hooks via `github.com/cilium/ebpf` (programs attached with
  `link.AttachLSM`, maps pinned under `/sys/fs/bpf/snitch`). Requires a kernel with
  `CONFIG_BPF_LSM` and `bpf` in the active LSM list; developed on Debian forky, kernel 7.2.
- **TUI**: bubbletea (planned). Reference implementation: the Python/Textual client `snitch`.
- **Packaging**: static Go binaries; GitHub releases pinned by sha256 by the consuming repo;
  Nix flake (`buildGoModule`) later. systemd units in `systemd/`.

## Key Libraries

- `cilium/ebpf` (+ `bpf2go` as a Go tool dependency): the only BPF library. The generated
  bindings and the compiled `.o` are committed so `go build` works without clang.
- `golang.org/x/sys/unix`: clock, stat, socket constants. Avoid cgo.

## Development Standards

### Correctness over cleverness
The BPF program is small on purpose: fixed-size keys, bounded loops, one `decide()` shared by
both hooks. New kernel-side logic must keep the verifier happy on the committed kernel and
must not add a path that can deny local traffic or deny when the daemon is gone.

### Type and ABI discipline
C structs shared with Go are exported through BTF (`-type` flags in `internal/bpf/gen.go` plus
a `const struct x *unused __attribute__((unused));`). A struct must not share its name with a
map. Changing a struct means regenerating with `go generate ./internal/bpf/` and committing
the output; CI never runs clang.

### Code quality
`gofmt -l .` clean, `go vet ./...` clean; Python client checked with ruff (settings in
`pyproject.toml`); shell with shellcheck; workflows with actionlint. CI is
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
  `(major << 20) | minor`, event decoding).
- Kernel behaviour is tested on the VM with a bounded run (`-duration`) and a shell trap that
  resets mode and kill switch. Enforce tests follow the script in `CLAUDE.md` (allow curl →
  one prefix, expect EPERM elsewhere, kill switch on/off, SIGSTOP the daemon → fail open after
  15 s). Never leave an enforce run unattended or without the revert.

## Development Environment

### Required Tools
Go (see `go.mod`), `bpftool` (kill switch, BTF dump), root on the VM for attaching. For
regenerating the BPF object only: clang, llvm, libbpf-dev.

### Common Commands
```bash
# code-shape caps (CI runs the same script)
scripts/caps.sh

# build + bounded monitor run
go build -o /tmp/snitchd ./cmd/snitchd && sudo /tmp/snitchd -mode monitor -duration 10s
# regenerate bindings after editing bpf/snitch.bpf.c
go generate ./internal/bpf/
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
  (shape: `snitch-trial` + its systemd units). The lockout of 2026-10-09 is why.
- **Domain rules via a DNS tap, not synchronous resolution**: a BPF tap on DNS answers feeds
  an IP → name cache; rules by name are compiled to prefixes live.
- **Enrichment stays outside the hot path**: Velociraptor supplies the process graph and
  OpenObserve the fleet view (Sankey); the kernel program never waits on either.

---
_Document standards and patterns, not every dependency_
