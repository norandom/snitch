# Project Structure

## Organization Philosophy

A standard Go module layout around two BPF programs. The kernel side lives in `bpf/`, its
generated Go bindings in `internal/bpf/`, each binary under `cmd/`. Shared daemon logic goes
into `internal/<domain>/` packages as it appears (rules, api, dns, enrich); nothing under
`internal/` is importable from outside the module. Both `snitchd` and the user-side
`snitch` binary (TUI, status, trial verbs, and KDE tray) are pure Go.

## Directory Patterns

### BPF program
**Location**: `bpf/`
**Purpose**: two programs — `snitch.bpf.c` (the egress decision: one `decide()`, both LSM
hooks call it) and `dns.bpf.c` (the DNS tap) — two authored headers — `contract.h`
(build-time and runtime contracts) and `rules_abi.h` (the one definition of the `rules` trie
key and value, shared by both programs) — and `vmlinux.h` (CO-RE types from the running
kernel's BTF, included as a system header). `cppcheck-suppressions.txt` holds the analyzer's
reasoned suppressions.
**Example**: adding a new map or struct → edit here with its size/offset contracts, then
`scripts/bindings-regen.sh --docker --write`.

### Generated bindings
**Location**: `internal/bpf/`
**Purpose**: bpf2go output (`snitch_x86_bpfel.go`, `dns_x86_bpfel.go`, their `.o`) and
`gen.go` with the generate directives. Committed so CI and users build without clang; the
bindings check regenerates in the pinned image and compares. Never edited by hand.

### Binaries
**Location**: `cmd/snitchd/` (root daemon), `cmd/snitch/` (user binary: `snitch` overview TUI,
`egress`, `status`, `default`, `tray`, `-version`)
**Purpose**: `main` packages: flag parsing, wiring, signal handling. Logic that needs a unit
test moves into an `internal/` package. `go build -o snitch ./cmd/snitch` (or `/tmp/snitch`
when keeping the repo root clean) builds the unified operator binary.

### Domain packages (as they appear)
**Location**: `internal/lsm/`, `internal/rules/`, `internal/api/`, `internal/dns/`, `internal/client/`,
`internal/ask/`, `internal/clean/`, `internal/conf/`, `internal/logfile/`, `internal/table/`,
`internal/tui/`, `internal/term/`, `internal/verbs/`, `internal/tray/`, `internal/sni/`, ...
**Purpose**: one concern per package: kernel hook probe (`internal/lsm`, stdlib +
`internal/contract` only); rules file → map entries; the unix socket API; the DNS
tap and IP → name cache; TUI core (`table` + pure `tui` model + `term` Bubble Tea adapter)
and one-shot verbs; the 7-state KDE tray (`sni` imports `tray`, which imports `ask` and `client`).
**Example**: `internal/rules` owns parsing, path/glob → inode+dev resolution and the map
encoding, and is tested without root.

### Service units and assets
**Location**: `systemd/` (`snitchd.service`, `snitchd-trial-boot.service`), `desktop/`, `packaging/`, `docs/*.png`
**Purpose**: daemon service and boot-revert units, desktop tray autostart, Debian packaging inputs (control metadata, GRUB drop-in, `lsm-cmdline` helper, `postinst`/`postrm` maintainer scripts), and documentation screenshots. Lint `scripts/*.sh` and `packaging/*.sh` with `shellcheck`.

### Documentation
**Location**: `README.md`, `docs/*.md`, `examples/`
**Purpose**: the README addresses the Linux user (install, use, trial, rules, fail-safes) and
indexes the docs by concern; reference material lives in `docs/`: `daemon.md` (running
`snitchd`, service, trial, names, API), `tray.md`, `tui.md`, `development.md` (build, checks,
release), plus the feature records `c-hardening.md`, `ci-debs.md`, `rugged.md`, `parity.md`.
Developer and operator detail goes into `docs/` and is linked from the README, not written into it.

### Specs and steering
**Location**: `.kiro/steering/` (this memory), `.kiro/specs/<feature>/`
**Purpose**: one spec per shippable step (requirements → design → tasks). Specs cite the
fail-safes they touch.

## Naming Conventions

- **Go files**: lower-case, one word where possible (`main.go`, `reader.go`, `rules.go`);
  tests `_test.go` beside the code.
- **Go identifiers**: standard Go style; exported only when another package needs it.
- **BPF**: C identifiers snake_case; map names are nouns (`programs`, `rules`, `control`,
  `kill`, `events`); verdict enum `V_*`; struct names never equal a map name.
- **Pinned paths**: `/sys/fs/bpf/snitch/<map>`.
- **Rule files**: TOML or similar, one base file plus optional per-host file (fleet phase).
- **Commits**: `<area>: <what, lower case>` (`snitchd: ...`, `bpf: ...`, `docs: ...`), authored as
  `git -c user.name=marius -c user.email=wishinet@gmail.com commit`.

## Import Organization

```go
import (
	"stdlib"                                // standard library first

	"github.com/cilium/ebpf"                // third party
	"golang.org/x/sys/unix"

	snitchbpf "github.com/norandom/snitch/internal/bpf"   // module-local, aliased when the
)                                                         // package name would clash
```

Module path `github.com/norandom/snitch`; no replace directives, no vendoring.

## Code Organization Principles

- **Kernel decides, daemon configures, TUI displays.** No layer reaches past its neighbour:
  the TUI never opens BPF maps; the BPF program never depends on the daemon being alive to
  allow traffic.
- **Fail-safes live in the C program**, not in Go and not in rule files (see `fail-safes.md`).
- **Everything follows documented specs and wire contracts**: TUI views and keys follow `.kiro/specs/tui/` (`docs/tui.md`);
  the daemon's JSON lines follow `examples/api.md`.
- **Committed generated code**: bindings and the BPF object are build inputs, regenerated
  deliberately and reviewed in the diff.

---
_Document patterns, not file trees. New files following patterns shouldn't require updates_
