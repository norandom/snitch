# Project Structure

## Organization Philosophy

A standard Go module layout around one BPF program. The kernel side lives in `bpf/`, its
generated Go bindings in `internal/bpf/`, each binary under `cmd/`. Shared daemon logic goes
into `internal/<domain>/` packages as it appears (rules, api, dns, enrich); nothing under
`internal/` is importable from outside the module. The legacy Python client and its systemd
units stay at the top level until the Go TUI replaces them.

## Directory Patterns

### BPF program
**Location**: `bpf/`
**Purpose**: the C program (`snitch.bpf.c`) and `vmlinux.h` (CO-RE types from the running
kernel's BTF). One program, one `decide()`, both LSM hooks call it.
**Example**: adding a new map or struct → edit here, then `go generate ./internal/bpf/`.

### Generated bindings
**Location**: `internal/bpf/`
**Purpose**: bpf2go output (`snitch_x86_bpfel.go`, `.o`) and `gen.go` with the generate
directive. Committed so CI and users build without clang. Never edited by hand.

### Binaries
**Location**: `cmd/snitchd/` (root daemon), `cmd/snitch/` (TUI, planned)
**Purpose**: `main` packages: flag parsing, wiring, signal handling. Logic that needs a unit
test moves into an `internal/` package.

### Domain packages (as they appear)
**Location**: `internal/rules/`, `internal/api/`, `internal/dns/`, `internal/enrich/`, ...
**Purpose**: one concern per package: rules file → map entries; the unix socket API; the DNS
tap and IP → name cache; Velociraptor / OpenObserve clients.
**Example**: `internal/rules` owns parsing, path/glob → inode+dev resolution and the map
encoding, and is tested without root.

### Legacy Python client
**Location**: `snitch` (uv script, root of the repo), `snitch-trial`, `systemd/`, `docs/*.png`
**Purpose**: the behavioural reference for the TUI (views, keys, popup flow, trace) and the
trial/revert shape. Lint only (ruff, shellcheck); no new features.

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
- **Everything user-facing has a reference**: TUI views and keys follow the Python client;
  the daemon's JSON lines follow the shapes that client already consumes.
- **Committed generated code**: bindings and the BPF object are build inputs, regenerated
  deliberately and reviewed in the diff.

---
_Document patterns, not file trees. New files following patterns shouldn't require updates_
