# Project Structure

## Organization Philosophy

A standard Go module layout around two BPF programs. The kernel side lives in `bpf/`, its
generated Go bindings in `internal/bpf/`, each binary under `cmd/`. Shared daemon logic goes
into `internal/<domain>/` packages as it appears (rules, api, dns, enrich); nothing under
`internal/` is importable from outside the module. The legacy Python client and its systemd
units stay at the top level until the Go TUI replaces them.

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
**Location**: `cmd/snitchd/` (root daemon), `cmd/snitch/` (user binary: `snitch tray` today,
`snitch -version`; the TUI verb is planned)
**Purpose**: `main` packages: flag parsing, wiring, signal handling. Logic that needs a unit
test moves into an `internal/` package. Build `cmd/snitch` to `/tmp`, never
`go build -o snitch` in the repo root: there `snitch` is the legacy Python client, which
owns the name until parity.

### Domain packages (as they appear)
**Location**: `internal/rules/`, `internal/api/`, `internal/dns/`, `internal/client/`,
`internal/ask/`, `internal/tray/`, `internal/sni/`, `internal/enrich/`, ...
**Purpose**: one concern per package: rules file → map entries; the unix socket API; the DNS
tap and IP → name cache; Velociraptor / OpenObserve clients. The tray's four point one way:
`internal/sni` (the session bus: item, menu, notifications, icons, over
`github.com/godbus/dbus/v5` v5.2.4 — pure Go, BSD-2-Clause, no cgo) imports `internal/tray`
(the pure tray model), which imports `internal/ask` (which events ask, the rule an answer
stands for) and `internal/client` (the API as typed messages, with reconnect), and those two
import only `internal/api`'s types — `sni` has no client, `tray` has no D-Bus, and nothing
points the other way.
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
