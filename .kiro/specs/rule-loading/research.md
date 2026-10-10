# Gap Analysis: rule-loading

Date: 2026-10-10. Requirements approved (9 requirements). Codebase: two commits of Go + BPF,
the Python client as reference.

## 1. Current State

### Assets that exist

| Asset | Location | What it gives this feature |
|---|---|---|
| BPF program with `programs` hash, `rules` LPM trie, fixed lookup order | `bpf/snitch.bpf.c` (245 lines) | The kernel side of Req 3 is done: `lookup()` does program-specific then any-program, exact proto+port → proto → any; the trie gives longest prefix within a tier. Keys: `exe_key{ino u64, dev u32}`, `rule_key{prefixlen, program u32, family u8, proto u8, port u16, addr[16]}`, value `u8` (1 allow, 2 deny). |
| Event struct with `exe_ino`, `exe_dev`, `program`, `verdict`, `hook` | same | Req 5.1/5.2 need only userspace work. Req 5.3 (which rule applied) has no field yet. |
| Kernel device identity | `BPF_CORE_READ(exe, f_inode, i_sb, s_dev)` | The daemon must produce the *superblock's* `s_dev`, kernel-encoded `(major << 20) \| minor`. |
| Generated bindings (`SnitchExeKey`, `SnitchRuleKey`, `SnitchControlState`, `SnitchEvent`) | `internal/bpf/` | Typed `Map.Put` / `Delete` work directly; `-type` list in `gen.go` must grow if the C structs change. |
| Daemon skeleton: load with `PinPath`, heartbeat ticker, `-mode`, `-duration`, ringbuf reader, printing | `cmd/snitchd/main.go` (152 lines) | Flags, lifecycle, signal handling to extend. `LoadSnitchObjects` with `PinPath` reuses the pinned `kill` map, so Req 6.4 (never touch the kill switch) holds already as long as nothing writes it. |
| Trial shape | `snitch-trial`, `systemd/snitch-trial*` | Out of scope here (persistent trial is its own spec), but the test procedure follows its spirit (revert on every exit). |
| Rule vocabulary and path globs | Python `snitch`: `DEV_TOOLS`, `BASELINE`, `narrow()` | Shows the rule shapes operators already write: program paths with narrow globs (`~/.local/share/claude/versions/*`, `/usr/lib/go-*/bin/go`), destinations as domains or `ip:<cidr,...>`, port ranges (`67-68`), protocol, `localnet`, `any`. Domain rules are out of scope, the rest should carry over. |
| CI | `.github/workflows/lint.yml` | `go build`/`vet`/`gofmt`, shellcheck on `snitch-trial`: a test script needs adding to the shellcheck line; Go tests need a `go test ./...` step. |

### Conventions observed
- One `main` package per binary, logic that needs tests goes to `internal/<domain>` (steering
  `structure.md`); nothing under `internal/` yet except the bindings.
- Comments say why; file headers state fail-safe implications.
- Deps minimal: `cilium/ebpf`, `x/sys`. No TOML, no fsnotify, no test helpers.
- Generated code committed; CI has no clang. clang 21 + bpftool exist on the dev VM, so a C
  change is possible here and must be committed as regenerated output.

### Facts verified on the dev VM (2026-10-10)
- Root filesystem ext4, mount `8:1`; `stat` gives `st_dev` 2049 (glibc encoding `0x801`);
  kernel `s_dev` for the same file is `(8 << 20) | 1 = 8388609`. For ext4 the conversion from
  `stat` is enough. For btrfs `stat` returns the subvolume's anonymous dev, for overlayfs the
  upper/lower's; both differ from `i_sb->s_dev`. `/proc/self/mountinfo` column 3 is printed by
  the kernel as `MAJOR(sb->s_dev):MINOR(sb->s_dev)`, so mountinfo is the portable source
  (Req 2.2).
- `bpf_d_path` is available to `lsm` programs on this kernel (`bpftool feature probe`). It
  can give the executable path from inside the hook, which solves the short-lived-process
  problem (Req 9.9, Req 5.2) without a `/proc` race.
- Go 1.26.8; `go` module cache 35 MB, build cache 118 MB (clean up after the work).

## 2. Requirement → Asset Map

| Req | Need | Status |
|---|---|---|
| 1 Rules file | parser, validation with file:line, default path, comments | **Missing**. Format open (see options). |
| 2 Programs → inode+dev | path/glob resolution, symlink follow, superblock dev from mountinfo, conflict detection, keep rules for unresolved programs | **Missing**. Constraint: `exe_key.dev` is `s_dev`, not `st_dev`. |
| 3 Rules in kernel | encode `rule_key` per rule, Put into trie; precedence | Kernel side **exists**; encoding **Missing**. v4-mapped handled in C. Deny in monitor mode: C already returns -EPERM for `V_DENY_RULE` regardless of mode. |
| 3.6 Load summary | counts | Missing, trivial. |
| 4 Stay current | file change ≤5 s, exe change ≤10 s, SIGHUP, invalid reload keeps old, no ruleless window | **Missing**. Diff-apply vs swap (see options). Watch mechanism open. |
| 5 Events name program + rule | name lookup by program id: userspace; **rule id**: no field in event or map value | 5.1/5.2 Missing (easy). 5.3 **Missing + C change or userspace re-evaluation** (see options). |
| 6 Bounded enforce | refuse enforce without `-duration`; exit detaches | 6.1 Missing (one check). 6.2/6.3 **exist** (links not pinned, `defer l.Close()`; a crash closes fds too). 6.4 exists (nothing writes `kill`). |
| 7 Enforce verification | shell script with trap, curl probes, kill switch toggles, SIGSTOP/SIGCONT, LAN/RDP checks, printed reset facts | **Missing**. Needs the operator present; must be run only on explicit go. |
| 8 Tests without root | parser, dev identity, precedence/encoding tests | **Missing**; `go test` not in CI. Dev identity test needs an expected value: compare against a real event on the VM, or against mountinfo arithmetic. |
| 9 Learning mode | record (exe, addr, proto, port) with counts/times, write rules file periodically and at exit, read back, refuse with enforce, exe path for exited processes | **Missing**. Exe path for short-lived processes: `bpf_d_path` in C (Research Needed: verifier limits, path buffer size, cost per event) or a userspace inode→path cache. |

Complexity signals: algorithmic (encoding, precedence) + file watching workflow + one kernel
change if 5.3/9.9 go the C route. No external integrations.

## 3. Implementation Approach Options

### Option A: Extend `cmd/snitchd/main.go` only
Put parsing, resolution and map filling into more files in `cmd/snitchd/`.
- ✅ Fastest start, no package design.
- ❌ `main` packages are untestable from CI without root unless carefully split; contradicts
  steering ("logic that needs a unit test moves into an `internal/` package"); `main.go`
  bloats past readability.

### Option B: New `internal/rules` package + thin daemon wiring (recommended baseline)
`internal/rules`: file model, parser/writer, resolver (paths → `exe_key`, via mountinfo),
encoder (rules → `rule_key`/value), differ (old vs new entries → puts/deletes). The daemon
owns map handles, the watch loop, the heartbeat, learning aggregation and printing.
- ✅ Parser/resolver/encoder tested without root (Req 8); learning writer reuses the same
  file model (Req 9.8 "loadable without edits" for free).
- ✅ Fits steering structure; TUI and later specs reuse the model.
- ❌ Interface between package and daemon has to be designed (small: `Load(path) (*Set, error)`,
  `Set.Entries() (programs map[ExeKey]uint32, rules map[RuleKey]uint8)`, `Diff(old, new)`).

### Option C: B + a small C change (hybrid)
Same as B plus two kernel additions: (1) map value becomes `struct { u8 verdict; u32 rule; }`
(or the rule id packed in a u32) and the event carries `rule`; (2) the event carries the exe
path via `bpf_d_path` (e.g. 256 bytes, or a second ringbuf record only in learning mode).
- ✅ 5.3 exact ("which rule applied" is what the kernel used, not a userspace guess); 9.9 and
  5.2 robust for processes that exit in microseconds (curl does).
- ❌ Regenerate and commit bindings; verifier work; a larger event (256 B path) on every
  connection, or extra complexity for a conditional record. Must not touch the decision order.

### Sub-decisions with options

**Rules file format**
- A1 TOML (`[[program]]` / `[[rule]]` tables): matches the Python client's config and
  steering; needs a dependency (`github.com/pelletier/go-toml/v2` or `BurntSushi/toml`);
  writing the learned file by hand is simple for a fixed shape, and `line` numbers for errors
  come from the decoder. Go stdlib has no TOML.
- A2 Line-oriented own format (`program curl /usr/bin/curl`, `allow curl 10.0.0.0/8 tcp 443`):
  zero deps, trivial file:line errors, easy to write; but another format for operators to
  learn and the TUI to emit.
- A3 JSON (stdlib): no comments (Req 1.5 fails) unless pre-stripped. Not recommended.

**Atomic rule replacement (Req 4.1 "no ruleless window")**
- R1 Diff-apply: compute new entry set, `Put` additions and changed values, then `Delete`
  removals. Tiny window where both an old and a new rule exist; never a window with none.
  Simple; works for both maps.
- R2 Map-in-map (`ARRAY_OF_MAPS` holding the trie): build a fresh trie, swap the pointer.
  Truly atomic; needs a C change, more map handling, and the `programs` hash still needs the
  same treatment.

**Watching for changes (Req 4.1 ≤5 s, 4.3 ≤10 s)**
- W1 Poll: stat the rules file every 2 s on the existing heartbeat ticker; re-resolve
  paths/globs every 10 s (or every 2 s: a few dozen `stat`/`glob` calls are cheap). No deps,
  survives editors that replace the file (rename), and symlinked configs.
- W2 inotify via `x/sys/unix` (already a dependency) on the file's directory plus a periodic
  re-resolve for executables (inotify on every parent dir of globs is unwieldy). Faster, more
  code.
- W3 fsnotify dependency. Not worth a dep for one file.

**Device identity (Req 2.2)**
- D1 `unix.Stat` → `unix.Major/Minor` → `(maj << 20) | min`. Correct on ext4/xfs, wrong on
  btrfs subvolumes and overlayfs.
- D2 `statx` with `STATX_MNT_ID` → mount id → `/proc/self/mountinfo` row → major:minor
  column → `(maj << 20) | min`. Correct everywhere; small parser; verifiable against the
  kernel's `exe_dev` in a real event (Req 8.2).
- D1 as fallback when D2 fails (no mountinfo in some container), with a warning.

**Program id for unresolved programs (Req 2.3)**
Program ids are assigned from the file (1..n in declaration order) regardless of resolution;
rules are loaded for all programs; `programs` entries only for resolved files. Works with no
extra design.

**Learning aggregation key (Req 9.3)**
Keyed on `(exe_key, addr, proto, port)` in the daemon; exe path from `/proc/pid/exe` at first
sight, or from `bpf_d_path` (Option C). Write a TOML/own-format file with `# count=… first=…
last=…` comments; a `[learned]` section or an `x-learned` key per rule would make reading back
(Req 9.6) exact rather than comment-parsing. Research Needed: whether to carry counts as data
fields (loadable by the normal parser, ignored by it) rather than comments.

## 4. Effort and Risk

| Area | Effort | Risk | Why |
|---|---|---|---|
| `internal/rules` parser + encoder + tests | S | Low | Pure Go, fixed key layout already in BTF bindings. |
| Resolver with mountinfo (D2) | S | Medium | mountinfo parsing and `STATX_MNT_ID` are well documented, but wrong dev = rules silently never match. Verified against a real event on the VM. |
| Diff-apply reload + watch loop (R1 + W1) | S | Low | Polling on an existing ticker; map Put/Delete. |
| Rule id + `bpf_d_path` in C (Option C) | M | Medium | Verifier iteration, regen, larger events; must keep decision order and fail-safes untouched. |
| Learning mode | M | Low | Aggregation and a writer; the hard part (exe path) depends on the C decision. |
| Enforce test script | S | **High (operational)** | Not technically hard; the risk is to the operator's session. Mitigated by trap, `-duration`, local-net allow in C, explicit go, console open. |
| CI additions (`go test`, shellcheck new script) | S | Low | |

Overall: **M (≈ 4–6 days)**, Medium risk, dominated by the device-identity correctness and the
kernel change if taken.

## 5. Recommendations for the Design Phase

- **Preferred approach: Option C**, staged so B is useful alone: B first (loader, reload,
  events with program name, bounded enforce, tests), then the C additions (rule id in value +
  event; `bpf_d_path` for the exe path) as a separate task group with its own regen and
  monitor-mode verification before any enforce run.
- **Format: A1 TOML** with `[[program]]` and `[[rule]]`, one dependency, shapes carried from
  the Python client (`paths = [...]` globs, `to = "10.0.0.0/8"`, `proto`, `port` incl. ranges
  expanded to entries, `verdict`). Learned files are the same format plus `count`/`first`/
  `last` fields the loader accepts and ignores.
- **Replacement: R1 diff-apply. Watching: W1 polling** on the heartbeat ticker (2 s file
  stat, 10 s re-resolve). **Device: D2 with D1 fallback.**
- **Enforce test**: shell script in the repo (e.g. `scripts/enforce-test.sh`), shellcheck'd,
  takes the rules file path and a duration, traps EXIT to clear the kill switch and kill the
  daemon, prints the three reset facts (Req 7.7). Run only with the operator's go and the
  hypervisor console open.
- **Research to carry forward**: (1) `bpf_d_path` in an `lsm/socket_connect` program on
  kernel 7.2: buffer size vs ringbuf record size, verifier acceptance with the existing
  `BPF_CORE_READ` chain; (2) learned-file counts as data fields vs comments; (3) whether
  `programs` should also key on the exe *path* reported by `bpf_d_path` for a future
  path-based fallback (out of scope, note only); (4) port ranges: expand to one trie entry per
  port (bounded, ok for `67-68`) or reject ranges in this spec.

---

# Design Discovery Log (2026-10-10, light discovery: extension of `snitchd`)

## Summary
- **Feature**: `rule-loading`
- **Discovery Scope**: Extension (existing daemon + BPF program); light discovery.
- **Key Findings**:
  - The kernel's device identity is the superblock's `s_dev`; `/proc/self/mountinfo` prints
    exactly that per mount, and `statx` gives a file's mount id (`x/sys/unix` v0.49 has
    `STATX_MNT_ID` and `Statx_t.Mnt_id`). This makes resolution correct on btrfs/overlayfs.
  - `bpf_d_path` is allowed in `lsm/*` programs on this kernel (bpftool probe), and
    `struct file.f_path` is in `vmlinux.h`: the hook can emit the executable path itself,
    which removes the `/proc/<pid>/exe` race for short-lived programs.
  - The operator's own session tooling (Claude Code, binary `~/.local/share/claude/versions/*`)
    opens new connections constantly; an enforce run without a rule for it cuts the session
    the test is driven from. The requirements' test case (curl → private prefix) exercised the
    built-in local-net allow, not a rule; 7.2/7.3/7.6 were amended during design.

## Research Log

### Device identity for `programs` keys
- **Context**: `exe_key.dev` is `BPF_CORE_READ(exe, f_inode, i_sb, s_dev)`, kernel `dev_t`.
- **Sources**: VM check (`stat` 2049 vs mountinfo `8:1` for ext4 root); kernel `show_mountinfo`
  prints `MAJOR(sb->s_dev):MINOR(sb->s_dev)`; btrfs `getattr` reports the subvolume anon dev;
  `statx(2)` `STATX_MNT_ID`.
- **Findings**: `(unix.Major(st_dev) << 20) | unix.Minor(st_dev)` is right for ext4/xfs and
  wrong for btrfs subvolumes and overlayfs. mountinfo + mount id is right everywhere.
- **Implications**: resolver = `statx` (ino, mnt_id) + mountinfo lookup; stat-based fallback
  with a warning when mountinfo is unreadable. Unit test with a fake mountinfo; VM test
  compares with `exe_dev` from a real event (Req 8.2).

### Rules file format
- **Context**: Req 1 (comments, file:line errors), Req 9.8 (learned file loads unchanged).
- **Sources**: `go list -m -versions`: `github.com/pelletier/go-toml/v2` v2.4.3 (MIT),
  `github.com/BurntSushi/toml` v1.6.0 (MIT). Python client config is TOML (`tomllib`).
- **Findings**: go-toml/v2 decodes into structs, `DisallowUnknownFields()`, `*toml.DecodeError`
  carries line/column and a rendered excerpt; no comment-preserving writer (none needed: the
  learned file has a fixed shape and is written by hand).
- **Implications**: adopt go-toml/v2; one new dependency. Learned metadata (`count`, `first`,
  `last`) are ordinary fields the loader accepts, so round-trip is exact (no comment parsing).

### Rule id and executable path in the kernel event
- **Context**: Req 5.3 (which rule applied) and 9.9 / 5.2 (exe of an exited process).
- **Sources**: `bpf_d_path` helper (id 147) in `bpf_helper_defs.h`; `bpftool feature probe`
  lists it for `lsm`; `vmlinux.h` has `const struct path f_path` in `struct file`.
- **Findings**: LPM trie values can be any size: `struct rule_val { u8 verdict; u8 pad[3];
  u32 id; }`. The event grows by `u32 rule` and `char path[256]`; the 1 MiB ring buffer still
  holds > 3000 events. `bpf_d_path` returns < 0 when the buffer is too small or the path is
  not resolvable; the daemon falls back to `/proc/<pid>/exe` then.
- **Implications**: a C change (regen, commit bindings), the decision order untouched. The
  value struct needs `-type rule_val` in `gen.go` and the unused-pointer trick.

### Watching the rules file and the executables
- **Findings**: editors replace files by rename; a stat poll on the path catches both edits
  and replacement. Glob re-evaluation is a handful of syscalls. No dependency needed.
- **Implications**: poll on the existing 2 s heartbeat tick (file), re-resolve every 10 s
  (executables), SIGHUP for both, meeting Req 4.1 (≤ 5 s) and 4.3 (≤ 10 s).

### Enforce test hazards on the dev VM
- **Findings**: default route via the gateway on the local network (allowed in C); DNS may be
  a local resolver (allowed) but is not guaranteed; the session's own client is a program like
  any other.
- **Implications**: the test uses IP literals only (no DNS dependence); the generated test
  rules allow the session tooling anywhere; the run is bounded by `-duration` and a `trap`;
  the script asks for confirmation unless `-y`; it clears the kill switch and writes mode 0
  into `control` on exit, and prints `bpftool prog show` evidence that nothing is attached.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Notes |
|---|---|---|---|---|
| A: all in `cmd/snitchd` | parser, resolver, map filling as files in `main` | quick | untestable from CI, bloats main | rejected (steering) |
| B: `internal/rules` + daemon wiring | pure package: model, parse, resolve, encode, diff, learned writer | CI tests without root, reused by TUI/fleet | small interface to design | **baseline** |
| C: B + C changes (`rule_val`, `event.rule`, `event.path`) | kernel reports rule id and exe path | exact attribution, no `/proc` race | regen + verifier work | **selected**, staged after B |

## Design Decisions

### Decision: one file model for live and learned rules
- **Context**: Req 1, 9.4–9.8.
- **Selected**: `rules.File` (programs + rules) is the only model; learning aggregates into it;
  the writer emits TOML the parser reads back. Learned-only fields are optional on every rule.
- **Rationale**: Req 9.8 by construction; one parser to test. Generalization: "a rules file" is
  the single concept; learning is a producer, loading a consumer.

### Decision: diff-apply, puts before deletes
- **Alternatives**: map-in-map swap (atomic, C change, more map plumbing).
- **Selected**: compute entry sets, `Put` new/changed, then `Delete` removed, for both maps.
- **Trade-off**: a sub-millisecond window where old and new rules coexist; never one with no
  rules (Req 4.1). Good enough for a single operator's file.

### Decision: program ids from declaration order, rules loaded even when unresolved
- **Selected**: id = 1-based index; `programs` entries exist only for resolved files, `rules`
  entries for every rule. Unresolved programs are reported by name (Req 2.3) and start matching
  when the next re-resolve finds the file.

### Decision: kernel emits rule id and exe path (Option C)
- **Alternatives**: userspace re-evaluation of the lookup order for 5.3 (duplicate logic that
  can drift); `/proc` lookup plus inode → path cache for 9.9 (racy for `curl`).
- **Selected**: `rule_val{verdict,id}`, `event.rule`, `event.path` via `bpf_d_path`; fallback
  to `/proc/<pid>/exe` when the path is empty.
- **Follow-up**: verifier acceptance of `bpf_d_path(&exe->f_path, ...)` after the CO-RE chain;
  measure event size impact in monitor mode before any enforce run.

### Decision: TOML via go-toml/v2 (adopt), mountinfo parser and polling (build)
- **Rationale**: TOML matches the Python client's config and the steering note; a comments-free
  writer is enough. mountinfo parsing is ~30 lines; fsnotify would be a dependency for one file.

### Decision: enforce test as a repo script with a generated rules file
- **Selected**: `scripts/enforce-test.sh` (root, shellcheck'd) generates
  `rules.toml` with `curl → ALLOW_IP/32 tcp 443 allow` and `claude → 0.0.0.0/0 + ::/0 allow`,
  runs the daemon with `-mode enforce -duration`, probes with `curl` to IP literals, toggles
  the kill switch with `bpftool`, SIGSTOP/SIGCONT, probes a local address, and resets in a
  `trap`. Requires `-y` or an interactive confirmation (Req 7.1).

### Synthesis outcomes
- Generalization: learning = monitor mode + a recorder producing a `rules.File`.
- Build vs adopt: adopt go-toml/v2; build mountinfo lookup, polling, diff.
- Simplification: no plugin/strategy interfaces; one `internal/rules` package with four
  concerns in four files; the daemon stays a `main` package with wiring files. Port ranges
  are expanded to entries (cap 256 per rule) rather than adding a range type.

## Risks & Mitigations
- Wrong device → rules never match silently → VM test compares `exe_dev` of a real event with
  the resolver's value for the same path (Req 8.2) before the enforce run.
- `bpf_d_path` rejected by the verifier → ship Option B behaviour (path from `/proc`,
  rule attribution missing) and keep the C change in a separate task; 5.3/9.9 degrade, noted.
- Enforce run cuts the session → session tooling allowed in the generated rules; `-duration`
  hard ceiling; trap; operator confirms with console open.
- Trie full (`E2BIG`) on load → report and keep previous rules (Req 4.2 behaviour on reload;
  refuse at start).

## References
- cilium/ebpf v0.22 `Map.Put/Delete`, `CollectionOptions.Maps.PinPath` (pinned map reuse).
- Linux `statx(2)` `STATX_MNT_ID`; `proc(5)` mountinfo field 3 = `major:minor` of the
  superblock device.
- `bpf-helpers(7)` `bpf_d_path`: allowed for LSM programs.
- go-toml v2: https://github.com/pelletier/go-toml (DecodeError positions,
  DisallowUnknownFields).

---

# Design review outcome (2026-10-10, /kiro-validate-design)
GO with three revisions, applied: (1) daemon as `jobs.Job` delegates under one `jobs.Run`
with an `atomic.Pointer` snapshot (no shared mutable state); (2) size/complexity caps and the
delegate/immutability/contract rules in design + steering + CI; (3) `bpf_d_path` gated by
`program == 0 || control.flags & want_path`, fixed-layout event decode. User additions: code
contracts (`internal/contract`, always on, fail-open by exit) and tasks as self-contained briefs
for an external implementer (Codex over MCP).

# Task-graph sanity review (2026-10-10, independent subagent)
Pass 1: NEEDS_FIXES, 15 findings (kernel types before encoder, jobs assembly before daemon
checks, file-level boundaries in the daemon group, CI caps scoping, 2.x split, mappings). All
applied. Pass 2: NEEDS_FIXES with three one-line items (provisional pump job in 6.3, drop the
unprovided device print from 7.2's pre-check, 6.5's short-lived check must use an unmapped
program) plus four minor notes; all applied verbatim after the review. tasks.md written as
generated, not approved: the operator approves with this history known.

---

# 7.1 Monitor-mode integration pass (2026-10-10, dev VM, kernel 7.2, bounded runs, trap-protected)

Build: `go build -o /tmp/snitchd ./cmd/snitchd` at the state after task 6.6 (commit 897ce7f).
Finding of the pass: with a glob on an empty directory the summary read
`rules: 2 programs (1 resolved, 1 unresolved (curl)), 4 executables mapped, …` although curl's
`/usr/bin/curl` was mapped (the 4 executables include it). Fixed in `summary()` during 7.1: a
program is resolved when at least one executable maps, unmatched patterns are listed apart.
Re-run of the start check with the fixed binary, same rules file:
`rules: 2 programs (2 resolved, 0 unresolved), 1 patterns unmatched (curl:…/bin/*), 4 executables
mapped, 2 rules effective (2 entries)`. All other rows below are from the first run (the
transcript `pass71.log`, before the fix); the fix changes only that line.
Rules file for the pass: curl (`/usr/bin/curl` + a glob on an initially empty directory) and
the Claude Code glob; rules: allow curl → 1.1.1.1/32 tcp 443, deny curl → 9.9.9.9/32.

| Check | Req | Observed |
|---|---|---|
| start, summary | 3.6 | first run: `… (1 resolved, 1 unresolved (curl)) …` (the bug above); fixed binary: `(2 resolved, 0 unresolved), 1 patterns unmatched (curl:…)`, 4 executables mapped, 2 rules effective |
| allow by rule | 5.1, 5.3 | `allow (rule) connect pid … curl tcp -> 1.1.1.1:443 program curl rule #1 curl 1.1.1.1/32 tcp 443 allow` |
| deny by rule in monitor mode | 3.5 | curl exit 7 "Could not connect"; `DENY (rule) … program curl rule #2 curl 9.9.9.9/32 any any deny` |
| no rule | 5.1 | `allow (monitor) … -> 1.1.1.1:80 program curl` |
| unmapped copy of curl | 5.2, 9.9 | `allow (monitor) … curl-copy … program /…/curl-copy (unknown)` (path from the kernel) |
| file edited | 4.1 | new summary after 1.6 s; `rules` map 2 entries with the new address |
| file broken | 4.2 | `reload failed, keeping the previous rules: …/rules.toml:1: toml: array is incomplete`; entries unchanged |
| executable copied into the globbed dir | 4.3 | `5 executables mapped` after 0.8 s |
| SIGHUP | 4.4 | summaries 3 → 5 within 0.5 s (HUP plus the file watcher) |
| SIGTERM | 6.3 | exit 0; 0 snitch programs attached |
| learning cycle | 9.1, 9.4, 9.8 | learn 6 s with no rules → file with curl → 1.1.1.1 tcp 443; loaded as `-rules`: `allow (rule) … rule #1` |
| contract or verifier errors | — | none in any log |
| kill map after everything | 6.4 | value 0 (never written) |

Full transcript: scratchpad `pass71.log` of this session (not committed).

# 7.2 Enforce test script, check-only phase (2026-10-10)

`sudo scripts/enforce-test.sh --check-only`: rules loaded (2 programs resolved), a curl event
names `program curl` (the resolver's identity equals the kernel's), both public addresses
reachable in monitor mode, local probe 10.0.0.1:53 answers; trap reset read back mode monitor
(heartbeat 0) and kill switch value 0, 0 attached programs; exit 0. Review finding fixed before
acceptance: curl 8.22 prints the connect errno only with `-v`, so the EPERM detector uses
`curl -sS -v` and greps `failed: Operation not permitted`; checked against a network namespace
without network (ENETUNREACH must not match). The enforce phase (7.3) has NOT been run.

# 7.3 Enforce test run (2026-10-10, dev VM, `sudo scripts/enforce-test.sh -y -d 120`)

Operator's go given with the Proxmox serial console open (serial_console set up via the VM
repo first, commit 974c5fe there). Transcript:

```
== phase 1: monitor, identity pre-check (nothing is blocked)
  PASS  rules loaded: 2 programs resolved
  PASS  curl event names 'program curl' (identity matches the kernel)
  PASS  curl 1.1.1.1 reachable in monitor mode
  PASS  curl 9.9.9.9 reachable in monitor mode
  PASS  local probe 10.0.0.1:53 answers

== phase 2: ENFORCE for 120s. Everything not in the generated rules is denied for every
   program on this machine (local network excepted). Keep the hypervisor console open.
-- rules
  PASS  C1 curl 1.1.1.1:443 allowed
  PASS  C1 log: allow (rule) for curl
  PASS  C2 curl 9.9.9.9:443 denied with EPERM
  PASS  C2 log: DENY (default) for curl
  PASS  C3 local probe 10.0.0.1:53 still works
-- kill switch
  PASS  K1 kill switch on: curl 9.9.9.9 works
  PASS  K2 kill switch off: curl 9.9.9.9 denied
-- heartbeat
  PASS  P1 daemon stopped 16 s: curl 9.9.9.9 works (heartbeat stale)
  PASS  P2 daemon resumed: curl 9.9.9.9 denied again
-- done: stopping the daemon
  PASS  hooks detached after exit
reset: mode: monitor heartbeat 0 (read back); kill switch value: 0 (read back)
reset: attached snitch programs: 0
failed steps: 0
```

Every step passed: allow by rule, default deny with EPERM, local network still open, kill
switch on and off, heartbeat fail-open after 16 s of SIGSTOP and deny again after SIGCONT,
hooks detached at exit; the trap read back mode monitor and kill switch 0. The RDP session
driving this run stayed up (the Claude Code binary was allowed by the generated rules).
