# Agentic SDLC and Spec-Driven Development

Kiro-style Spec-Driven Development on an agentic SDLC

## Project Context

### Paths
- Steering: `.kiro/steering/`
- Specs: `.kiro/specs/`

### Steering vs Specification

**Steering** (`.kiro/steering/`) - Guide AI with project-wide rules and context
**Specs** (`.kiro/specs/`) - Formalize development process for individual features

### Active Specifications
- Check `.kiro/specs/` for active specifications
- Use `/kiro-spec-status [feature-name]` to check progress

## Development Guidelines
- Think in English, generate responses in English. All Markdown content written to project files (e.g., requirements.md, design.md, tasks.md, research.md, validation reports) MUST be written in the target language configured for this specification (see spec.json.language).

## Minimal Workflow
- Phase 0 (optional): `/kiro-steering`, `/kiro-steering-custom`
- Discovery: `/kiro-discovery "idea"` — determines action path, writes brief.md + roadmap.md for multi-spec projects
- Phase 1 (Specification):
  - Single spec: `/kiro-spec-quick {feature} [--auto]` or step by step:
    - `/kiro-spec-init "description"`
    - `/kiro-spec-requirements {feature}`
    - `/kiro-validate-gap {feature}` (optional: for existing codebase)
    - `/kiro-spec-design {feature} [-y]`
    - `/kiro-validate-design {feature}` (optional: design review)
    - `/kiro-spec-tasks {feature} [-y]`
  - Multi-spec: `/kiro-spec-batch` — creates all specs from roadmap.md in parallel by dependency wave
- Phase 2 (Implementation): `/kiro-impl {feature} [tasks] [--review required|inline|off]`
  - Without task numbers: autonomous mode (subagent per task + independent review + final validation)
  - With task numbers: manual mode (selected tasks in main context, still reviewer-gated before completion)
  - `--review off` skips task-local review; use it intentionally and keep `/kiro-validate-impl {feature}` as the final quality gate
  - `/kiro-validate-impl {feature}` (standalone re-validation)
- Progress check: `/kiro-spec-status {feature}` (use anytime)

## Skills Structure
Skills are located in `.claude/skills/kiro-*/SKILL.md`
- Each skill is a directory with a `SKILL.md` file
- Skills run inline with access to conversation context
- Skills may delegate parallel research to subagents for efficiency
- Additional files (templates, examples) can be added to skill directories
- `kiro-review` — task-local adversarial review protocol used by reviewer subagents
- `kiro-debug` — root-cause-first debug protocol used by debugger subagents
- `kiro-verify-completion` — fresh-evidence gate before success or completion claims
- Use skills explicitly requested by the user and skills relevant to the task's domain, including design, accessibility, and UX.
- Select skills from their descriptions or metadata first, then read only the selected skills and the references needed for the task.
- Follow explicit host and project rules and retain required workflow checks. Do not skip relevant skills just because the task is small.

## Development Rules
- 3-phase approval workflow: Requirements → Design → Tasks → Implementation
- Human review required each phase; use `-y` only for intentional fast-track
- Keep steering current and verify alignment with `/kiro-spec-status`
- Follow the user's instructions precisely, and within that scope act autonomously: gather the necessary context and complete the requested work end-to-end in this run, asking questions only when essential information is missing or the instructions are critically ambiguous.

## Steering Configuration
- For spec and implementation work, load the core steering files below from `.kiro/steering/`. Reuse current context rather than rereading unchanged files.
- Load additional steering only when required by project rules or relevant to the task.
- Default files: `product.md`, `tech.md`, `structure.md`
- Custom files are supported (managed via `/kiro-steering-custom`)

# snitch

Little-Snitch-style egress control for Linux, open source, eBPF. Two binaries, one repo:

- `snitchd` (root, Go + BPF C): decides at `connect()` / unconnected `sendmsg()` inside the kernel
  (BPF LSM hooks), keyed by the program's executable (inode + device) and the destination.
- `snitch` (TUI, bubbletea, planned): the same views and keys as the Python client it replaces
  (`snitch`, the file in the repo root, talks to Little Snitch's web UI; it stays until parity).

Started as part of github.com/norandom/hyperland-forky-worker-vm (a Hyprland thin client over
RDP). That repo deploys releases of this one pinned by sha256 (`group_data/all.py`:
`snitch_version`, `snitch_sha256`, `snitch_trial_sha256`); `littlesnitch_enabled = False` there
keeps Little Snitch and the Python popups off while snitchd replaces them.

## Fail-safes: design constraints, not options

Deny by default with Little Snitch cut RDP and SSH once (2026-10-09, reboot + Proxmox console).
Never again:

1. Egress only. Nothing looks at accept() or inbound traffic.
2. The local network (RFC 1918, link-local, loopback, fc00::/7, fe80::/10, ::1) is allowed
   inside the BPF program, not by a rule anyone can delete.
3. Heartbeat: the daemon writes a timestamp into the pinned `control` map every 2 s; stale for
   15 s (daemon wedged) or absent (daemon not started) means allow everything. Links are not
   pinned: a dead daemon detaches the programs.
4. Kill switch, usable from a serial console as root, no network or daemon needed:
   `bpftool map update pinned /sys/fs/bpf/snitch/kill key 0 0 0 0 value 1 0 0 0`
   (`value 0 0 0 0` to clear). A restart must keep it until cleared.
5. Deny mode only as a timed trial with a boot revert (see `snitch-trial` for the shape).

Never switch a mode or deploy anything that can cut the user's RDP session without asking;
test on this VM with `-duration`, and the kill switch reset in a trap.

## Layout and commands

- `bpf/snitch.bpf.c` the program; `bpf/vmlinux.h` CO-RE types (regenerate on a new kernel:
  `sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h`)
- `internal/bpf/` bpf2go output, committed (`go build` needs no clang). Regenerate after editing
  the C: `go generate ./internal/bpf/` (needs clang, llvm, libbpf-dev; cflags in `gen.go`).
  New C structs the Go side needs: add `-type <name>` in gen.go and a
  `const struct x *unused __attribute__((unused));` so the type lands in BTF. A struct must not
  share its name with a map (bpf2go: "found multiple types").
- `cmd/snitchd/` the daemon. Build + try: `go build -o /tmp/snitchd ./cmd/snitchd &&
  sudo /tmp/snitchd -mode monitor -duration 10s`.
- Go module `github.com/norandom/snitch`; deps: cilium/ebpf v0.22, x/sys. Lint: `gofmt -l .`,
  `go vet ./...`; CI (`.github/workflows/lint.yml`): go, ruff (Python client), shellcheck,
  actionlint. Commit as `git -c user.name=marius -c user.email=wishinet@gmail.com commit`.
  Before every push: no secrets in the diff.
- Rule maps (see the C): `programs` hash (exe inode+dev -> program id), `rules` LPM trie
  (prefixlen | program | family | proto | port | addr[16] -> rule_val {verdict 1 allow / 2 deny,
  rule id}; 0 = any for program/proto/port), `control` array (heartbeat_ns, mode 0 monitor /
  1 enforce, flags bit 0 = want exe path in events), `kill`. Events carry the rule id and the
  exe path (bpf_d_path via the bpf_get_task_exe_file kfunc, Linux >= 6.12; only for unknown
  programs or with the flag).
  Lookup order: program-specific then any-program; exact proto+port, proto, any.

## Status (2026-10-10) and next steps

Works on Debian forky 7.2 (BPF LSM active): attach, heartbeat, mode, local-net classification,
IPv4/IPv6/v4-mapped, TCP + UDP (connect and unconnected sendmsg), events with verdicts.
Done since (spec `rule-loading`, 2026-10-10, see `.kiro/specs/rule-loading/`): rules file
(`examples/rules.toml`, `-rules`) resolved to inode + superblock device via mountinfo and
loaded into the maps, reload on change / exe change / SIGHUP, learning mode (`-learn`, writes
`-learned`), events with program name and rule, enforce only bounded (`-mode enforce` needs
`-duration`); `scripts/enforce-test.sh` passed 16/16 on this VM with the serial console open;
`scripts/fail-open.sh` is the console recovery. Needs Linux >= 6.12 (kfuncs in the C).
Spec `persistent-trial` (2026-10-10, see `.kiro/specs/persistent-trial/`) implemented:
`systemd/snitchd.service` plus the boot-revert oneshot, the daemon follows the trial and kept
files under `/var/lib/snitch` when started without `-mode`, the verbs `snitchd trial | keep |
unkeep | end | status`, and phase 3 of `scripts/enforce-test.sh`, which passed 63/63 on this VM
(2026-10-10, serial console open); validated GO on 2026-10-11. Nothing is installed or enabled
here yet: spec `deploy-service` (release, pyinfra task, rules file) does that.
Not done yet, in order:

1. Deployment (spec `deploy-service`): GitHub release with sha256, the VM repo's snitchd task,
   `/etc/snitch/rules.toml` translated from the Python client's rules; until then enforce runs
   only through the test script.
2. Daemon API over a unix socket (JSON lines, same shapes the Python TUI consumes), event
   dedupe, per-socket byte counting (cgroup skb programs, socket cookie) for the egress graph.
3. Domain rules: BPF tap on DNS answers -> IP->name cache -> rules by name compile live.
4. Popups + kernel-side process trace; then the bubbletea TUI, key for key like the Python one.
5. Velociraptor (server in the k3s cluster at 10.0.0.63) enrichment: it supplies the
   CrowdStrike-style graph (process tree -> socket -> destination) behind a verdict. OpenObserve
   (http://10.0.0.54:40002, org default; OTLP gateway in k3s :4317/:4318) gets one batch per
   host every 10 min and shows that graph as a (limited) Sankey: process -> destination -> verdict.
   Then fleet rules as files (base + per host), Nix flake (buildGoModule), releases.
