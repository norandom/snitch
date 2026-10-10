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
  (prefixlen | program | family | proto | port | addr[16] -> 1 allow / 2 deny; 0 = any for
  program/proto/port), `control` array (heartbeat_ns, mode 0 monitor / 1 enforce), `kill`.
  Lookup order: program-specific then any-program; exact proto+port, proto, any.

## Status (2026-10-10) and next steps

Works on Debian forky 7.2 (BPF LSM active): attach, heartbeat, mode, local-net classification,
IPv4/IPv6/v4-mapped, TCP + UDP (connect and unconnected sendmsg), events with verdicts.
Not done yet, in order:

1. Load rules from a file into `programs` + `rules` (resolve exe paths/globs to inode+dev,
   convert stat dev to the kernel's `(major << 20) | minor`); then the enforce test on this VM:
   deny-by-default + allow curl -> 10.0.0.0/8 only: `curl 10.0.0.1` works, `curl example.com`
   fails with EPERM; kill switch on -> works; off -> fails; SIGSTOP the daemon -> after 15 s
   works (heartbeat); SIGCONT. Reset everything in a trap.
2. Daemon API over a unix socket (JSON lines, same shapes the Python TUI consumes), event
   dedupe, per-socket byte counting (cgroup skb programs, socket cookie) for the egress graph.
3. Domain rules: BPF tap on DNS answers -> IP->name cache -> rules by name compile live.
4. Popups + kernel-side process trace; then the bubbletea TUI, key for key like the Python one.
5. Velociraptor (server in the k3s cluster at 10.0.0.63) enrichment; OpenObserve
   (http://10.0.0.54:40002, org default; OTLP gateway in k3s :4317/:4318) one batch per host
   every 10 min; fleet rules as files (base + per host), Nix flake (buildGoModule), releases.
