# Product Overview

snitch is Little-Snitch-style egress control for Linux, open source: a root daemon (`snitchd`)
decides in the kernel whether a program may open an outbound connection, and a terminal UI
(`snitch`) shows every connection as process › host › address, lets the user block or allow
with one key, draws an egress graph of who sends how much to where, and pops up a question for
connections nobody has decided on yet.

It replaces two things the author used before: the closed-source Little Snitch for Linux daemon
and the Python client in the repo root that drives its web UI. The Python client stays in the
repo as the behavioural reference until the Go TUI reaches parity, key for key.

## Who it is for

A single developer VM today (a Hyprland thin client reached over RDP), a small fleet of such
hosts tomorrow. The user is the operator, the auditor and the person who gets locked out when
the firewall is wrong. Rules are configuration files, deployed like any other config.

## Core Capabilities

1. **Verdicts in the kernel**: allow or deny at `connect()` and unconnected `sendmsg()`
   via BPF LSM hooks, keyed by the program's executable (inode + device) and the destination
   (address prefix, protocol, port). No proxy, no userspace round trip per connection.
2. **Observation first**: monitor mode reports every decision without blocking; enforce
   (deny by default) is a timed trial that reverts on its own and at boot.
3. **Fail-safes in the design** (see `fail-safes.md`): egress only, local network always
   allowed, heartbeat fail-open, kill switch reachable from a serial console.
4. **Operator UI**: a TUI with the same views and keys as the Python client (overview,
   egress graph, popups with a process trace), fed by the daemon over a unix socket.
5. **Fleet view, later**: domain rules via a DNS tap, enrichment from Velociraptor (the
   CrowdStrike-style graph process tree › socket › destination behind a verdict) and batches
   to OpenObserve, which renders that graph as a limited Sankey (process › destination ›
   verdict), one batch per host every 10 minutes.

## Target Use Cases

- See which program talks to where, how much, and block it with one key.
- Catch a package phoning home: in enforce mode it is blocked and asked about; in monitor
  mode it shows up in the overview and the egress graph.
- Pre-approve dev tooling (Claude Code, git, apt, package managers) so overnight jobs run
  without popups; general-purpose tools such as curl always ask.
- Across a fleet: the same rule files (base + per host), events in one place, a graph per host.

## Value Proposition

Little Snitch's workflow, but open source, eBPF-based, and built so a wrong rule cannot cut the
operator's own RDP or SSH session. The 2026-10-09 lockout (deny by default cut RDP and SSH,
recovery took a reboot and the hypervisor console) is the founding incident; every design
decision is checked against "can this lock me out again?".

## Delivery

Releases are consumed by the author's VM-provisioning repo pinned by sha256, later as a Nix
flake. Phases are shippable one by one: enforcement + TUI, domain rules + popups + trace,
Velociraptor enrichment, OpenObserve batches, fleet rules + packaging.

---
_Focus on patterns and purpose, not exhaustive feature lists_
