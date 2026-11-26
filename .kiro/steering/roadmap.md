# Roadmap

## Overview

snitch is Little-Snitch-style egress control for Linux: `snitchd` decides in the kernel, and the
user-side `snitch` binary shows and asks. The daemon side is shipped through v0.4.0 (rule
loading, persistent trial, deploy service, daemon API, DNS tap). What is left is the user side:
nothing under `cmd/snitch/` exists yet, and the Python client in the repo root is still the
only operator UI.

This phase builds the user side in three shippable steps, all clients of the API in
`examples/api.md`, none of them touching BPF. It starts with a KDE tray because the operator
now also works on a KDE Plasma host (chandali, Ubuntu 26.04, Plasma 6.6 on Wayland), where the
Hyprland-only pieces of the Python client (waybar module, `foot` popups) do not apply.

## Approach Decision

- **Chosen**: one user binary, `snitch`, with verbs, like the Python client it replaces
  (`snitch tray` first, later `snitch watch`, `snitch ask`, `snitch status`, and the TUI as the
  default verb). The tray speaks D-Bus directly through `github.com/godbus/dbus/v5`:
  `org.kde.StatusNotifierItem` with a `com.canonical.dbusmenu` menu, and
  `org.freedesktop.Notifications` for the notifications. The API client and the
  "answer becomes a rule" logic live in `internal/` packages so the popups and the TUI reuse them.
- **Why**: pure Go, one new dependency (BSD-2-Clause, no cgo), so the static build and the
  release workflow stay as they are. Speaking StatusNotifierItem directly gives the `Status`
  property (`NeedsAttention` for kill switch and daemon gone) and a tooltip, and it is
  testable against a private session bus. The icons turned out differently from what this
  line first promised: the tray draws its own pixmaps for all six states, not theme names —
  every state differs in shape and every stroke carries a light halo, so they read on Breeze
  light and dark alike (`kde-tray` research.md, Decision: icons).
- **Rejected alternatives**:
  - `fyne.io/systray`: less code of ours, but icons only as pixmap bytes, no `Status`, a
    process-global API that fights the jobs and delegates rules of `tech.md`, and godbus would
    still be needed for the notifications.
  - A Plasma applet (QML) or a Qt/Python tray: a second language and a runtime dependency on
    the desktop host, against the "Go for both binaries" decision.
  - Extending the Python client: it is lint-only, the reference until parity, no new features.

## Scope

- **In**: the KDE tray (status icon, status menu, notifications with Allow and Block), the
  popups with a kernel-side process trace, the bubbletea TUI at parity with the Python client.
- **Out**: trial verbs in the tray menu (the operator decided against them on 2026-11-23; they
  stay on `snitchd trial | keep | unkeep | end` and, later, the TUI); a remote transport for
  the API (the tray talks to the daemon on its own host); inbound traffic (fail-safe 1); any
  change to the decision hook for the tray.

## Constraints

- Fail-safes (`fail-safes.md`) are design constraints. No user-side client may switch the mode
  on its own; a client that dies or hangs changes nothing in the kernel.
- `tech.md` code shape is binding: caps, delegates over interfaces, jobs, contracts.
- Everything user-facing is built against `examples/api.md`, not against the Go types.
- Clients must run as an ordinary user. Writes (`rule.add`) need the operator role
  (`/etc/snitch/operator`); a reader's tray shows and notifies but cannot answer.
- A deny by name is refused by the API: Block is always by address.

## Boundary Strategy

- **Why this split**: the tray needs no kernel change and no terminal, so it ships alone and
  proves the client package. The popups add the only kernel work of the phase (the process
  trace) and the terminal question. The TUI is the large port and comes last, on a client
  package two specs have already exercised.
- **Shared seams to watch**:
  - The API client package (connect, reconnect, subscribe, resync after `dropped`): owned by
    `kde-tray`, reused unchanged by the other two.
  - "Which event deserves a question" and "an answer becomes an overlay rule": owned by
    `kde-tray` as a pure package; `popups-trace` adds the trace and the terminal front end and
    must not fork the logic.
  - Notifications against popups: on KDE the notification is the question; the terminal popup
    is for hosts without a notification server with actions. One host runs one of them.

## Direct Implementation Candidates

- [ ] dns-tap bookkeeping -- tasks 1.4, 2.5, 3.3, 3.4 and the three parents are unchecked and
  `spec.json` says `tasks-approved`, although the commits record them as done and v0.4.0 is
  released. Run `/kiro-validate-impl dns-tap`, then tick the boxes and set the phase.
- [ ] snitchd on chandali -- only with the operator's go: `bpf` into the kernel's LSM list
  (`CONFIG_BPF_LSM=y` is there; the active list is `lockdown,capability,landlock,yama,apparmor,ima,evm`,
  so it needs `lsm=...,bpf` on the kernel command line and a reboot), the release binary, the
  units, a rules file for this host, `/etc/snitch/operator`, monitor mode only. Kernel 7.3 is
  newer than the 7.2 the bindings were generated on; CO-RE should carry it, the bounded monitor
  run proves it.

## Specs (dependency order)

- [x] kde-tray -- `snitch tray`: StatusNotifierItem icon and status menu, KDE notifications with Allow and Block for undecided or denied connections; creates `cmd/snitch` and the API client package. Dependencies: none
- [ ] popups-trace -- kernel-side process trace on events, `snitch watch` and `snitch ask` (the terminal question, with the trace), the trace in the tray's notifications. Dependencies: kde-tray
- [ ] write-gate -- mandatory (see `.kiro/specs/tui/requirements.md`, Mandatory Follow-up): the daemon authorises writes by uid alone, so any program of the operator's account can send them itself; loosening writes (allow rule, deny removal) and `trial` / `keep` must need more than the uid, tightening writes and the way back stay easy. Before popups-trace is implemented. No brief yet. Dependencies: daemon-api
- [ ] tui -- the bubbletea TUI, key for key like the Python client (overview, egress graph, rule edits, trial verbs), then the Python client retires. Dependencies: kde-tray, popups-trace

## Later phases (no briefs yet)

In the order of `CLAUDE.md`: Velociraptor enrichment (process tree, socket, destination behind
a verdict), OpenObserve batches (one per host every 10 min, the Sankey), fleet rules as files
(base + per host), the Nix flake.

---
_created 2026-11-23 by discovery: "continue with this project and also add KDE tray support"_
