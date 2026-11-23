# Brief: kde-tray

## Problem

The operator now also works on a KDE Plasma host (chandali: Ubuntu 26.04, Plasma 6.6, Wayland).
There, nothing shows what snitchd is doing: the Python client's status indicator is a waybar
module and its popups open in `foot` through Hyprland, neither of which exists on KDE. Without
an indicator the operator does not notice a running enforce trial, a set kill switch, a daemon
that is gone or a rules file that failed to load; without a question, a connection nobody
decided on goes by unseen in monitor mode and is silently denied in enforce mode.

## Current State

- `snitchd` v0.4.0 serves the local API on `/run/snitch/api.sock` (`examples/api.md`): `status`,
  `subscribe` with `event`, `summary` and `state` lines, `rule.add` into the overlay for the
  operator. The document already names the tray as a client.
- No Go client exists: `cmd/snitch/` is planned, not created. `internal/api` is the server side.
- The Python client's `snitch status` prints waybar JSON (shield solid for deny, outline for
  allow, red when the popups are not running); `snitch watch` asks about denied connections.
- chandali has a StatusNotifier watcher and host (kded6, plasmashell) and a notification server
  with actions. It has no snitchd yet and `bpf` is not in its active LSM list.

## Desired Outcome

`snitch tray`, started in the Plasma session by an ordinary user, puts one icon into the system
tray that tells the daemon's state at a glance (monitor, enforce trial with its deadline,
enforce kept, kill switch, daemon not running, rules error), opens a menu with the daemon's
facts, and raises a KDE notification for a connection no rule covers, with Allow and Block; the
operator's answer becomes an overlay rule through the API. When the daemon is absent or
restarts, the tray says so and reconnects on its own. Nothing the tray does or fails to do
changes a kernel decision other than through a rule the operator chose.

## Approach

A new binary `snitch` (`cmd/snitch`) with the verb `tray`, pure Go, speaking D-Bus on the
session bus through `github.com/godbus/dbus/v5`: `org.kde.StatusNotifierItem` registered with
`org.kde.StatusNotifierWatcher`, a `com.canonical.dbusmenu` menu, and
`org.freedesktop.Notifications` with actions. Icons are theme icon names, so they follow the
desktop's light or dark theme. The daemon side is the existing API, unchanged: one connection,
`status` plus `subscribe`, a resync after `dropped`, reconnect with backoff.

Chosen over `fyne.io/systray` (pixmap icons only, no `Status` property, process-global API,
godbus still needed for notifications) and over a QML applet (second language, desktop runtime
dependency). See `.kiro/steering/roadmap.md`.

## Scope

- **In**:
  - `cmd/snitch` with `snitch tray` and `snitch -version`; a user unit or autostart entry.
  - An API client package: connect, request and reply, subscribe, reconnect, resync.
  - The tray item: icon, title, tooltip and `Status` per daemon state; re-registration when
    the watcher or plasmashell restarts.
  - The status menu: mode, trial deadline, kept, kill switch, learning, rule and program
    counts, rules error, DNS tap facts, daemon version, whether this user is the operator; quit.
  - Notifications for connections no rule covers (`deny-default` in enforce, `allow-monitor`
    in monitor), with Allow and Block, rate-limited and deduplicated per program and
    destination; the answer is a `rule.add` (Allow by name when the event has one, else by
    address; Block by address). A reader's tray notifies without actions.
  - A notification when the state changes for the worse: trial started or ended, kill switch
    set, daemon gone, rules error.
  - Unit tests without root and without a desktop (a fake API socket, a private session bus
    where available); a check on chandali.
- **Out**:
  - Trial verbs (`trial`, `keep`, `unkeep`, `end`) in the menu: decided against, 2026-11-23.
  - Removing or listing rules from the tray (the TUI's job).
  - The kernel-side process trace and the terminal popup (`popups-trace`).
  - `snitch status` waybar JSON and anything Hyprland-specific (parity work in `tui`).
  - Installing snitchd or enabling BPF LSM on chandali (a direct step, with the operator's go).
  - Any change to `snitchd`, the API or the BPF programs.

## Boundary Candidates

- API client (transport, envelope, reconnect, subscription) as its own `internal/` package.
- Pure state mapping: status and state lines to an icon, a tooltip and menu rows.
- Pure question policy: which events ask, dedupe and rate limit, answer to `rule.add` request.
- D-Bus adapters: StatusNotifierItem, dbusmenu, notifications; thin, behind function values.
- `cmd/snitch`: flags, wiring, jobs.

## Out of Boundary

- The daemon's authorization, overlay merge and rule validation: the tray shows the daemon's
  `text` and `error` strings, it does not re-implement them.
- Mode changes of any kind.
- Desktop environments other than Plasma are not a target; other StatusNotifier hosts may work
  but are not tested.

## Upstream / Downstream

- **Upstream**: `daemon-api` (the socket, the shapes, the operator role), `dns-tap` (the
  `name` on events, the `dns` block of status).
- **Downstream**: `popups-trace` (reuses the client and the question policy, adds the trace to
  the notification), `tui` (reuses the client).

## Existing Spec Touchpoints

- **Extends**: none. `examples/api.md` is read, not changed.
- **Adjacent**: `daemon-api` (do not duplicate its types by importing server internals into the
  client beyond the wire shapes), `deploy-service` (the release workflow gains a second binary
  only if this spec says so; the VM repo deploys `snitchd` alone today).

## Constraints

- Fail-safes 1 to 5 hold untouched: the tray never switches the mode, never writes a rule
  without an explicit operator action, and its absence or crash changes nothing in the kernel.
- A notification must not be answerable by accident: no default action on click that writes a
  rule; Allow and Block are explicit buttons.
- Pure Go, no cgo, static build; one new dependency (`godbus/dbus/v5`).
- `tech.md` code shape: functions at most 40 lines, files at most 300, delegates, jobs under
  one `jobs.Run`, contracts for programming errors.
- Runs as an ordinary user; the session bus only, never the system bus.
- Notifications carry program names, paths, addresses and names of this host only to the
  local notification server; nothing leaves the host.
