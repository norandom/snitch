# Brief: popups-trace

## Problem

A question about a connection ("may `node` talk to 203.0.113.7:443?") cannot be answered from
the executable alone: the operator needs to know which process tree started it. The Python
client reads `/proc` after the fact, so short-lived programs such as `curl` have exited by then
and the popup can only say so. On hosts without a notification server with actions (the
Hyprland VM), there is no question at all once the Python client is gone.

## Current State

- Events carry `pid`, `ppid`, `comm`, `path`; `examples/api.md` notes that `viaExecutable` has
  no counterpart and that "the process trace comes with the popups spec".
- `kde-tray` (upstream) owns the API client, the question policy (which events ask, dedupe,
  answer to `rule.add`) and the KDE notification front end.
- The Python client's `snitch watch` (user service) and `snitch ask FILE` define the popup
  flow: one popup at a time, `o` allow, `x` block, `O` / `X` temporary, `esc` later, keys
  ignored for the first 0.6 s, the trace below the destination.

## Desired Outcome

Every event that can lead to a question carries a process trace captured in the kernel at the
moment of the decision (the chain of ancestors with their executables), so it is complete even
when the process has exited. `snitch watch` asks in a terminal popup on hosts without KDE
notifications, with the same keys as the Python client; the tray's notification shows the same
trace. The answer is an overlay rule, as in `kde-tray`.

## Approach

Capture the ancestor chain in the BPF program on the paths that already report an event
(bounded walk over `real_parent`, executable identity per level), carry it on the event and the
API's `event` line as an optional field, and render it in both front ends. The terminal popup
is a small bubbletea program started like the Python one (`terminal = ...` in the config).

## Scope

- **In**: the kernel-side trace and its Go decoding; the optional `trace` field in the API and
  `examples/api.md`; `snitch watch`, `snitch ask`; temporary rules (`O` / `X`) and snooze if
  the overlay can express them; the trace in the tray's notification.
- **Out**: the overview and the egress graph (`tui`); Velociraptor enrichment (the fleet
  process graph); any decision based on the trace (it informs the operator, it is not a key).

## Boundary Candidates

- BPF: the bounded ancestor walk and the event layout.
- Daemon: decode, the wire field, the document.
- Client: trace rendering shared by notification and popup; the popup program; the watcher.

## Out of Boundary

- The question policy and the API client: reused from `kde-tray`, not forked.
- The verdict logic of the decision hook: the trace must not add a path that can deny.

## Upstream / Downstream

- **Upstream**: `kde-tray` (client, question policy), `daemon-api` (event shape).
- **Downstream**: `tui` (shows the trace in its detail view), Velociraptor enrichment.

## Existing Spec Touchpoints

- **Extends**: `daemon-api` (one optional field on `event`; `scripts/api-check.sh` gains it).
- **Adjacent**: `dns-tap` (its design pinned the decision hook as unchanged against v0.3.1;
  this spec is the one that changes it, and says so).

## Constraints

- Fail-safes: the walk is bounded and cannot fail closed; a verifier-rejected program means the
  daemon does not attach, which is allow. Enforce-mode tests are trap-protected trials.
- The event must stay within the ring buffer's budget; the trace is captured only where an
  event is reported anyway.
- Regenerated bindings are committed; CI never runs clang.
