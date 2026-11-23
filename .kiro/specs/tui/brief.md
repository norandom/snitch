# Brief: tui

## Problem

The operator UI is still the Python client in the repo root, which talks to Little Snitch's
web UI. Little Snitch was retired on the VM on 2026-10-11, so that client has no backend there
any more: the overview (process, host, address), the egress graph and one-key block or allow
exist only as a reference, not as a working tool against snitchd.

## Current State

- The API offers everything the views need: `snapshot` with windows, `summary` every 2 s,
  `rules`, `programs`, `learned`, `rule.add`, `rule.remove`, the trial verbs. The field names
  were chosen to map onto the Python client's (`examples/api.md`, "Field names against the
  Python client").
- `kde-tray` supplies the API client package, `popups-trace` the trace and the popup.
- The Python client (`snitch`, Textual) is the behavioural reference: views, keys, sort modes,
  the protection of critical entries ("press x again"), `snitch status` for waybar.

## Desired Outcome

`snitch` without a verb opens a bubbletea TUI with the same views and keys as the Python
client, fed by snitchd: the overview, the egress graph, block and allow with one key (overlay
rules), the trial verbs for the operator, and `snitch status` as waybar JSON. When it is at
parity, the Python client, its units and its lint job leave the repo.

## Approach

A bubbletea program in `cmd/snitch` on the client package: one model per view, the table fed
by `snapshot` and kept current by `summary` lines, writes through the API with the daemon's
`text` shown as is. Parity is checked against a key-by-key list taken from the Python client.

## Scope

- **In**: overview, egress graph, rule edits, trial verbs with confirmation, `snitch status`,
  the parity list, retiring the Python client and `snitch-trial`.
- **Out**: fleet views (OpenObserve, Velociraptor), a remote transport, new features the
  Python client does not have.

## Boundary Candidates

- View models (pure update functions) per view; rendering; the key map; the waybar status verb.

## Out of Boundary

- The client package and the question policy (`kde-tray`), the trace and the popup
  (`popups-trace`).

## Upstream / Downstream

- **Upstream**: `kde-tray`, `popups-trace`, `daemon-api`.
- **Downstream**: the VM repo (deploys the `snitch` binary and drops the Python client).

## Existing Spec Touchpoints

- **Extends**: `deploy-service` (a second release asset, `snitch`).
- **Adjacent**: `persistent-trial` (the TUI calls its verbs through the API, it does not touch
  the trial files).

## Constraints

- Starting a trial from the TUI needs an explicit confirmation and shows the deadline;
  fail-safe 5 stays the daemon's.
- Key for key like the Python client; a deviation is listed and justified.
- bubbletea and its dependencies are the only new ones; pure Go, static build.
