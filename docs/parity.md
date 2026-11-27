# Parity List: Python `snitch` vs. Go `snitch`

Every key, view, column, verb, CLI flag, and configuration key of the Python reference client (`snitch` in the repository root) compared against the Go `snitch` binary.

- Status markers: **`same`** (matches the Python client's behaviour) or **`deviation`** (intentional difference with reason).
- Every item below is checked (`- [x]`) and confirmed against the running Go binary (`debb` VM monitor-mode run at `3dc2a1b` + operator sign-off, 2026-11-27).

## Keys

### Overview & Navigation (`Connections.BINDINGS`, `Snitch.BINDINGS`, and `DataTable`)

- [x] `up` / `down` (`DataTable` navigation) — **`same`**: moves the cursor up or down one row in the overview table; the detail pane updates for the selected row.
- [x] `pgup` / `pgdown` / `home` / `end` (`DataTable` navigation) — **`same`**: moves the cursor by one page or to the first/last row in the overview table (`internal/tui/keys.go` binds them explicitly).
- [x] `enter`, `right`, `l` (`Connections.BINDINGS`: `app.open`) — **`same`**: expands a collapsed row one level in the overview tree.
- [x] `left`, `h` (`Connections.BINDINGS`: `app.close`) — **`same`**: collapses an expanded row, or moves the cursor to its parent row when already collapsed.
- [x] `x`, `space` (`Connections.BINDINGS`: `app.block`) — **`deviation`**: toggles blocking on the selected row, with protected programs (`protect`) requiring a second `x`/`space` press directly after the warning; however, **unblock removes the rule** (sends `rule.remove` against the overlay deny rule instead of flipping a Little Snitch rule), local-network addresses (`ask.Local`) are refused locally, and action-key guards apply (ignore key repeat, ignore keys within 50 ms, refuse on foreign non-root socket or unreachable daemon).
- [x] `t` (`Snitch.BINDINGS`: `period`) — **`deviation`**: cycles to the next time window in `periods` in both overview and egress graph, **limited to the daemon's five time windows only** (`15m`, `30m`, `1h`, `24h`, `7d`) and querying `snapshot` over the Unix socket.
- [x] `1`, `2`, `3`, `4`, `5`, `6`, `7`, `8`, `9` (`Snitch.BINDINGS`: `period(0..8)`) — **`deviation`**: jumps to the 1st–9th window in `periods` in both overview and egress graph, **limited to the daemon's five time windows only** (`periods` has at most five entries, so `6`–`9` are unused unless fewer/reordered windows are configured, matching Python's `if n < len(self.periods)` check).
- [x] `/` (`Snitch.BINDINGS`: `slash` / `search`) — **`deviation`**: opens the search input line in the overview, where typing edits the `*m.search` input buffer and does not filter rows until `enter` applies the query (**`same`** submit-on-`enter` behaviour as Python's `Input` + `on_input_submitted`, not live filtering; `backspace` deletes one rune, `esc` clears and closes, bracketed paste goes only to the open search line), **but** **search and sorting are done by the TUI** locally over `program › host › address` paths rather than sending `setSearch` to the daemon.
- [x] `esc` (`Snitch.BINDINGS`: `escape` / `clear_search`) — **`deviation`**: clears an active search filter and closes the search input; when the search input is open it clears and closes it immediately, done locally by the TUI rather than via daemon `setSearch`.
- [x] `enter` (in `#search` `Input`) — **`same`**: applies the typed search filter and returns focus to the overview table (search filtering itself is done locally by the TUI).
- [x] `s` (`Snitch.BINDINGS`: `sort_activity`) — **`deviation`**: sorts each tree level by activity (most recent first, frozen rank, new rows on top) and cycles through `resort` intervals (`10s`, `20s`), with **search and sorting done by the TUI** over the flat daemon `snapshot` tree rather than re-sorting a daemon-maintained `Tree`.
- [x] `S` (`Snitch.BINDINGS`: `sort_name`) — **`deviation`**: sorts each tree level alphabetically by title (case-insensitive), with **search and sorting done by the TUI** over the locally constructed tree.
- [x] `e` (`Snitch.BINDINGS`: `egress`) — **`same`**: toggles between the overview and the egress graph view.
- [x] `q` (`Snitch.BINDINGS`: `quit`) — **`same`**: quits the TUI cleanly and restores the terminal (`q` also quits when the terminal is smaller than `80x20`).
- [x] `ctrl+c` (Textual built-in quit) — **`same`**: quits the TUI cleanly and restores the terminal (explicitly listed in `internal/tui/keys.go`).

### Popup Keys (`snitch ask`)

- [x] `o` / `x` / `O` / `X` / `esc` (in `snitch ask` popup) — **`deviation`**: **no `watch`, `ask` and `baseline` verbs** in this binary; interactive allow/block/temporary/snooze popups return with `popups-trace`.

### New Keys in the Go Binary

- [x] `T` (overview, egress graph) — **`deviation`**: **new key `T`**; starts an enforce trial for the configured `trial` duration after a `[y/N]` confirmation prompt (and handles the daemon's no-rules question if returned). Python only offered `snitch default deny` on the CLI.
- [x] `K` (overview, egress graph) — **`deviation`**: **new key `K`**; keeps enforce mode beyond the trial deadline and across reboots after a `[y/N]` confirmation prompt. Python only offered `snitch default deny --keep` on the CLI.
- [x] `E` (overview, egress graph) — **`deviation`**: **new key `E`**; ends enforce/trial and returns to monitor mode immediately (no confirmation prompt). Python only offered `snitch default allow` on the CLI.
- [x] `U` (overview, egress graph) — **`deviation`**: **new key `U`**; unkeeps enforce mode immediately (returns to trial/non-kept state without confirmation). Python had no equivalent key or verb.
- [x] `y` (confirmation prompt) — **`deviation`**: **new key `y`**; confirms an open `[y/N]` prompt (`T`, `K`, or daemon no-rules question) after the 0.6 s gate and action-key guards; any other non-repeat key cancels.

## Views and Panes

### Overview View

- [x] Tree hierarchy (`program > host > address` and `IP Addresses` group) — **`same`**: three-level tree (`program › host › address`) with unnamed addresses grouped under `IP Addresses`, plus an `unknown` bucket row for entries with unknown program/path and no address.
- [x] `x via y` sender rows (parent-launcher nesting) — **`deviation`**: **no `x via y` senders and no process trace (`popups-trace`)**; `snitchd` reports program and executable path per entry without `via` nesting.
- [x] `Inbound` group rows — **`deviation`**: **no received bytes and no inbound rows (egress only)**; `snitchd` tracks outbound (egress) connections only.
- [x] `n more` overflow rows (`isMoreItems`) — **`deviation`**: **no `n more` rows**; the daemon `snapshot` returns aggregated entries directly without collapsed overflow rows.
- [x] Header bar (`#head`) — **`deviation`**: keeps `snitch | last <window> | <N> programs | sort: ...`, but replaces Little Snitch's `127.0.0.1:3031` and `FILTER OFF (all allowed)` with `snitchd` state (`mode: monitor|enforce (trial .../kept)`, `search: ...`, `FOREIGN (not root)`, `STALE (...)`, `ALL ALLOWED (kill switch / stale heartbeat)`, and socket path).
- [x] Detail / inspector pane (`#info`) — `path` line — **`same`**: displays the breadcrumb `program › host › address` (using `›` instead of `>`).
- [x] Detail / inspector pane (`#info`) — `program` line — **`deviation`**: displays program name and executable path plus `[undeclared]` / `[writable dir]` warnings, with **no `x via y` senders and no process trace (`popups-trace`)**.
- [x] Detail / inspector pane (`#info`) — `remote` line — **`deviation`**: displays remote hostname, address, port, and protocol (or `multiple (N)` for multi-entry parent rows); omits `inbound`/`outbound` because there are **no inbound rows (egress only)**.
- [x] Detail / inspector pane (`#info`) — `traffic` line — **`deviation`**: shows **no received bytes (`down`)**, shows **byte totals (`sent`) since the daemon first saw a connection**, shows **the rate over the daemon's last 10 s**, and shows `last allowed` / `last denied` ages.
- [x] Detail / inspector pane (`#info`) — `default` / `mode` line — **`deviation`**: shows `mode` (`monitor`, `enforce (trial ...)`, `enforce (kept)`, plus `all allowed` reason) instead of Little Snitch's `defaultAction`.
- [x] Detail / inspector pane (`#info`) — `rule` lines — **`deviation`**: shows up to two matching program `RuleView` rules (`verdict`, `to`, `proto/port`, `note`, `source`, `(+N more)`) rather than Little Snitch's `coveringRules`, `relatedRules`, and `blocklist` entries.
- [x] Detail / inspector pane (`#info`) — process trace — **`deviation`**: **no `x via y` senders and no process trace (`popups-trace`)**; `/proc` ancestry/cmdline/cwd tracing returns in `popups-trace`.
- [x] Log pane (`RichLog`, `~/.local/state/snitch/snitch.log`) — **`same`**: loads last 5 lines on startup, appends timestamped `BLOCKED`, `UNBLOCKED`, `denied` (10 s deduplication per `program > dest`), and `mode` transitions; Go also enforces `0700`/`0600` permissions, `O_NOFOLLOW`, and owner checks, and writes no `(popup)` lines.
- [x] Search input (`#search`) — **`deviation`**: **search and sorting done by the TUI** locally over row paths, rendered inline above the key hint line; bracketed pastes are sanitised and accepted only while search is open.
- [x] Confirmation, notice, key hint, and minimum-size lines — **`deviation`**: Go adds an inline `[y/N]` prompt / notice line, a one-line key hint footer (instead of Textual `Footer`), and a size warning screen below `80x20` where `q` quits.

### Egress Graph View (`snitch egress` / `e`)

- [x] Top-10 senders and top-5 destinations per sender + `+ N more` summary — **`same`**: shows up to 10 senders sorted by bytes sent, up to 5 destinations per sender, and a `+ N more` remainder line per sender (note: this `+ N more` destination summary in the egress graph is kept, unlike the `n more` tree rows removed in the overview).
- [x] Logarithmic bar scale and 8-level sparkline bars (` ▏▎▍▌▋▊▉█`, green → yellow → red) — **`same`**: 1 KiB floor, 2 KiB denominator floor, 0.04 minimum positive fraction, 8-cell block characters, 2 s refresh cadence.
- [x] `x via y` senders in egress graph — **`deviation`**: **no `x via y` senders (`popups-trace`)**; flows are grouped by `Who` (program name or path).
- [x] `in ` prefix for inbound destinations in egress graph — **`deviation`**: **no received bytes and no inbound rows (egress only)**.
- [x] Byte totals in egress graph — **`deviation`**: **byte totals since the daemon first saw a connection** (subtitle states `totals: connections active in last <window>, bytes counted since first seen`; also displays `byte counting is off` when `Status.Counting` is false).
- [x] Transfer rate in egress graph — **`deviation`**: **the rate over the daemon's last 10 s** (sums daemon-supplied `Entry.Rate` instead of computing delta bytes between 2 s TUI refreshes).

### Alert Popup View (`snitch ask`)

- [x] Alert popup terminal view (`snitch ask FILE`) — **`deviation`**: **no `watch`, `ask` and `baseline` verbs**; deferred to `popups-trace`.

## Overview Table Columns

In `snitch`, `DataTable.add_columns(" ", "connection", "last", "down", "up", "ok/denied", "rule")`:

- [x] `" "` (column 1: `[x]` / `[ ]` block indicator) — **`same`**: renders `[x]` (red) or `[ ]` (green); Go computes it locally as a prediction from `table.Cover` over overlay/program rules rather than `updateRuleButtons`.
- [x] `"connection"` (column 2: tree hierarchy with `│ ` guides, `v `/`> ` arrows, title) — **`same`**: renders `│ ` depth guides, `v `/`> ` disclosure arrows, and titles (without `x via y`, `Inbound`, or `n more` rows).
- [x] `"last"` (column 3: relative age of last activity) — **`same`**: formats time since `LastSeen` (`now`, `Ns`, `Nm`, `Nh`, `Nd`, `-`).
- [x] `"down"` (column 4: received bytes) — **`deviation`**: **no received bytes and no inbound rows (egress only)**; column removed in Go.
- [x] `"up"` (column 5: sent bytes, renamed `"sent"` in Go) — **`deviation`**: renamed `"sent"` and shows **byte totals since the daemon first saw a connection** rather than Little Snitch's window-scoped `bytesSent`.
- [x] `"ok/denied"` (column 6: allowed / denied counts) — **`same`**: renders `allow/deny` counts per row, highlighted in red when denied count > 0.
- [x] `"rule"` (column 7: effective verdict, renamed `"verdict"` in Go) — **`deviation`**: renamed `"verdict"` and displays the kernel's actual verdict reported by `snitchd` (e.g. `allow-default`, `deny-rule`) rather than Little Snitch's `updateRuleButtons` label (`allowByDefault`, `denyByRule`).

## Verbs

Every verb in Python's `argparse` `choices=["overview", "egress", "watch", "ask", "status", "default", "baseline"]`, plus Go additions:

- [x] `(no verb)` / `overview` — **`deviation`**: invoking `snitch` with no verb opens the overview (**`same`**); however, passing the literal word `snitch overview` exits `2` as an unknown command in Go (whereas Python accepted both no verb and `overview`).
- [x] `egress` (`snitch egress`) — **`same`**: opens the TUI directly on the egress graph view.
- [x] `watch` (`snitch watch`) — **`deviation`**: **no `watch`, `ask` and `baseline` verbs**; background popup watcher is deferred to `popups-trace`.
- [x] `ask` (`snitch ask FILE`) — **`deviation`**: **no `watch`, `ask` and `baseline` verbs**; alert popup command is deferred to `popups-trace`.
- [x] `status` (`snitch status`) — **`deviation`**: prints the same Waybar JSON (`text` with `\U000F0498`/`\U000F0499` shield + 1 h denied count, `class` `allow`/`deny`/`down`, `tooltip`) and exits `0`, **but** queries `snitchd` over the Unix socket with an 800 ms timeout and ignores `config.toml` instead of reading `/var/lib/littlesnitch/...` and `$XDG_RUNTIME_DIR/snitch/status.json`.
- [x] `default` (`snitch default deny|allow [--keep]`) — **`deviation`**: keeps `snitch default deny|allow [--keep]` CLI syntax, **but** sends `trial`/`keep`/`end` RPCs to `snitchd` over the Unix socket (5 s per-RPC timeout, 0.6 s `[y/N]` terminal confirmation when the daemon asks a question) instead of calling `sudo`, `snitch-trial`, `systemctl`, `baseline`, or `pkill waybar`.
- [x] `baseline` (`snitch baseline [--dev]`) — **`deviation`**: **no `watch`, `ask` and `baseline` verbs**; `snitchd` loads declarative baseline and program rule files directly rather than injecting imperative rules from the client.
- [x] `tray` (`snitch tray`) — **`deviation`**: new verb in the Go binary (StatusNotifierItem desktop tray client from `kde-tray`; absent in the Python client).
- [x] `-version` / `--version` — **`deviation`**: new in the Go binary (prints build version and exits `0`; absent in the Python client).

## CLI Flags

- [x] `--since` (`--since WINDOW`, also `-since` in Go) — **`deviation`**: selects the starting time window in overview and `egress`, **restricted to the daemon's five time windows only** (`15m`, `30m`, `1h`, `24h`, `7d`; exit `2` otherwise) and accepted only on overview/`egress` (rejected on `status`/`default`, whereas Python's `argparse` parsed it globally).
- [x] `--dev` (`snitch baseline --dev`) — **`deviation`**: removed along with the `baseline` verb (**no `watch`, `ask` and `baseline` verbs**).
- [x] `--keep` (`snitch default deny --keep`, also `-keep` in Go) — **`deviation`**: keeps enforce mode across deadlines and reboots, **but** sends a `keep` RPC to `snitchd` instead of deleting `/var/lib/snitch-trial/deadline` via `sudo`.
- [x] `-h` / `--help` (`argparse` help) — **`deviation`**: not implemented in Go; unknown flags print an error and the one-line usage string with exit code `2`.
- [x] `-api PATH` / `--api PATH` — **`deviation`**: new flag in Go selecting the `snitchd` Unix socket (default `/run/snitch/api.sock`; overview, `egress`, `status`, and `default` accept both `-api PATH` and `--api PATH`, whereas `tray` accepts `-api PATH` only); Python hardcoded `ws://127.0.0.1:3031/stream`.
- [x] `-ask all|enforce` (`snitch tray`) — **`deviation`**: new flag in Go for the `tray` verb.
- [x] `-operator-file PATH` (`snitch tray`) — **`deviation`**: new flag in Go for the `tray` verb (default `/etc/snitch/operator`).

## Configuration Keys (`~/.config/snitch/config.toml`)

- [x] `periods` (default `["15m", "30m", "1h", "24h", "7d"]`) — **`deviation`**: same default, **restricted to the daemon's five time windows only** (`15m`, `30m`, `1h`, `24h`, `7d`); empty lists or other durations fail with exit `2`.
- [x] `since` (default `"1h"`) — **`deviation`**: same default, **restricted to the daemon's five time windows only** (`15m`, `30m`, `1h`, `24h`, `7d`); ignored by `snitch status`.
- [x] `protect` (Python code default `["hypr-rdp", "sshd", "littlesnitch"]`, docstring `["hypr-rdp", "sshd"]`) — **`deviation`**: Go defaults to `["hypr-rdp", "sshd"]` (without `"littlesnitch"`), and `config.toml` entries only **add** to this floor so `hypr-rdp` and `sshd` stay protected even if omitted in `config.toml`.
- [x] `resort` (default `[10, 20]`) — **`same`**: positive whole-second intervals cycled by `s`; Go rejects empty or non-positive values with exit `2`.
- [x] `temporary` (default `"15m"`) — **`deviation`**: ignored without error by `conf.Load` because **no `watch`, `ask` and `baseline` verbs** exist yet; popup keys return with `popups-trace`.
- [x] `snooze` (default `"10m"`) — **`deviation`**: ignored without error by `conf.Load` because **no `watch`, `ask` and `baseline` verbs** exist yet; popup keys return with `popups-trace`.
- [x] `trial` (default `"10m"`) — **`deviation`**: same default, **but** parsed via `time.ParseDuration` and bounded to `1m`..`1h` (exit `2` outside bounds) to match `snitchd` (and ignored by `snitch status`).
- [x] `session` (default `"/usr/bin/start-hyprland"`) — **`deviation`**: ignored without error by `conf.Load` because **no `watch`, `ask` and `baseline` verbs** (and no `x via y` senders) exist in this binary.
- [x] `terminal` (default `"foot --app-id=snitch-alert -e"`) — **`deviation`**: ignored without error by `conf.Load` because **no `watch`, `ask` and `baseline` verbs** exist yet; popup keys return with `popups-trace`.
