# `snitch` Terminal UI and User CLI

`snitch` is the unprivileged user binary for `snitchd`. It talks only to the daemon's Unix socket (`/run/snitch/api.sock` by default) and never touches BPF maps or kernel state directly. Hanging, killing, or crashing `snitch` leaves the daemon's mode, rules, trial deadline, and kernel verdicts unchanged.

## Verbs and Flags

```
usage: snitch [egress | status | default | tray] | snitch -version
```

| Invocation | Behaviour |
|---|---|
| `snitch [-api PATH] [--since WINDOW]` | Default verb: opens the interactive connection overview (`program › host › address`). Requires `stdin` and `stdout` to be terminals. |
| `snitch egress [-api PATH] [--since WINDOW]` | Opens the interactive TUI directly on the egress graph view. Requires `stdin` and `stdout` to be terminals. |
| `snitch status [-api PATH]` | Queries the daemon once (800 ms timeout), ignores `config.toml`, prints one Waybar JSON line to `stdout`, and exits `0`. |
| `snitch default deny\|allow [--keep] [-api PATH]` | Starts an enforce trial (`deny`, duration from `trial` in `config.toml`), keeps enforce across deadlines and reboots (`deny --keep`), or returns to monitor mode and clears any trial/kept state (`allow`). Uses a 5 s per-RPC timeout; if the daemon asks a `[y/N]` question, requires a terminal, flushes typeahead, waits 0.6 s, and continues only on `y`. |
| `snitch tray [-api PATH] [-ask all\|enforce] [-operator-file PATH]` | Starts the StatusNotifierItem desktop tray client (defaults: `-ask all`, `-operator-file /etc/snitch/operator`). |
| `snitch -version` / `snitch --version` | Prints the build version (`dev` for an unlinked build) and exits `0`. |

Common flags:

- `-api PATH` / `--api PATH` (also `-api=PATH` / `--api=PATH` for overview, `egress`, `status`, `default`): daemon Unix socket path (default `/run/snitch/api.sock`).
- `--since WINDOW` / `-since WINDOW` (overview and `egress`): starting time window; must be one of `15m`, `30m`, `1h`, `24h`, `7d`.

## Keys

### Overview and Shared Keys

| Key | Where | Action |
|---|---|---|
| `up`, `down`, `pgup`, `pgdown`, `home`, `end` | overview | Move cursor by one row, one page, or to first/last row |
| `enter`, `right`, `l` | overview | Open a closed row one level |
| `left`, `h` | overview | Close an open row, or move to its parent row |
| `x`, `space` | overview | Block or unblock the selected program, host, `IP Addresses` group, or address via overlay rules (protected programs require a second `x` or `space` after the warning; any other key disarms) |
| `s` | overview | Sort by activity, cycling through the `resort` intervals |
| `S` | overview | Sort by name (case-insensitive) |
| `/` | overview | Open incremental search (`enter` applies, `backspace` deletes one rune, `esc` clears and closes) |
| `esc` | overview | Clear an active search filter or close search |
| `t` | overview, graph | Cycle to the next time window in `periods` |
| `1`, `2`, `3`, `4`, `5`, `6`, `7`, `8`, `9` | overview, graph | Jump to the 1st–9th time window in `periods` |
| `e` | overview, graph | Toggle between overview and egress graph |
| `T` | overview, graph | Start an enforce trial for the configured `trial` duration (opens `[y/N]` confirmation) |
| `K` | overview, graph | Keep enforce mode beyond the trial deadline and across reboots (opens `[y/N]` confirmation) |
| `E` | overview, graph | End enforce/trial and return to monitor mode immediately (no confirmation) |
| `U` | overview, graph | Unkeep enforce mode immediately (no confirmation) |
| `y` | confirmation | Confirm an open `[y/N]` prompt after the 0.6 s gate; any other non-repeat key cancels |
| `q`, `ctrl+c` | overview, graph | Quit and restore the terminal (`q` also quits when the terminal is below `80x20`) |

### Action-Key Guards

Before any write or mode-change key (`x`, `space`, `T`, `K`, `E`, `U`, `y`) is accepted:

1. Key repeat (`Repeat`) is ignored so a held key cannot toggle rules.
2. Keys arriving within 50 ms of the previous key are ignored (burst guard for terminals without bracketed paste).
3. While a confirmation prompt is open, all keys are ignored for the first 0.6 s.
4. If the daemon socket does not belong to `uid 0` (`FOREIGN (not root)`), writes are refused locally.
5. If the daemon is unreachable, writes are refused locally.

Bracketed pastes are routed only as sanitised text into an open search line and never trigger action keys.

## Configuration

`snitch` reads `~/.config/snitch/config.toml` for the overview, `egress`, and `default` verbs (`status` ignores it). When the file does not exist, built-in defaults apply.

| Key | Default | Description |
|---|---|---|
| `periods` | `["15m", "30m", "1h", "24h", "7d"]` | Non-empty ordered subset of the five daemon windows (`15m`, `30m`, `1h`, `24h`, `7d`) cycled by `t` and `1`–`9`. |
| `since` | `"1h"` | Starting time window; one of `15m`, `30m`, `1h`, `24h`, `7d` (overridden by `--since`). |
| `protect` | `["hypr-rdp", "sshd"]` | Programs requiring two `x` / `space` presses to block. Entries in `config.toml` only add to this floor; `hypr-rdp` and `sshd` stay protected. |
| `resort` | `[10, 20]` | Activity re-sort intervals in whole positive seconds, cycled by `s`. |
| `trial` | `"10m"` | Duration for `T` and `snitch default deny`; bounded to `1m`..`1h`. |

Popup keys from the retired Python client (`temporary`, `snooze`, `session`, `terminal`) and unknown keys are ignored without error.

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | Clean quit (`q` / `ctrl+c`), `SIGINT`/`SIGTERM`, `-version`, `status` (always exits `0`), or successful `default`. |
| `1` | `stdin` or `stdout` is not a terminal (`snitch` / `snitch egress`); `prctl(PR_SET_DUMPABLE, 0)` hardening failed; daemon refusal/error, declined prompt, or non-terminal confirmation in `default`; session-bus failure in `tray`. |
| `2` | Usage error (unknown verb or flag, missing flag value, extra arguments to `-version`) or invalid configuration (`--since` / `periods` / `since` naming an unserved window, `trial` outside `1m..1h`, empty `periods` or `resort`, unparseable `config.toml`). |
| `70` | Internal contract violation. The terminal is restored before the stack trace is printed to `stderr`; kernel decisions are unaffected. |

## Status Bar Example (Waybar)

Invoke `snitch status` by its absolute path in Waybar's custom module configuration:

```json
"custom/snitch": {
  "exec": "/usr/bin/snitch status",
  "return-type": "json",
  "interval": 5
}
```

`snitch status` outputs a single JSON object with `text`, `class`, and `tooltip`:

- `class`: `"allow"` in monitor mode, `"deny"` in enforce mode, or `"down"` if the daemon cannot be reached within 800 ms, the kill switch is set, or the socket is not owned by `uid 0`.
- `text`: shield icon (solid `\U000F0498` for `deny`, outline `\U000F0499` for `allow`/`down`), followed by the count of connections denied in the last hour when greater than zero.
- `tooltip`: sanitised multi-line summary of daemon state, mode/trial deadline, denied count, and any rules error.

## Limits

- **Log file vs. daemon journal**: `~/.local/state/snitch/snitch.log` (opened with `0700`/`0600` permissions, `O_NOFOLLOW`, and owner checks) is a local convenience for the TUI's log pane. The `snitchd` systemd journal is the authoritative audit record for every rule change and mode transition.
- **Client protections do not hold on X11 or against direct socket writes**: The TUI's defences against another program of the same user (0.6 s confirmation gate, paste isolation, 50 ms burst guard, repeat guard, terminal output sanitisation, `PR_SET_DUMPABLE = 0` anti-attach hardening, and `SO_PEERCRED` root check) do not hold in an X11 session, where other X11 clients can observe and inject input. They also cannot stop another program running under the operator's account from connecting to `/run/snitch/api.sock` directly and sending `rule.add`, `rule.remove`, `trial`, or `keep`, because the daemon currently authorises writes by peer UID alone (closing that gap is the planned `write-gate` follow-up).
- **The block marker is a prediction**: The `[x]` / `[ ]` marker is calculated locally from the rules and program metadata the daemon reports, following the kernel's lookup order. Port-range rules are reported by the daemon with port `0` and therefore appear wider in the marker than they are, and rules matched by DNS name stop matching a row if the daemon no longer attaches that name to the connection entry. The `verdict` column shows what the kernel actually did.
- **Use absolute paths in autostart and status bars**: Both desktop autostart entries (`Exec=/usr/bin/snitch tray`) and status bar modules (`"exec": "/usr/bin/snitch status"`) should call the binary by its absolute path (such as `/usr/bin/snitch`) so a modified `PATH` cannot shadow it.
