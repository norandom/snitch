# snitch: network control for a thin client

This VM is a thin client for day-to-day work: reached over RDP, updated often, with agents
that keep working on a task while you're away. It should stay that easy to work on without
handing your data and your work to a mistake or a poisoned package. `snitch` and the away
lock are the two pieces for that:

* **snitch** puts [Little Snitch for Linux](https://obdev.at/littlesnitch-linux) in the
  terminal: see every connection, block it with one key, and get a popup for anything new.
* **hypr-away** locks the box while you're not connected: no passwordless sudo, no rule
  changes, no reading other processes' memory.

## The overview

![snitch: connections](list.png)

`snitch` (or a click on the shield in the bar) shows the daemon's own tree: process ›
host › address, with the details of the selected row below and the log at the bottom.

| key | |
|---|---|
| ↑ ↓ | move, the details follow |
| enter / → | open · ← close |
| `x` | block · `x` again unblocks (`[x]`) |
| `t`, `1`…`5` | time window 15m / 30m / 1h / 24h / 7d |
| `s` / `S` | sort by activity (re-sorted every 10 s, `s` again 20 s) / by name |
| `/` | search |
| `e` | egress graph |

Blocking `hypr-rdp` (your session) takes a second `x`.

## Where does the data go?

![snitch: egress graph](egress.png)

`e` (or a right-click on the shield) shows what each program sends, and where to: btop-style
bars on a log scale, so 12 GB and 50 KB are both visible, plus the live rate. The sender is the
program that really talks (`ktop`), with the one that started it in brackets.

## Alerts

![snitch: alert popup](popup.png)

With **deny by default**, a connection no rule covers is blocked and a popup asks:

| key | |
|---|---|
| `o` / `x` | allow / block from now on |
| `O` / `X` | allow / block for 15 minutes (`temporary` in the config) |
| esc | decide later (asks again after `snooze`, 10 min) |

Below the destination the popup shows a **trace**: the running process behind the connection
and how it was started (`session › terminator › bash › claude`, with PIDs; the session itself is
known and shown as `session`), its command line and working directory. Little Snitch only names
the program, so `snitch` looks the process up in `/proc` the moment the block arrives;
short-lived programs such as `curl` may have exited by then, and the popup says so.

The popup ignores keys for its first 0.6 s, so it can't catch an `o` or `x` you were typing
somewhere else. The program has to retry after you allow it; nothing is held open.

Every answer is an ordinary Little Snitch rule (*"snitch popup …"*): listed, editable and
deletable in the web UI, and 15-minute rules expire inside the daemon itself. Decisions and
blocks are logged to `~/.local/state/snitch/snitch.log`.

```sh
snitch default deny          # a trial: baseline first, back to allow after 10 min and at the next boot
snitch default deny --keep   # keep it
snitch default allow         # back
```

**Deny by default locked this box out once** (2026-10-09): RDP and SSH were cut, it took a
reboot and the Proxmox console. Right after Little Snitch (1.1.0) starts, and for connections
that already exist when it restarts, its per-program rules don't apply yet, so everything is
denied, the RDP session included. Hence:

* the local network is always allowed (a baseline rule for any program, both directions)
* Anthropic (Claude Code) is allowed for any program: rules with a program path take minutes to
  apply after Little Snitch starts, and some connections come without an identified program
* `snitch default deny` is only a trial: a root timer goes back to allow after `trial` (10 min),
  and an open trial at boot is ended before Little Snitch starts
* recommended: stay on allow, watch the overview and the egress graph, block with `x`

In the bar, the shield is solid for deny, an outline for allow, and red when the
popups aren't running (`snitch-watch.service`).

![the shield in the bar](bar.png)

### Dev tools and overnight jobs

Nobody answers popups while you're away, so jobs that run overnight need their rules before:

```sh
snitch baseline --dev
```

adds allow rules for the dev tools, each to its own hosts only: Claude Code → Anthropic,
Codex → OpenAI, Copilot / `gh` → GitHub, `git` (https and ssh) → GitHub / GitLab / Codeberg /
Gitea, `apt` from the session (sudo, deploys) → its repositories, `npm` → npmjs.org, `uv` / `pip` → PyPI,
`cargo` → crates.io, `go` → golang.org, `podman` → the registries, `helm` → chart sources and
the cluster on the local network, `kubectl` / `k9s` / `ktop` → the cluster, and the bar's quota
module.
Versioned installs are matched with narrow wildcards (`~/.local/share/claude/versions/*`), so
the rules survive updates. Each tool gets a rule for "started in the session" and one for
"running on its own"; there is no session-wide rule, which would open those hosts to
everything. General-purpose tools such as `curl` are left out on purpose: they get a popup.
Running it again only adds what's missing.

## The away lock

You are the pro while you're connected: nothing changes. When the RDP session is gone for
10 minutes (`away_grace_seconds`), `hypr-away` (root) locks:

* `sudo` asks for your password: agents still running on lose root
* nothing running as you can reach the Little Snitch UI: no rule changes, no "filter off"
* `ptrace_scope=1`: processes can't read each other's memory

Reconnect and it unlocks within seconds. "Connected" means a session from another machine,
served by the real `/usr/bin/hypr-rdp`, with picture data flowing, so a bare TCP connect
without the password, or a connection a local process makes itself, doesn't count.
`sudo journalctl -u hypr-away` shows every lock and unlock.

## What this does and doesn't stop

| | |
|---|---|
| ⚠️ a package phoning home | only with deny by default (popups); on allow you see it in the overview and block it with `x` |
| ✅ unattended agents doing something unplanned while you're away | no sudo, no new rules |
| ✅ malware adding allow rules while you're away | the UI is closed to your processes |
| ⚠️ malware while you're connected | you have passwordless sudo then, and that is root. Watch the popups and the egress graph |
| ⚠️ deny by default | cut RDP and SSH once (rules don't apply right after Little Snitch starts): only as a 10-minute trial |
| ⚠️ wildcards in rule paths | Little Snitch expands them on disk: `/**` hung its web server once. `snitch` refuses paths without two fixed leading components |
| ⚠️ the RDP password | stored in plain text in `~/.config/hypr-rdp/password`. Keep it different from your login password |
