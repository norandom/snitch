# snitch

A firewall you can see: every connection your machine makes, as process › host › address, with
one key to block it, a graph of who sends how much to where, and popups when something nobody
has decided on tries to connect.

Two pieces:

- **`snitchd`** (this repo, Go): the daemon. It decides at `connect()` in the kernel (BPF LSM),
  keyed by the program and the destination, from rules in a file. Monitor mode reports and
  denies by rule only; deny-by-default runs as a bounded trial you can keep. It also learns
  DNS names from the host's own plain-UDP answers, so a rule can say `to = "github.com"`
  instead of a list of IPs. The kernel programs carry runtime contracts that fail open and
  count their violations, and the daemon serves those counters in `status` (a non-zero
  contract counter means a bug, report it). See [docs/c-hardening.md](docs/c-hardening.md).
- **`snitch`** (this repo, Go): the operator binary — Bubble Tea TUI (`overview` default and
  `egress` graph), `snitch status` JSON, `snitch default deny|allow [--keep]` trial verbs,
  `snitch tray` for KDE Plasma, and `-version` (see [docs/tui.md](docs/tui.md)). Alert popups
  (`watch`, `ask`) and process tracing return with `popups-trace`.

**Agentic layer 7 filter.** snitch is built to be the network guardrail for AI agents running on
a machine: an agent's `curl` or `git` shows up as its own row, gets its own rules, and with
`popups-trace` a denied connection in enforce mode asks with its process chain. That agentic
featureset is work in progress: today the shipped piece is a thin client over a VM (see the
[Hyprland thin client over RDP](https://github.com/norandom/hyperland-forky-worker-vm)), where
it runs with deny by default, and the rule engine, trial flow, and DNS learning described
below are what an agent host builds on. More agentic features (per-agent policies, automatic
baselining, popup triage) are planned on top of this.

## snitchd

`snitchd` decides at `connect()` and unconnected `sendmsg()` in the kernel (BPF LSM),
keyed by the program's executable and the destination. Rules from a file, learning mode,
bounded enforce.

```sh
go build -o /tmp/snitchd ./cmd/snitchd
sudo /tmp/snitchd -rules examples/rules.toml -duration 60s           # monitor: report, deny by rule only
sudo /tmp/snitchd -learn -learned /tmp/learned.toml -duration 60s    # learn: write what connected, as rules
sudo scripts/enforce-test.sh --check-only                            # the enforce test's safe phase
```

* Rules: `examples/rules.toml` explains every field and the precedence. Programs are paths or
  globs, resolved to the executable's identity; rules are program (or `any`), address/prefix
  or name, proto, port, allow or deny (names are allow only). The file is reloaded within 5 s of a change, executables are checked
  every 10 s, `SIGHUP` reloads at once; a broken file keeps the previous rules.
* Fail-safes live in the kernel program, not in rules: the local network is always allowed,
  a stale heartbeat (daemon gone) allows everything, and the kill switch
  `bpftool map update pinned /sys/fs/bpf/snitch/kill key 0 0 0 0 value 1 0 0 0` allows
  everything until cleared. `scripts/fail-open.sh` does all of it from a console.
* Enforce (deny by default) runs only bounded: `-mode enforce -duration …` through
  `scripts/enforce-test.sh`, which resets everything in a trap, or as a trial (below).
  Needs Linux >= 6.12.

**Names.** A rule such as `program = "gh", to = "github.com", verdict = "allow"` allows
addresses learned for that name and its subdomains from this host's plain UDP DNS answers
(port 53, configured resolvers). The cache is host-wide: any matching name can allow a shared
CDN address for the rule's program. TCP 53, DoH, DoT and `/etc/hosts` supply no names; see
`examples/rules.toml` for the bounds and semantics. Egress decisions only: the DNS tap reads
answers to this host's own sockets, alters nothing, and can only add allow entries.
`-dns` defaults to true; `-dns=false` turns the tap off. Startup logs `dns tap on: N resolvers`
or `dns tap off: <reason>`. Events show names as `-> 1.1.1.1:443 (www.example.org)`;
`snitchd status` shows `dns: on seen N ignored N cache N names N compiled N` or
`dns: off: <reason>`.

**Service.** `systemd/snitchd.service` runs the daemon as root from boot with the default rules
file (`/etc/snitch/rules.toml`), restarts it on failure and never passes `-mode`: the daemon
starts in monitor mode with the DNS tap on by default and follows the trial and kept-enforce
files under `/var/lib/snitch`.
`systemd/snitchd-trial-boot.service` is a oneshot ordered before it that runs
`snitchd end -at-boot`, so a trial that was open at shutdown is gone before anything can
enforce. The runtime directory `/run/snitch` is 0755 so that the API socket in it is
reachable by every local user (the status file there stays 0600, the daemon's own); the
operator file `/etc/snitch/operator` names the one user besides root who may write over the
API (see **API** below). Neither unit is installed or enabled here: the `snitchd` task of the
[hyperland-forky-worker-vm](https://github.com/norandom/hyperland-forky-worker-vm) repo deploys
the binary (a release asset, pinned by version and sha256), the two units and the operator file
with the desktop user; that repo carries a copy of the two unit files, marked as copies of
these. By hand it would be:

```sh
sudo install -m 755 /tmp/snitchd /usr/local/sbin/snitchd
sudo install -m 644 systemd/snitchd.service systemd/snitchd-trial-boot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now snitchd-trial-boot.service snitchd.service
echo "$USER" | sudo install -m 644 /dev/stdin /etc/snitch/operator     # who may write over the API
```

**Trial.** With the service running (any daemon started without `-mode`), `sudo snitchd trial
10m` turns deny-by-default on for a bounded time (default 10 min, 1 to 60; verb flags such as
`-extend` go before the duration) and prints the deadline; `-extend` restarts the 60 minute cap from now. `snitchd status` shows the daemon,
mode, trial, kept, kill switch and rules, one line each (exit 1 when the daemon is not
running); `snitchd end` ends a trial early; `snitchd keep`, only during a trial, makes enforce
stay and prints the way back; `snitchd unkeep` takes it back. The daemon follows the two files
under `/var/lib/snitch` and ends a trial itself at its deadline; a reboot ends an open trial
(the boot oneshot above, and the daemon checks the boot id itself). A kept enforce is the one
exception, and it is a plain file: `rm /var/lib/snitch/enforce` from a console removes it, and
the kill switch (`scripts/fail-open.sh`) overrides it meanwhile. `scripts/enforce-test.sh`
runs the whole flow as its phase 3 (`--skip-trial` leaves it out). On a deployed host,
`sudo scripts/deploy-check.sh` checks the service read-only (active, version, status, a rule
event and a monitor event in the journal) and `--trial` adds a prompted two-minute trial with a
trap that ends it.

**API.** The daemon listens on `/run/snitch/api.sock` (`-api`; `-api ""` turns it off), JSON
lines in both directions: one request per line with an `id`, one reply or error with the same
`id`, and for subscribers the kernel's decisions as events (deduplicated within 10 s), a
summary of the changed connection-table rows every 2 s with bytes sent per socket, and a
`state` line on every mode, trial or rules change. Every local user reads (status, rules,
programs, learned, the table over a window of 15m to 7d); root and the user named in
`/etc/snitch/operator` also write: the four trial verbs, and rules added to or removed from
the overlay `/etc/snitch/rules.d/local.toml`, which is merged over the deployed file with
precedence. `examples/api.md` is the schema, with one example per message type, the limits
and the client one-liners; `scripts/api-check.sh`, run as the desktop user, proves it against
the running service.

**Release.** Before tagging, run the two-door suite ([docs/rugged.md](docs/rugged.md)):
`dagger call rugged --fuzz-duration 30s` (every lint check incl. the bindings check, then a
fuzz run of every target), then `sudo scripts/root-checks.sh --at <commit>` on a host with
the `bpf` LSM, which loads the kernel programs and runs the hostile-input corpus and a
bounded monitor run. A tag `vX.Y.Z` runs the lint checks (`.github/workflows/lint.yml`, the
same jobs as on every push) and then the release lanes (`.github/workflows/release.yml`): the
static amd64 builds (position-independent, `-buildmode=pie`) with the tag linked in, plus the
deb. The lanes dispatch into the repo's Dagger module, so CI and a local `dagger call` run
the same pipeline (see [docs/ci-debs.md](docs/ci-debs.md)); a failing check publishes nothing. Six assets are published in one step:
`snitchd`, `snitchd.sha256` (the form `sha256sum -c` reads), the user binary
`snitch-linux-amd64` and its `snitch-linux-amd64.sha256` (see [The TUI](#the-tui) and [The tray](#the-tray) below),
and the deb `snitch_<version>_amd64.deb` with its `snitch_<version>_amd64.deb.sha256`.
`snitchd -version` prints the tag (`dev` for a plain `go build`), and `snitchd status` shows
it. The VM repo pins the version and the sha256 of the `snitchd` asset (see **Service** above).

## The tray

`snitch tray`, run as an ordinary user with no privileges, puts snitch into the KDE system
tray: one item whose icon tells the daemon's state at a glance, a menu with the daemon's
facts, and questions with Allow and Block. It talks to the **API** above — everything it
shows comes from `/run/snitch/api.sock` — and the only thing it ever writes is the rule an
operator clicked, through the daemon's `rule.add`.

By hand:

```sh
go build -o snitch ./cmd/snitch && ./snitch -version   # or -o /tmp/snitch
./snitch tray
```

`usage: snitch tray [-api PATH] [-ask all|enforce] [-operator-file PATH]`, the defaults
being `-api /run/snitch/api.sock`, `-ask all` and `-operator-file /etc/snitch/operator`
(the file that decides who may answer). The exit codes:

| exit | when |
|---|---|
| `0` | Quit in the menu, or SIGINT/SIGTERM: the item is removed, the name released, still-open notifications closed first |
| `1` | no desktop session (no session bus), the session bus lost, or a tray is already running (the message names its pid) |
| `2` | a usage error |
| `70` | a bug in the tray's own wiring (a contract violation; the kernel notices nothing) |

**States.** The icon alone tells whether anything is enforced or wrong; when more than one
condition holds, the first that holds in this order wins: daemon not running, kill switch
set, rules error, enforce kept, enforce trial, monitor. The first three also mark the item
as needing attention, so the desktop does not hide them among the inactive ones. The icon
set is drawn by the program, not loaded from a theme: the six states differ in shape and
every stroke carries a light halo, so they read on a light and on a dark panel. The images
here are the 44 px ones; `docs/` holds both sizes (the 22 px pair is the panel's), written
by the icon test into the directory `SNITCH_TRAY_ICONS` names — from the repo root,
`SNITCH_TRAY_ICONS=$PWD/docs go test ./internal/sni -run TestPixmapsPNGHelper` (the path
must be absolute: `go test` runs in the package's directory):

| | state | the icon says |
|---|---|---|
| ![tray icon: daemon not running](docs/tray-gone-44.png) | **daemon not running** | dashed outline with a cross: snitchd's API is unreachable — not started, gone, or 10 s silent (the tooltip then says "not answering"). The tray retries on its own |
| ![tray icon: kill switch set](docs/tray-kill-44.png) | **kill switch set** | red slash: the kernel allows everything until the switch is cleared |
| ![tray icon: rules error](docs/tray-rules-error-44.png) | **rules error** | amber exclamation mark: the daemon's last rules load failed; the menu shows its error text in full |
| ![tray icon: enforce kept](docs/tray-kept-44.png) | **enforce kept** | green shield: enforcement stays on, also across reboots, until it is unkept |
| ![tray icon: enforce trial](docs/tray-trial-44.png) | **enforce trial** | shield half filled: a timed trial runs; the tooltip carries its deadline in local time and the minutes left |
| ![tray icon: monitor](docs/tray-monitor-44.png) | **monitor** | plain outline: deny by rule only; connections no rule covers are allowed and reported |

The tooltip names the state in words — and every other condition that holds too — plus
`learning` while the daemon learns and `questions paused` while questions are paused.

**Menu.** One click on the item opens the facts of `snitchd status`, with the state as the
first row (`snitch: monitor` — or whatever holds): the Mode, the Trial (its deadline and
time left, or `no trial`), Enforce kept, the Kill switch, Learning, Loaded (programs and
rules), the Rules file, the Overlay file, the DNS tap (on with its names and compiled
counts, or off with the daemon's reason), and snitchd's version and start time. The Role row
says whether this user may answer questions. Fact rows are information, never clickable —
while the daemon is gone the menu says so and lists nothing stale. The only actions are
`Pause questions` (a ticked row that pauses and resumes questions for the running tray;
while paused the tray asks nothing, keeps nothing waiting) and `Quit`.

**Questions.** When a connection that no rule covers is blocked (enforce) or allowed
because the daemon monitors, a notification asks: the program, its executable path, the
destination name when the daemon knows one, the address, the port, the protocol — and
whether it was blocked or allowed, not yet decided on. Nothing is asked for a connection a
rule decided, the local network, one allowed by the kill switch or a stale heartbeat, or
anything that connected before the tray started; `-ask enforce` leaves only the denied ones
in. One question is open at a time, up to 32 wait (the 33rd drops the oldest; the open one
says how many wait and were dropped), a question nobody answers closes after 60 s, and the
same program (or path, for an unknown program), destination, port and protocol is not asked
about again for 10 min. Closing a question or
clicking its body writes nothing; only Allow and Block do, both as one ordinary overlay
rule (the overlay `/etc/snitch/rules.d/local.toml`, see **API** above) through the daemon's
`rule.add` — the tray never edits a file itself:

| answer | the rule written |
|---|---|
| Allow, destination known by name | allow that program to that name (its subdomains included) for the connection's protocol and port |
| Allow, no name | allow that program to that single address, for the connection's protocol and port |
| Block | deny that program to that single address — by address even when a name is known (the API refuses a deny by name), and a deny rule applies in monitor mode too |

Every rule carries the note `snitch tray` and the time; the daemon answers with its outcome
sentence (`rule added: …`), shown as a notification that closes on its own. A refusal or 10 s
of silence writes nothing — "rule not added", and the same connection may ask again at once.
Allow and Block appear only for root and the user named in `/etc/snitch/operator`; with no
buttons the question says so (`No answer here: only the operator can decide`), and a program
that cannot be identified says that instead. For the button guess the operator file must be
world-readable (0644, as the deployment creates it): a file the tray cannot read shows the
tray as a reader (one line on stderr explains), while the daemon keeps the last word on the
write.

**Autostart.** Start the tray with the Plasma session by copying one file,
`desktop/snitch-tray.desktop`, to `~/.config/autostart/`:

```sh
cp desktop/snitch-tray.desktop ~/.config/autostart/
```

The entry runs `snitch tray` at KDE's earliest autostart phase (safe: the item appears
within 10 s of the tray host, whatever order Plasma starts in), and needs `snitch` on PATH:
the deb installs it as `/usr/bin/snitch`, or from the release assets install
`snitch-linux-amd64` as `snitch`:

```sh
install -m 755 snitch-linux-amd64 ~/.local/bin/snitch
```

Started by the session it behaves exactly as when started by hand (a second start still
exits 1).

**What it cannot do.** No mode ever changes from the tray: no menu entry and no verb starts,
keeps, unkeeps or ends a trial, sets or clears the kill switch, or changes the mode in any
other way — the operator decided against tray verbs; enforcement stays with `snitchd`. The
tray enforces nothing: the kernel decides with or without it, and hung, crashed or absent,
every verdict stays what it was. It writes only on the click: nothing but Allow and Block
reaches the daemon's `rule.add`, it edits no rule file, removes no rule, replaces no rule.
And a reader's tray cannot decide: without the operator role it shows and notifies but
answers nothing.

## The TUI

Install `snitch_<version>_amd64.deb` (which installs `/usr/bin/snitch`), install the static
`snitch-linux-amd64` release asset as `~/.local/bin/snitch`, or build from source:

```sh
go build -o ~/.local/bin/snitch ./cmd/snitch
snitch                       # the overview
```

See [docs/tui.md](docs/tui.md) for all verbs, keys, configuration keys, and exit codes.

## The overview

![snitch: connections](docs/list.png)

`snitch` shows the daemon's connection tree (`program › host › address`), with the details of
the selected row below and the log (`~/.local/state/snitch/snitch.log`) at the bottom.

| key | |
|---|---|
| ↑ ↓ | move, the details follow |
| enter / → | open · ← close |
| `x` / `space` | block · `x` / `space` again unblocks (`[x]`, removes overlay rule) |
| `t`, `1`…`5` | time window 15m / 30m / 1h / 24h / 7d |
| `s` / `S` | sort by activity (cycles `resort`, default 10 s / 20 s) / by name |
| `/` | search |
| `e` | egress graph |
| `T` / `K` / `E` / `U` | trial / keep / end / unkeep enforce mode |

Blocking a protected process (`protect` in `~/.config/snitch/config.toml`: always at least `hypr-rdp`, `sshd`) takes a second `x`.

## Where does the data go?

![snitch: egress graph](docs/egress.png)

`e` (or `snitch egress`) shows what each program sends, and where to: btop-style bars on a
log scale (1 KiB floor), so large and small flows stay visible, plus the daemon's 10 s transfer rate.

## Trials, status, and alert popups

`snitch status` prints Waybar custom-module JSON (`text`, `class`, `tooltip`) queried from
`snitchd`. `snitch default deny|allow [--keep]` manages timed enforce trials through `snitchd`
(using `/var/lib/snitch` and `systemd/snitchd-trial-boot.service` for deadline and boot-time
revert):

```sh
snitch default deny          # start an enforce trial (reverts at deadline and on reboot)
snitch default deny --keep   # keep enforce across reboots
snitch default allow         # return to monitor mode immediately
```

Interactive alert popups (`snitch watch`, `snitch ask`) and `/proc`/kernel process traces (`x via y`)
are deferred to `popups-trace`. Decisions and blocks from the TUI are logged to
`~/.local/state/snitch/snitch.log`.

![the shield in the bar](docs/bar.png)

## What this does and doesn't stop

| | |
|---|---|
| ⚠️ a package phoning home | in monitor mode you see it in the overview and block it with `x`; interactive alert popups (`watch`/`ask`) return with `popups-trace` |
| ⚠️ deny by default | only as a bounded trial (`snitchd` + `/var/lib/snitch` deadline + `snitchd-trial-boot.service`), with local network, heartbeat, and kill-switch fail-safes |
| ⚠️ write authorisation (`write-gate`) | API writes currently authorise by caller uid (`/etc/snitch/operator`); hardening loosening writes (`write-gate`) precedes `popups-trace` |

## License

MIT, see [LICENSE](LICENSE).
