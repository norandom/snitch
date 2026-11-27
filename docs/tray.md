# `snitch tray`: the KDE tray

`snitch tray`, run as an ordinary user with no privileges, puts snitch into the KDE system
tray: one item whose icon tells the daemon's state at a glance, a menu with the daemon's
facts, and questions with Allow and Block. It talks to the daemon's
[API](daemon.md#api) — everything it shows comes from `/run/snitch/api.sock` — and the only
thing it ever writes is the rule an operator clicked, through the daemon's `rule.add`.

By hand:

```sh
snitch tray
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

## States

The icon alone tells whether anything is enforced or wrong; when more than one
condition holds, the first that holds in this order wins: daemon not running, kill switch
set, rules error, enforce kept, enforce trial, monitor. The first three also mark the item
as needing attention, so the desktop does not hide them among the inactive ones. The icon
set is drawn by the program, not loaded from a theme: the six states differ in shape and
every stroke carries a light halo, so they read on a light and on a dark panel. The images
here are the 44 px ones; this directory holds both sizes (the 22 px pair is the panel's).

| | state | the icon says |
|---|---|---|
| ![tray icon: daemon not running](tray-gone-44.png) | **daemon not running** | dashed outline with a cross: snitchd's API is unreachable — not started, gone, or 10 s silent (the tooltip then says "not answering"). The tray retries on its own |
| ![tray icon: kill switch set](tray-kill-44.png) | **kill switch set** | red slash: the kernel allows everything until the switch is cleared |
| ![tray icon: rules error](tray-rules-error-44.png) | **rules error** | amber exclamation mark: the daemon's last rules load failed; the menu shows its error text in full |
| ![tray icon: enforce kept](tray-kept-44.png) | **enforce kept** | green shield: enforcement stays on, also across reboots, until it is unkept |
| ![tray icon: enforce trial](tray-trial-44.png) | **enforce trial** | shield half filled: a timed trial runs; the tooltip carries its deadline in local time and the minutes left |
| ![tray icon: monitor](tray-monitor-44.png) | **monitor** | plain outline: deny by rule only; connections no rule covers are allowed and reported |

The tooltip names the state in words — and every other condition that holds too — plus
`learning` while the daemon learns and `questions paused` while questions are paused.

## Menu

One click on the item opens the facts of `snitchd status`, with the state as the
first row (`snitch: monitor` — or whatever holds): the Mode, the Trial (its deadline and
time left, or `no trial`), Enforce kept, the Kill switch, Learning, Loaded (programs and
rules), the Rules file, the Overlay file, the DNS tap (on with its names and compiled
counts, or off with the daemon's reason), and snitchd's version and start time. The Role row
says whether this user may answer questions. Fact rows are information, never clickable —
while the daemon is gone the menu says so and lists nothing stale. The only actions are
`Pause questions` (a ticked row that pauses and resumes questions for the running tray;
while paused the tray asks nothing, keeps nothing waiting) and `Quit`.

## Questions

When a connection that no rule covers is blocked (enforce) or allowed
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
rule (the overlay `/etc/snitch/rules.d/local.toml`, see the [API](daemon.md#api)) through
the daemon's `rule.add` — the tray never edits a file itself:

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

## Autostart

Start the tray with the Plasma session by copying one file,
`snitch-tray.desktop`, to `~/.config/autostart/`. The deb installs it under
`/usr/share/applications/`; in a checkout it is `desktop/snitch-tray.desktop`:

```sh
cp /usr/share/applications/snitch-tray.desktop ~/.config/autostart/
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

## What it cannot do

No mode ever changes from the tray: no menu entry and no verb starts,
keeps, unkeeps or ends a trial, sets or clears the kill switch, or changes the mode in any
other way — the operator decided against tray verbs; enforcement stays with `snitchd`. The
tray enforces nothing: the kernel decides with or without it, and hung, crashed or absent,
every verdict stays what it was. It writes only on the click: nothing but Allow and Block
reaches the daemon's `rule.add`, it edits no rule file, removes no rule, replaces no rule.
And a reader's tray cannot decide: without the operator role it shows and notifies but
answers nothing.

## Regenerating the icon images

The PNGs in this directory are written by the icon test into the directory
`SNITCH_TRAY_ICONS` names. From the repo root (the path must be absolute: `go test` runs in
the package's directory):

```sh
SNITCH_TRAY_ICONS=$PWD/docs go test ./internal/sni -run TestPixmapsPNGHelper
```
