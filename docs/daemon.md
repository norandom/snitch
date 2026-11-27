# `snitchd`: the daemon

`snitchd` decides at `connect()` and unconnected `sendmsg()` in the kernel (BPF LSM),
keyed by the program's executable and the destination. Rules from a file, learning mode,
bounded enforce. Needs Linux >= 6.12 with the `bpf` LSM active.

This file is the operator's reference: running the daemon by hand, the rules file, the
fail-safes, rules by name, the systemd units, the trial verbs and the API. For the install
steps see the [README](../README.md#install); for the user binary see [tui.md](tui.md) and
[tray.md](tray.md).

## Run it by hand

```sh
go build -o /tmp/snitchd ./cmd/snitchd
sudo /tmp/snitchd -rules examples/rules.toml -duration 60s           # monitor: report, deny by rule only
sudo /tmp/snitchd -learn -learned /tmp/learned.toml -duration 60s    # learn: write what connected, as rules
sudo scripts/enforce-test.sh --check-only                            # the enforce test's safe phase
```

`snitchd -version` prints the release tag (`dev` for a plain `go build`), and
`snitchd check -rules FILE` validates a rules file without root.

## Rules

[`examples/rules.toml`](../examples/rules.toml) explains every field and the precedence.
Programs are paths or globs, resolved to the executable's identity; rules are program (or
`any`), address/prefix or name, proto, port, allow or deny (names are allow only). The file is
reloaded within 5 s of a change, executables are checked every 10 s, `SIGHUP` reloads at once;
a broken file keeps the previous rules.

## Fail-safes

Fail-safes live in the kernel program, not in rules: the local network is always allowed,
a stale heartbeat (daemon gone) allows everything, and the kill switch
`bpftool map update pinned /sys/fs/bpf/snitch/kill key 0 0 0 0 value 1 0 0 0` allows
everything until cleared (`value 0 0 0 0`). [`scripts/fail-open.sh`](../scripts/fail-open.sh)
does all of it from a console.

Enforce (deny by default) runs only bounded: `-mode enforce -duration …` through
`scripts/enforce-test.sh`, which resets everything in a trap, or as a [trial](#trial).

The kernel programs carry runtime contracts that fail open and count their violations, and
the daemon serves those counters in `status` (a non-zero contract counter means a bug, report
it). See [c-hardening.md](c-hardening.md).

## Names

A rule such as `program = "gh", to = "github.com", verdict = "allow"` allows
addresses learned for that name and its subdomains from this host's plain UDP DNS answers
(port 53, configured resolvers). The cache is host-wide: any matching name can allow a shared
CDN address for the rule's program. TCP 53, DoH, DoT and `/etc/hosts` supply no names; see
`examples/rules.toml` for the bounds and semantics. Egress decisions only: the DNS tap reads
answers to this host's own sockets, alters nothing, and can only add allow entries.
`-dns` defaults to true; `-dns=false` turns the tap off. Startup logs `dns tap on: N resolvers`
or `dns tap off: <reason>`. Events show names as `-> 1.1.1.1:443 (www.example.org)`;
`snitchd status` shows `dns: on seen N ignored N cache N names N compiled N` or
`dns: off: <reason>`.

## Service

`systemd/snitchd.service` runs the daemon as root from boot with the default rules
file (`/etc/snitch/rules.toml`), restarts it on failure and never passes `-mode`: the daemon
starts in monitor mode with the DNS tap on by default and follows the trial and kept-enforce
files under `/var/lib/snitch`.
`systemd/snitchd-trial-boot.service` is a oneshot ordered before it that runs
`snitchd end -at-boot`, so a trial that was open at shutdown is gone before anything can
enforce. The runtime directory `/run/snitch` is 0755 so that the API socket in it is
reachable by every local user (the status file there stays 0600, the daemon's own); the
operator file `/etc/snitch/operator` names the one user besides root who may write over the
[API](#api).

The deb unpacks both units and enables neither (see [ci-debs.md](ci-debs.md)). The `snitchd`
task of the [hyperland-forky-worker-vm](https://github.com/norandom/hyperland-forky-worker-vm)
repo deploys the binary (a release asset, pinned by version and sha256), the two units and the
operator file with the desktop user; that repo carries a copy of the two unit files, marked as
copies of these. By hand, without the deb, it would be:

```sh
sudo install -m 755 /tmp/snitchd /usr/local/sbin/snitchd
sudo install -m 644 systemd/snitchd.service systemd/snitchd-trial-boot.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now snitchd-trial-boot.service snitchd.service
sudo scripts/setup.sh                                                  # names who may write over the API
```

[`scripts/setup.sh`](../scripts/setup.sh) creates `/etc/snitch` (0755) and the operator file
(root-owned, 0644) naming the user who ran `sudo`; it refuses to replace another operator
without `--force`.

## Trial

With the service running (any daemon started without `-mode`), `sudo snitchd trial
10m` turns deny-by-default on for a bounded time (default 10 min, 1 to 60; verb flags such as
`-extend` go before the duration) and prints the deadline; `-extend` restarts the 60 minute
cap from now. `snitchd status` shows the daemon, mode, trial, kept, kill switch and rules, one
line each (exit 1 when the daemon is not running); `snitchd end` ends a trial early;
`snitchd keep`, only during a trial, makes enforce stay and prints the way back;
`snitchd unkeep` takes it back. The daemon follows the two files under `/var/lib/snitch` and
ends a trial itself at its deadline; a reboot ends an open trial (the boot oneshot above, and
the daemon checks the boot id itself). A kept enforce is the one exception, and it is a plain
file: `rm /var/lib/snitch/enforce` from a console removes it, and the kill switch
(`scripts/fail-open.sh`) overrides it meanwhile. `scripts/enforce-test.sh` runs the whole flow
as its phase 3 (`--skip-trial` leaves it out). On a deployed host,
`sudo scripts/deploy-check.sh` checks the service read-only (active, version, status, a rule
event and a monitor event in the journal) and `--trial` adds a prompted two-minute trial with a
trap that ends it.

## API

The daemon listens on `/run/snitch/api.sock` (`-api`; `-api ""` turns it off), JSON
lines in both directions: one request per line with an `id`, one reply or error with the same
`id`, and for subscribers the kernel's decisions as events (deduplicated within 10 s), a
summary of the changed connection-table rows every 2 s with bytes sent per socket, and a
`state` line on every mode, trial or rules change. Every local user reads (status, rules,
programs, learned, the table over a window of 15m to 7d); root and the user named in
`/etc/snitch/operator` also write: the four trial verbs, and rules added to or removed from
the overlay `/etc/snitch/rules.d/local.toml`, which is merged over the deployed file with
precedence. [`examples/api.md`](../examples/api.md) is the schema, with one example per
message type, the limits and the client one-liners; `scripts/api-check.sh`, run as the desktop
user, proves it against the running service.

Writes are authorised by the caller's uid alone today; hardening them is the planned
`write-gate` follow-up (see [tui.md](tui.md#limits)).
