# Requirements Document

## Introduction

The operator's terminal UI is still the Python client in the repo root, and it talks to Little
Snitch's web UI. Little Snitch was retired on the VM on 2026-10-11, so the overview, the egress
graph and one-key blocking exist only as a reference. This feature makes the Go `snitch` binary
the terminal UI of snitchd: `snitch` without a verb opens the overview (program › host ›
address), `e` shows the egress graph, `x` blocks and unblocks through overlay rules, the
operator runs the trial verbs from inside the TUI and from the command line, and
`snitch status` feeds a status bar. The Python client is the behavioural reference, key for
key; every deviation is listed with its reason. When the list is complete, the Python client
leaves the repo.

The TUI is a client. It changes the mode only on an explicit operator action, it writes a rule
only on a keypress, and whether it runs, hangs or crashes changes nothing in the kernel.

## Boundary Context

- **In scope**: the default verb of `snitch` (the overview) and the verbs `egress`, `status`
  and `default deny|allow [--keep]`; the overview table, the detail pane, the log pane, search,
  time windows and the two sort modes; the egress graph; block and unblock on program, host and
  address rows as overlay rules; the protection of critical programs; the trial verbs as keys
  in the TUI; the user's config file; resistance to other programs of the same user driving or
  deceiving the TUI; the parity list; retiring the Python client, `snitch-trial`, their units,
  lint and release assets; documentation and tests.
- **Out of scope**: the popups and the watcher (`snitch watch`, `snitch ask`) and the process
  trace behind a connection (popups-trace, not implemented yet; decided 2026-11-26 that tui
  does not wait for it); `snitch baseline` (rules are deployed files, not client writes);
  writing allow rules from the TUI (the second `x` removes the deny rule, decided 2026-11-26);
  extending a running trial (stays on `snitchd trial`); editing rules of the deployed rules
  file; received bytes and inbound connections (fail-safe 1: egress only); a stronger gate in
  the daemon for writes (authorising by more than the user; a spec of its own); fleet views
  (OpenObserve, Velociraptor); a remote transport; any change to snitchd, its API or the
  kernel programs; new views the Python client does not have.
- **Adjacent expectations**: the daemon's API (daemon-api) is used as documented in
  `examples/api.md` and stays unchanged: every local user reads, root and the operator named in
  `/etc/snitch/operator` write; the daemon validates, merges and applies overlay rules, runs
  the trial with its file deadline and boot revert (persistent-trial, fail-safe 5) and words
  its own outcomes, which the TUI shows as they are; names on entries come from dns-tap;
  connecting, reconnecting and resynchronising follow the behaviour kde-tray established for
  the tray; `snitch tray` and `snitch -version` keep their behaviour and exit codes; the VM
  repo deploys the binary and drops the Python client on its side.

## Mandatory Follow-up: the daemon's write gate

This spec leaves one gap open on purpose, and closing it is not optional.

- **The gap**: the daemon authorises a write by the user alone (the peer's uid on a socket
  every local user can open). Any program running under the operator's account can send
  `rule.add`, `rule.remove`, `trial` or `keep` to the socket itself, without the TUI or the
  tray. Requirement 13 makes the client hard to drive and hard to deceive; it cannot stop a
  program that does not use the client.
- **What is exposed**: removing a deny rule from the overlay and starting or keeping a trial
  in every mode; adding an allow rule for itself once enforce is on.
- **The follow-up**: a spec of its own, working name `write-gate`, that changes the daemon so
  that a loosening write (an allow rule, the removal of a deny rule) and a move toward enforce
  (`trial`, `keep`) need more than the operator's uid, while a tightening write (a deny rule,
  `end`, `unkeep`) stays as easy as it is. The way back to monitor must never become harder
  (fail-safes 3 to 5).
- **Order**: `write-gate` is specified before `popups-trace` is implemented, because the
  popups add the allow answer in a terminal, and before deny by default is kept on any host
  beyond a timed trial.
- **Until then**: the documentation of this feature states the gap in plain words
  (Requirement 13, criterion 12), and the journal's line for every write remains the record.

## Requirements

### Requirement 1: The overview as the default verb

**Objective:** As the operator, I want `snitch` to open the overview of who talks to where, so
that I see the host's egress in the terminal I already work in.

#### Acceptance Criteria

1. When `snitch` is started without a verb in a terminal, the snitch binary shall open the
   overview: a header line, the connection table, a detail pane, a log pane and a line listing
   the keys.
2. The overview shall show the daemon's connections of the selected time window as a tree of
   three levels: program, then host, then address with port and protocol.
3. The overview shall list a program's addresses that have no known name under one group row
   titled `IP Addresses` below that program.
4. The overview shall show for every row: a block marker (`[x]` blocked, `[ ]` not), the
   title indented by level with an open/closed mark, the time since the last activity, the
   bytes sent, the allowed and denied counts, and the last verdict the daemon reported.
5. The overview shall show the bytes of sockets the daemon could not attribute as one row
   titled `unknown`, which cannot be opened or blocked.
6. When the overview starts, the overview shall show every program row closed.
7. The header shall show the time window, the number of programs, the sort mode, the daemon's
   mode with a running trial's deadline and remaining time, and the daemon's socket path.
8. While the kill switch is set or the daemon reports a stale heartbeat, the header shall say
   that everything is allowed and why.
9. When a daemon summary reports changed rows, the overview shall show the change within 2 s
   and keep the cursor on the row it was on.
10. If the terminal is too small to show the table, the overview shall show a one-line notice
    with the size it needs instead of a broken layout.
11. If `snitch` is started without a verb and its input or output is not a terminal, the snitch
    binary shall print one error line and exit with status 1.
12. If a verb is unknown, the snitch binary shall print the usage and exit with status 2.

### Requirement 2: Moving, opening and inspecting

**Objective:** As the operator, I want the Python client's movement keys and its detail pane,
so that my hands need no retraining.

#### Acceptance Criteria

1. When up or down is pressed, the overview shall move the cursor one row; page up, page down,
   home and end shall move it by a page or to the first or last row.
2. When enter, right or `l` is pressed on a closed row that has rows below it, the overview
   shall open that row one level.
3. When left or `h` is pressed on an open row, the overview shall close it.
4. When left or `h` is pressed on a closed row or a row without rows below it, the overview
   shall move the cursor to that row's parent.
5. When the cursor moves to a row, the detail pane shall show for that row: its path
   (program › host › address), the program's name and executable, the name, address, port and
   protocol of the destination, the bytes sent and the current rate, when it was last allowed
   and last denied, the daemon's mode, and the effective rules that name the row's program,
   each with verdict, note and the file it comes from.
6. When `q` or ctrl+c is pressed, the snitch binary shall leave the terminal as it found it and
   exit with status 0.
7. The overview shall show the effect of a movement key within 100 ms with 4096 connections
   loaded.

### Requirement 3: Time window, sorting and search

**Objective:** As the operator, I want to choose the period, the order and a filter, so that I
find the connection I am looking for.

#### Acceptance Criteria

1. When `t` is pressed, the overview shall switch to the next configured time window and after
   the last one to the first.
2. When a digit `1` to `9` is pressed, the overview shall switch to the configured time window
   at that position; a digit beyond the list shall change nothing.
3. When the time window changes, the overview and the egress graph shall show the connections
   of the new window and the header shall name it.
4. The overview shall start sorted by activity: within every level, the rows with the most
   recent activity first.
5. While sorted by activity, the overview shall keep the order fixed between re-sorts, re-sort
   every 10 s, and place rows that appear in between at the top.
6. When `s` is pressed while sorted by activity, the overview shall switch the re-sort interval
   to the next configured one (10 s, 20 s by default), re-sort at once and show the interval.
7. When `s` is pressed while sorted by name, the overview shall sort by activity and show the
   re-sort interval.
8. When `S` is pressed, the overview shall sort the rows of every level by title without regard
   to case and say so.
9. When `/` is pressed, the overview shall open a search line; when enter is pressed there, the
   overview shall show only the rows whose path contains the text, without regard to case,
   together with their parents.
10. When escape is pressed, the overview shall close the search line, clear the search and show
    all rows again.
11. While a search is active, the header shall show the search text.

### Requirement 4: The egress graph

**Objective:** As the operator, I want to see which program sends how much to where, so that a
program phoning home stands out.

#### Acceptance Criteria

1. When `e` is pressed, the TUI shall show the egress graph in place of the table and the
   detail pane; when `e` is pressed again, the TUI shall show them again.
2. When `snitch egress` is started, the TUI shall open with the egress graph shown.
3. The egress graph shall show the ten programs that sent the most bytes, the largest first,
   each with its total, a bar, its current rate, and up to five destinations with their bytes
   and bars; further destinations of a program shall be summed in one line `+ n more`.
4. The egress graph shall name a destination by its name when the daemon knows one and by its
   address otherwise.
5. The egress graph shall scale every bar logarithmically from 1 KiB to the largest flow shown,
   so that a small flow next to a large one stays visible.
6. While the egress graph is shown, the TUI shall refresh it every 2 s.
7. The egress graph shall say in its heading what the totals cover: the connections active in
   the time window, with the bytes the daemon has counted for them since it first saw them.
8. If nothing was sent in the time window, the egress graph shall say that it is collecting.
9. If the daemon reports that byte counting is off, the egress graph shall say so instead of
   showing empty bars.
10. While the egress graph is shown, the keys for the time window and for quitting shall work
    as in the overview.

### Requirement 5: Block and unblock with one key

**Objective:** As the operator, I want `x` to block what the cursor is on and to take the block
back, so that stopping a connection costs one key.

#### Acceptance Criteria

1. When `x` or space is pressed on an address row that is not blocked, the TUI shall ask the
   daemon for one deny rule: that row's program to that address, with the row's protocol and
   port.
2. When `x` or space is pressed on a host row or an `IP Addresses` row whose addresses are not
   all blocked, the TUI shall ask the daemon for one deny rule per address listed under the row
   that is not blocked yet, each with its protocol and port.
3. When `x` or space is pressed on a program row that is not blocked, the TUI shall ask the
   daemon for a deny rule from that program to every destination, any protocol and port.
4. When a program-level block is stored, the TUI shall say that the local network stays
   reachable (fail-safe 2).
5. The TUI shall name a declared program by its name and an undeclared one by its executable's
   path in the rule, and shall give every rule a note saying that the TUI wrote it and when.
6. When `x` or space is pressed on a row blocked by overlay rules of that row's own level, the
   TUI shall ask the daemon to remove exactly those rules, so that the destination is
   undecided again.
7. If `x` or space is pressed on a row that is blocked only by a rule of an enclosing row, the
   TUI shall say which row holds the rule and change nothing.
8. If `x` or space is pressed on an address in the local network, the TUI shall say that the
   local network is always allowed and write no rule; a host-level block shall leave such
   addresses out.
9. If `x` or space is pressed on a row whose program is unknown and has no executable path,
   the TUI shall say that no rule can name it and write no rule.
10. When the daemon answers a rule request, the TUI shall show the daemon's text as it is,
    for an accepted rule and for a refusal alike; this covers a reader's refusal and a deny
    that lives in the deployed rules file.
11. The overview shall mark a row as blocked when a deny rule of the effective rules covers
    it: an address row by its own rule or an enclosing one, a host or `IP Addresses` row when
    all its addresses are blocked, a program row by a program-level rule.
12. When the daemon announces changed rules, the overview shall show the new block markers
    within 2 s.
13. If a host-level block or unblock succeeds for some addresses and fails for others, the TUI
    shall say how many succeeded and show the first refusal's text.
14. The TUI shall write a rule only as the direct result of `x` or space, one keypress at a
    time.

### Requirement 6: Protection of critical programs

**Objective:** As the operator, I want a second keypress before I block a program my session
depends on, so that a slip of the finger does not cost me the session's outbound side.

#### Acceptance Criteria

1. When `x` or space is pressed on an unblocked row whose program is in the protected list, the
   TUI shall not block and shall say `<program> is protected: press x again to block it`.
2. When `x` or space is pressed again on the same row directly after that message, the TUI
   shall block as in Requirement 5.
3. When the cursor moves to another row or any other key is pressed after the message, the TUI
   shall drop the armed state.
4. The TUI shall unblock a protected program's row without a second keypress.
5. The protected list shall always contain `hypr-rdp` and `sshd`; the config file can add
   programs to it and cannot remove these two.

### Requirement 7: The log

**Objective:** As the auditor, I want a record of what was blocked, unblocked and denied, so
that I can reconstruct what happened.

#### Acceptance Criteria

1. When the overview starts, the log pane shall show the last five lines of the log file
   `~/.local/state/snitch/snitch.log`.
2. When a block is stored, the TUI shall add a line `BLOCKED <path>` with the local date and
   time to the log pane and the log file; when a block is removed, a line `UNBLOCKED <path>`.
3. When the daemon reports a denied connection, the TUI shall add a line
   `denied <program> > <destination>` to the log pane and the log file, at most once per 10 s
   for the same program and destination.
4. When the mode changes, the TUI shall add a line with the daemon's reason to the log pane and
   the log file.
5. If the log file cannot be written, the TUI shall say so once in the log pane and keep
   working.

### Requirement 8: The trial verbs in the TUI

**Objective:** As the operator, I want to start, keep and end an enforce trial from the TUI,
so that I can try deny by default while watching what it denies.

#### Acceptance Criteria

1. When `T` is pressed, the TUI shall ask for confirmation with the trial's duration and the
   local time at which it will end, and shall state that connections no rule allows are denied
   until then.
2. When the confirmation is answered with `y`, the TUI shall ask the daemon to start the trial
   for the configured duration (10 minutes unless the config file says otherwise); any other
   key shall cancel and say so.
3. If the daemon answers a trial request with a question of its own (no rules are loaded), the
   TUI shall show the daemon's question as it is and start the trial only after a second `y`.
4. When `K` is pressed, the TUI shall ask for confirmation, stating that enforce then stays
   beyond the deadline and across reboots, and shall ask the daemon to keep enforce only after
   `y`.
5. When `E` is pressed, the TUI shall ask the daemon to end the trial at once, without a
   confirmation: the way back to monitor is one key.
6. When `U` is pressed, the TUI shall ask the daemon to unkeep enforce at once, without a
   confirmation.
7. When the daemon answers a trial verb, the TUI shall show the daemon's text as it is, for an
   outcome and for a refusal alike.
8. While a confirmation is open, the TUI shall act on no key other than the answer.
9. When the daemon reports a mode change, the header shall show the new mode within 2 s,
   whoever caused it.
10. The TUI shall never start, extend or keep a trial without the keypress and the confirmation
    of this requirement, and shall leave the deadline and the boot revert to the daemon
    (fail-safe 5).

### Requirement 9: The mode from the command line and the status verb

**Objective:** As the operator, I want the Python client's command-line verbs for the mode and
for the status bar, so that scripts and the bar keep working.

#### Acceptance Criteria

1. When `snitch default deny` is run, the snitch binary shall ask the daemon to start a trial
   for the configured duration, print the daemon's text and exit with status 0.
2. If the daemon answers `snitch default deny` with its question about missing rules, the
   snitch binary shall print the question and continue only after `y` typed at a terminal;
   without a terminal it shall exit with status 1 and start nothing.
3. When `snitch default deny --keep` is run, the snitch binary shall ask the daemon to keep
   enforce, print the daemon's text and exit with status 0.
4. When `snitch default allow` is run, the snitch binary shall ask the daemon to return to
   monitor, whether a trial is running or enforce is kept, print the daemon's text and exit
   with status 0.
5. If the daemon refuses a `default` verb or cannot be reached, the snitch binary shall print
   the refusal or the reason on standard error and exit with status 1.
6. If `snitch default` is run without `deny` or `allow`, the snitch binary shall print the
   usage and exit with status 2.
7. When `snitch status` is run, the snitch binary shall print one line of JSON with the fields
   `text`, `class` and `tooltip` and exit with status 0.
8. The status line's `class` shall be `allow` in monitor mode, `deny` in enforce mode, and
   `down` when the daemon cannot be reached, the kill switch is set or the heartbeat is stale.
9. The status line's `text` shall be the shield symbol of the mode, followed by the number of
   destinations denied within the last hour when that number is not zero.
10. The status line's `tooltip` shall name the mode, a running trial's deadline, the number of
    destinations denied within the last hour, and the reason when the class is `down`.
11. The snitch binary shall finish `snitch status` within 1 s, also when the daemon does not
    answer.

### Requirement 10: Following the daemon

**Objective:** As the operator, I want the TUI to survive the daemon's restarts and my own slow
terminal, so that what I see is never silently stale.

#### Acceptance Criteria

1. If the daemon cannot be reached, the header shall say so with the reason, and the TUI shall
   keep trying until it connects or is quit.
2. While the daemon is not reachable, the TUI shall keep the last table visible, mark it as
   stale, and answer `x`, `T`, `K`, `E` and `U` with a message that the daemon is not
   reachable.
3. When the connection returns, the TUI shall load the table, the rules and the state anew and
   remove the stale mark.
4. When the daemon reports that it dropped messages for this client, the TUI shall load the
   table anew.
5. Where `-api PATH` is given, the snitch binary shall talk to the daemon's socket at that
   path instead of the default one.

### Requirement 11: Configuration

**Objective:** As the operator, I want my existing config file to keep working, so that the
switch to the Go binary needs no migration.

#### Acceptance Criteria

1. The snitch binary shall read `~/.config/snitch/config.toml` when it exists and work with
   the defaults when it does not.
2. The snitch binary shall honour the keys `periods` (default `15m`, `30m`, `1h`, `24h`,
   `7d`), `since` (default `1h`), `protect`, `resort` (default 10 and 20 seconds) and `trial`
   (default `10m`).
3. Where `--since WINDOW` is given, the overview shall start with that time window.
4. If `periods`, `since` or `--since` names a time window the daemon does not serve, the
   snitch binary shall print the windows it serves and exit with status 2.
5. If `trial` lies outside the daemon's bounds of one minute to one hour, the snitch binary
   shall say so and exit with status 2.
6. The snitch binary shall ignore the Python client's keys that belong to the popups
   (`temporary`, `snooze`, `session`, `terminal`) without an error.
7. If the config file cannot be parsed, the snitch binary shall name the file and the error and
   exit with status 2.

### Requirement 12: Fail-safes and roles

**Objective:** As the person who gets locked out when the firewall is wrong, I want the TUI
unable to cut my session by accident, so that the 2026-10-09 lockout cannot repeat from here.

#### Acceptance Criteria

1. The TUI shall change nothing on the host except through the daemon's API and its own log
   file.
2. If the TUI exits, hangs or is killed at any moment, the daemon's mode, rules and trial shall
   be what they were before.
3. The TUI shall offer no key and no verb that decides on inbound connections (fail-safe 1).
4. The TUI shall never present an address in the local network as blocked or blockable
   (fail-safe 2).
5. While the user is not the operator, the TUI shall show everything a reader may read, and
   every write shall end in the daemon's refusal shown as it is.
6. The snitch binary shall run as an ordinary user and shall not ask for elevated rights.

### Requirement 13: Resistance to other programs of the same user

**Objective:** As the operator, I want the TUI hard to drive and hard to deceive for another
program running under my account, so that a program cannot quietly unblock itself or start a
trial through my own tool.

The limit is stated, not hidden: the daemon authorises a write by the user alone, so a program
of the operator's account can send the same request itself. Closing that is the daemon's part
and a spec of its own; this requirement covers what the client can do.

#### Acceptance Criteria

1. When a confirmation opens, the TUI shall discard the keys typed before it appeared and
   ignore every key for the first 0.6 s.
2. The TUI shall treat pasted text as text only: no character of a paste shall block, unblock,
   answer a confirmation or run a trial verb.
3. The TUI shall show every string that comes from the daemon (program names, executable
   paths, destination names, rule notes, the daemon's own texts) with control characters,
   escape sequences and characters that change the writing direction removed or made visible,
   so that no such string can move the cursor, recolour or overwrite another part of the
   screen.
4. The log file shall receive the same cleaned strings, one line per entry.
5. The detail pane shall show the executable's full path, shall mark a program that no rule
   file declares, and shall mark an executable whose directory someone other than root can
   write to (the directory does not belong to root, or is writable by its group or by
   others), because such a program can be replaced without root.
6. The TUI shall show a destination name that contains characters outside ASCII in its ASCII
   (punycode) form.
7. When a name or path is too long for its column, the TUI shall shorten it in the middle and
   keep its end visible: the last labels of a name, the file name of a path.
8. If the socket the snitch binary connected to does not belong to root, the snitch binary
   shall refuse to write through it and shall mark everything it shows as not coming from the
   system daemon; `snitch status` shall then report the class `down` and say why.
9. The snitch binary shall open no listening socket and no named pipe, and shall keep no
   runtime file that another program could write to influence it; `snitch status` shall ask
   the daemon itself.
10. The snitch binary shall create its log file readable and writable by the user only, in a
    directory of the same kind, and shall refuse to write a log file that is a symbolic link
    or belongs to another user, saying so once.
11. While the snitch binary runs, another program of the same user shall not be able to attach
    to it as a debugger or read its memory.
12. The documentation shall say that the log file is a convenience and the daemon's journal is
    the audit record, that the measures of this requirement do not hold on an X11 session or
    against a program that sends requests to the daemon itself, and that the autostart entry
    and the status bar should call the binary by its absolute path.

13. When this feature is released, the roadmap shall list the `write-gate` spec of the
    section Mandatory Follow-up as open and ordered before `popups-trace`, and the release
    notes shall name the gap.

### Requirement 14: Parity list and retiring the Python client

**Objective:** As the maintainer, I want one checked list of every key, view and verb of the
Python client, so that retiring it is a decision on evidence.

#### Acceptance Criteria

1. The repository shall contain a parity list that names every key, view, column, verb, flag
   and config key of the Python client, each marked as the same in the Go binary or as a
   deviation with its reason.
2. The parity list shall record at least these deviations: no received bytes and no inbound
   rows (egress only); no `x via y` senders and no process trace (popups-trace); no `n more`
   rows; search and sorting done by the TUI; the daemon's five time windows only; byte totals
   since the daemon first saw a connection; the rate over the daemon's last 10 s; unblock
   removes the rule; the new keys `T`, `K`, `E`, `U`; no `watch`, `ask` and `baseline` verbs.
3. When every item of the parity list is checked against the running binary, the Python
   client `snitch`, `snitch-trial`, their service and timer units, the Python lint and code
   scanning jobs and their two release assets shall leave the repository.
4. When the Python client has left, the release shall ship the Go binary so that an installed
   `snitch` opens the overview and `snitch tray` still starts the tray.
5. When the Python client has left, the repository's documentation and steering shall no
   longer name it as the operator UI or as the reference, and shall say that popups return
   with popups-trace.
6. The release build of the snitch binary shall stay a static binary that needs no runtime
   beyond the kernel.

### Requirement 15: Documentation and verification

**Objective:** As the maintainer, I want the TUI documented and checkable without root, so that
a change to it is reviewed like the rest of the repo.

#### Acceptance Criteria

1. The documentation shall list every key and verb of the snitch binary, the config keys, the
   exit codes, and an example of the status verb in a status bar.
2. The tests shall cover the overview, the egress graph, block and unblock, the protection,
   the trial confirmations, the status verb and the reconnect behaviour without root, without
   a running daemon and without a terminal.
3. The tests shall feed the TUI hostile strings (escape sequences, control and
   direction-changing characters, over-long and non-ASCII names) in every field the daemon
   supplies, a paste containing action keys, keys typed ahead of a confirmation, and a socket
   that does not belong to root.
4. The verification shall include one run on the development VM against the deployed daemon in
   monitor mode: the overview, the egress graph, one block and its removal, and the status
   verb.
5. The verification shall start a trial from the TUI only with the operator's explicit go and
   an open way back, and shall end it before the check finishes.
