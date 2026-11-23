## Introduction

snitchd decides in the kernel and tells what it knows over its local API, but on a KDE Plasma
desktop nothing listens: the indicator and the popups of the Python client belong to waybar and
Hyprland. This feature adds the first verb of the Go user binary, `snitch tray`: one system
tray item that shows the daemon's state at a glance, a menu with the daemon's facts, and desktop
notifications that ask about connections no rule covers, where the operator's answer becomes a
rule in the daemon's overlay.

The tray is a client. It never switches the mode, it writes a rule only when the operator
presses Allow or Block, and whether it runs, hangs or crashes changes nothing in the kernel.

## Boundary Context

- **In scope**: the `snitch` binary with the verbs `tray` and `-version`; the tray item, its
  states, tooltip and menu; following the daemon across restarts of either side; questions as
  desktop notifications for connections no rule covers, with Allow and Block; the answer as an
  overlay rule; notifications about state changes; a way to start the tray with the desktop
  session; documentation; tests without root and without a desktop, and a check on the KDE host.
- **Out of scope**: the trial verbs (`trial`, `keep`, `unkeep`, `end`) and any other mode change
  from the tray (decided 2026-11-23); listing, editing or removing rules (tui); the process
  trace behind a question and the terminal popup (popups-trace); the waybar status verb and
  anything Hyprland-specific (tui); installing snitchd or activating BPF LSM on the KDE host (a
  separate step with the operator's go); any change to snitchd, its API or the kernel programs;
  desktops other than KDE Plasma (they may work, they are not verified).
- **Adjacent expectations**: the daemon's API (daemon-api) is used as documented in
  `examples/api.md` and stays unchanged: reading for every local user, `rule.add` for root and
  the operator named in `/etc/snitch/operator`; the names on events and the DNS facts come from
  dns-tap; the daemon validates, merges and applies overlay rules and words its own outcomes,
  the tray shows that wording; the later specs popups-trace and tui reuse this feature's client
  and its rules for when to ask, so those rules are stated here once.

# Requirements Document

## Project Description (Input)
kde-tray: `snitch tray`, a system tray item for KDE Plasma that shows what snitchd is doing and asks about connections no rule covers, as the first verb of the Go user binary `snitch`.

Who: the operator, who now also works on a KDE Plasma host (chandali: Ubuntu 26.04, Plasma 6.6 on Wayland) besides the Hyprland dev VM, and who is the person locked out or left blind when the firewall's state goes unnoticed.

Current situation: snitchd v0.4.0 serves the local API on /run/snitch/api.sock (examples/api.md: status, subscribe with event, summary and state lines, rule.add into the overlay for the operator), and that document already names the tray as a client; but no Go client exists (cmd/snitch is planned, not created). The Python client's indicator is a waybar module (`snitch status`) and its popups open in `foot` through Hyprland; neither exists on KDE. On Plasma nothing shows a running enforce trial, a set kill switch, a daemon that is gone or a rules file that failed to load, and a connection nobody decided on goes by unseen in monitor mode and is silently denied in enforce mode. chandali has a StatusNotifier watcher and host and a notification server with actions; it has no snitchd yet (a separate step with the operator's go).

What should change: `snitch tray`, started in the Plasma session by an ordinary user, puts one icon into the system tray that tells the daemon's state at a glance (monitor, enforce trial with its deadline, enforce kept, kill switch, daemon not running, rules error); its menu lists the daemon's facts (mode, trial, kept, kill, learning, rule and program counts, rules error, DNS tap, version, whether this user is the operator); a KDE notification with Allow and Block appears for a connection no rule covers, rate-limited and deduplicated, and the operator's answer becomes an overlay rule through rule.add (Allow by name when the event has one, else by address; Block by address); state changes for the worse are notified; the tray reconnects on its own when the daemon or the tray host restarts. Decided 2026-11-23: no trial verbs in the menu; the tray never switches the mode; no change to snitchd, the API or the BPF programs; pure Go on the session bus through godbus/dbus/v5 (StatusNotifierItem, dbusmenu, org.freedesktop.Notifications). The API client and the question policy are packages the later specs popups-trace and tui reuse. Details and boundaries: brief.md in this directory and .kiro/steering/roadmap.md.

## Requirements

### Requirement 1: A tray item in the desktop session
**Objective:** As the operator on a KDE Plasma desktop, I want one command that puts snitch into
the system tray, so that the daemon's state is in view without a terminal.

#### Acceptance Criteria
1. When an ordinary user runs `snitch tray` in a desktop session with a system tray, the tray
   shall show exactly one snitch item within 5 s, without root and without any privilege.
2. If a tray is already running for the same user and session, then a second `snitch tray` shall
   exit with a message that names the running one, and shall add no second item.
3. If the session has no system tray yet or the tray's host restarts, then the tray shall keep
   running and its item shall appear, or reappear, within 10 s of the host being available.
4. When the user chooses Quit in the menu or the process receives a termination signal, the
   tray shall remove its item, close every notification it still has open and exit with
   status 0.
5. If no desktop session is reachable at start, then `snitch tray` shall exit with a non-zero
   status and one line that says so.
6. When `snitch -version` is run, the snitch binary shall print its release version and exit.
7. The feature shall provide a documented way to start the tray with the Plasma session, and
   the tray started that way shall behave as when started by hand.

### Requirement 2: The daemon's state at a glance
**Objective:** As the operator, I want the icon alone to tell me whether anything is being
enforced or is wrong, so that a trial, a kill switch or a dead daemon never goes unnoticed.

#### Acceptance Criteria
1. The tray shall show one of six states, distinguishable from each other by the icon alone:
   daemon not running, kill switch set, rules error, enforce kept, enforce trial, monitor.
2. While more than one condition holds, the tray shall show the first that holds in this order:
   daemon not running, kill switch set, rules error, enforce kept, enforce trial, monitor.
3. While the state is daemon not running, kill switch set or rules error, the tray shall mark
   the item as needing attention, so that the desktop does not hide it among inactive items.
4. The tooltip shall name the state in words, every other condition of 2.2 that holds, and,
   during a trial, the deadline in local time and the time left.
5. While a trial runs, the tooltip's time left shall be no more than 60 s behind.
6. While the daemon is learning, the tooltip shall say so.
7. The icons shall stay legible on a light and on a dark panel.

### Requirement 3: A menu with the daemon's facts
**Objective:** As the operator, I want the facts `snitchd status` prints one click away, so that
I do not need a terminal to see what is loaded and what failed.

#### Acceptance Criteria
1. When the user opens the item's menu while the daemon runs, the menu shall list: the mode;
   the trial deadline or that no trial runs; whether enforce is kept; the kill switch; learning;
   the numbers of programs and rules loaded; the rules file and the overlay file; the DNS tap as
   on with its name and compiled counts, or off with the daemon's reason; the daemon's version
   and start time; and whether this user may answer questions (operator) or only read.
2. While the daemon reports a rules error, the menu shall show the daemon's error text in full.
3. While the daemon is not running, the menu shall say so and shall list no stale fact of a
   daemon that is gone.
4. The menu shall offer Quit, and a switch that pauses and resumes questions (Requirement 5)
   for the running tray.
5. The menu shall offer no entry that starts, keeps, unkeeps or ends a trial, sets or clears
   the kill switch, or changes the mode in any other way.
6. The menu's facts shall be no older than the state shown by the icon.

### Requirement 4: Following the daemon
**Objective:** As the operator, I want the tray to stay truthful across restarts of the daemon,
so that I can trust the icon without restarting anything by hand.

#### Acceptance Criteria
1. When the daemon's mode, trial, kept state or rules change, the tray shall show the change
   within 5 s.
2. When the kill switch is set or cleared, a rules error appears or clears, or learning starts
   or stops, the tray shall show the change within 15 s.
3. When the daemon stops, dies or its API becomes unreachable, the tray shall show daemon not
   running within 5 s.
4. If the daemon's API accepts the connection but does not answer for 10 s, then the tray shall
   show daemon not running and say "not answering" in the tooltip.
5. While the daemon is not running, the tray shall retry on its own, no more often than once a
   second and at least once every 30 s, and shall show the daemon's state within 5 s of a
   successful retry.
6. If the daemon reports that it dropped messages for this client, then the tray shall refresh
   its facts from the daemon instead of trusting what it has.
7. If the daemon runs without its API, then the tray shall show daemon not running; it shall not
   read the daemon's state by any other way.
8. If a line from the daemon cannot be understood, then the tray shall ignore that line, keep
   running, and record the fact once in its own log output.

### Requirement 5: Questions about connections no rule covers
**Objective:** As the operator, I want to be asked when a program reaches a destination nobody
decided on, so that an unexpected connection is noticed in monitor mode and can be allowed in
enforce mode without a terminal.

#### Acceptance Criteria
1. When the daemon reports a connection that no rule covered and that was denied by default
   (enforce), the tray shall raise a desktop notification that names the program, its executable
   path, the destination name when the daemon knows one, the address, the port, the protocol,
   and that the connection was blocked.
2. When the daemon reports a connection that no rule covered and that was allowed because the
   daemon monitors, the tray shall raise the same notification, saying that the connection was
   allowed and not yet decided on.
3. The tray shall raise no question for a connection a rule decided, a connection to the local
   network, or a connection allowed because the kill switch is set or the heartbeat is stale.
4. While a question for the same program (or the same executable path for an unknown program),
   destination, port and protocol is open, was answered, or was closed or left unanswered less
   than 10 min ago, the tray shall not ask about it again.
5. The tray shall have at most one question open at a time; further questions shall wait, at
   most 32 of them, the oldest shown next; when a 33rd arrives, the tray shall drop the oldest
   waiting one and count it.
6. While questions are waiting or were dropped, the open notification shall say how many wait
   and how many were dropped since the tray last had none waiting.
7. If a question is neither answered nor closed within 60 s, then the tray shall close it
   without writing a rule and treat it as left unanswered.
8. When the reason for a waiting question is gone (a rule now covers it, the mode changed so
   that its wording is wrong, or the daemon is gone), the tray shall discard it instead of
   showing it.
9. Where the user started the tray with questions in monitor mode switched off, the tray shall
   ask only about connections denied by default.
10. While questions are paused from the menu, the tray shall raise none and keep none waiting;
    the pause shall end when the user resumes it or the tray restarts, and the tooltip shall say
    that questions are paused.
11. The tray shall not ask about connections that happened before it connected to the daemon.

### Requirement 6: An answer becomes a rule
**Objective:** As the operator, I want Allow and Block on the question itself, so that a decision
takes one click and is an ordinary rule I can see, edit and remove later.

#### Acceptance Criteria
1. While the user is root or the daemon's operator, a question shall offer exactly two answers,
   Allow and Block, as explicit buttons.
2. When the operator presses Allow on a question whose connection has a destination name, the
   tray shall ask the daemon to add an overlay rule that allows that program to that name for
   the connection's protocol and port.
3. When the operator presses Allow on a question without a destination name, the tray shall ask
   the daemon to add an overlay rule that allows that program to that single address for the
   connection's protocol and port.
4. When the operator presses Block, the tray shall ask the daemon to add an overlay rule that
   denies that program to that single address for the connection's protocol and port, also
   when the connection has a name.
5. Where the program is one no rule file declares, the rule shall be asked for by the
   executable's path; if the daemon reported no path for it, then the question shall offer no
   answers and say that the program cannot be identified.
6. Every rule the tray asks for shall carry a note that says it came from the tray and when.
7. When the daemon accepts the rule, the tray shall show the daemon's outcome sentence in a
   notification that closes on its own.
8. If the daemon refuses the rule or does not answer within 10 s, then the tray shall show the
   daemon's error text, or that the daemon did not answer, shall write nothing itself, and shall
   allow the same connection to be asked about again without the 10 min wait.
9. While the user is neither root nor the operator, a question shall offer no answers and shall
   say that only the operator can decide.
10. When the user closes a question, clicks its body, or lets it expire, the tray shall write no
    rule; only Allow and Block write.
11. If an answer arrives for a question the tray no longer has open, then the tray shall ignore
    it and write no rule.
12. The tray shall write nothing except through the daemon's `rule.add`: it shall edit no rule
    file, and it shall never remove or replace a rule.

### Requirement 7: Notice of state changes
**Objective:** As the operator, I want to be told when the firewall's state changes, so that a
trial that starts or ends, or a daemon that dies, does not depend on my looking at the icon.

#### Acceptance Criteria
1. When a trial starts, the tray shall notify once with the deadline in local time.
2. When enforcement ends (the trial's deadline, the operator, or a boot revert), the tray shall
   notify once with the daemon's reason.
3. When enforce is kept or unkept, the tray shall notify once.
4. When the kill switch is set or cleared, the tray shall notify once.
5. When a rules error appears, the tray shall notify once with the daemon's error text; when it
   clears, once that the rules load again.
6. When the daemon stops answering and is still gone after 10 s, the tray shall notify once;
   when it is back, once; a restart shorter than 10 s shall produce no notification.
7. The tray shall not notify about the state it finds when it starts, and shall not notify for
   a rules reload that changes neither mode nor error.
8. State notifications shall carry no answers and shall never wait behind questions.

### Requirement 8: Fail-safes and privacy
**Objective:** As the person who gets locked out when the firewall is wrong, I want the tray to
be unable to cause a lockout or leak what it sees, so that running it is never a risk.

#### Acceptance Criteria
1. The tray shall never start, extend, keep, unkeep or end a trial, never touch the kill
   switch, and never send the daemon any request that writes other than `rule.add`
   (fail-safes 4 and 5).
2. If the tray is not running, hangs or crashes, then every kernel decision shall be what it
   would be without a tray (fail-safe 3 is the daemon's; the tray has no part in the heartbeat).
3. The tray shall never ask about, and never offer to block, a destination on the local network
   (fail-safe 2), and shall ask about egress only (fail-safe 1).
4. The tray shall run without root, and shall refuse to offer answers rather than ask for
   privileges.
5. What the tray learns from the daemon shall go only to the user's own desktop session
   (the tray item, its menu, notifications) and to the tray's own log output; the tray shall
   open no network connection.
6. If the notification service is unavailable or cannot offer buttons, then the tray shall keep
   showing state, shall raise questions without answers or none at all, and shall say in the
   menu that questions cannot be answered here.
7. While the tray waits for the daemon or the desktop, it shall use no measurable CPU: no busy
   loop, and no request to the daemon more often than once every 2 s outside an answer.

### Requirement 9: Documentation and verification
**Objective:** As the operator and as the implementer of the next specs, I want the tray's
behaviour written down and proven, so that popups-trace and tui build on it without rereading
the code.

#### Acceptance Criteria
1. The README shall describe `snitch tray`: the six states with their icons, the menu, the
   questions and what each answer writes, how to start it with the session, and what it cannot
   do (no mode changes).
2. The steering documents and `CLAUDE.md` shall record the `snitch` binary, the tray and the new
   dependency.
3. The feature's tests shall run without root, without a kernel program and without a desktop
   session, and shall prove the state order (2.2), the rules for asking (5.3 to 5.8), what each
   answer asks the daemon for (6.2 to 6.5), and reconnection (4.3 to 4.5) against a stand-in
   for the daemon.
4. When the release workflow runs, it shall build `snitch` as a static binary beside `snitchd`
   and publish it with its checksum; `snitchd` and its checksum shall be unchanged in name.
5. A check on the KDE host shall record, with a stand-in daemon and, once snitchd runs there,
   with the daemon in monitor mode: the item appears, each state shows, a question appears,
   Allow writes the expected overlay rule and Block the expected deny rule, and the tray
   survives a restart of the daemon and of the tray's host.
6. The code-shape caps and the lint of `tech.md` shall pass with the new binary included.
