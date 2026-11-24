# Implementation Plan

Every task below is a self-contained brief for an implementer without conversation context.
Before a task, read `.kiro/steering/tech.md`, `.kiro/steering/fail-safes.md`, the design
sections named in the task (`.kiro/specs/kde-tray/design.md`), `research.md` in the same
directory, and `examples/api.md` for every wire shape. Conventions as in the earlier specs:
delegates (function values) for OS seams, contracts with a violation test each, immutable
values, every loop a `jobs.Job`, caps via `scripts/caps.sh` (functions at most 40 lines, files
at most 300, cyclomatic at most 10). `_Boundary:_` names the files a task may touch. A Go task
is done when its "Done when" command succeeds and `gofmt -l .`, `go vet ./...`,
`go test -race ./...` and `sh scripts/caps.sh` are clean.

Rules for this spec: nothing under `cmd/snitchd`, `internal/api`, `internal/rules`,
`internal/trial`, `internal/dns`, `internal/bpf`, `bpf/` or `examples/api.md` is edited. No task
needs root, a kernel program or a running snitchd. Never build with `-o snitch` in the repo
root: `snitch` there is the Python client; build to `/tmp/snitch`. D-Bus code lives only in
`internal/sni` and its test helper; tests that need a bus start a private `dbus-daemon` and skip
when it is not installed, and never touch the developer's real session bus. Tests tagged `live`
do use the real session bus of the KDE host (chandali); they are run by hand, never in CI.
The names of godbus calls in the design are from memory: read the module source before using
one. chandali is the development host of this spec: Go and this checkout are there, so live
tests and the host check run from the working tree. What a bus can assert (the item is
registered, a notification was posted) is asserted by the test; what only eyes can confirm (the
icon is visible, the menu opens) waits for the operator at the desktop and is recorded in
research.md. Pushes, tags and releases are not part of any task. Tasks in the same Go package run one
at a time; `(P)` tasks touch disjoint files.

- [ ] 1. Foundation: the binary, the session bus, the stand-in daemon
- [x] 1.1 The `snitch` binary's skeleton and its import pin
  - A second `main` package beside snitchd's, in the same shape: a bare word is a verb, `tray`
    is the only one and for now answers `snitch tray: not built yet` with exit 1; `-version`
    prints the linked-in version (`dev` for a plain build) and exits 0; anything else is a
    usage error with exit 2; a contract violation exits 70 with the stack, as in snitchd
  - A test pins the packages the binary may never import: the BPF bindings, cilium/ebpf, the
    rules, trial and dns packages (design, Allowed Dependencies); it reads the dependency list
    of the package and fails on a forbidden entry
  - Done when: `go build -o /tmp/snitch ./cmd/snitch && /tmp/snitch -version` prints `dev`,
    `/tmp/snitch nonsense` exits 2, and `go test ./cmd/snitch -run 'Version|Usage|Imports'`
    is green
  - _Boundary: cmd/snitch/main.go, version.go, main_test.go, imports_test.go_
  - _Requirements: 1.6, 4.7, 8.4, 8.5_
- [x] 1.2 The session bus: connect, single instance, and a private bus for tests
  - The godbus dependency enters the module here; the implementer reads the v5.2.4 source for
    the connection, name request, export, property and signal calls the design names and
    records the real names and any deviation in research.md
  - Opening the session bus (never the system bus) with a clear error when there is none;
    claiming the instance name without queueing, with an error that names the owner's pid
    when it is taken; closing
  - A test helper package starts a private `dbus-daemon` for a test, hands out its address and
    raw godbus connections and stops it with the test; it reports "not installed" so callers
    can skip. The helper imports godbus only, never `internal/sni` (the adapter's own tests
    import the helper); tests point the adapter at the private bus through
    `DBUS_SESSION_BUS_ADDRESS`, which is also how opening finds the session bus
  - Done when: `go test ./internal/sni/... -run 'Open|Claim'` proves on the private bus that a
    second claim fails naming the first one's pid, and that opening with an unreachable bus
    address returns the no-session error; without `dbus-daemon` the tests skip
  - _Boundary: go.mod, go.sum, internal/sni/bus.go, bus_test.go, internal/sni/snitest/bus.go,
    .kiro/specs/kde-tray/research.md_
  - _Requirements: 1.2, 1.5_
- [x] 1.3 (P) The stand-in daemon
  - The daemon's own API server with facts held in memory and scripted by commands: mode,
    trial, end, keep, unkeep, kill, rules error, learning, an event, refuse rule edits, quit;
    the operator uid is a parameter (the command-line tool passes the invoking user, a test
    may pass another uid to be a reader); a rule edit is recorded and answered with a rule
    sentence, or refused when told to; a trial or mode command emits the `state` line the
    real daemon would
  - The logic is a package tests can run in-process; the command-line tool reads the commands
    from stdin and prints each recorded rule edit as one JSON line on stdout
  - Done when: `go test ./internal/client/clienttest` proves that a scripted event reaches a
    subscribed connection, that `kill on` shows in the next `status`, and that a `rule.add`
    is recorded; `go run ./tools/fakedaemon -api /tmp/fake.sock` answers the `status` example
    of `examples/api.md`
  - _Boundary: internal/client/clienttest/standin.go, standin_test.go, tools/fakedaemon/main.go_
  - _Requirements: 9.3, 9.5_

- [ ] 2. The daemon channel and the question policy
- [x] 2.1 (P) The API client: one connection, kept alive, as messages
  - The message types of the design's Event Contract; one session per connection: the literal
    subscribe line (events on, local off, summary off), a first `status`, then lines in order
    as messages; `status` again every poll period, once after a `state` line and once after
    `dropped`, never two polls within 2 s; requests handed in with a caller's token and
    answered exactly once (the reply's text, the daemon's error, "the daemon did not answer"
    after the wait, or "the daemon is not running" without a session); the operator refusal
    marked on the answer; an unparsable or unknown line ignored and logged once per session
  - Reconnect as a job: `Down` once per loss with `not running` or, when a `status` stays
    unanswered for the wait, `not answering`; backoff from the minimum, doubling to the
    maximum, reset when a session is up; no `snapshot` request anywhere
  - Every delegate and duration is required by contract, with a violation test
  - Done when: `go test -race ./internal/client -run 'Session|Reconnect|Answer|Dropped|Garbage'`
    proves against the stand-in: `Up` then facts; one status per state line; `Down` and `Up`
    across a restart within the backoff bounds; a write as a reader (the stand-in's operator
    set to another uid; skipped under uid 0) answered with the role mark; and against a raw
    scripted listener in the test (the real server cannot be made to do these): `not
    answering` when it accepts and stays silent, one status after a `dropped` line, a garbage
    line logged once
  - _Depends: 1.3_
  - _Boundary: internal/client/msg.go, session.go, client.go, session_test.go, client_test.go_
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.8, 5.11, 6.7, 6.8_
- [x] 2.2 The role guess
  - Writer for uid 0 and for the user named on the first line of the operator file when the
    file is a regular file owned by root and not writable by group or others; reader
    otherwise and on any read error; file access through delegates
  - Done when: `go test ./internal/client -run Role` covers root, the named user, another
    user, a group-writable file, a file not owned by root, a missing file and an empty file,
    the same cases as snitchd's operator tests (`cmd/snitchd`, read for reference only)
  - _Boundary: internal/client/role.go, role_test.go_
  - _Requirements: 6.1, 6.9_
- [x] 2.3 (P) Which connection asks, and what an answer writes
  - A question from an event only for the verdicts `deny-default` and `allow-monitor`, the
    latter not in the enforce-only scope; never for a destination on the local network
    (the prefixes of fail-safe 2, IPv4-mapped included); the key: program name, or the path
    for an unknown program; the name when the event has one, else the address; protocol; port
  - The `rule.add` request of an answer by the table in the design's Data Contracts: Allow to
    the name or else the address, Block to the address, the event's protocol and port,
    `program` or `path`, the note `snitch tray <local time to the minute>`; an unknown program
    without a path is not answerable, and asking for its rule is a contract violation
  - Done when: `go test ./internal/ask -run 'From|Local|Key|RuleFor|Answerable'` covers the
    seven verdicts in both scopes, each local prefix, the four rule forms and the violation
  - _Boundary: internal/ask/question.go, rule.go, question_test.go, rule_test.go_
  - _Requirements: 5.1, 5.2, 5.3, 5.9, 6.2, 6.3, 6.4, 6.5, 6.6, 8.3_
- [x] 2.4 The waiting list
  - An immutable queue: one open question, at most 32 waiting, oldest first; an offer for a
    key that is open, waiting or snoozed is ignored; the 33rd drops the oldest waiting one
    and counts it; settling the open one as answered or unanswered snoozes its key for
    10 min, as failed does not; a flush drops waiting questions by a predicate without a
    snooze; the counts of waiting and dropped, the latter reset when nothing waits
  - Done when: `go test ./internal/ask -run Queue` proves each rule with a fake time,
    including that a key asks again after 10 min and that the invariant (a key in at most one
    of open, waiting, snoozed) holds after every operation of a random script
  - _Boundary: internal/ask/queue.go, queue_test.go_
  - _Requirements: 5.4, 5.5, 5.6_

- [ ] 3. The core: model, view, notices, questions, loop
- [x] 3.1 The model and what the desktop shows
  - The model value, the options, every message and effect type of the design's Service
    Interface (so the adapters of group 4 can compile against them), and the pure rendering:
    the six states in their order, attention for the first three, the title, the tooltip
    (state in words, every other condition that holds, the trial's deadline in local time
    and the minutes left, learning, paused, not answering), and the closed set of menu rows
    with the daemon's facts, the rules error in full, the role, the hint that questions
    cannot be answered here, the pause switch and Quit; with the daemon gone, no fact rows
  - Done when: `go test ./internal/tray -run 'State|Tooltip|Menu'` proves the state for all
    32 combinations of the five conditions, the tooltip's minutes left at two times, that
    the row set has no entry for a trial, the kill switch or the mode, and that a gone
    daemon shows no fact row
  - _Depends: 2.1, 2.4_
  - _Boundary: internal/tray/model.go, view.go, model_test.go, view_test.go_
  - _Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 3.1, 3.2, 3.3, 3.5, 3.6_
- [x] 3.2 Following the facts and giving notice
  - The update for the client's messages: up, down, facts, a state line (mode, trial and kept
    at once); the notices as the difference between the last known and the new facts: trial
    started (deadline in local time), enforcement ended (the state line's reason), kept,
    unkept, kill switch set or cleared, rules error appeared (its text) or cleared; the first
    facts after start are the baseline; a reload that changes neither mode nor error is
    silent; a daemon gone for 10 s is noticed once on the tick and once when it is back, a
    shorter gap not at all; notices carry no actions, close on their own and are posted at
    once; the model keeps the note id of every posted notice until its closed message, so
    that quitting can retract them; the note texts, plain
  - Every update ends with a show effect for the new view; a message type outside the
    design's list is a contract violation; the design's types this task does not handle yet
    (events, pressed, menu click, capabilities, stop) pass through unchanged until 3.3 to 3.5
    add them
  - Done when: `go test ./internal/tray -run 'Facts|Notice|Gone'` proves each notice from a
    pair of facts, the baseline, the silent reload, 9 s against 11 s of absence, and that a
    posted notice's id is remembered until it is closed
  - _Boundary: internal/tray/update.go, facts.go, notes.go, facts_test.go, notes_test.go_
  - _Requirements: 4.1, 4.2, 4.3, 4.4, 7.1, 7.2, 7.3, 7.4, 7.5, 7.6, 7.7, 7.8_
- [x] 3.3 Questions: asking and answering
  - An event becomes a question through the policy; when none is open the next is posted:
    program, path, name, address, port, protocol, blocked or allowed and not yet decided, the
    waiting and dropped counts; Allow and Block for a writer when the notification service
    has buttons; no actions and "only the operator can decide" for a reader; no actions and
    "the program cannot be identified" when not answerable; the capabilities message sets
    whether notes can be posted at all and whether they can carry actions
  - An answer counts only for the open question's note: retract, send the rule request under
    a token, settle as answered; the daemon's sentence becomes a notice; an error becomes a
    notice and lifts the snooze; the role mark turns the model into a reader; a failed post
    settles as failed
  - Done when: `go test ./internal/tray -run 'Question|Answer|Reader|Capab'` proves each rule
    as a message script with a fake time, that an answer for another note id sends nothing,
    that a notice is posted while a question is open, and that the set of request types sent
    over all scripts of the package is exactly `rule.add`
  - _Boundary: internal/tray/questions.go, update.go (the dispatch lines for events, posted,
    post failed, pressed, answered, capabilities), notes.go (the question and outcome texts),
    questions_test.go_
  - _Requirements: 5.1, 5.2, 5.6, 6.1, 6.5, 6.7, 6.8, 6.9, 6.11, 6.12, 8.1, 8.6_
- [x] 3.4 Questions: closing, timing out, discarding, pausing
  - Closed by the user or the server, or open for 60 s on the tick: settled unanswered,
    nothing sent; a state line with a rules change flushes the waiting ones; a mode change
    flushes the waiting ones whose wording no longer fits and retracts an open one that no
    longer fits; down flushes all and retracts the open one; the menu's pause click toggles
    the pause: pausing retracts the open one, flushes the waiting ones and ignores events
    until resumed
  - Done when: `go test ./internal/tray -run 'Closed|Timeout|Flush|Pause'` proves each rule as
    a message script with a fake time: 59 s against 61 s, a rules change with three waiting,
    a mode change with one fitting and one unfitting question, down with an open question,
    and a pause click that checks the row and a second that unchecks it
  - _Boundary: internal/tray/discard.go, update.go (the dispatch lines for closed, tick's
    timeout, the pause click), discard_test.go_
  - _Requirements: 3.4, 5.7, 5.8, 5.10, 6.10_
- [x] 3.5 The loop
  - A job that owns the model: it reads messages, updates, runs the effects through
    delegates, feeds the result of a post back as a message before the next one, shows a view
    only when it differs from the last one shown, and ends cleanly after the quit effect;
    the update for Quit from the menu and for the stop message (a signal): retract every note
    still open, the question and the notices, then quit
  - Done when: `go test -race ./internal/tray -run 'Run|Quit|Stop|Idle'` proves with recording
    delegates that 100 ticks without a change show the view once, that Quit with an open
    question and an open notice retracts both and ends the job with nil, that stop does the
    same, and that a pause click through the loop shows a view with the row checked
  - _Boundary: internal/tray/run.go, update.go (the dispatch lines for Quit and stop),
    run_test.go_
  - _Requirements: 1.4, 3.4, 8.7_

- [ ] 4. The session-bus adapters
- [x] 4.1 (P) The icons
  - Six pixmaps at 22 and 44 px, ARGB32 in network byte order, drawn by the program: a shared
    shield outline; monitor (outline), trial (lower half filled), kept (filled), kill switch
    (outline with a slash), rules error (outline with an exclamation mark), gone (dashed
    outline with a cross); dark strokes carry a light halo
  - Done when: `go test ./internal/sni -run Pixmap` proves every state has both sizes with
    the right byte length, no pixmap is empty, the six are pairwise different at each size,
    and every pixmap contains both light and dark opaque pixels; a helper test writes the
    twelve PNGs to a directory given by an environment variable for looking at them
  - May run beside 3.2 to 3.5: it needs only the state type of 3.1
  - _Depends: 3.1_
  - _Boundary: internal/sni/icons.go, icons_test.go_
  - _Requirements: 2.1, 2.7_
- [x] 4.2 The tray item and its registration
  - The item object with the properties and no-op methods of the design, its conventional bus
    name, showing a view (properties set, a signal for each one that changed, the attention
    status and icon), registration with the watcher at start when it has an owner and again
    whenever the watcher name gets a new owner, release of the name on removal; the watch on
    a bus name's owner is added to the bus file here, general enough for 4.4 to reuse for the
    notification service; loss of the bus is reported by the item's signal handling as an error (4.4
    composes that handling into the adapter's job); every call bounded by 2 s
  - Not parallel to 4.1 (same package); may run beside 3.2 to 3.5
  - The test helper gains a fake watcher that records registrations and can be restarted
  - Done when: `go test ./internal/sni/... -run 'Item|Register'` proves on the private bus:
    one registration at start, a second after the fake watcher restarts, the status
    `NeedsAttention` with the signal for an attention view, and no registration left after
    removal; and on chandali `go test -tags live ./internal/sni -run LiveItem` registers the
    item on the real session bus, asserts it in the watcher's list of registered items, and
    holds each of the six states for 20 s; the operator confirms what is visible (noted in
    research.md). 4.3 and 4.4 may proceed on the bus assertion; the visual confirmation is
    required before 5.4 closes
  - _Depends: 1.2, 3.1, 4.1_
  - _Boundary: internal/sni/item.go, bus.go (the owner watch), item_test.go, live_test.go,
    internal/sni/snitest/watcher.go,
    .kiro/specs/kde-tray/research.md_
  - _Requirements: 1.1, 1.3, 2.3_
- [x] 4.3 The menu
  - The flat menu object: layout, group properties, single property, about-to-show (both
    forms), event (both forms), the interface properties; rows as label, enabled, separator
    and checkmark with its state; a changed row set bumps the revision and announces the
    layout; a click on an enabled row becomes a menu-click message, on a disabled row or an
    unknown id nothing
  - Done when: `go test ./internal/sni -run Menu` proves on the private bus that the layout
    returns the rows of a view in order with their properties, that a second view bumps the
    revision and emits the signal, and that a clicked Quit row yields the message; and by
    hand on chandali the live test's menu opens on a left and a right click and shows the
    rows (noted in research.md, with any method Plasma asked for that the design omits)
  - _Boundary: internal/sni/menu.go, menu_test.go, live_test.go (the menu part),
    .kiro/specs/kde-tray/research.md_
  - _Requirements: 3.4, 3.6_
- [x] 4.4 Notifications
  - Posting a note: escaped body, actions as key and label pairs and never a `default` key,
    the hints for urgency, transient and the desktop entry, the timeout; retracting; action
    and closed signals for ids this process posted become messages, others are ignored; the
    capabilities at start and whenever the notification service changes owner (absent
    service: not available) become a message; the constructor that exports item and menu,
    subscribes to the signals and returns the loop's delegates and the adapter's job is
    created here, in its own file
  - The test helper gains a fake notification server that records calls and can emit the
    two signals, with and without the `actions` capability
  - Done when: `go test ./internal/sni/... -run 'Notify|Capab|Tray'` proves on the private
    bus: a posted question arrives with exactly the keys `allow` and `block`; `<` and `&` in
    a path arrive escaped; an invoked action for a foreign id yields no message; a server
    without `actions` yields the capabilities message with actions off; no server yields not
    available
  - _Boundary: internal/sni/notify.go, tray.go, notify_test.go, internal/sni/snitest/notifications.go_
  - _Requirements: 6.10, 8.6_

- [ ] 5. Integration, release, documents, the host check
- [x] 5.1 `snitch tray`: flags, wiring, exit codes (integration)
  - The flags `-api`, `-ask all|enforce`, `-operator-file` with their defaults; the role guess
    at start, its file access passed in as delegates so a test can be a writer with a
    temporary file; under one job run: the client, the adapter's job, the loop, a 1 s tick, the
    signals; one inbox for both sides; exit 0 after Quit or a signal with the item removed,
    1 for no session bus, a lost bus or a running instance (with its message), 2 for usage;
    the log lines of the design's Monitoring section on stderr
  - Done when: `go test -race ./cmd/snitch -run 'Tray|Flags|Exit'` proves with the stand-in
    daemon and the fake bus services: the item registers; a scripted `deny-default` event
    produces a notification; the invoked `allow` produces the expected `rule.add` at the
    stand-in (by name for an event with a name); with `-ask enforce` an `allow-monitor`
    event produces none; a stopped stand-in turns the status to attention and a restarted
    one back; SIGTERM exits 0 and the item name is gone; a second instance exits 1
  - _Depends: 2.2, 3.5, 4.4_
  - _Boundary: cmd/snitch/tray.go, main.go (the verb), main_test.go (the placeholder case of
    1.1), tray_test.go_
  - _Requirements: 1.1, 1.2, 1.4, 1.5, 4.5, 4.7, 5.9, 5.11, 8.2, 8.4_
- [x] 5.2 (P) The autostart entry and the release asset
  - A desktop entry that starts `snitch tray` with the session; the release workflow builds
    the second static binary with the tag linked in, checks its `-version`, and publishes it
    as `snitch-linux-amd64` with `snitch-linux-amd64.sha256`; the four existing assets and
    their steps are unchanged
  - Done when: `desktop-file-validate desktop/snitch-tray.desktop` is clean (the tool is in
    `desktop-file-utils`; if it cannot be installed, that is recorded and the entry is
    compared by eye with the Desktop Entry keys Type, Name, Exec, Icon, X-KDE-autostart-phase),
    actionlint is clean on the workflow, and the build
    line run locally (`CGO_ENABLED=0 ... -o /tmp/dist/snitch-linux-amd64`) yields a static
    binary whose `-version` prints the given tag
  - _Boundary: desktop/snitch-tray.desktop, .github/workflows/release.yml_
  - _Requirements: 1.7, 9.4_
- [x] 5.3 (P) Documents
  - README: the tray (six states with their icons as images written by the icon test, the
    menu, the questions and what each answer writes, that Block denies in monitor mode too,
    autostart, what it cannot do); steering `tech.md` and `structure.md` and `CLAUDE.md`: the
    `snitch` binary, the four packages and their dependency direction, the dependency, the
    build path warning; the roadmap's icon note corrected to pixmaps
  - Done when: every state, flag and exit code of the design appears in the README section,
    and `grep -n 'godbus' .kiro/steering/tech.md CLAUDE.md` finds the dependency
  - _Depends: 4.1_
  - _Boundary: README.md, docs/tray-*.png, .kiro/steering/tech.md, structure.md, roadmap.md,
    CLAUDE.md_
  - _Requirements: 9.1, 9.2_
- [x] 5.4 The host check on chandali
  - Prerequisite, stated by the script when it is missing: the tray offers Allow and Block
    only to the operator, and the role guess accepts only a root-owned `/etc/snitch/operator`
    naming the user; the operator creates it once with sudo (the file snitchd will use on
    this host anyway). Without it the script runs everything else and records the answer
    steps as skipped
  - A script for the KDE host: phase A with the stand-in daemon (no root beyond that file):
    start the tray,
    assert through the session bus that the item is registered, drive the six states and
    assert the item's status and tooltip for each, script an event and assert a notification
    was posted (the script watches the notification service), then ask the operator to press
    Allow and Block and assert the two recorded `rule.add` lines, restart the stand-in and
    assert the tray follows, ask the operator to restart plasmashell and assert the item is
    registered again, and record the tray's CPU time over 10 min idle; screenshots on Breeze
    and Breeze Dark are taken by the operator. Phase B (`--daemon`) repeats the question
    steps against a real snitchd in monitor mode, checks the rule in the overlay and removes
    it; it refuses to run when the daemon's mode is not monitor
  - The script never starts a trial, never touches the kill switch and never restarts
    snitchd; steps that touch the desktop session ask first
  - Done when: shellcheck is clean, phase A passes on chandali with the operator at the
    desktop, and research.md holds the record (date, versions, CPU time, anything Plasma did
    differently); phase B is recorded as pending until snitchd runs on the host
  - _Depends: 5.1_
  - _Boundary: scripts/tray-check.sh, .kiro/specs/kde-tray/research.md_
  - _Requirements: 2.7, 8.7, 9.5_
- [x] 5.5 Caps, contracts, constraints and CI
  - Every contract of the new packages has a violation test or is documented as untrippable;
    the design constraints pinned where a test can: the import pin covers the final binary,
    the only request type the binary can send besides `status` and the subscribe line is
    `rule.add` (a test over the source of the new packages: no other request type literal),
    no exported identifier of the new packages is without a caller; `git diff` against the
    spec's first commit shows no change under the paths this spec may not edit; the design's
    file plan corrected to what was built; `lint.yml` gains `go vet -tags live ./...` so the
    live tests keep compiling
  - Done when: every command of `lint.yml` passes locally including `sh scripts/caps.sh`,
    and `go test ./... -run 'Violation|Constraint|Imports'` is green
  - _Depends: 5.1, 5.2, 5.3, 5.4_
  - _Boundary: `*_test.go` of this spec's packages, minor non-test cleanups in this spec's
    packages, .github/workflows/lint.yml, .kiro/specs/kde-tray/design.md (file plan),
    .kiro/specs/kde-tray/research.md_
  - _Requirements: 3.5, 6.12, 8.1, 8.5, 9.3, 9.6_

## Implementation Notes
- 1.1: the import pin (`cmd/snitch/imports_test.go`) runs `go list -deps` without build tags, so files tagged `live` are not pinned; 5.5 should run it once more with `-tags live`. The `net` dialer ban is not an import pin (a unix client needs `net`); 5.5 pins it over the source.
- 1.2: godbus v5.2.4 facts are in research.md "godbus v5.2.4, verified" (use SessionBusPrivateNoAutoStartup, never the autolaunching variants; RequestName has no context, call it through CallWithContext). Bus tests use t.Setenv(DBUS_SESSION_BUS_ADDRESS) and cannot run in parallel.
- 1.3: the stand-in (`internal/client/clienttest`) replies to `rule.add` before it announces the reload (`Options.ReloadAfter`, default 100 ms), as the daemon does; tests that depend on the order must not assume the state line comes first. The fact setters live in `commands.go`.
- 2.1: the client's `Config.Gap` (minimum between status requests) is required; 5.1 sets it to 2 s. `Down` may arrive twice in a row when the reason changes (`not running` <-> `not answering`): the tray treats `Down` as idempotent and updates the reason. Every `Send` gets exactly one `Answered` while the job runs; after the job's context ends nothing is answered, so shutdown code must not wait for an answer. A `Sink` that blocks longer than `AnswerWait` can produce a false `not answering`: the tray loop must not block on effects for seconds (bus calls are bounded by 2 s).
- 2.2: wiring (5.1) passes `os.Stat` (not Lstat: the daemon follows symlinks), `os.ReadFile`, and the name from `user.LookupId(uid)` (not `$USER`). The tray can say reader where the daemon grants writer (operator file 0600/0640 or `/etc/snitch` not traversable): 5.1 logs one stderr line when the guess is reader because of a stat or read error, and the README says the file must be 0644.
- 2.3: `ask.RuleFor` sends no `port` for port 0 and no `proto` for an empty protocol (`omitempty`), which the daemon reads as "any"; connect and sendmsg events always carry both, so this is accepted, not guarded. `TestRuleForNote` swaps `time.Local`: no test in `internal/ask` may start goroutines or call `t.Parallel`. `KeyOf`, `Local`, `Unknown`, `NoteLayout` are exported; 5.5 unexports any without a caller outside the package.
- 2.4: `Queue.Stats().Dropped` resets whenever nothing waits, including when `Next` opens the last waiting question; 3.3 reads `Stats()` before `Next` when composing the note so the drops since the queue last had none waiting are shown. Snoozes expire at exactly 10 min.
- 3.1: `Model` (internal/tray/model.go) declares every field 3.2–3.5 need; its maps (`notices`, `pending`) and `facts` are copy-on-write. `gone` starts true and stays true after `Up` until that session's first `Facts`; the last facts stay as the notice baseline. `nextToken` is incremented before use (0 is never a token). Enforce without a deadline renders as Trial "(no deadline)". Menu labels may contain `_`: the sni menu adapter (4.3) escapes it as `__` for dbusmenu. `canNotify`/`canAct` start false until `Capabilities` arrives.
- 3.2: `Update` (update.go) is a type switch; notices come from facts.go's diff, each change told once; a trial extension is silent; "daemon back" is posted on the first `Facts` after a noticed loss. `Model.posting` (notice tokens awaiting `Posted`) was added under a controller authorization; question tokens are 3.3's. Notices are not yet gated on `canNotify`: 3.3 gates them in update.go (its boundary may also touch facts.go's `post` for that one condition).
- 3.3: question posts use `Model.askToken`; a press counts only when the open note was posted with actions (`Model.openActs`), for the open note id, allow or block. A failed `rule.add` calls `ask.Queue.Forget(key)` (added under authorization). Notices and questions are gated on `canNotify`; `facts_test.go`'s `started` helper sends full `Capabilities` first. `questions_test.go` is at the 300-line cap: 3.4 puts its tests in `discard_test.go`. Not handled yet (3.4): the notification service disappearing while a question is open or waiting.
- 3.4: closing, the 60 s timeout, discards and the pause live in `discard.go`. Closed and the timeout settle Unanswered (snoozed); tray-initiated retractions (mode change, Down, pause, notification service gone) settle Failed (no snooze). Fit is judged on the mode before and after each message. Quit and Stop still pass through `Update` for 3.5.
- 3.5: `Run` (run.go) requires all five delegates (violation test) and runs one goroutine over the model and the last shown view; a `Post` runs inside `handle` and its `Posted`/`PostFailed` is applied before the next message is taken, so adapters keep `Post` bounded (2 s, the 2.1 note). The job returns nil after `Quit` (the trailing `Show` of that list is skipped), nil on a closed `in` (the shutdown path 5.1 should take) and ctx's error on cancel. `quitAll` (update.go: `MenuClick` RowQuit via `menuClick`, and `Stop`) retracts the open question then the notices by sorted id, then `Quit{}`; `TestFactsPassThrough` no longer lists `Stop`.
- 4.1: `Pixmaps(tray.State)` and `Pixmap{W, H, ARGB}` (icons.go, 294/300 lines) are the design's exported names; 4.2's item consumes them (5.5: they are not unused exports). The PNG helper test skips unless `SNITCH_TRAY_ICONS` names a directory, then writes `tray-<state>-{22,44}.png` — 5.3 generates the README images with it. 22 px has sub-pixel halo snippets on diagonal corners (non-antialiased fringe, no cardinal gaps); if 5.4's visual check dislikes them, widen `haloHalf` (0.10 → ~0.12) inside the 6-line file headroom, or split the file under a controller authorization (the File Structure Plan commits all six icons to one file).
- 4.2: the item exports its props with `EmitFalse` and emits `PropertiesChanged` itself with the changed values (`prop.SetMust`+`EmitTrue` would panic on a bus that dies mid-Show; rationale + verified godbus facts in research.md); `RegisterStatusNotifierItem` retries only on the next owner change of the watcher name, nothing polls. `Owner`/`WatchOwner` (bus.go) are the general name-owner watch 4.4 reuses; `Watch` ends with the exported `ErrBusLost`. `live_test.go` (`//go:build live`, done-when run: `go test -tags live ./internal/sni -run LiveItem`) is never run by agents — its operator run (item registered, then six states held 20 s each) is the visual confirmation required before 5.4 closes; 4.2 stays unchecked until research.md records what the operator saw. `item_test.go` is at the 300-line cap; 4.3/4.4 use their own files.
- 4.3: `(*Bus).Menu(sink func(any), log)` serves `com.canonical.dbusmenu` at the `menuPath` the item's Menu property already names; `Show(tray.View)` clones the rows into an immutable `atomic.Pointer` snapshot, bumps the revision and emits `LayoutUpdated` only when the row set changed; enabled Quit/Pause clicks sink `tray.MenuClick{Row}` (4.4 wires the sink into the loop's inbox), a disabled row, an unknown id and hover are silent. dbusmenu wire facts are verified from this host's libdbusmenu-glib/Plasma importer (research.md "### 4.3 additions, verified": GetLayout(i,i,as), Event timestamp uint32, Version uint32=3, no idsOfInterest here); conventions no fact could settle are marked verify-at-live there (GetProperty unknown → InvalidArgs, AboutToShow always false, separators type+visible). `menu.go` and `menu_test.go` sit at exactly 300 lines: any post-live fix needs a controller-authorized split. The hand-run part (menu opens on left AND right click, rows readable) is pending as the "4.3 live run" runbook in research.md; 4.4 may proceed on the private-bus assertions. The research.md 4.2-note citation nit (conn.go:493) is fixed.
- 4.4: `(*Bus).Tray(sink, log) (*Tray, error)` is the design's composed constructor: once per Bus (contract, violation test — probed through the item name format, which is duplicated from `item.go`: hoist into one helper if item.go is ever reopened), delegates slot into `tray.Effects{Show: tr.Show, ...}`, `Job()` = `jobs.Run(ctx, item.Watch, notes.watch)` so bus loss ends `ErrBusLost` and ctx cancel `ctx.Err()`. Capabilities-at-start is the watch's first statement (a constructor-time sink would deadlock the unbuffered inbox before `jobs.Run`; posting is gated on `Capabilities` anyway per 3.3's note). Posted ids: `sync.Map`, wiped on every owner change, `LoadAndDelete` on own `NotificationClosed`; foreign ids are ignored on both signals. Escaping covers `<`, `>`, `&`; hints: urgency byte 1/2, transient, desktop-entry. 5.5 notes: `urgencyNormal` (1) has no assertion (notify_test.go is at the 300 cap) and `snitest.SetCapabilities` is an unused helper. Known unfixable TOCTOU: the microseconds between an owner change and a late Notify reply can leave a stale id (accepted, documented in review).
- 5.1: `snitch tray` wires the verb: `startTray` (Open -> exit 1 "no desktop session"; Claim -> "already running (pid N)", exit 1), ONE buffered-256 inbox for both sinks, `jobs.Run(client.Job, tr.Job, tray.Run, 1 s Tick, jobs.OnSignal(SIGINT+SIGTERM -> tray.Stop))`, `Config.Gap` 2 s, the role guess through `os.Stat` (not Lstat)/`os.ReadFile`/`user.LookupId` delegates with exactly one stderr line when reader because of a stat/read error; exits 0 (Quit/signals, item removed, name released, open notes closed first) / 1 (no session, lost bus, existing instance) / 2 (usage) / 70 (contract.Invariant on an unexpected end). Requirement 4.7 also rides here (the import pin + the unix-only dial). CONTROLLER AUTHORIZATION (2026-11-24): design.md's Monitoring line "registration with the watcher" needed a success line in `internal/sni/item.go` (outside 5.1's boundary): `registerAtStart` and `Watch`'s re-registration now log `tray item registered with the system tray as <name>` (item.go:100 and :263; failure branches unchanged, no double-logging; item_test.go untouched — its items use quiet log delegates). Documented, not applied (suggestion-level, unreachable at these message rates): the tick sender's and `ruleLog.answered`'s inbox writes have no ctx-select, a theoretical full-inbox exit hang — harden if tray.go is ever reopened for 5.5. The bus-lost exit-1 path is covered by the sni-level ErrBusLost tests plus trayEnd's trivial branch.
- 5.2: `desktop/snitch-tray.desktop` carries exactly the five eye-compare keys plus why-comments: `Exec=snitch tray` (design-pinned), `Icon=security-medium` (stock Breeze name, the one the notifications carry as `notifyIcon` in internal/sni/notify.go:39; icon lookup is cosmetic, a miss never stops the launch; the repo ships no theme icon — the item draws pixmaps and the roadmap's theme-icon wording is 5.3's correction), `X-KDE-autostart-phase=0` (earliest phase safe by 1.3: registration retries on the watcher's next owner change, nothing polls). The file keeps the name `snitch-tray.desktop` so the notifications' `desktop-entry` hint matches; making that hint resolvable needs the file in an applications dir and stays out of this task. release.yml: a sibling build step for `./cmd/snitch` (same flags, `-X main.version=${GITHUB_REF_NAME}`) into `dist/snitch-linux-amd64` with its own `-version` check, two sha256 lines in the existing checksum step (`sha256sum -c` form), and the two new assets appended to the publish array — the snitchd build/checksum/publish lines and the four original assets are byte-identical (reviewer and controller each verified the pure-addition diff; the asset name is pinned `snitch-linux-amd64` because the Python client already owns the `snitch` asset name, design.md's rename trigger line). actionlint taught a real YAML edge in RED->GREEN: a colon+space inside a plain step-name scalar is a mapping error; reword. Local proofs ran with pseudo-tags (implementer, reviewer and controller each used their own): statically linked, stripped, `-version` equality, `sha256sum -c` OK; a real tag push is still needed to see a release end-to-end. No controller authorization was needed; nothing was applied beyond the boundary.
- 5.3: README's `## The tray` (lines 112-226, after the API paragraphs): state table embeds the 44 px icons from `docs/tray-{gone,kill,rules-error,kept,trial,monitor}-44.png` (both sizes live in `docs/`, written by `SNITCH_TRAY_ICONS=$PWD/docs go test ./internal/sni -run TestPixmapsPNGHelper` — the path must be ABSOLUTE because `go test` runs in the package dir; a relative one wrote `internal/sni/docs/`, hit once and removed), priority order + the attention trio, the usage line with all three flags and defaults, the 0/1/2/70 exit table, the menu rows (Pause questions and Quit the only actions), question numbers (one open, 32 wait, 60 s, 10 min dedup), the answer table (allow by name includes subdomains, allow/block by address, a deny by name is refused by the API, a deny applies in monitor mode too), the operator/reader split with the 0644 note, autostart (`cp desktop/snitch-tray.desktop ~/.config/autostart/` plus `install -m 755 snitch-linux-amd64 ~/.local/bin/snitch` for PATH), and the cannot-do list (no mode changes, no trial verbs, writes only on the click). The build-path warning (never `go build -o snitch` in the root) rides in the hand-run paragraph. godbus recorded: tech.md:50 and CLAUDE.md:126,175 (v5.2.4, BSD-2-Clause, pure Go, `internal/sni` only; release builds `snitch-linux-amd64`); structure.md lists the four packages with the import direction the reviewer verified through `go list` (sni -> tray -> ask/client -> api, no reverse edges); roadmap's "Why" bullet theme-icon claim corrected to drawn pixmaps with Status/tooltip preserved; its `[ ] kde-tray` box stays unticked until 5.4/5.5 (correct). One in-boundary truth fix beyond the task list: README's pre-existing Release sentence now lists `snitch-linux-amd64`+`.sha256` (the tray section names the asset; the old list would contradict). Review FYIs left unapplied (out of the task's list): the README does not mention the deadline-less "enforce trial (no deadline)" render, and the roadmap's preserved "(NeedsAttention for kill switch and daemon gone)" parenthetical is not exhaustive (rules error also sets attention) — pre-existing text.
- 5.4: `scripts/tray-check.sh` (bash, `set -euo pipefail`, ~547 lines, mode 755): phase A on the real session bus (registration via the watcher's RegisteredStatusNotifierItems, the six states asserted as Status+ToolTip through `busctl --user get-property` with an anchored tail regex, the question watched as Notify on `busctl --user monitor`, the two rule.add lines asserted from fakedaemon stdout, stand-in restart, the operator's `systemctl --user restart plasma-plasmashell` + 45 s re-registration poll, 600 s idle CPU from /proc, ask-first on every desktop-touching step, the trap stopping only what it started), phase B `--daemon` refusing non-monitor mode after a read-only status probe and asking the operator's own curl for the question steps, the overlay assert + rule.remove by the reported key. Review round 1 REJECTED three defects (the `#http://` strip leaving `to=="https:"`; A12/A13 bare `answer_is` aborting under `set -e` on one missed press — now `answer_steps` through step(); missing +x) — all fixed round 2 along with findings 4-8 (state_is desc-literal ` until ` for A10; A17 an unasserted SKIP "operator task"; `.get("rules", [])`; b_rule_remove's ok-check; the refusal wording; the version fallback). Live-run finding (operator runs, controller fix, 5.1-style documented): TWO wait_for call sites held `$( )` in the call arguments, which bash expands once, so the poll re-tested a frozen string and could never pass — `rules_added_since`/`b_rule_present` helpers re-run per poll now, press_answer's baseline is taken before the prompt (a press during the prompt counts), and each wait prints "watching for the recorded rule (up to 90 s)". Takes: 1-2 (~18:30) aborted during the pre-fix silent windows though the operator's Allow presses were accepted (evidence: fake.out JSON + tray.err sent/accepted, twice); take 3 (19:14, 16/1/1) — Allow pressed on the Block question, caught on the recorded line; take 4 (19:32, 16/1/1) — Block pressed on the first question, recorded as deny-by-address to 203.0.113.10 (live proof of the named-question deny-by-address wiring); take 5 (20:23:56+01:00, 17/1/0, exit 0) — the recorded pass, CPU 0.22 s/22 ticks (takes 3-5: 0.20/0.21/0.22 s). A17 skipped by the operator's choice (legibility rests on the 4.2 live run + the PNGs); nothing Plasma did differently. Research.md "5.4 host check on chandali, phase A (done)" holds the record; phase B pending until snitchd runs on chandali. Interlude provenance: the operator's one-liner failed on the missing /etc/snitch, so scripts/setup.sh exists as a separate user-requested commit (1537db8) outside this spec's boundary.
- 5.5: the contract census: 39 Require/Ensure/Invariant sites across cmd/snitch, internal/{client,clienttest,ask,tray,sni} — each with a violation test or a documented untrippable (cmd/snitch's run-end Invariant, tray's unknown-effect and unknown-client-message, ask's queue over MaxWaiting, sni's notify constructors in a NEW file notifyconstruct_test.go: notify_test at the cap); the dbus method names stay exported on purpose (godbus dispatches by the Go method name on the wire — research.md documents the exception). Pins in cmd/snitch/pins_test.go (mutation-RED-proven twice, once per review round): request literals — only status, the subscribe line and rule.add over the five binary-linked packages' non-test sources, the forbidden set built from all thirteen api.md request types, clienttest/snitest tooling excluded as not-linked fixtures (go list proof); a legal-literals-exist guard so the ban cannot pass vacuously; the unix-only dial pin (package-level net.Dial(/net.DialContext( and tcp/udp tokens banned; every .DialContext( line must carry "unix" — cmd/snitch's dialUnix is the one legal dialer; needle scope recorded honestly in research.md: a quoted literal trips the request pin, a bare comment word does not; a .Dial( method form passes the dial scan — "pinned where a test can"). Unexport sweep: ask KeyOf/local/noteLayout/snooze, client noSession, tray's seven loop-only types (post->postNotices, postFailed->postFailedNote, posted->killPosted), sni instanceName/errNoSession/owner/watchOwner/item/menu, clienttest reason consts + endTrial/keep/unkeep/setRulesError, snitest six — kept with callers: ask Unknown/MaxWaiting, sni Pixmaps/Pixmap (4.2's item consumes them), the dbus names. urgencyNormal=1 asserted in sni/urgency_test.go. THE ROUND-1 LESSON (review REJECTED, round 2 restored byte-identically): the sweep had renamed two QUOTED WIRE STRINGS — the SNI "Menu" property to "menu" (the surface 4.2 verified on the host) and the operator-facing row label "Quit" to "quit", and bent item_test's want-map to match; unexport targets are Go identifiers, and a guarding test is never bent to a regression; view.go ended byte-identical to HEAD (the sweep had also bent its header comment). -tags live import pin: ran once green with no adaptation (live files join the package; the pin holds), and lint.yml gained one line `go vet -tags live ./...` (actionlint clean). Design's file plan corrected to what was built (setup.sh named as a user-requested out-of-spec utility, provenance 1537db8; docs/tray-*.png; the at-cap list names seven files incl. standin_test.go). git diff vs the spec-first commit ddea6da: empty under every protected path. Review FYIs left as-is: Test*Contract* names predate the 'Violation|Constraint|Imports' selector (they stay green through lint's go test queue), and design.md 527's `questions cannot be answered here` vs the code's capital-Q wording is a pre-existing disagreement, named for the feature gate. Every lint.yml command green locally (gofmt pipeline, build, vet, vet -tags root, test, caps, shellcheck via shellcheck-py, ruff 0.16.10, actionlint via actionlint-py) + race + the selector, all rerun by the controller.
