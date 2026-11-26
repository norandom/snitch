# Implementation Plan

Every task below is a self-contained brief for an implementer without conversation context.
Before a task, read `.kiro/steering/tech.md`, `.kiro/steering/fail-safes.md`, the design
sections named in the task (`.kiro/specs/tui/design.md`), `research.md` in the same directory,
and `examples/api.md` for every wire shape. Conventions as in the earlier specs: delegates
(function values) for OS seams, contracts with a violation test each, immutable values, every
loop a `jobs.Job`, caps via `scripts/caps.sh` (functions at most 40 lines, files at most 300,
cyclomatic at most 10). `_Boundary:_` names the files a task may touch. A Go task is done when
its "Done when" command succeeds and `gofmt -l .`, `go vet ./...`, `go test -race ./...` and
`sh scripts/caps.sh` are clean.

Rules for this spec: nothing under `cmd/snitchd`, `internal/api`, `internal/rules`,
`internal/trial`, `internal/dns`, `internal/bpf`, `bpf/` or `examples/api.md` is edited. No task needs root or a kernel
program; only 8.7 needs a running snitchd. Never build with
`-o snitch` in the repo root until task 9.1 has removed the Python client: build to
`/tmp/snitch`. Only `internal/term` imports `charm.land/...`; the names of Bubble Tea calls in
the design come from research, so read the module source at the pinned version before using
one. The tray's tests are never edited to make them pass: an edit to `internal/client` or
`internal/ask` that turns a tray test red is wrong. The one exception is named in 7.1 (the
usage test's no-argument case, whose behaviour Requirement 1.1 changes). No task switches a mode on a real host;
task 8.7 starts a trial only with the operator's explicit go. Pushes, tags and releases are not
part of any task. Tasks in the same Go package run one at a time; `(P)` tasks touch disjoint
files. In group 5 the files `model.go`, `update.go`, `keys.go` and `screen.go` are shared:
task 5.1 creates them with every model field of the design and one stub per key and per
message; tasks 5.2 to 5.8 replace their own stubs there and nowhere else, strictly in order.

- [x] 1. Foundation: the terminal library in the module, confined to one package
  - Add Bubble Tea v2.1.3 and Lip Gloss v2.1.1 to the module (needs network once); a first
    file of the adapter package imports them so the requirement stays after tidying, with a
    package comment stating that no other package may import the library
  - Extend the import pin of the user binary: only the adapter package may depend on
    `charm.land/`; `charm.land/bubbles`, `ntcharts`, `golang.org/x/text` and
    `github.com/atotto/clipboard` are forbidden for the whole binary
  - Done when: `CGO_ENABLED=0 go build -o /tmp/snitch ./cmd/snitch` succeeds,
    `go list -deps ./cmd/snitch` names none of the forbidden modules, and
    `go test ./cmd/snitch -run Imports` is green (it fails when a second package imports the
    library)
  - _Boundary: go.mod, go.sum, internal/term/doc.go, cmd/snitch/imports_test.go_
  - _Requirements: 13.9, 14.6_

- [ ] 2. Leaf packages
- [x] 2.1 (P) Text that may be drawn: the safe type and the sanitiser
  - A string type that only this package produces; the sanitiser replaces every control
    character, escape, C1 control, direction-changing and invisible formatting character and
    invalid UTF-8 with a visible dot, so one input is one line; a constructor for this
    repository's own literals and a join
  - A test walks the module's source and fails when another package converts a value to the
    safe type or calls the literal constructor with anything but a string literal
  - Fuzz target: the result never holds a replaced character and sanitising twice changes
    nothing
  - Done when: `go test ./internal/clean -run 'Text|Const|OnlySource'` is green and
    `scripts/fuzz.sh -t 20s clean` finds nothing
  - _Boundary: internal/clean/safe.go, safe_test.go_
  - _Requirements: 13.3, 13.4_

- [ ] 2.2 Names, paths and cutting
  - A destination name with characters outside ASCII is shown in its punycode form by an
    encoder of this package (RFC 3492, no new dependency), checked against the RFC's sample
    strings; nothing is resolved or compared with it
  - Cutting in the middle by cell width keeps the tail: the last labels of a name, the file
    name of a path; sizes (`0B` to `T`) and ages (`now`, `5s`, `3m`, `2h`, `4d`, `-`) as the
    Python client prints them
  - Fuzz target: the cut result is never wider than asked and still safe
  - Done when: `go test ./internal/clean` is green including the RFC vectors and
    `scripts/fuzz.sh -t 20s clean` finds nothing
  - _Boundary: internal/clean/name.go, cut.go, name_test.go, cut_test.go_
  - _Requirements: 13.5, 13.6, 13.7_

- [ ] 2.3 (P) The config file
  - Defaults when the file is missing; the keys `periods`, `since`, `protect`, `resort`,
    `trial`; the popup keys and unknown keys are ignored; `hypr-rdp` and `sshd` are always
    protected and the file can only add
  - Errors that name the file, the key and, for a time window the daemon does not serve, the
    five it serves; a trial outside one minute to one hour is an error; `--since` goes
    through the same check
  - Fuzz target on the loader: it returns a config or an error, never panics
  - Done when: `go test ./internal/conf` is green with one case per rule above, including a
    file that tries to empty `protect`
  - _Boundary: internal/conf/conf.go, conf_test.go_
  - _Requirements: 3.1, 6.5, 11.1, 11.2, 11.3, 11.4, 11.5, 11.6, 11.7_

- [ ] 2.4 (P) The log file, opened safely
  - Creates the directory for the user only and the file for the user only; never follows a
    symbolic link; refuses a file or directory that belongs to someone else; narrows an
    existing wider mode; returns the last five lines, sanitised; appends one line with the
    local date and time
  - Every refusal is an error value the caller can show once; nothing panics
  - Done when: `go test ./internal/logfile` is green with a planted symbolic link, a file
    reported as another user's (injected), an existing 0644 file that ends 0600, and a tail of
    a file holding escape sequences
  - _Boundary: internal/logfile/logfile.go, logfile_test.go_
  - _Depends: 2.1_
  - _Requirements: 7.1, 7.5, 13.4, 13.10_

- [ ] 2.5 (P) One exported list of the local network
  - The question policy's local-network check becomes callable from other packages, with the
    same prefixes and the same handling of IPv4-mapped addresses and zones; its existing
    caller keeps its behaviour
  - Done when: `go test ./internal/ask ./internal/tray` is green without an edit to an
    existing test, and a new test covers each prefix of fail-safe 2 through the exported name
  - _Boundary: internal/ask/question.go, question_test.go_
  - _Requirements: 5.8, 12.4_

- [ ] 3. The client feeds a table (additive, opt-in)
- [ ] 3.1 (P) Summaries, snapshots and whole replies for a caller that asks
  - A switch in the client's configuration, off by default: on, the subscription includes
    summaries, a summary arrives as its own message, a `dropped` line arrives as its own
    message (the status refresh stays), and `snapshot` may be sent; every answer carries the
    whole reply so `rules`, `programs` and `snapshot` can be read
  - Off, the bytes on the wire and the message set are what the tray has today
  - Done when: `go test ./internal/client ./internal/tray ./cmd/snitch` is green with no edit
    to an existing test, and new tests show a summary, a dropped count and a snapshot's
    entries arriving with the switch on and none of them with it off; these tests script the
    daemon's side over the dial delegate (the stand-in learns these lines only in 3.3)
  - _Boundary: internal/client/client.go, session.go, msg.go, their new tests_
  - _Requirements: 1.9, 10.3, 10.4_

- [ ] 3.2 Whose socket it is, and the daemon's own question
  - An optional delegate reports the uid of the socket's other end; the connection message
    carries it (unknown when no delegate is set)
  - An answer is marked as a question when the daemon's error text ends in `[y/N]`, next to
    the existing mark for the operator refusal; these two suffix checks are the only places a
    daemon text is inspected, and the question check is exported so the one-shot verbs call
    the same one
  - Done when: `go test ./internal/client` shows the uid passed through, the unknown case,
    and the question mark set for the documented no-rules text and for nothing else
  - _Boundary: internal/client/client.go, session.go, msg.go, their new tests_
  - _Requirements: 8.3, 13.8_

- [ ] 3.3 The stand-in daemon answers what the TUI asks
  - The test stand-in answers `trial`, `keep`, `unkeep`, `end` with the documented texts and
    state lines, asks the no-rules question when it has no rules, emits summaries for changed
    entries, serves `rules`, `programs` and `snapshot` from its in-memory facts, applies
    `rule.add` and `rule.remove` to them, and can be told to send a `dropped` line
  - A rule added by path makes the stand-in declare a program the way the daemon's overlay
    does (read `cmd/snitchd` and `internal/rules` for the naming, edit neither); the real
    daemon's behaviour is confirmed on the VM in 8.7
  - Done when: `go test ./internal/client/clienttest` is green with one test per verb and the
    tray's tests that use the stand-in are green unchanged
  - _Boundary: internal/client/clienttest/standin.go, commands.go, their tests_
  - _Requirements: 15.2_

- [ ] 4. The connection table as data
- [ ] 4.1 Entries as a tree of rows
  - A store of the daemon's entries by their key, replaced by a snapshot and updated by a
    summary; rows on three levels (program, host, address with port and protocol), addresses
    without a name under one `IP Addresses` row, the unattributed bytes as one `unknown` row
    that has nothing below it; every row sums its addresses (last activity, bytes, rate,
    counts) and has an identity that survives a new snapshot
  - Titles are sanitised here; the raw values stay in the row's keys
  - Done when: `go test ./internal/table -run 'Store|Rows'` is green for a fixture with
    named and unnamed addresses, two programs, the unknown bucket, and a summary that changes
    one row without changing its identity
  - _Boundary: internal/table/store.go, tree.go, their tests_
  - _Depends: 2.2_
  - _Requirements: 1.2, 1.3, 1.4, 1.5_

- [ ] 4.2 Order and search
  - Activity order within every level, frozen between re-sorts, rows that appeared since on
    top; name order without regard to case; a search that keeps the matching rows and their
    parents, matching the path (program, host, address) without regard to case
  - Done when: `go test ./internal/table -run 'Rank|Name|Filter'` is green, including a row
    that becomes active between two re-sorts and keeps its place
  - _Boundary: internal/table/sort.go, search.go, their tests_
  - _Requirements: 3.4, 3.5, 3.8, 3.9_

- [ ] 4.3 Which rule covers a row
  - For a row's key, the covering rule in the kernel's documented order (program-specific
    before any-program; exact protocol and port, then protocol, then any; longest prefix),
    name rules by the entry's name, an unknown program resolved through the declared
    programs' paths; the result says whether the rule is the row's own, from the overlay, and
    on which level it sits
  - The two known limits (port ranges reported as port 0, names) are pinned by tests that
    state them
  - Done when: `go test ./internal/table -run Cover` is green with one case per ordering
    step, both address families, overlay against file, and the two limit tests
  - _Boundary: internal/table/cover.go, cover_test.go_
  - _Requirements: 2.5, 5.11_

- [ ] 4.4 What `x` stands for
  - One function from a row to either the requests to send or a refusal text, by the plan
    table of the design: address, host and `IP Addresses`, program (two rules, one per
    address family, with the note that the local network stays reachable), the unblock of own
    overlay rules, the refusal for a row blocked by an enclosing rule or a file rule of
    another key, for a local address, for an unnameable program and for the unknown bucket
  - A declared program by name, an undeclared one by path; every added rule carries the note
    `snitch tui` with the local date and time
  - Contracts with a violation test each: no request ever names a local address; a plan has
    requests or a refusal, never both and never neither
  - Done when: `go test ./internal/table -run Plan` is green with one case per cell of the
    plan table
  - _Boundary: internal/table/plan.go, plan_test.go_
  - _Depends: 2.5_
  - _Requirements: 5.1, 5.2, 5.3, 5.4, 5.5, 5.6, 5.7, 5.8, 5.9, 12.4_

- [ ] 4.5 The egress flows
  - The ten programs with the most bytes sent, each with up to five destinations and the rest
    summed as `+ n more`; a destination by name when known, else by address; the logarithmic
    scale from 1 KiB to the largest flow; a bar in eighths of a cell
  - Done when: `go test ./internal/table -run 'Flows|Scale|Bar'` is green, including a 50 KiB
    flow next to a 12 GiB one that still gets a visible bar
  - _Boundary: internal/table/egress.go, egress_test.go_
  - _Requirements: 4.3, 4.4, 4.5_

- [ ] 4.6 Rows carry order, search and block markers
  - The row builder applies the chosen order and the search to every level and sets each
    row's block marker from the covering rules: an address row by its own or an enclosing
    rule, a host or `IP Addresses` row when all its addresses are blocked, a program row by a
    program-level rule
  - Done when: `go test ./internal/table -run RowsMarked` is green for one fixture drawn in
    both orders, with a search, and with a rule on each of the three levels
  - _Boundary: internal/table/tree.go, tree_test.go_
  - _Requirements: 3.4, 3.9, 5.11_

- [ ] 5. The UI state machine (pure, no terminal)
- [ ] 5.1 The model, the key table and the guards
  - The model as a value with every field the design lists, the inbound messages and outbound
    effects of the design, the screen as lines of styled spans of safe text; one named stub
    per key and per message, which the later tasks of this group fill, and a render function
    that already switches between the overview, the graph and the too-small notice; the
    update function dispatches and panics by
    contract on a message type it does not know; an unknown key does nothing; `q` and ctrl+c
    quit; a size below 80 by 20 renders one line with the size needed and only `q` acts
  - The whole key table in one place, with a test that it holds exactly the keys of the
    design, none that concerns inbound connections, and that every key reaches a named
    handler
  - The guards before an action key acts, in the design's order: repeat, 50 ms burst, the
    0.6 s gate of an open confirmation, a socket that is not root's, the daemon being down;
    pasted text reaches only an open search line
  - Done when: `go test ./internal/tui -run 'Keys|Guards|Quit|Small|Unknown'` is green,
    including a paste holding `x`, `y` and `T` that changes nothing and a second key 10 ms
    after the first that is dropped
  - _Boundary: internal/tui/model.go, update.go, keys.go, screen.go, their tests_
  - _Requirements: 1.10, 2.6, 12.3, 13.1, 13.2_

- [ ] 5.2 Following the daemon
  - On connection: ask for rules, programs and the snapshot of the current window; a summary
    updates the store; a state line with changed rules asks for rules and programs again; a
    dropped message, a window change and every 30 s ask for the snapshot again; on loss the
    table stays and is marked stale; tokens say what an answer is for and an unknown token is
    ignored
  - The mode, the trial deadline, the kill switch and a stale heartbeat (an `allow-stale`
    event in the last 15 s) are kept for the header; a socket that is not root's marks the
    session as foreign
  - Done when: `go test ./internal/tui -run Feed` is green with scripted message sequences
    for start, summary, rules change, drop, loss and return, and the foreign socket
  - _Boundary: internal/tui/feed.go, feed_test.go_
  - _Depends: 3.1, 3.2, 4.1_
  - _Requirements: 1.9, 5.12, 10.1, 10.2, 10.3, 10.4, 13.8_

- [ ] 5.3 Moving, opening, windows, order and search
  - Cursor by row identity (it stays on its row across refreshes and takes the nearest row
    when its own is gone); up, down, page, home, end; open on enter, right, `l`; close or go
    to the parent on left, `h`; every program closed at start
  - `t` and the digits switch the window (a digit beyond the list does nothing) and ask for
    the new snapshot; `s` and `S` with the re-sort interval cycling and a notice saying what
    is in force; while sorted by activity the order is re-ranked when the interval has
    passed (on the tick) and stays fixed in between; `/` opens the search line, enter
    applies, escape clears
  - Rows are rebuilt only when data changed and at most every 500 ms; a movement key never
    rebuilds
  - Done when: `go test ./internal/tui -run 'Nav|Window|Sort|Search'` is green, including a
    test that counts row rebuilds across 100 movement keys (zero) and one that shows the
    order changing only after the interval
  - _Boundary: internal/tui/nav.go, nav_test.go_
  - _Depends: 4.6_
  - _Requirements: 1.6, 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.5, 3.6, 3.7, 3.10, 3.11_

- [ ] 5.4 Block, unblock and the protection
  - `x` and space turn the cursor's row into the plan and send its requests; a refusal of the
    plan is shown as a notice and nothing is sent; a batch reports when its last answer is in
    (how many succeeded, the first refusal's text); the daemon's text is shown as it is,
    sanitised; a program-level block adds the note about the local network
  - A protected program's unblocked row needs the second `x` directly after the message
    `<program> is protected: press x again to block it`; any other key or a cursor move
    disarms; unblocking needs no second key
  - A stored block appends `BLOCKED <path>`, a removed one `UNBLOCKED <path>`, on the
    daemon's acceptance and not on the keypress; one keypress never sends more than its own
    plan
  - Done when: `go test ./internal/tui -run 'Block|Protect|Batch'` is green, including a
    batch of five with two refusals and a reader's refusal shown verbatim
  - _Boundary: internal/tui/block.go, block_test.go_
  - _Depends: 4.4, 4.6_
  - _Requirements: 5.10, 5.13, 5.14, 6.1, 6.2, 6.3, 6.4, 7.2, 12.5_

- [ ] 5.5 The trial keys and the confirmation
  - `T` asks with the configured duration and the local time the trial would end, stating
    that connections no rule allows are denied until then; `K` asks, stating that enforce then
    stays beyond the deadline and across reboots; only `y` after 0.6 s proceeds, any other
    key cancels with a notice, and no other key acts while the question is open
  - The daemon's own question (the marked answer) is shown as it is and needs a second `y`
    before the request goes out again with the confirmation set; `E` and `U` send at once
  - The daemon's text is shown for an outcome and a refusal alike; a state line changes the
    header's mode whoever caused it; no code path sends `trial` or `keep` without the `y`,
    and none sends `trial` with extend (a test enumerates the effects of every key in every
    state and checks this)
  - Done when: `go test ./internal/tui -run 'Trial|Confirm'` is green with the state diagram
    of the design walked edge by edge
  - _Boundary: internal/tui/trial.go, trial_test.go_
  - _Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7, 8.8, 8.9, 8.10_

- [ ] 5.6 The log lines
  - The log pane starts with the tail handed in; a denied connection (`deny-rule`,
    `deny-default`) appends `denied <program> > <destination>` at most once per 10 s for the
    same pair; a mode change appends the daemon's reason; a failed write is said once in the
    pane and the session goes on
  - Done when: `go test ./internal/tui -run Log` is green, including two denials 3 s apart
    (one line) and 11 s apart (two lines)
  - _Boundary: internal/tui/feed.go (the event and state branches), log_test.go_
  - _Requirements: 7.1, 7.3, 7.4, 7.5_

- [ ] 5.7 Drawing the overview
  - The header (window, number of programs, sort mode, mode with a running trial's deadline
    and remaining time, the socket path, the search text, the stale and foreign marks, and
    that everything is allowed with the reason while the kill switch is set or the heartbeat
    is stale); the table window with marker, indented title with the open or closed mark,
    age, bytes sent, allowed and denied counts and the last verdict; the detail pane with
    path, program and full executable path, destination, bytes and rate, last allowed and
    denied, the mode, and the rules naming the row's program with verdict, note and file; the
    mark for an undeclared program; the mark for an executable whose directory someone other
    than root can write to, for which the model asks once per path through the inspect
    effect and keeps the answer (it never touches the file system itself); the log pane; the
    key line
  - Long names and paths are cut in the middle; only the rows inside the window are drawn
  - Done when: `go test ./internal/tui -run 'Render|Header|Detail'` is green against golden
    text (spans flattened) for the overview, a trial running, the kill switch, a search, a
    stale table, a foreign socket, and a row before and after its inspect answer arrived;
    100 cursor moves over rows of one executable emit one inspect effect and a row without a
    path emits none
  - _Boundary: internal/tui/overview.go, overview_test.go, testdata/, the inspect stub and
    its emit hook in the shared files_
  - _Requirements: 1.1, 1.4, 1.7, 1.8, 2.5, 3.11, 13.5, 13.7_

- [ ] 5.8 The egress graph
  - `e` shows the graph in place of the table and the detail pane and `e` again brings them
    back; the model can start in the graph; while shown it is recomputed every 2 s; the
    window keys, the trial keys and quit work there, the table keys do not
  - The heading says what the totals cover (connections active in the window, bytes counted
    since the daemon first saw them); the collecting line when nothing was sent; a line that
    byte counting is off when the daemon says so
  - Done when: `go test ./internal/tui -run Graph` is green against golden text for a filled
    graph, the empty one and counting off, and a test that `x` in the graph sends nothing
  - _Boundary: internal/tui/graph.go, graph_test.go, testdata/_
  - _Depends: 4.5_
  - _Requirements: 4.1, 4.2, 4.6, 4.7, 4.8, 4.9, 4.10_

- [ ] 6. The terminal adapter and the one-shot verbs
- [ ] 6.1 Bubble Tea around the model
  - A job that runs the program on the alternate screen without mouse and cursor, with a
    constant window title; key presses, pastes and sizes become the model's messages (paste
    markers are dropped); one command waits on the inbox, drains what is waiting into one
    batch and is issued again; effects become commands (send, append to the log with a single
    failure message fed back, the directory inspection through its delegate with the answer
    fed back, quit); the screen becomes styled cells with the 16 ANSI colours
    and the bar gradient
  - The program takes its context from the job and leaves signals to the caller; it never
    writes raw bytes, prints above the view or asks the terminal for its colours
  - Done when: `go test ./internal/term` is green on buffers with a fixed size: `q` ends the
    job with nil and the output ends by leaving the alternate screen, a paste never reaches
    an action key, a cancelled context ends the job with the terminal restored
  - _Boundary: internal/term/program.go, input.go, paint.go, their tests (doc.go is merged
    into program.go)_
  - _Depends: 1, 5.8_
  - _Requirements: 1.1, 2.6, 13.2, 13.3, 13.5_

- [ ] 6.2 (P) One request, one reply, and the status-bar line
  - A one-shot exchange with the daemon under a deadline: dial, check whose socket it is,
    send, read the replies
  - The status line from the daemon's status and the one-hour snapshot: class `allow`,
    `deny` or `down` (unreachable or no answer within the deadline, which is also what a
    stale heartbeat looks like from here; the kill switch; a socket that is not root's), the shield symbol of the mode followed by the number of
    destinations denied within the last hour when not zero, a tooltip with mode, deadline,
    that number and the reason for `down`; all daemon strings sanitised
  - Done when: `go test ./internal/verbs -run 'Ask|Bar'` is green, including a dial that
    never answers ending within the deadline and each class
  - _Boundary: internal/verbs/oneshot.go, bar.go, their tests_
  - _Depends: 2.2, 3.3_
  - _Requirements: 9.7, 9.8, 9.9, 9.10, 9.11, 13.8_

- [ ] 6.3 `default deny`, `default deny --keep`, `default allow`
  - `deny` asks for a trial of the configured duration; the daemon's question is printed,
    typed-ahead input is discarded, 0.6 s pass, and only a typed `y` at a terminal continues
    (without a terminal: nothing is started, exit 1); `--keep` asks to keep; `allow` asks to
    end, which returns to monitor from a trial and from kept enforce
  - The daemon's text goes to standard output with exit 0, a refusal or an unreachable daemon
    to standard error with exit 1, anything else than `deny` or `allow` is usage with exit 2
  - Done when: `go test ./internal/verbs -run Default` is green against the stand-in for each
    verb, the question answered `y`, answered `n`, and without a terminal
  - _Boundary: internal/verbs/mode.go, mode_test.go_
  - _Depends: 3.2_
  - _Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 13.1_

- [ ] 6.4 The request and network pins cover the new packages
  - The pin test scans the seven new packages too; the allowed request types become per
    package: the tray's packages keep their three, the TUI core and the one-shot verbs may
    also name `snapshot`, `rules`, `programs`, `rule.remove`, `trial`, `keep`, `unkeep`,
    `end`; the table package may name `rule.add` and `rule.remove`, which its plans build;
    `learned` and `unsubscribe` stay forbidden everywhere
  - The network pin (no listener, no dialer other than the unix socket, no protocol-name
    literals) applies to the new packages unchanged; add `mkfifo`/`Mkfifo` and
    `XDG_RUNTIME_DIR` to the banned words for them
  - Done when: `go test ./cmd/snitch -run Pins` is green, and a temporary file with
    `net.Listen(` or `"learned"` in one of the new packages turns it red (tried, then removed)
  - _Boundary: cmd/snitch/pins_test.go_
  - _Depends: 2.3, 2.4, 4.4, 5.8, 6.1, 6.3_
  - _Requirements: 13.9_

- [ ] 7. Integration: the binary
- [ ] 7.1 Hardening first, then the verbs
  - The process makes itself non-dumpable before anything else, for every verb including the
    tray; a failure is one line and exit 1
  - No argument now means the overview; `egress`, `status` and `default` are verbs; an
    unknown verb prints the new usage and exits 2; `tray` and `-version` behave as before;
    until 7.2 and 7.3 the four new verbs answer `not built yet` with exit 1 from stubs in the
    dispatch file, which those tasks replace
  - The usage test's no-argument case changes from "usage error" to "the overview verb is
    chosen"; no other existing test is edited
  - Done when: `go test ./cmd/snitch -run 'Usage|Dispatch|Version|Harden'` is green, the
    existing tray tests are green unchanged, and a test reads the process's own dumpable flag
    after the call
  - _Boundary: cmd/snitch/main.go, harden.go, main_test.go, harden_test.go_
  - _Requirements: 1.12, 12.6, 13.11_

- [ ] 7.2 The overview and `egress` wired
  - Flags `-api` and `--since`; the config file (exit 2 with its error); standard input and
    output must be terminals (one line, exit 1) because the library would otherwise read the
    controlling terminal behind a pipe; the log is opened (a refusal becomes the pane's one
    line); the client runs with the table switch and the socket-owner delegate from the
    connection's peer credentials; the directory-inspection delegate (true when the
    executable's directory is not root's, is writable by group or others, or cannot be
    read); client, adapter and the signal job run as one group
  - Exit 0 on quit or a signal; a contract violation in any job ends the group first so the
    terminal is restored before the stack is printed, then exit 70
  - The process creates nothing but the log file and its directory
  - Done when: `go test ./cmd/snitch -run 'Tui|Egress'` is green: not a terminal exits 1, a
    bad `--since` exits 2 naming the five windows, and a run on a pseudo-terminal against the
    stand-in shows a program row and ends 0 on `q` (the pseudo-terminal is opened through
    `golang.org/x/sys/unix`, no new dependency; the test skips where `/dev/ptmx` is missing);
    the delegate is tested on a temporary directory with each of the three conditions
  - _Boundary: cmd/snitch/tui.go, tui_test.go, main.go (its stub only)_
  - _Depends: 6.1, 5.8, 2.3, 2.4_
  - _Requirements: 1.1, 1.11, 4.2, 10.5, 11.3, 12.1, 13.5_

- [ ] 7.3 `status` and `default` wired
  - `snitch status [-api PATH]` prints one JSON line and exits 0 in every case, within one
    second also when nothing answers; `snitch default deny|allow [--keep] [-api PATH]` with
    the exit codes of 6.3; only `default` reads the config file (`status` needs no key from
    it and must not fail on a broken one)
  - Done when: `go test ./cmd/snitch -run 'Status|Default'` is green: valid JSON with the
    three fields against the stand-in, class `down` against a dead path in under a second,
    and `default` without a word exits 2
  - _Boundary: cmd/snitch/oneshot.go, oneshot_test.go, main.go (its stubs only)_
  - _Depends: 6.2, 6.3_
  - _Requirements: 9.5, 9.6, 9.7, 9.11_

- [ ] 8. Validation
- [ ] 8.1 The whole client side against the stand-in
  - Model, client and stand-in together, without a terminal: start and first snapshot; a
    summary changes a row within one tick and the cursor stays; block and unblock on an
    address, a host and a program row with the stand-in's recorded edits compared and the
    markers following the rules change; a reader's write ends in the refusal shown; the
    stand-in restarted (stale mark, then everything loaded anew); a dropped line (new
    snapshot); the client killed mid-batch leaves the stand-in's mode, rules and trial as
    they were
  - An undeclared program blocked by path is then shown as blocked, whichever of the two
    names the stand-in reports for it afterwards (both forms are tested)
  - Done when: `go test -race ./internal/tui -run Integration` is green
  - _Boundary: internal/tui/integration_test.go_
  - _Depends: 3.3, 5.4, 5.5_
  - _Requirements: 5.12, 10.2, 10.3, 12.2, 12.5, 15.2_

- [ ] 8.2 Hostile input
  - Escape sequences, control and direction-changing characters, over-long and non-ASCII
    names in every field the daemon supplies (program, path, name, note, text, error, reason):
    neither the flattened screen nor the log holds a replaced character, and the row count on
    screen is unchanged
  - A paste containing action keys, keys typed ahead of a confirmation, a burst, and a socket
    that does not belong to root: no request leaves
  - Done when: `go test ./internal/tui ./internal/term -run Hostile` is green with the corpus
    kept under `testdata/`
  - _Boundary: internal/tui/hostile_test.go, internal/term/hostile_test.go, testdata/_
  - _Requirements: 13.1, 13.2, 13.3, 13.4, 13.6, 13.8, 15.3_

- [ ] 8.3 (P) The 100 ms budget
  - A benchmark and a test with 4096 entries, every row open: one movement key (update and
    render) stays under 100 ms, and a summary changing all entries costs one rebuild;
    the timing assertion is skipped under the race detector, the rebuild count is not
  - Done when: `go test ./internal/tui -run Budget -bench Move -benchtime 100x` passes on the
    development machine and the measured time is in the test's log
  - _Boundary: internal/tui/budget_test.go_
  - _Requirements: 2.7_

- [ ] 8.4 (P) The documentation of the binary
  - `docs/tui.md`: every key and verb, the config keys with defaults, the exit codes, a
    status-bar example with the absolute path, and the limits in plain words: the log file is
    a convenience and the journal is the record; the measures against other programs do not
    hold on X11 or against a program that writes to the daemon itself; the block marker is a
    prediction (port ranges, names); the autostart entry and the bar should use the absolute
    path
  - Done when: the file exists, a test in `cmd/snitch` checks that every key of the key table
    and every verb of the usage text occurs in it
  - _Boundary: docs/tui.md, cmd/snitch/docs_test.go_
  - _Depends: 7.3_
  - _Requirements: 13.12, 15.1_

- [ ] 8.5 The parity list
  - `docs/parity.md`: every key, view, column, verb, flag and config key of the Python client
    (read from the file `snitch` in the repo root), each marked same or deviation with its
    reason, with a checkbox per item for the check against the running binary; the deviations
    of Requirement 14.2 are all present
  - Done when: the file exists and a script-free read confirms every binding in the Python
    client's `BINDINGS`, every `choices` verb, every flag and every config key of its
    docstring has a row
  - _Boundary: docs/parity.md_
  - _Depends: 7.3_
  - _Requirements: 14.1, 14.2_

- [ ] 8.6 The host-check script
  - `scripts/tui-check.sh [-api PATH] [--trial]` (no root): `snitch status` prints valid
    JSON; the overview starts and quits on a pseudo-terminal; one connection attempt to a
    TEST-NET address (`192.0.2.1`, one second, expected to fail) makes its row exist; the
    script then drives the overview on the pseudo-terminal (search for the address, open the
    rows, `x`), confirms the deny rule through the API's `rules`, presses `x` again and
    confirms it is gone; the running process is not dumpable; nothing appears under the
    user's runtime directory. With `--trial` only: `T`, `y`, the deadline shown, `E`, and
    monitor again before the script ends; a trap sends `end` and removes the TEST-NET rule,
    so an aborted run leaves neither a trial nor an overlay rule behind
  - Done when: `shellcheck scripts/tui-check.sh` is clean and the script, run without
    `--trial` against `tools/fakedaemon` on the workstation, ends with zero failed steps
    (steps that need the real daemon are reported as skipped there)
  - _Boundary: scripts/tui-check.sh_
  - _Depends: 3.3, 7.3, 8.1_
  - _Requirements: 15.4, 15.5_

- [ ] 8.7 The run on the development VM and the parity check
  - The operator runs the script on the VM against the deployed daemon in monitor mode and
    pastes the output (the agent has no sudo and switches no mode); `--trial` only with the
    operator's explicit go and the hypervisor console open
  - Under which name the daemon reports a path-blocked undeclared program afterwards is read
    from that run and recorded in `research.md`, closing the design's open question
  - Every checkbox of the parity list is ticked against the running binary or its deviation
    confirmed
  - Done when: the script's output with zero failed steps is recorded in `research.md` and
    `docs/parity.md` has no unticked item
  - _Boundary: docs/parity.md, .kiro/specs/tui/research.md_
  - _Depends: 8.2, 8.5, 8.6_
  - _Requirements: 14.3, 15.4, 15.5_

- [ ] 9. Retiring the Python client (only after 8.7 is recorded)
- [ ] 9.1 The client, its units, its lanes and its assets leave
  - Delete the Python client, `snitch-trial`, the watch unit and the three trial units of the
    Python client, the Python lint configuration, its lock file and the tracked bytecode
    file; remove the ruff job, the ruff cache line of the ignore file, the CodeQL python lane
    with its part of the CodeQL configuration, the pipeline module's Ruff check with its image and version pins and the two frozen
    asset names (regenerate the module's generated file); the release publishes six assets
    and its existence check counts six; shellcheck no longer lists `snitch-trial`
  - The deb still installs the Go binary as `/usr/bin/snitch`; an installed `snitch` opens
    the overview and `snitch tray` starts the tray; the build stays static
  - Done when: `git grep -n -e snitch-trial -e ruff -e snitch-client.py -e snitch-watch --
    . ':!*.md' ':!.kiro'` hits nothing, `actionlint` and `dagger call lint-all` are clean, and
    `go build -o snitch ./cmd/snitch && ./snitch -version` works in the repo root (then the
    binary is removed)
  - _Boundary: snitch, snitch-trial, pyproject.toml, uv.lock, __pycache__/, .gitignore,
    .github/codeql-config.yml, systemd/snitch-watch.service,
    systemd/snitch-trial.service, systemd/snitch-trial-boot.service,
    systemd/snitch-trial.timer, .github/workflows/release.yml, lint.yml, codeql.yml,
    .dagger/checks.go, composites.go, pins.go, rugged.go, dagger.gen.go_
  - _Depends: 8.7_
  - _Requirements: 14.3, 14.4, 14.6_

- [ ] 9.2 The documents say what is now true
  - `README.md`, `CLAUDE.md`, the steering files, `docs/ci-debs.md` and `docs/rugged.md` no
    longer name the Python client as the operator UI or the reference; they describe the Go
    TUI, say that popups return with popups-trace, and describe the trial's shape by the
    daemon's own units; the "never build to `snitch` in the repo root" rule is removed
  - The roadmap lists `write-gate` as open and before `popups-trace` and ticks `tui`; a
    release-notes paragraph for the next tag is added to `.kiro/handover.md`, naming the
    write-gate gap, the removed assets and the missing popups; the handover's wrong line
    about popups-trace being done is corrected
  - Done when: `git grep -n -i -e 'python client' -e snitch-trial -e ruff -e snitch-watch`
    hits only history sections and the specs, and
    the roadmap and handover hold the lines above
  - _Boundary: README.md, CLAUDE.md, .kiro/steering/*.md, .kiro/handover.md, docs/ci-debs.md,
    docs/rugged.md_
  - _Requirements: 13.13, 14.5_
