# Research & Design Decisions: tui

## Summary
- **Feature**: `tui`
- **Discovery Scope**: New Feature on an existing client stack (full discovery: codebase map
  and external library verification, 2026-11-26)
- **Key Findings**:
  - The shared client (`internal/client`) cannot feed a table today: it subscribes with
    `summary:false`, refuses `snapshot`, returns only a reply's text, and swallows `dropped`.
    The TUI needs an additive, opt-in extension; the tray's suite is the regression proof.
  - Bubble Tea v2 parses view content into cells but still honours SGR, OSC 8 hyperlinks,
    APC/DCS strings, `\r` and `\n`. It does not sanitise. Untrusted text must be cleaned by
    us, and the cleaning is enforced by a type (`clean.Safe`).
  - `bubbles`' text input links `atotto/clipboard`, which executes `wl-paste`/`xclip`/`xsel`
    found on `$PATH`. A security tool does not want that; the search line is hand-written and
    `bubbles` is forbidden.

## Research Log

### The existing client stack
- **Context**: the brief says the TUI reuses the client package unchanged.
- **Sources Consulted**: `internal/client/{client,session,msg,role}.go`,
  `internal/client/clienttest`, `internal/tray/{model,update,run}.go`, `internal/ask`,
  `cmd/snitch/{main,tray,pins_test,imports_test}.go`, `tools/caps`, `scripts/caps.sh`.
- **Findings**:
  - `client.New(Config)`, `Job()`, `Send(token, req)`; messages `Up`, `Down`, `Facts`,
    `StateLine`, `EventLine`, `Answered{Token, Text, Err, Role}` through `Config.Sink`.
  - Subscribe line is the literal `events:true, local:false, summary:false`; `Send` panics on
    `snapshot`; `dropped` only triggers a status refresh; no peer-credential check.
  - `tray.Update(m, msg, now) (Model, []any)` panics on an unknown message type.
  - `pins_test.go` scans five packages and allows the literals `"status"`, `"subscribe"`,
    `"rule.add"`; it bans `"tcp"`, `"udp"` and every listener or non-unix dialer.
  - `ask.local` (fail-safe 2's prefixes) is unexported.
  - `clienttest.StandIn` wraps the real API server; its trial verbs answer "not available".
- **Implications**: "unchanged" cannot hold. The extension is opt-in (`Config.Table`,
  `Config.Peer`) so the tray's wire behaviour stays byte for byte; new message types go only
  to a caller that set `Table`. The pin test becomes per package. `ask.Local` is exported.
  The stand-in learns the trial verbs and summaries.

### Daemon facts the design rests on
- **Sources Consulted**: `examples/api.md`, `examples/rules.toml`, `cmd/snitchd/trialops.go`,
  `cmd/snitchd/api.go`, `internal/api/{types,auth,window}.go`.
- **Findings**:
  - "Every destination" is two rules, `0.0.0.0/0` and `::/0` (the rules file's own example).
  - `end` clears the trial and the kept marker; `snitch default allow` is one request.
  - `rule.remove` needs the program's name; a rule added by `path` makes the overlay declare
    a program named after the base name.
  - Entry counts and bytes are all-time totals; the window only filters which entries appear.
  - The socket is 0666 in a root-owned 0755 directory; the role comes from `SO_PEERCRED`.
  - The daemon's question for a trial without rules arrives as an `error` whose text ends in
    `[y/N]`.
- **Implications**: the plan table in `design.md`; the egress heading's wording; the second
  text exception (`Answered.Question`).

### Bubble Tea v2
- **Context**: the operator asked which TUI library fits charts, bandwidth bars, logs and
  activity views.
- **Sources Consulted**: upstream source at the release tags and a static test build
  (Go 1.26.10, `CGO_ENABLED=0`): bubbletea `tea.go`, `options.go`, `cursed_renderer.go`,
  `UPGRADE_GUIDE_V2.md`; ultraviolet `styled.go`, `terminal_reader.go`; bubbles
  `textinput`, `UPGRADE_GUIDE_V2.md`; lipgloss `UPGRADE_GUIDE_V2.md`; colorprofile `env.go`;
  x/ansi; ntcharts `LICENSE`, `NOTICE.md`.
- **Findings**:
  - Versions: bubbletea v2.1.3 (v2.2.0 tagged 2026-11-26, not on the proxy yet), lipgloss
    v2.1.1, bubbles v2.2.2; all MIT, Go floor 1.26.0. Transitive set is MIT/BSD-3, no cgo;
    needs `x/sys` ≥ 0.47 (the repo has 0.49). `ultraviolet` and `uniseg` are pinned by
    pseudo-version (supply-chain note).
  - `View() tea.View`; alt screen, mouse, cursor and title are fields of the view. Keys are
    `tea.KeyPressMsg` (`String()`, `Text`, `IsRepeat`). ctrl+c is a key press, not a signal.
  - Bracketed paste is on by default and arrives as one `tea.PasteMsg`, but only if the
    terminal honours mode 2004; otherwise pasted bytes are key presses.
  - With stdin not a terminal, Bubble Tea opens `/dev/tty` on its own.
  - Start-up queries (Kitty keyboard, DECRQM); a reply delayed past the 50 ms escape timeout
    is decoded as `esc` plus text keys.
  - Renderer: see Key Findings. `tea.Raw` and `View.WindowTitle` bypass the cell parser.
  - A panic in Update/View restores the terminal; a panic in our own goroutine does not.
  - `teatest/v2` is experimental and pinned to `v2.0.0-rc.1`.
  - `x/ansi` has `Truncate`/`StringWidth` with `Wc` variants and no sanitiser.
  - ntcharts v2.9.0: MIT except `picture/` (MPL-2.0); active; API "subject to change";
    imports `bubbles`.
- **Implications**: check for a terminal before starting; the burst guard (50 ms) answers
  both the non-bracketed paste and the misread reply; no action on bare `esc`; no
  `RequestBackgroundColor`; contract violations cancel the context so the terminal is
  restored; tests call the pure functions.

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Notes |
|--------|-------------|-----------|---------------------|-------|
| Pure core + Bubble Tea adapter | `tui.Update/Render` pure, `term` wraps them | tested without a terminal; the library in one package; the tray's pattern | one translation layer (keys in, Screen out) | selected |
| Bubble Tea model directly | `tea.Model` holds everything | least code | library types across the code base; untrusted strings reach `View` unchecked | rejected |
| tview (+ tvxwidgets) | widget tree with callbacks | ready-made table and charts | callbacks against pure updates; a global application; no opt-out of its own text handling | rejected |
| termdash | dashboard grid | line charts built in | dashboards only; weak for a keyed tree | rejected |
| termui / gotui | widgets on termbox/tcell | charts | original dormant | rejected |

## Design Decisions

### Decision: Bubble Tea v2 and Lip Gloss v2 only; no bubbles, no ntcharts
- **Context**: charts, bars, logs, a tree table, a search line.
- **Alternatives Considered**: 1. bubbles for table, viewport, text input. 2. ntcharts for
  bars and sparklines. 3. hand-written rows, bars and search line.
- **Selected Approach**: 3. The bars are block characters on a log scale (the Python client
  needs about fifty lines); the row list is a window over cached rows.
- **Rationale**: `bubbles/table` cannot style a row by verdict; `textinput` executes
  clipboard helpers; ntcharts pulls bubbles in and says its API may change. The brief allows
  "bubbletea and its dependencies" only.
- **Trade-offs**: more code of ours, all of it pure and small.
- **Follow-up**: if a bandwidth-over-time chart is wanted later, ntcharts'
  `timeserieslinechart` is the candidate; avoid its `picture` package (MPL-2.0).

### Decision: `clean.Safe` as a type
- **Context**: Requirement 13.3; the renderer honours part of what untrusted text can carry.
- **Alternatives Considered**: 1. clean at ingestion. 2. clean at render by convention.
  3. a type only the cleaner produces.
- **Selected Approach**: 3. Raw strings stay in `table` (they go back to the daemon in
  requests); `Span.Text` and the log's `Append` accept only `clean.Safe`.
- **Rationale**: 1 would corrupt requests; 2 is forgotten once.
- **Trade-offs**: `clean.Const` for our own literals is a hole, closed by a grep test.

### Decision: punycode by an own RFC 3492 encoder
- **Alternatives Considered**: `golang.org/x/net/idna` (needs `golang.org/x/text`, a new
  module with large tables) against forty lines with the RFC's vectors and a fuzz target.
- **Selected Approach**: own encoder, display only; nothing is resolved or compared with it.

### Decision: extend `internal/client`, opt-in
- **Alternatives Considered**: 1. a second client in `internal/tui`. 2. extend the shared one.
- **Selected Approach**: 2, with `Config.Table` and `Config.Peer`; zero values are today's
  behaviour.
- **Rationale**: reconnect, backoff, tokens and the status poll exist once.
- **Trade-offs**: a `kde-tray` package changes; its suite and `tray-check.sh` revalidate.

### Decision: rule coverage is predicted, the verdict is shown
- **Context**: 5.11 wants a block marker; the API has no "which rule covers this" request.
- **Selected Approach**: `table.Cover` follows the documented kernel order; the marker is
  advisory and the `verdict` column shows what the kernel did. Limits (port ranges reported
  as port 0, names) are documented.
- **Follow-up**: `write-gate` or a later API change could add the covering rule to an entry.

### Decision: one burst guard for paste and misread replies
- **Selected Approach**: an action key within 50 ms of the previous key, or flagged as a
  repeat, is dropped. Movement keys are not guarded.
- **Trade-offs**: holding `x` does nothing, which is wanted.

### Decision: the whole binary is not dumpable
- **Selected Approach**: `prctl(PR_SET_DUMPABLE, 0)` first in `runMain`, tray included.
- **Trade-offs**: no core dumps of `snitch`; contract violations print their stack anyway.

### Synthesis outcomes
- **Generalisation**: block, unblock and the three row levels are one function,
  `table.MakePlan`, returning requests or a refusal; `status` and `default` share one
  one-shot `verbs.Ask`.
- **Build vs adopt**: adopt Bubble Tea, Lip Gloss, go-toml, the shared client; build the
  cleaner, the encoder, the row list, the bars.
- **Simplification**: no `bubbles`, no chart library, no test harness dependency, no theme
  detection, no mouse, no runtime files; `logfile` is one file.

## Risks & Mitigations
- The client extension breaks the tray — zero-value compatibility, the tray's suite unchanged.
- A future Bubble Tea release passes more sequences through — the hostile-input tests run on
  every dependency bump (Revalidation Triggers).
- A path-blocked unknown program is reported under a new name — resolved (see VM Validation & Open Question Resolution below): `rule.add` with `path` creates an ad-hoc `[[program]]` named `filepath.Base(path)` (suffixed `-2`, `-3` on collision), and `table.Cover` resolves through `m.rules.Programs` (`Paths` match on `execPath`) so `[x]` and unblocking keep working before and after daemon reload.
- File and function caps on a large port — the file plan splits by area; `update.go` only
  dispatches.
- The stated gap (uid-only authorisation) — the mandatory follow-up `write-gate`.

## VM Validation & Open Question Resolution (2026-11-27)

### Monitor-mode host check (`debb`, commit `3dc2a1b`)
- Ran `sh scripts/tui-check.sh` against the deployed `snitchd` in monitor mode (`/run/snitch/api.sock`, `peer_uid=0`, `writer=mc`, `overlay=/etc/snitch/rules.d/local.toml`):
  - `PASS  build snitch binary from tree` (`snitch dev`)
  - `PASS  daemon answers on /run/snitch/api.sock in monitor mode`
  - `PASS  snitch status prints valid JSON` (`class=allow text='\U000f0499'`)
  - `PASS  overview PTY: start, egress graph (e), non-dumpable, runtime dir clean, quit (q)`
  - `PASS  TEST-NET (192.0.2.1) connect (1s, expected to fail) makes row exist` (`program=curl verdict=allow-monitor`)
  - `PASS  PTY search 192.0.2.1, open rows, x block -> rules, x unblock -> gone`
  - `== summary: 6 passed, 0 skipped, 0 failed`
- `--trial` (`T -> y -> enforce -> E -> monitor`) was skipped for this run by operator choice; PTY rendering of `trial` -> `end` transition (`monitor`) was additionally verified against `tools/fakedaemon`.
- All items in `docs/parity.md` were confirmed against the VM check and signed off by the operator.

### Closed Open Question: Path-blocked undeclared program name
- Per `cmd/snitchd/apiwrite_rules.go` (`editProgram` / `adHocName`), a `rule.add` request sent with `path` (for an undeclared executable) appends an ad-hoc `[[program]]` entry to `/etc/snitch/rules.d/local.toml` named `filepath.Base(path)` (or `<base>-2`, `<base>-3`, ... on collision with any existing base/overlay program name or `"any"`).
- Once the daemon reloads the merged rules within 2 s, the resolver maps that executable's `(inode, device)` to the ad-hoc program ID, so subsequent events and snapshot entries report it under that ad-hoc program name. Note `rule.remove` removes the overlay rule while leaving the ad-hoc `[[program]]` declaration in `local.toml`.
- `table.Cover` (`internal/table/cover.go`) resolves rules through `m.rules.Programs` (matching `execPath` against `p.Paths`), so both pre-reload (`unknown` + path) and post-reload (ad-hoc program name) rows show `[x]` and generate matching `rule.remove` requests.

## References
- [Bubble Tea v2 upgrade guide](https://github.com/charmbracelet/bubbletea/blob/main/UPGRADE_GUIDE_V2.md) — Model, View, keys, removed options
- [Bubble Tea options](https://github.com/charmbracelet/bubbletea/blob/main/options.go) — program options
- [ultraviolet styled.go](https://github.com/charmbracelet/ultraviolet/blob/main/styled.go) — what view content may carry
- [ultraviolet terminal_reader.go](https://github.com/charmbracelet/ultraviolet/blob/main/terminal_reader.go) — paste buffering, escape timeout
- [bubbles textinput](https://github.com/charmbracelet/bubbles/blob/main/textinput/textinput.go) — the clipboard helper
- [Lip Gloss v2 upgrade guide](https://github.com/charmbracelet/lipgloss/blob/main/UPGRADE_GUIDE_V2.md) — downsampling
- [x/ansi](https://github.com/charmbracelet/x/tree/main/ansi) — width and truncation
- [ntcharts NOTICE](https://github.com/NimbleMarkets/ntcharts/blob/main/NOTICE.md) — licence carve-out
- [RFC 3492](https://www.rfc-editor.org/rfc/rfc3492) — punycode
- `examples/api.md`, `.kiro/specs/kde-tray/design.md` — the API and the pattern copied
