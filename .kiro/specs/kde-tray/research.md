# Research & Design Decisions: kde-tray

## Summary
- **Feature**: `kde-tray`
- **Discovery Scope**: New Feature (first user-side binary; full discovery)
- **Key Findings**:
  - The KDE host offers everything the tray needs on the session bus: `org.kde.StatusNotifierWatcher`
    (kded6) with a registered host (plasmashell 6.6.6), and `org.freedesktop.Notifications`
    (Plasma, spec 1.2) with the `actions` capability. Measured on chandali, 2026-11-23.
  - The API needs no change, but two of its details shape the client: `state` lines carry only
    mode, trial, kept and reloads, so kill switch, rules error and learning need a `status`
    poll; and `api.Request` cannot express `summary: false` (`omitempty` drops it and the
    daemon's default is true), so the client writes its subscribe line itself.
  - The release already publishes an asset named `snitch` (the Python client). The Go binary
    cannot take that asset name without breaking a pinned consumer.

## Research Log

### StatusNotifierItem on this host
- **Context**: requirements 1.1 to 1.3 and 2.1 to 2.7 need an item that Plasma shows, that
  can ask for attention and that survives a restart of the tray's host.
- **Sources Consulted**: `busctl --user introspect org.kde.StatusNotifierWatcher
  /StatusNotifierWatcher`; the same on a live item (`org.kde.StatusNotifierItem-<pid>-1`,
  tailscale); freedesktop StatusNotifierItem specification.
- **Findings**:
  - Watcher methods: `RegisterStatusNotifierItem(s)`; property
    `IsStatusNotifierHostRegistered` (true here); signals for host and item registration.
  - Item interface `org.kde.StatusNotifierItem`: properties `Category`, `Id`, `Title`,
    `Status` (`Passive`, `Active`, `NeedsAttention`), `IconName`, `IconPixmap a(iiay)`,
    `AttentionIconName`, `AttentionIconPixmap`, `OverlayIcon*`, `ToolTip (sa(iiay)ss)`,
    `ItemIsMenu b`, `Menu o`, `IconThemePath`, `WindowId`; methods `Activate`, `ContextMenu`,
    `SecondaryActivate`, `Scroll`; signals `NewIcon`, `NewAttentionIcon`, `NewOverlayIcon`,
    `NewTitle`, `NewToolTip`, `NewStatus(s)`, `NewMenu`.
  - The live item uses the conventional bus name `org.kde.StatusNotifierItem-<pid>-<n>`, an
    empty `IconName` with `IconPixmap`, `ItemIsMenu` true and a menu object.
  - The watcher is kded6, the host is plasmashell: a plasmashell restart leaves the item
    registered with the watcher; a watcher restart loses it, visible as a `NameOwnerChanged`
    of `org.kde.StatusNotifierWatcher`.
- **Implications**: register by the conventional name; re-register on every new owner of the
  watcher name; `ItemIsMenu` true so a left click opens the menu and `Activate` needs no
  behaviour; pixmaps are a first-class way to ship icons.

### dbusmenu
- **Context**: requirement 3 needs a menu; SNI hosts read it from `com.canonical.dbusmenu`.
- **Sources Consulted**: the dbusmenu interface description (libdbusmenu), Plasma's importer
  behaviour as observed with existing items.
- **Findings**: the host calls `GetLayout(parent, depth, props) -> (u revision, (ia{sv}av))`,
  `GetGroupProperties`, `AboutToShow`, `Event(id, "clicked", data, timestamp)`; the item
  announces changes with `LayoutUpdated(revision, parent)` and `ItemsPropertiesUpdated`.
  Item properties used: `label`, `enabled`, `visible`, `type` (`separator`), `toggle-type`
  (`checkmark`), `toggle-state` (0 or 1). Interface properties: `Version` (3), `Status`
  (`normal`), `TextDirection`, `IconThemePath`.
- **Implications**: a flat menu (no submenus) needs `GetLayout`, `GetGroupProperties`,
  `GetProperty`, `Event`, `EventGroup`, `AboutToShow`, `AboutToShowGroup` and
  `LayoutUpdated`. Every change of the rows bumps the revision and emits `LayoutUpdated`;
  `ItemsPropertiesUpdated` is not needed for a menu this small.

### Notifications
- **Context**: requirements 5 to 7 and 8.6.
- **Sources Consulted**: `GetCapabilities`, `GetServerInformation` and the introspection of
  `org.freedesktop.Notifications` on chandali; Desktop Notifications Specification 1.2.
- **Findings**:
  - Capabilities here: `body`, `body-markup`, `actions`, `persistence`, `inline-reply`, others.
  - `Notify(app_name, replaces_id, app_icon, summary, body, actions as, hints a{sv},
    expire_timeout i) -> u`; `CloseNotification(u)`; signals `ActionInvoked(u id, s key)`,
    `NotificationClosed(u id, u reason)` (1 expired, 2 dismissed, 3 closed by call).
  - The action key `default` is what a click on the body invokes. A notification without that
    key has no body action.
  - `body-markup` means the body is parsed as markup: `<`, `>` and `&` in a path or a name
    must be escaped.
  - Hints: `urgency` (byte 0 to 2), `transient` (bool: not kept in the history),
    `desktop-entry` (string: ties the notification to an installed desktop file).
- **Implications**: questions carry exactly the keys `allow` and `block`, never `default`
  (requirement 6.10); `transient` keeps an expired question out of the history, where its
  buttons would outlive the question; the tray keeps its own 60 s timer and closes the
  question itself instead of trusting `expire_timeout`; bodies are escaped; a server without
  `actions` gets questions without answers (8.6).

### godbus/dbus/v5
- **Context**: the one new dependency; it must fit a static, cgo-free build.
- **Sources Consulted**: module index (`go list -m -versions`: latest v5.2.4), the package's
  documentation as known; BSD-2-Clause licence.
- **Findings**: pure Go; `SessionBusPrivate` plus `Auth` and `Hello` for a connection the tray
  owns; `RequestName` with `NameFlagDoNotQueue`; `Export` and `ExportMethodTable` for objects;
  the `prop` subpackage serves `org.freedesktop.DBus.Properties` with change signals; the
  `introspect` subpackage serves introspection data; `AddMatchSignal` and `Signal` for
  `NameOwnerChanged`, `ActionInvoked`, `NotificationClosed`.
- **Implications**: no code of ours touches the wire format. The exact v5.2.x API is read from
  the module source when the adapter tasks start (the names above are from memory and are
  verified at implementation, not assumed).

### The API from a client's side
- **Context**: requirement 4 and the adjacent expectation that the API stays unchanged.
- **Sources Consulted**: `examples/api.md`, `internal/api/types.go`, `codec.go`, `auth.go`,
  `server.go`, `cmd/snitchd/api.go` (`operatorUID`, `operatorFileProblem`).
- **Findings**:
  - `state` lines: mode, trial, kept, `rulesChanged`, reason. Kill switch, `rulesError` and
    learning are only in `status`.
  - `subscribe` defaults: events true, local false, summary true. `api.Request` has
    `omitempty` booleans, so a marshalled request cannot say `summary: false`.
  - The role is decided by the daemon from peer credentials; no request tells a client its
    role. The only observable is a refused write (`<type>: write requires the operator`),
    which is also journaled.
  - `operatorUID` accepts the file only as a regular file owned by root and not writable by
    group or others, first line a user name. It lives in `package main` of snitchd.
  - `api.New(Deps)` builds a complete server from function values; `Server.Job(listener)`
    serves it; `Emit` and `StateChanged` push lines. A stand-in daemon is this server with
    scripted delegates.
  - Event dedupe is 10 s per key and verdict; a steady stream re-emits once per window.
- **Implications**: status poll every 5 s plus one after each `state` line and `dropped`;
  the client writes its own subscribe line; the client guesses its role from uid and the
  operator file with the daemon's acceptance rules and corrects itself on a refused write;
  tests and the host check use the real server as the stand-in.

### Icons
- **Context**: requirements 2.1 and 2.7: six states, distinguishable by the icon alone,
  legible on a light and on a dark panel.
- **Sources Consulted**: `/usr/share/icons/breeze/status/22/` (has `security-high`,
  `security-medium`, `security-low`, `firewall-applet*`); tools on the host (no
  `rsvg-convert`, no inkscape, no ImageMagick).
- **Findings**: the theme has no six icons whose meaning fits the six states, other themes
  have fewer, and theme names would make the meaning depend on the installed theme. SVGs of
  our own would need a renderer at development time (none installed) or an installed icon
  directory announced through `IconThemePath`, whose handling differs between hosts.
- **Implications**: pixmaps drawn by the program itself (see the decision below).

### Release assets
- **Context**: requirement 9.4.
- **Sources Consulted**: `.github/workflows/release.yml`, `README.md`.
- **Findings**: the assets are `snitchd`, `snitchd.sha256`, `snitch` (the Python client) and
  `snitch-trial`. The VM repo pins `snitchd` by sha256.
- **Implications**: the Go binary gets an asset name of its own (decision below).

## Architecture Pattern Evaluation

| Option | Description | Strengths | Risks / Limitations | Notes |
|--------|-------------|-----------|---------------------|-------|
| Pure core with one loop | all state in one immutable model; `Update(model, msg) -> (model, effects)`; adapters turn D-Bus and socket traffic into messages and run effects | every rule of requirements 2, 5, 6, 7 is a pure function under test; no locks; the same shape bubbletea uses, so the TUI reuses the habit | one more indirection than calling D-Bus where the event arrives | selected |
| Callbacks with shared state | D-Bus handlers and the socket reader mutate a struct under a mutex | least code at first | question queue, timers and reconnect interleave; hard to test without a bus | rejected |
| A library tray (`fyne.io/systray`) | the library owns the item and the menu | no menu protocol of ours | pixmap only is fine, but no `Status`, a process-global API, and notifications still need godbus | rejected in discovery (roadmap) |

## Design Decisions

### Decision: one event loop, pure update, effects as function values
- **Context**: three sources of events (daemon socket, session bus, time) and rules with
  timers (snooze, question timeout, the 10 s grace for a daemon restart).
- **Alternatives Considered**:
  1. Mutex-guarded state touched from every goroutine.
  2. One goroutine owning the model, fed by a channel; pure `Update`.
- **Selected Approach**: option 2. `tray.Run` is a `jobs.Job` that reads messages, calls
  `Update` and runs the returned effects through an `Effects` struct of function values.
- **Rationale**: `tech.md` asks for immutable values, delegates and jobs; requirement 9.3 asks
  for the rules to be proven without a desktop.
- **Trade-offs**: an effect that calls D-Bus blocks the loop for the call; calls are bounded
  by a 2 s timeout.
- **Follow-up**: measure that a `Notify` call on chandali returns in milliseconds.

### Decision: generalize the client, not the tray
- **Context**: `popups-trace` and `tui` reuse the API client; the tray needs only status,
  state, events and `rule.add`.
- **Selected Approach**: `internal/client` delivers typed messages and takes any
  `api.Request` with a caller token; it knows nothing about trays. Only the requests the tray
  needs are exercised now.
- **Rationale**: the interface is general, the implementation stays as small as this spec
  needs (synthesis: generalize the interface, not the implementation).
- **Follow-up**: `tui` adds `snapshot` and `summary` handling as new message types; a change
  of the existing ones is a revalidation trigger.

### Decision: the role is guessed locally and corrected by the daemon
- **Context**: 6.1 and 6.9 need to know before asking whether this user may answer; the API
  does not say and must not change.
- **Alternatives Considered**:
  1. Probe with a write at connect (journals a refusal per connect for every reader).
  2. Read `/etc/snitch/operator` with the daemon's acceptance rules, plus uid 0.
  3. Always offer buttons and show the refusal.
- **Selected Approach**: option 2, with the daemon's answer as the authority: a refusal
  `write requires the operator` turns the tray into a reader until the next connect.
- **Rationale**: no API change, no journal noise, and a wrong guess cannot write anything:
  the daemon decides.
- **Trade-offs**: the acceptance rules exist twice (20 lines); a test pins the same cases as
  `cmd/snitchd`'s. If the daemon moves the file (`-operator`), the tray's `-operator-file`
  must follow.

### Decision: icons are pixmaps the program draws
- **Context**: six states, two panel colours, a static binary, no renderer on the dev host.
- **Alternatives Considered**:
  1. Theme icon names (`security-*`, `firewall-applet-*`).
  2. Own SVGs, rendered to PNG at development time and embedded.
  3. Own SVGs installed and announced with `IconThemePath`.
  4. Pixmaps drawn in Go at start (a shield outline and five variations), 22 and 44 px.
- **Selected Approach**: option 4. Each state differs in shape, not only in colour; every
  stroke has a contrasting halo so it reads on light and dark panels.
- **Rationale**: no build tool, no install step, identical on every host, testable (six
  pixmaps, pairwise different, non-empty at both sizes).
- **Trade-offs**: the icons do not follow the theme's style, and this revises the roadmap's
  note that icons would be theme names. Drawing code is about 100 lines.
- **Follow-up**: screenshots on chandali with Breeze and Breeze Dark in the host check.

### Decision: a waiting question is discarded on any rules reload
- **Context**: 5.8 wants a waiting question dropped when a rule now covers it. Knowing that
  exactly would mean evaluating rules in the client, a second copy of the daemon's lookup.
- **Selected Approach**: a `state` line with `rulesChanged` discards every waiting question
  (not the open one) without recording a snooze. A connection that is still uncovered asks
  again when it next happens (the daemon re-emits after its 10 s dedupe window).
- **Rationale**: never shows a question a rule already answered; no rule logic in the client.
- **Trade-offs**: an Allow or Block by the tray itself reloads the rules and so empties the
  waiting list; in enforce mode the denied programs retry and ask again, in monitor mode the
  connection went through anyway.

### Decision: one question per program and name, not per address
- **Context**: 5.4 dedupes by "destination". Names behind CDNs resolve to many addresses.
- **Selected Approach**: the destination of a question's key is the name when the event has
  one, else the address.
- **Rationale**: one question for `api.github.com`, not one per address. Allow by name then
  covers all of them.
- **Trade-offs**: Block writes one address (the API refuses a deny by name); other addresses
  of the same name are quiet for 10 min and ask again after that.

### Decision: the Go binary is the asset `snitch-linux-amd64`
- **Context**: `snitch` is already an asset (the Python client).
- **Alternatives Considered**:
  1. Replace the Python asset with the Go binary under the same name.
  2. Rename the Python asset.
  3. Publish the Go binary under a new name and leave the four existing assets alone.
- **Selected Approach**: option 3: `snitch-linux-amd64` and `snitch-linux-amd64.sha256`,
  installed as `snitch`.
- **Rationale**: no existing asset changes meaning; `deploy-service` needs no revalidation.
- **Trade-offs**: asset name and installed name differ until `tui` retires the Python client
  and settles the name.

### Decision: single instance by a bus name
- **Context**: 1.2.
- **Selected Approach**: the tray requests `io.github.norandom.snitch.Tray` on the session
  bus without queueing; a second tray reads the owner's pid from the bus and names it.
- **Rationale**: the session bus is exactly "same user and session"; no lock file to go stale.

## Synthesis Outcomes
- **Generalizations**: requirements 5 and 6 are one capability, "an uncovered connection
  becomes a question, an answer becomes a `rule.add`", independent of how the question is
  shown. It lives in `internal/ask` with no D-Bus in it, so `popups-trace` adds a terminal
  front end without touching it. Requirements 2, 3 and 7 are three renderings of one diff of
  the daemon's facts.
- **Build vs adopt**: adopted: godbus (wire protocol, properties, introspection), the daemon's
  own `api.Server` as the stand-in daemon, `jobs`, `contract`. Built: the SNI item, the flat
  dbusmenu, the notification calls (three thin adapters), the icons.
- **Simplifications**: no configuration file (three flags); no `ItemsPropertiesUpdated`; no
  submenus; no persistence (snooze and pause live in memory, as 5.10 asks); no summary
  subscription; no theme icon lookup; no separate desktop-file installer (one file to copy).

## Risks & Mitigations
- Plasma's dbusmenu importer may want a method or property the flat menu omits: the adapter
  task starts with the live check on chandali, before the rest builds on it.
- Monitor-mode questions on a busy desktop: one at a time, 10 min snooze per key, 32 waiting,
  `-ask enforce` and the pause switch. The host check counts questions over a browsing session.
- The operator guess drifts from the daemon's rule: the daemon stays the authority (a refusal
  demotes), and a test pins the shared cases.
- godbus API details remembered wrongly: verified against the module source in the first
  adapter task; nothing else in the design depends on a specific call.
- A private session bus is missing on a CI runner: the adapter tests skip without
  `dbus-daemon`; the pure packages carry the proof 9.3 asks for.

## References
- `examples/api.md`, `internal/api/types.go`: the wire shapes the client reads.
- freedesktop.org StatusNotifierItem specification: item, watcher, host.
- Desktop Notifications Specification 1.2: `Notify`, hints, signals, close reasons.
- libdbusmenu `com.canonical.dbusmenu` interface description: layout, events, properties.
- `github.com/godbus/dbus/v5` v5.2.4: the session bus library.
- `.kiro/steering/roadmap.md`: order, scope decisions of 2026-11-23.

## godbus v5.2.4, verified
Read from the module source (`$(go env GOMODCACHE)/github.com/godbus/dbus/v5@v5.2.4`) in task
1.2. Signatures as they are; deviations from the memory names above are marked.

- **Connecting (used in 1.2)**: `dbus.SessionBusPrivateNoAutoStartup(opts ...ConnOption)
  (*Conn, error)` dials only; the caller runs `(*Conn).Auth(methods []Auth) error` (nil means
  EXTERNAL then DBUS_COOKIE_SHA1 for the euid) and `(*Conn).Hello() error`. Deviation: the
  design's `SessionBusPrivate` and `ConnectSessionBus` look up the address with autolaunch, and
  when neither `DBUS_SESSION_BUS_ADDRESS` (nor `autolaunch:`) nor `/run/user/<uid>/bus` gives one
  they run `dbus-launch` and start a fresh bus: a tray without a desktop would then "succeed" on
  a bus nobody watches. The NoAutoStartup variant returns `dbus: couldn't determine address of
  session bus` instead. Note that the lookup `os.Setenv`s the variable when it discovers
  `/run/user/<uid>/bus`. `dbus.Connect(address, opts...)` is Dial + Auth + Hello in one (the
  test helper uses it). Neither `Auth` nor `Hello` takes a context; `sni.Open` arms a
  `time.AfterFunc(2s, conn.Close)`, and closing the transport unblocks both (pending calls are
  finalized with an error).
- **Calls with a timeout**: `(*Conn).BusObject() BusObject`, `(BusObject).CallWithContext(ctx,
  method string, flags Flags, args ...any) *Call` (synchronous: it waits for the reply or the
  context), then `(*Call).Store(retvalues ...any) error`. Deviation: the convenience
  `(*Conn).RequestName(name string, flags RequestNameFlags) (RequestNameReply, error)` and
  `ReleaseName` use `Call` without a context, so `sni.Claim` calls
  `org.freedesktop.DBus.RequestName` itself through `CallWithContext` with a 2 s deadline.
- **Name flags and replies**: `RequestNameFlags` uint32: `NameFlagAllowReplacement` 1,
  `NameFlagReplaceExisting` 2, `NameFlagDoNotQueue` 4. `RequestNameReply` uint32:
  `RequestNameReplyPrimaryOwner` 1, `RequestNameReplyInQueue` 2, `RequestNameReplyExists` 3,
  `RequestNameReplyAlreadyOwner` 4. `ReleaseNameReply`: `ReleaseNameReplyReleased` 1,
  `ReleaseNameReplyNonExistent` 2, `ReleaseNameReplyNotOwner` 3. The pid of a name's owner is
  `org.freedesktop.DBus.GetConnectionUnixProcessID(s) -> u`; it accepts a well-known name
  directly (no `GetNameOwner` first). `(*Conn).Names() []string` lists the unique name first.
- **Closing**: `(*Conn).Close() error`, idempotent (closeOnce); it closes the `Signal` channels
  and cancels `(*Conn).Context()`. Closing releases every name the connection owns (bus
  daemon side), which is how `Remove` and a crash both drop the item (1.4).
- **Exporting (for 4.2-4.4)**: `(*Conn).Export(v any, path ObjectPath, iface string) error`
  exports the methods of `v` whose last return value is `*dbus.Error`; parameters of type
  `dbus.Sender` / `dbus.Message` are filled in and not part of the signature; each call runs in
  its own goroutine (handlers must be safe for concurrent calls); `v == nil` unexports.
  `ExportAll` (any trailing `error`), `ExportWithMap(v, mapping map[string]string, path,
  iface)` (Go name -> D-Bus name), `ExportSubtree`, `ExportMethodTable(methods map[string]any,
  path ObjectPath, iface string) error` (name -> func; non-functions ignored),
  `ExportSubtreeMethodTable`. `org.freedesktop.DBus.Peer` is answered for every object.
- **Signals out**: `(*Conn).Emit(path ObjectPath, name string, values ...any) error`, with
  `name` as `"interface.Member"` (e.g. `org.kde.StatusNotifierItem.NewIcon`).
- **Properties (`prop`)**: `prop.Export(conn *dbus.Conn, path dbus.ObjectPath, props prop.Map)
  (*prop.Properties, error)` (`prop.New` is the same but returns nil on error); `prop.Map =
  map[string]map[string]*prop.Prop` (iface -> name -> prop); `prop.Prop{Value any; Writable
  bool; Emit EmitType; Callback func(*prop.Change) *dbus.Error}`; `EmitFalse`, `EmitTrue`,
  `EmitInvalidates`, `EmitConst`. Updates: `(*Properties).SetMust(iface, property string, v
  any)` (panics on an unknown name; emits `PropertiesChanged` per the prop's `Emit`),
  `(*Properties).Set(iface, property string, newv dbus.Variant) *dbus.Error` is the D-Bus
  method (writable props only); `GetMust`. `(*Properties).Introspection(iface)
  []introspect.Property` feeds introspection. SNI hosts listen for `NewIcon` and friends, not
  `PropertiesChanged`, so props use `EmitFalse` and the adapter emits those signals itself.
- **Introspection (`introspect`)**: types `Node{Name; Interfaces []Interface; Children
  []Node}`, `Interface{Name; Methods; Signals; Properties; Annotations}`, `Method`, `Signal`,
  `Property{Name, Type, Access}`, `Arg{Name, Type, Direction}`; vars `introspect.IntrospectData`
  and `prop.IntrospectData` (the standard interfaces); `introspect.NewIntrospectable(n *Node)
  Introspectable` exported with `conn.Export(x, path, "org.freedesktop.DBus.Introspectable")`;
  `introspect.Methods(v any) []Method` derives methods from an exported value.
- **Signals in (for 4.2, 4.4)**: `(*Conn).AddMatchSignal(options ...MatchOption) error` and
  `AddMatchSignalContext(ctx, ...)` (deviation: there is a context form, use it for the 2 s
  bound), `RemoveMatchSignal`; options `dbus.WithMatchSender(s)`, `WithMatchInterface(s)`,
  `WithMatchMember(s)`, `WithMatchObjectPath(p)`, `WithMatchArg(idx int, value string)` (e.g.
  arg0 = the watcher name for `NameOwnerChanged`), `WithMatchPathNamespace`,
  `WithMatchDestination`, `WithMatchOption(key, value)`. Delivery: `(*Conn).Signal(ch chan<-
  *dbus.Signal)` registers a channel (several allowed; closed when the conn closes; a full
  channel is not dropped but handed to a goroutine per signal, which can reorder signals, so
  buffer it), `RemoveSignal(ch)`. `dbus.Signal{Sender string;
  Path ObjectPath; Name string ("iface.Member"); Body []any; Sequence}`.
- **Test bus**: `dbus-daemon --config-file=F --nofork --print-address` with a config of type
  `session`, `<listen>unix:dir=…</listen>`, EXTERNAL auth, an allow-all policy and no service
  directories, so nothing (a real notification server, a watcher) is ever activated on it.
  The socket directory is a short `os.MkdirTemp` path, not `t.TempDir` (108-byte socket path
  limit). Checked on dbus-daemon 1.16.2.

### 4.2 additions, verified (the tray item and its registration)

Read from the module source for task 4.2, in the same manner as the sections above; the
numbers are lines of godbus v5.2.4 as found in the module cache.

- **RegisterStatusNotifierItem**: the item calls it on the watcher's own object:
  `conn.Object("org.kde.StatusNotifierWatcher", "/StatusNotifierWatcher").CallWithContext(ctx,
  "org.kde.StatusNotifierWatcher.RegisterStatusNotifierItem", 0, name).Err` — `Object`
  (object.go:493) takes destination and path, the method string may carry its interface. The
  handler runs in a goroutine of its own (export.go:267) and the synchronous call returns
  only after the handler has answered, so a fake watcher's recording is visible the moment
  the call returns. Bounded by the 2 s context as everything else.
- **PropertiesChanged, emitted by the adapter**: `conn.Emit(path,
  "org.freedesktop.DBus.Properties.PropertiesChanged", iface, map[string]dbus.Variant{…},
  []string{})` — Emit returns `ErrClosed` when the connection is already closed
  (export.go:221-247), it does not panic. The props of the item are `EmitFalse` (the line
  above holds: hosts listen for the item's signals), and Show emits the standard
  PropertiesChanged itself, once, with the changed values in the map — because
  `prop.SetMust` PANICS on any error of its `set()` (prop.go:339-348), and with `EmitTrue`
  a failing Emit (a bus that just died mid-Show) would be such an error. The private-bus
  tests assert the contents of that signal, not just that something was emitted.
- **Signatures** (sig.go getSignature): Go `int` and `int32` both map to `i`, so
  `Pixmap{W, H int; ARGB []byte}` is `(iiay)`, `[]Pixmap` is `a(iiay)`, the item's ToolTip
  struct `{string, []Pixmap, string, string}` is `sa(iiay)ss` — exactly the host's
  introspection above — and `dbus.ObjectPath` is `o`, `bool` `b`. Exported struct fields in
  order make the tuple; unexported fields and `dbus:"-"`-tagged ones are skipped.
- **Exporting methods**: `conn.Export(v, path, iface)` exports every exported method whose
  last return type is `*dbus.Error`, and the D-Bus method name is the Go method name as it
  is (getMethods builds `methods[name]` — no case mangling), so `Activate`,
  `SecondaryActivate`, `ContextMenu` and `Scroll` keep their names. Each call runs in its
  own goroutine; `org.freedesktop.DBus.Peer` is answered on every object. The fake watcher
  uses `ExportMethodTable(map[string]any{…}, path, iface)` whose values are functions with
  the same `*dbus.Error` rule.
- **NameOwnerChanged watch**: `conn.AddMatchSignalContext(ctx,
  WithMatchInterface("org.freedesktop.DBus"), WithMatchMember("NameOwnerChanged"),
  WithMatchArg(0, name))` — one arg0 match rule per watched name (arg0 matching works on
  this daemon; the re-registration test drives it). The body is (name, old owner, new
  owner), empty string meaning "no owner". Every channel registered with `conn.Signal(ch)`
  sees every signal matched by the CONNECTION (defaultSignalHandler.DeliverSignal posts to
  all), so a consumer filters by name itself; and the private-bus tests empirically caught
  `org.freedesktop.DBus.NameAcquired` (carrying a unique name) on a subscriber channel —
  the bus's own ownership signals arrive alongside the matched ones, unfiltered. A full
  channel hands each signal to a goroutine of its own (reorder hazard), so the watch
  buffers and the tests collect by name.
- **NameLost**: unicast to the connection that lost the name (see handleSignal) — useless
  for watching a foreign name. NameOwnerChanged is the one general owner watch; the
  notifications service (4.4) reuses the same watch.
- **Bus loss**: `conn.Close()` — also invoked by inWorker on a transport error (EOF, the
  dead daemon) — terminates the signal handler, which CLOSES every channel registered with
  `Signal()` (default_handler.go Terminate). A `for range ch` loop over such a channel ends:
  that is the item's bus-loss error path, no poll anywhere. `RemoveSignal` only unregisters.
- **ReleaseName**: the convenience `(*Conn).ReleaseName` uses the context-less `Call`
  (export.go:413), like `RequestName`; the item calls `org.freedesktop.DBus.ReleaseName`
  itself through the 2 s `CallWithContext`. Replies: released 1, non-existent 2, not-owner 3.
- **GetNameOwner errors**: `GetNameOwner` of a name without owner fails with
  `org.freedesktop.DBus.Error.NameHasNoOwner`, and the error arrives as a `dbus.Error`
  VALUE, not a pointer — `callTracker.handleDBusError` stores `Error{name, body}`
  (conn.go:959). `errors.As` therefore needs a `dbus.Error` target, not a `*dbus.Error`;
  an `*dbus.Error` target silently fails (a trap the 4.2 test hit).
- **The SNI words of 4.2**, as introspected on this host (block above) and now implemented:
  properties `Category` `SystemServices`, `Id` `snitch`, `Title`, `Status` `Active` or
  `NeedsAttention` (with the view's `Attention`), empty `IconName`, `IconPixmap` and
  `AttentionIconPixmap` from `icons.go`, `ToolTip`, `ItemIsMenu` `true`, `Menu`
  `/StatusNotifierItem/menu`; the four inert methods above; signals `NewIcon`,
  `NewAttentionIcon`, `NewStatus(s)`, `NewTitle`, `NewToolTip` for what changed; the
  conventional item bus name `org.kde.StatusNotifierItem-<pid>-1`; the watcher's
  `RegisteredStatusNotifierItems` property (`as`) is what the live run asserts.

### 4.2 live run (done)
Run 2026-11-24 on chandali in the operator's Plasma session, by hand:
`go test -tags live -count=1 -run LiveItem -test.v ./internal/sni` — **PASS in 120.17 s**.
The item registered as `org.kde.StatusNotifierItem-569369-1` and the watcher listed it
(`org.kde.StatusNotifierItem-569369-1/StatusNotifierItem`); each of the six states was
held 20 s: gone ("daemon not running") 09:32:22, kill switch set 09:32:42, rules error
09:33:02, enforce kept 09:33:22, enforce trial 09:33:42, monitor 09:34:02; the release at
the end left the panel again.

The first attempt failed in 0.00 s at the registration assertion: the item was
registered, but the test compared the bare bus name while the real watcher lists each
entry as bus name plus object path (`org.kde.StatusNotifierItem-568739-1/StatusNotifierItem`;
the session's own entries, e.g. `:1.71/org/blueman/sni`, show the same shape). The
assertion now compares `it.name + itemPath`; the entry format is a verified fact now,
not a remembered one.

The operator's confirmation: "icon is visible, not clickable or so where smth would
happen" — visibility confirmed; a click doing nothing is the design at this stage (the
item's methods are inert, the menu is 4.3's and the notifications 4.4's). Nothing
beyond the six icons was reported — no dialog, complaint or oddity from Plasma, and
the item's log printed no error during the run.
