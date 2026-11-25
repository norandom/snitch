#!/usr/bin/env bash
# shellcheck disable=SC2317,SC2329  # the step helpers and the phasers call plain function named in step()/must()/wait_for(); cleanup runs through the EXIT trap
# tray-check (kde-tray task 5.4, requirement 9.5): the host check on chandali, run BY THE
# OPERATOR AT THE DESKTOP. Phase A (the default) drives the tray on the real Plasma session
# bus against the stand-in daemon (tools/fakedaemon) on its own private socket; phase B
# (--daemon) repeats the question steps against a real snitchd, in monitor mode only, and
# removes the rule the operator answered for. What a bus can assert (registration, each
# state's status and tooltip, the posted notification, the two rule.add lines) is asserted
# here; what only eyes can confirm (the icons, the menu, both themes) asks the operator.
#
# Safety: the script never starts a trial, never touches the kill switch and never restarts
# snitchd; every step that touches the desktop session (a question to click, the plasmashell
# restart, the screenshots) asks first and says what is about to happen. It writes nothing
# outside its own temp dir and (in phase B) removing the rule this run added; the only root
# it speaks of is the operator file, and for that it prints the one-liner but never runs it.
# The exit code is 0 with every step passed, 1 when a step failed, 2 for usage or for phase
# B's monitor-mode refusal.
#
# The phase map (each step prints one PASS/SKIP/FAIL line; the counters, the CPU record and
# the tray's exit status at the end are the research.md record):
#   A1  build: the tray and the stand-in from this tree
#   A2  the session bus is reachable (the bus the tray itself will open)
#   A3  the role guess: writer (answerable questions) or reader (the answer steps recorded
#       as skipped, with the sudo one-liner for /etc/snitch/operator)
#   A4  registration: the watcher lists the item (name plus object path, research.md 4.2)
#   A5  gone: NeedsAttention and "daemon not running" (the stand-in is not up yet)
#   A6  the stand-in up: monitor and Active within one reconnect backoff
#   A7  kill switch set: NeedsAttention, the tooltip's first line
#   A8  rules error: NeedsAttention, the tooltip's first line
#   A9  enforce kept: Active, "enforce kept"
#   A10 enforce trial: Active, "enforce trial" with the deadline
#   A11 a question is posted: the Notify call on the notification service (busctl monitor)
#   A12 Allow: the recorded rule.add, allow to the event's name (skipped for a reader)
#   A13 Block: the recorded rule.add, deny to the address (skipped for a reader)
#   A14 the stand-in restarted: gone, then monitor again (the tray follows it)
#   A15 plasmashell restarted by the operator: the watcher lists the item again (1.3)
#   A16 idle: the tray's CPU time over 10 min idle (8.7)
#   A17 screenshots on Breeze and Breeze Dark (2.7): an operator task recorded as SKIP,
#       no bus assertion -- legibility is eyes' work
#   A18 stop: the tray ends cleanly on SIGTERM (exit 0, the panel item gone)
#   B1  the daemon answers over the API socket and its mode is monitor (refused otherwise)
#   B2..B7: build, registration, the tray follows the daemon, a preflight (the allow URL
#       must parse into a plain colon-free destination), the Allow question (the overlay
#       rule checked and removed), the Block question (the deny rule likewise), stop
#
# --headless runs phase A's bus-assertion pulse only (ci-debs' in-container smoke, group 8):
#   the same A-numbered steps, the registration assert read from the item's own bus name
#   (no watcher on a bare bus), every desktop/operator step a recorded SKIP, never a FAIL,
#   exit contract unchanged (0 pass, 1 a failed step). It demands --bin and --fake: the
#   container that runs it has no Go tree and must not strip the desktop's default phase.
#
# usage: scripts/tray-check.sh [--daemon] [-s SOCKET] [-a URL] [-b ADDR] [--bin BIN] [--fake BIN] [--headless] [-h]
set -euo pipefail

usage() {
  cat <<'U'
usage: scripts/tray-check.sh [--daemon] [-s SOCKET] [-a URL] [-b ADDR] [--bin BIN] [--fake BIN] [--headless] [-h]
  run as the desktop user, at the desktop, never as root (exit 2)
  phase A (default): the tray on the session bus, driven by the stand-in daemon
  --daemon   phase B: a real snitchd, monitor mode only (refused otherwise); the
             question steps repeat through it and the overlay rule is removed again
  -s <path>  the API socket phase B talks to (default /run/snitch/api.sock, the unit's;
             the -api PATH of a hand-started snitchd). Phase A's stand-in always uses a
             socket in the script's own temp dir.
  -a <url>   phase B's allow question: the operator CURLS this URL after the prompt
             (default https://example.org/; the allow goes to the name the daemon's DNS
             tap learned for it, so the URL must resolve)
  -b <addr>  phase B's block question: CURLed bare, no name (default 192.0.2.20), so the
             deny rule goes to the address
  --bin <p>  run this tray binary instead of building one from the tree
  --fake <p> run this stand-in daemon instead of building one from the tree
  --headless phase A as far as a headless container allows: only the bus
             assertions, on a session bus the caller wraps the script in
             (dbus-run-session); the registration assert is the item's own bus
             name (no watcher lives on such a bus), and the desktop and operator
             steps are recorded as SKIP, never FAIL. Needs --bin and --fake:
             a container has no Go tree to build from. The in-container deb
             smoke drives this pulse (ci-debs group 8); the desktop's own
             phase A stays the default and is unchanged.
  -h         this text
exit 0 every step passed, 1 a step failed, 2 usage or phase B's monitor-mode refusal
U
}

daemon=0; headless=0; sock=/run/snitch/api.sock; allow_url=https://example.org/; block_addr=192.0.2.20
bin_arg=""; fake_arg=""
while [ $# -gt 0 ]; do
  case "$1" in
    --daemon) daemon=1 ;;
    -s) [ $# -ge 2 ] || { echo "-s needs a socket path" >&2; exit 2; }; sock=$2; shift ;;
    -a) [ $# -ge 2 ] || { echo "-a needs a URL" >&2; exit 2; }; allow_url=$2; shift ;;
    -b) [ $# -ge 2 ] || { echo "-b needs an address" >&2; exit 2; }; block_addr=$2; shift ;;
    --bin) [ $# -ge 2 ] || { echo "--bin needs a binary path" >&2; exit 2; }; bin_arg=$2; shift ;;
    --fake) [ $# -ge 2 ] || { echo "--fake needs a binary path" >&2; exit 2; }; fake_arg=$2; shift ;;
    --headless) headless=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
[ "$(id -u)" -ne 0 ] || { echo "run as the desktop user, not root" >&2; exit 2; }
if [ "$headless" -eq 1 ] && { [ -z "$bin_arg" ] || [ -z "$fake_arg" ]; }; then
  echo "--headless needs --bin and --fake: a container has no Go tree to build from" >&2
  exit 2
fi
if [ "$headless" -eq 1 ]; then
  command -v busctl >/dev/null 2>&1 || { echo "busctl is needed" >&2; exit 2; }
else
  # the desktop runs build (go) and measure the idle window (getconf): a headless
  # container has neither and needs neither (its binaries arrive via --bin/--fake)
  for tool in busctl go getconf; do
    command -v "$tool" >/dev/null 2>&1 || { echo "$tool is needed" >&2; exit 2; }
  done
fi
[ "$daemon" -eq 0 ] || command -v python3 >/dev/null 2>&1 \
  || { echo "python3 is needed for phase B (the API socket client)" >&2; exit 2; }

cd "$(dirname "$0")/.."   # the repo root: the build step compiles from the working tree

me=$(id -un)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tray-check.XXXXXX")
api="$tmp/api.sock"; fifo="$tmp/fake.in"; fake_out="$tmp/fake.out"
BIN="$tmp/snitch"; FAKE="$tmp/fakedaemon"
watcher=org.kde.StatusNotifierWatcher
operator_file=/etc/snitch/operator
overlay=/etc/snitch/rules.d/local.toml
idle_seconds=600      # 8.7's ten minutes; the record prints the measured window
allow_name=tray-check-allow.example.org; allow_addr=203.0.113.10   # reserved (RFC 5737): nobody real
curl_path=/usr/bin/curl
failed=0; passed=0; skipped=0; cpuline="(idle CPU not measured)"
tray_pid=0; fake_pid=0; mon_pid=0
ITEM=""           # the item's bus name, org.kde.StatusNotifierItem-<pid>-1, set by tray_start
snitch_ver=""; tray_rc=""; b_rule=""   # phase B: the rule key cleanup removes if it is left

now_ms() { date +%s%3N; }
note() { echo "        $*"; }
ask() { read -r -p "  $1 (Enter to go on) " _ || true; }
step() { # step <name> <command...>: prints PASS/FAIL, counts failures
  local name
  name=$1; shift
  if "$@"; then echo "  PASS  $name"; passed=$((passed + 1));
  else echo "  FAIL  $name"; failed=$((failed + 1)); fi
}
skip() { # skip <name> <why>: recorded as skipped, not failed (the reader's answer steps)
  echo "  SKIP  $1"; note "$2"; skipped=$((skipped + 1))
}
must() { # must <name> <command...>: a step the rest of the run needs
  local before=$failed
  step "$@"
  [ "$failed" -eq "$before" ] || { echo "stopping: the remaining steps need this one"; exit 1; }
}
wait_for() { # wait_for <seconds> <interval> <command...>: polls until the command succeeds
  local deadline interval=$2
  deadline=$(( $(now_ms) + $1 * 1000 )); shift 2
  until "$@"; do
    [ "$(now_ms)" -ge "$deadline" ] && return 1
    sleep "$interval"
  done
}

# -- the item on the session bus. One CLI per purpose: busctl for property reads (one line,
#    stable shape: 's "Active"', the tooltip flattened to a line that ends with the title
#    and the description as the last two quoted strings). gdbus is not used: its monitor
#    prints signals only, and a posted question is a Notify METHOD CALL, which busctl
#    monitor shows (its SERVICE argument filters the stream to that service).
item_prop() { # item_prop <property>: the raw one-line value, empty on error
  busctl --user -l get-property "$ITEM" /StatusNotifierItem org.kde.StatusNotifierItem "$1" 2>/dev/null
}
registered() { # the watcher lists our item: bus name plus object path (research.md 4.2)
  busctl --user get-property "$watcher" /StatusNotifierWatcher "$watcher" \
    RegisteredStatusNotifierItems 2>/dev/null \
    | grep -Fq -- "\"$ITEM/StatusNotifierItem\""
}
state_is() { # state_is <words> <Active|NeedsAttention> [desc-literal]: one sample in which the
  # title, the status and the tooltip all name the state (wait_for wraps this in a poll
  # window). The status of a view is Active or NeedsAttention (2.3); the tooltip's bold
  # title is "snitch: <state>" and its description starts with the state in words -- a
  # multi-line description prints as \n inside the quotes, and a trial adds " until ..." --
  # which a step can demand with the third argument (A10's deadline words, 2.4 to 2.6).
  local words=$1 want=$2 extra=${3:-} line desc tip_title
  [ "$(item_prop Title)" = "s \"snitch: $words\"" ] || return 1
  [ "$(item_prop Status)" = "s \"$want\"" ] || return 1
  line=$(item_prop ToolTip) || return 1
  # the flattened tooltip (sa(iiay)ss) ends with: ..."snitch: <words>" "<description>
  [[ $line =~ ^.*\"([^\"]*)\"\ \"([^\"]*)\"$ ]] || return 1
  tip_title=${BASH_REMATCH[1]}; desc=${BASH_REMATCH[2]}
  [ "$tip_title" = "snitch: $words" ] || return 1
  case $desc in
    "$words"|"$words\\n"*|"$words "*) ;;
    *) return 1 ;;
  esac
  [ -z "$extra" ] && return 0
  case $desc in *"$extra"*) return 0 ;; esac
  return 1
}
assert_state() { wait_for "$1" 0.25 state_is "$2" "$3" "${4:-}"; }  # <secs> <words> <status> [desc-literal]

# -- the stand-in daemon: commands on a fifo held open by fd 9, stdout the rule.add record
fake_start() {
  [ -p "$fifo" ] || mkfifo "$fifo"
  [ -e /proc/self/fd/9 ] || exec 9<>"$fifo"   # open read+write: neither end blocks
  "$FAKE" -api "$api" <&9 >>"$fake_out" 2>"$tmp/fake.err" &
  fake_pid=$!
  wait_for 5 0.1 [ -S "$api" ]
}
fake_cmd() { printf '%s\n' "$*" >&9; }   # the stdin grammar of tools/fakedaemon (commands.go)
fake_stop() {
  [ "$fake_pid" -ne 0 ] || return 0
  kill "$fake_pid" 2>/dev/null || true
  wait "$fake_pid" 2>/dev/null || true
  fake_pid=0
}

# -- the tray itself, and what it costs idle
tray_start() { # tray_start [flags...]: $! IS the tray (no wrapping shell in between)
  "$BIN" tray "$@" >"$tmp/tray.out" 2>"$tmp/tray.err" &
  tray_pid=$!
  ITEM="org.kde.StatusNotifierItem-$tray_pid-1"
  sleep 1
}
tray_stop() { # the wiring exits 0 on SIGTERM (open notes retracted, names released)
  [ "$tray_pid" -ne 0 ] || return 0
  kill "$tray_pid" 2>/dev/null || true
  wait "$tray_pid" 2>/dev/null && tray_rc=0 || tray_rc=$?
  tray_pid=0
}
cpu_ticks() { # cpu_ticks <pid>: utime+stime (fields 14+15 of /proc/<pid>/stat)
  local after_comm utime stime
  after_comm=$(sed -n 's/^.*) //p' "/proc/$1/stat")
  read -r _ _ _ _ _ _ _ _ _ _ _ utime stime _ <<<"$after_comm"
  echo $((utime + stime))
}
add_lines() { grep -c '"type":"rule.add"' "$fake_out" 2>/dev/null || true; }
rules_added_since() { [ "$(add_lines)" -gt "$1" ]; }   # a wait_for poll: a $( ) written in the call arguments would expand once and freeze there
last_add() { grep '"type":"rule.add"' "$fake_out" | tail -n 1; }
rule_has() { # rule_has <line> <literal>...: every literal must appear in the recorded line
  local line=$1 k
  shift
  for k in "$@"; do case $line in *"$k"*) ;; *) return 1 ;; esac; done
}

# -- the notification watch
mon_start() {
  busctl --user monitor org.freedesktop.Notifications >"$tmp/notify.log" 2>&1 &
  mon_pid=$!
}
mon_stop() {
  [ "$mon_pid" -ne 0 ] || return 0
  kill "$mon_pid" 2>/dev/null || true
  wait "$mon_pid" 2>/dev/null || true
  mon_pid=0
}
notify_seen() { # notify_seen <substring>: a Notify call carried this question
  grep -Fq 'Member=Notify' "$tmp/notify.log" 2>/dev/null \
    && grep -Fq -- "$1" "$tmp/notify.log" 2>/dev/null
}

# -- the role guess, mirrored from internal/client/role.go (the tray's own): writer is the
#    user named on the first line of a root-owned regular file neither group nor others can
#    write; the daemon decides the writes, this only predicts whether questions get buttons.
role_guess() {
  local owner mode name
  [ -f "$operator_file" ] || return 1
  owner=$(stat -c %u "$operator_file" 2>/dev/null) \
    && mode=$(stat -c %a "$operator_file" 2>/dev/null) || return 1
  [ "$owner" = 0 ] || return 1
  [ $(( 8#$mode & 8#22 )) -eq 0 ] || return 1
  name=$(head -n1 "$operator_file" | tr -d '[:space:]')
  [ -n "$name" ] && [ "$name" = "$me" ]
}

# -- the API client for phase B (python3: this host's nc has no -U; the shapes are
#    examples/api.md's). It can only ever ASK: status, rules, and the rule.remove that takes
#    this run's own rule out again -- no mode word, no trial verb, no kill switch, no
#    rule.add: the tray's Allow and Block buttons are the only writers on this host.
py=$(cat <<'PY'
import json, socket, sys

sock, mode, argv = sys.argv[1], sys.argv[2], sys.argv[3:]

def reply(req):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(sock)
    except OSError as e:
        print(f"connect {sock}: {e}", file=sys.stderr); sys.exit(1)
    s.sendall(json.dumps(req).encode() + b"\n")
    buf = b""
    while b"\n" not in buf:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
    s.close()
    print(buf.split(b"\n", 1)[0].decode())

if mode == "call":   # rule.remove carries the fields the found rule reported
    req = {"type": argv[0], "id": 1}
    for kv in argv[1:]:
        k, _, v = kv.partition("=")
        req[k] = int(v) if v.isdigit() else v
    reply(req)
elif mode == "get":  # a field of a reply on a dotted path: true/false, a string, a number
    at = json.loads(argv[0])
    for part in argv[1].split("."):
        at = at[part]
    print("true" if at is True else "false" if at is False else at)
elif mode == "rule":  # the tray rule for this destination in the overlay: program\tto\tproto\tport
    for r in json.loads(argv[0]).get("rules", []):
        if r.get("source") == argv[1] and r.get("to") == argv[2] \
                and str(r.get("note", "")).startswith("snitch tray "):
            print(f'{r["program"]}\t{r["to"]}\t{r.get("protocol", "")}\t{r.get("port", 0)}')
            sys.exit(0)
    sys.exit(1)
PY
)
pyrun() { python3 -I -u -c "$py" "$sock" "$@"; }

# -- phase A --------------------------------------------------------------------
a_build() { # both binaries from the working tree (never -o snitch in the repo root), or in full
  # from --bin/--fake (a headless run's caller hands both over; the -version assert runs
  # either way, so a broken binary fails here before anything starts)
  if [ -n "$bin_arg" ]; then BIN="$bin_arg"; else go build -o "$BIN" ./cmd/snitch; fi
  if [ -n "$fake_arg" ]; then FAKE="$fake_arg"; else go build -o "$FAKE" ./tools/fakedaemon; fi
  snitch_ver=$("$BIN" -version)
  [ -n "$snitch_ver" ]
}
a_gone() { assert_state 20 "daemon not running" NeedsAttention; }
a_monitor() { assert_state 45 monitor Active; }   # reconnect backoff: up to one 30 s wait
a_kill() {
  fake_cmd "kill on"
  assert_state 15 "kill switch set" NeedsAttention   # status-only change: the 5 s poll
  fake_cmd "kill off"
}
a_error() {
  fake_cmd "error tray-check: the rules are broken"
  assert_state 15 "rules error" NeedsAttention
  fake_cmd "error none"
}
a_kept() {
  fake_cmd "mode enforce"
  fake_cmd "keep"
  assert_state 8 "enforce kept" Active
  fake_cmd "unkeep"
}
a_trial() {
  fake_cmd "trial 10m"
  assert_state 8 "enforce trial" Active " until "   # the tooltip's deadline words (2.4, 2.5)
  fake_cmd "end"
}
a_question() { # A11: one scripted event; the notification service is watched for the post
  local rc=0
  mon_start
  ask "A question about curl wants $allow_name will appear on the desktop (nothing to press yet)"
  fake_cmd "event curl $curl_path ${allow_addr}=${allow_name} 443 tcp deny-default"
  wait_for 20 0.5 notify_seen "$allow_name" || rc=1
  mon_stop
  [ "$rc" -eq 0 ] || note "no Notify call on the service: look at $tmp/tray.err (no notification service? no actions?)"
  [ "$rc" -eq 0 ]
}
reader_skips() { # the reader's two answer steps: skipped, with the one-liner once
  local why="reader: $operator_file does not name $me, so the tray offers no buttons; create it once with: echo $me | sudo tee $operator_file >/dev/null && sudo chmod 0644 $operator_file"
  skip "A12 Allow: rule.add allow to $allow_name" "$why"
  skip "A13 Block: rule.add deny to $block_addr" "$why"
}
press_answer() { # press_answer <to> <verdict> <press> [stand-in event]: one operator press;
  # only ever called for a writer and through step(), so a late or missed press is a FAIL
  # line the run continues past (A14 onward), not an abort of the whole script
  local to=$1 verdict=$2 press=$3 before line
  before=$(add_lines)   # before the ask: the question is already up (A11), the press may land first
  ask "Press $press on the question about $to (it closes itself after 60 s)"
  [ "$#" -lt 4 ] || fake_cmd "$4"   # the Block step's event goes out when the operator is ready
  note "watching for the recorded rule (up to 90 s)"
  wait_for 90 1 rules_added_since "$before" \
    || { note "no rule.add arrived: no button, a late press (60 s), or a refused note; the last recorded line: $(last_add)"; return 1; }
  line=$(last_add)
  rule_has "$line" '"type":"rule.add"' '"program":"curl"' "\"to\":\"$to\"" \
    '"verdict":"'"$verdict\"" '"proto":"tcp"' '"port":443' '"note":"snitch tray' \
    || { note "the recorded line was: $line"; return 1; }
}
answer_steps() { # A12/A13, gated on A3's role fact, each through step (a late press FAILs)
  if ! role_guess; then reader_skips; return 0; fi
  step "A12 Allow: rule.add allow to $allow_name" press_answer "$allow_name" allow Allow
  step "A13 Block: rule.add deny to $block_addr" press_answer "$block_addr" deny Block \
    "event curl $curl_path $block_addr 443 tcp deny-default"
}
a_stand_in_restart() { # the stand-in dies, the tray follows, a fresh one serves the socket
  fake_stop
  assert_state 20 "daemon not running" NeedsAttention
  fake_start
  a_monitor
}
a_plasma() { # the operator restarts the tray's host themselves; the item re-registers (1.3)
  ask "Restart plasmashell yourself now: systemctl --user restart plasma-plasmashell"
  wait_for 45 0.5 registered
}
a_idle() {
  local t0 t1 hz d s cs
  t0=$(cpu_ticks "$tray_pid")
  note "measuring the idle window of ${idle_seconds} s: keep the desktop quiet, nothing to click"
  sleep "$idle_seconds"
  t1=$(cpu_ticks "$tray_pid")
  hz=$(getconf CLK_TCK)
  d=$(( t1 - t0 )); s=$(( d / hz )); cs=$(( (d % hz) * 100 / hz ))
  cpuline="tray CPU over ${idle_seconds} s idle: ${s}.${cs} s (${d} ticks / ${hz} Hz)"
  note "$cpuline"
}
a_screens() { # 2.7 asks the operator only: the tray stays up while they switch themes
  ask "Switch between Breeze and Breeze Dark and screenshot the tray item in both"
}
a_stop() { # SIGTERM: exit 0, and the item's name is released (the panel item disappears)
  local rc=0
  tray_stop
  [ "$tray_rc" = 0 ] || rc=1
  wait_for 5 0.5 item_gone || rc=1   # the release may lag a moment on a busy bus
  [ "$rc" -eq 0 ] || note "tray exit ${tray_rc:-none}; its stderr: $(tail -n 3 "$tmp/tray.err" 2>/dev/null || true)"
  [ "$rc" -eq 0 ]
}
item_gone() { ! registered; }
a_session() { busctl --user status >/dev/null 2>&1; }
item_owned() { busctl --user status "$ITEM" >/dev/null 2>&1; }   # the item's bus name is up, watcher or none
item_released() { ! item_owned; }
a_role() { # A3 is a fact, not a gate: a reader runs everything else, the answers skip
  if role_guess; then
    echo "writer: $operator_file names $me; the questions will offer buttons"
  else
    echo "reader: the answer steps will be recorded as skipped; create the file once with:"
    printf '        echo %s | sudo tee %s >/dev/null && sudo chmod 0644 %s\n' \
      "$me" "$operator_file" "$operator_file"
  fi
  return 0
}
a_stand_in() { # the stand-in serves the API socket; the tray follows into monitor
  fake_start
  a_monitor
}

phase_a() {
  echo "== phase A: the tray against the stand-in, on the session bus, as $me"
  must "A1 build: the tray and the stand-in from this tree" a_build
  must "A2 session bus: busctl reaches it" a_session
  step "A3 the role guess (writer or reader, the tray's own)" a_role
  tray_start -api "$api"
  must "A4 registration: the watcher lists the item" wait_for 30 0.5 registered
  must "A5 gone: NeedsAttention and 'daemon not running'" a_gone
  must "A6 stand-in up: monitor and Active" a_stand_in
  step "A7 kill switch set: NeedsAttention and the tooltip" a_kill
  step "A8 rules error: NeedsAttention and the tooltip" a_error
  step "A9 enforce kept: Active and the words" a_kept
  step "A10 enforce trial: Active and the deadline words" a_trial
  must "A11 a question is posted: the Notify call about $allow_name" a_question
  answer_steps
  must "A14 stand-in restart: gone, then back and monitor" a_stand_in_restart
  step "A15 plasmashell restart (operator): registered again" a_plasma
  step "A16 idle: $((idle_seconds / 60)) minutes, the CPU record (8.7)" a_idle
  a_screens   # asks the operator for the two screenshots while the tray is still up
  skip "A17 screenshots: Breeze and Breeze Dark (2.7)" "operator task, not a bus assertion: legible icons on a light and a dark panel are eyes' work; the two screenshots are the record"
  must "A18 stop: the tray ends cleanly, exit 0" a_stop
}

# -- phase A, headless (the ci-debs smoke's group 8) -------------------------------
# One bus, one tray, one stand-in: the assertions phase A makes against the bus run
# verbatim (the state views, the view changes, the follow over a stand-in restart,
# the clean exit), while everything that needs the desktop or the operator (the
# watcher plasmashell owns, the notification service, the pressed buttons, the idle
# and screenshot measurements) is a recorded SKIP, never a FAIL and never silently
# dropped: the record keeps the full phase A step map either way.
a_stop_headless() { # SIGTERM: exit 0, and the item's own bus name is released (no watcher
  # to forget it: the release IS the observable on a bare bus)
  local rc=0
  tray_stop
  [ "$tray_rc" = 0 ] || rc=1
  wait_for 5 0.5 item_released || rc=1
  [ "$rc" -eq 0 ] || note "tray exit ${tray_rc:-none}; its stderr: $(tail -n 3 "$tmp/tray.err" 2>/dev/null || true)"
  [ "$rc" -eq 0 ]
}
phase_a_headless() {
  echo "== phase A (headless): the tray against the stand-in, on a private session bus, as $me"
  must "A1 provided tray: $BIN answers -version" a_build
  must "A2 session bus: busctl reaches it" a_session
  step "A3 the role guess (writer or reader, the tray's own)" a_role
  tray_start -api "$api"
  must "A4 registration: the item's bus name is owned ($ITEM)" wait_for 30 0.5 item_owned
  must "A5 gone: NeedsAttention and 'daemon not running'" a_gone
  must "A6 stand-in up: monitor and Active" a_stand_in
  step "A7 kill switch set: NeedsAttention and the tooltip" a_kill
  step "A8 rules error: NeedsAttention and the tooltip" a_error
  step "A9 enforce kept: Active and the words" a_kept
  step "A10 enforce trial: Active and the deadline words" a_trial
  skip "A11 a question is posted: the Notify call" "headless: no notification service on a bare bus and no operator at a desktop to watch the popup"
  answer_steps   # A12/A13: a smoke container has no operator file, so the reader's skips print, as at a desktop
  step "A14 stand-in restart: gone, then back and monitor" a_stand_in_restart
  skip "A15 plasmashell restart (operator): registered again" "headless: no panel to restart; the re-registration path needs the watcher only a desktop has"
  skip "A16 idle: the CPU record (8.7)" "headless: the ten-minute idle window is the desktop's own measurement, not a bus assertion"
  skip "A17 screenshots: Breeze and Breeze Dark (2.7)" "headless: no themes to switch and no eyes to judge legibility"
  must "A18 stop: the tray ends cleanly, exit 0" a_stop_headless
}

# -- phase B --------------------------------------------------------------------
d_status=""
b_refused=""
daemon_status() { # one status reply, kept for the mode and overlay checks
  d_status=$(pyrun call status) || return 1
  [ "$(pyrun get "$d_status" type)" = reply ] && [ "$(pyrun get "$d_status" ok)" = true ]
}
b_rule_find() { # b_rule_find <to>: this run's tray rule for the destination, or nothing
  local reply
  reply=$(pyrun call rules) || return 1
  pyrun rule "$reply" "$overlay" "$1"
}
b_rule_remove() { # removes this run's rule by the key the rules view reported. A refused
  # reply (the daemon answered ok:false) fails exactly like a broken transport: either way
  # the overlay may still hold the rule, which the step and the trap have to face. The
  # reply line is printed, so the caller's note can show what the daemon said.
  local prog to proto port reply
  IFS=$'\t' read -r prog to proto port <<<"$b_rule"
  reply=$(pyrun call rule.remove "program=$prog" "to=$to" "proto=$proto" "port=$port") || return 1
  [ "$(pyrun get "$reply" ok 2>/dev/null)" = true ] || { echo "$reply"; return 1; }
  echo "$reply"
}
b_rule_gone() { ! b_rule_find "$1"; }
b_rule_present() { [ -n "$(b_rule_find "$1")" ]; }   # a wait_for poll: a $( ) in the call args would expand once and freeze, like B5 caught live
b_question() { # b_question <to> <verb> <curl target>: the operator's own real connect; the
  # answer's rule lands in the overlay, is shown, then removed again by the key the view gave
  local to=$1 verb=$2 target=$3 rc=0 remove_reply=""
  ask "In your terminal run: curl -sSf $target ; then press $verb on the question (60 s)"
  wait_for 60 2 b_rule_present "$to" || rc=1
  b_rule=$(b_rule_find "$to") || rc=1
  [ "$rc" -eq 0 ] || { note "no tray rule for $to with note 'snitch tray ...' in $overlay: a rule may already cover the curl, or the press missed the 60 s window"; return 1; }
  note "the overlay rule: $(printf '%s' "$b_rule" | tr '\t' ' ')"
  if ! remove_reply=$(b_rule_remove); then
    rc=1; note "rule.remove failed for the key above: ${remove_reply:-no reply at all (the socket?)}"
  fi
  wait_for 10 1 b_rule_gone "$to" || rc=1
  b_rule=""
  [ "$rc" -eq 0 ] && note "the overlay rule is gone again; $overlay is as it was"
  [ "$rc" -eq 0 ]
}
phase_b() {
  echo "== phase B: the questions against the real daemon on $sock (monitor mode only)"
  must "B1 snitchd answers over $sock (mode is checked next)" daemon_status
  if [ "$(pyrun get "$d_status" status.mode)" != monitor ]; then
    b_refused="monitor-mode refusal: snitchd on $sock is in mode $(pyrun get "$d_status" status.mode); nothing ran but the read-only status probe, and the tray never started"
    echo "REFUSED: snitchd on $sock is in mode $(pyrun get "$d_status" status.mode); monitor mode only"
    echo "         (a question must never reach an enforcing daemon). No step runs after the"
    echo "         status probe; the tray is not started. Exit 2."
    exit 2
  fi
  overlay=$(pyrun get "$d_status" status.rules.overlay)
  note "monitor mode confirmed; overlay $overlay"
  must "B2 build: the tray from this tree" a_build
  tray_start -api "$sock"
  must "B3 registration: the watcher lists the item" wait_for 30 0.5 registered
  must "B4 tray follows the daemon: monitor and Active" assert_state 20 monitor Active
  # the allow URL's host is the rule's destination (allow goes to the name), so it has to
  # parse cleanly before any question step: a scheme, a path and credentials all go, and
  # what remains must be one colon-free host -- a colon (an IPv6 literal with brackets
  # stripped or still in) cannot be the `to` the daemon's DNS tap would have learned.
  if role_guess; then
    must "B5 preflight: a colon-free destination parses out of $allow_url" b_allow_dest
    step "B5 the Allow question: the rule checked in the overlay and removed" \
      b_question "$allow_dest" Allow "$allow_url"
    step "B6 the Block question: the deny rule checked and removed" \
      b_question "$block_addr" Block "https://$block_addr/"
  else
    skip "B5/B6 the question steps" "reader: $operator_file does not name $me (phase A prints the one-liner); answers need the operator"
  fi
  must "B7 stop: the tray ends cleanly, exit 0" a_stop
  echo "note: phase B never restarts snitchd and asks no mode change; the kernel was untouched"
}
allow_dest=""
b_allow_dest() { # the host of the allow URL, asserted non-empty and colon-free (into $allow_dest)
  local d=${allow_url#*//} why
  d=${d%%/*}
  why="empty destination (a bare scheme with nothing after it)"
  case $d in
    *:*) why="a colon in '$d' (an IPv6 literal or a scheme left behind; use an IPv4 address or a name)" ;;
  esac
  if [ -z "$d" ] || [[ $d == *:* ]]; then
    note "cannot ask the Allow question against '$allow_url': $why"
    return 1
  fi
  allow_dest=$d
}

# -- the end: record, then cleanup
record() {
  echo "== record for research.md"
  echo "date: $(date -Is) on $(hostname), as $me"
  if [ -n "$bin_arg" ]; then
    echo "snitch ${snitch_ver:-(not built this run)} (provided: $BIN)"
  else
    echo "snitch ${snitch_ver:-(not built this run)} ($(go version | cut -d' ' -f3)) from this tree"
  fi
  echo "plasma: $(plasmashell --version 2>/dev/null | head -n 1 || echo unknown)"
  echo "steps: $passed passed, $skipped skipped, $failed failed"
  echo "$cpuline"
  if [ "$daemon" -eq 1 ]; then
    if [ -n "$b_refused" ]; then echo "phase B on the real daemon ($sock): $b_refused"
    else echo "phase B on the real daemon ($sock): $([ "$failed" -eq 0 ] && echo passed || echo INCOMPLETE)"; fi
  else
    echo "phase B: pending until snitchd runs on this host (rerun with --daemon)"
  fi
}
cleanup() {
  set +e
  mon_stop
  if [ -n "$b_rule" ]; then b_rule_remove >/dev/null 2>&1 && echo "trap: the phase B rule was removed"; fi
  tray_stop
  fake_stop
  [ -n "$tray_rc" ] && echo "tray exit status: $tray_rc"
  record
  echo "failed steps: $failed"
  rm -rf "$tmp"
}
trap cleanup EXIT

if [ "$daemon" -eq 1 ]; then phase_b
elif [ "$headless" -eq 1 ]; then phase_a_headless
else phase_a; fi
if [ "$failed" -eq 0 ]; then exit 0; else exit 1; fi
