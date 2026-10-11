#!/usr/bin/env bash
# shellcheck disable=SC2329,SC2317  # the step helpers are invoked through step(), cleanup through the trap (SC2317 on older shellcheck)
# api-check: prove the daemon's local API step by step, as the desktop user (spec daemon-api,
# Req 6.4; design "Docs and verification"). Nothing here needs root, and the script refuses to
# run as root: the point is what a plain user gets through the 0666 socket.
#
# The socket is talked to by an embedded python3 client (AF_UNIX; this VM's nc has no -U):
#   call  one connection, one request line, the reply line with the same id
#   sub   one connection kept open: subscribe, then every line the daemon sends for N seconds
# The same two shapes are the command lines examples/api.md documents.
#
# A1 status reply: running true, a version (printed), the pid kept for A6; mode monitor, which
#    A2 and B2 rely on (allow-monitor is the monitor verdict for an unruled destination)
# A2 subscribe, curl https://DENY/  -> an event for curl (program curl, or the curl path while
#    no rules file declares it) with verdict allow-monitor within 1 s
# A3 when status says counting: curl https://1.1.1.1/ -> that entry's bytesSent grows within 5 s
#    in a 15m snapshot (skipped with a note when counting is off)
# A4 rule.add as this user: refused ("rule.add: write requires the operator") unless this user
#    is the operator named in /etc/snitch/operator (the script prints which it expects)
# B  only after A4 was accepted (this user is the operator): the deny rule for curl -> DENY is
#    listed within 5 s; then curl to DENY fails with EPERM (a deny-rule verdict is enforced by
#    the kernel in every mode, bpf/snitch.bpf.c: no mode gate on V_DENY_RULE) and the event says
#    deny-rule; rule.remove restores: curl connects again and the event says allow-monitor. The
#    trap removes the rule when the script dies in between, with the key the add reply named
#    (ad hoc programs can be curl-2 on a name collision).
# A5 only after A4 was refused: trial as a non-operator -> refused. The trial request is never
#    sent on a connection the daemon just accepted a write from: a mis-detected operator would
#    start an enforce trial, and no check script switches a mode.
# A6 status again: running true and the same pid as A1 (the status has no heartbeat age: the
#    daemon that answers with its pid unchanged kept running through every probe and write).
# The run ends with one line to paste into research.md:
#   state: mode <m> trial <none|deadline> kept <no|yes> kill <clear|SET>
#
# The daemon dedupes identical events for 10 s: a curl to DENY within 10 s before a run hides
# the A2 event (the verdict flips in B are always fresh). Wait 10 s between runs.
#
# usage: scripts/api-check.sh [-s socket] [-x deny-addr] [--fake] [-h]
# Exit 0: every step passed; 1: a step failed (A1 stops the run); 2: usage or run as root.
set -euo pipefail

usage() {
  cat <<'U'
usage: scripts/api-check.sh [-s socket] [-x deny-addr] [--fake] [-h]
  run as the desktop user, never as root (exit 2)
  A1 status reply (running, version, mode)    A2 subscribe + curl event within 1 s
  A3 bytes grow within 5 s (when counting)    A4 rule.add refused for a reader
  B  as the operator: deny rule -> curl fails with EPERM and the event says deny-rule,
     remove -> curl connects again, allow-monitor again
  A5 trial refused for a non-operator         A6 status: running, same pid
  -s <socket>  the API socket (default /run/snitch/api.sock; -api of a hand-started daemon)
  -x <addr>    address no rule covers (default 9.9.9.9); an IPv6 address bare, no brackets
  --fake       the socket is served by a fake with no kernel behind it (script development):
               the curl EPERM and reconnect assertions in B are skipped and said so
  -h           this text
  wait 10 s between runs: the daemon dedupes identical events for 10 s
exit 0 all steps passed, 1 a step failed, 2 usage or root
U
}

sock=/run/snitch/api.sock; deny=9.9.9.9; fake=0
while [ $# -gt 0 ]; do
  case "$1" in
    -s) [ $# -ge 2 ] || { echo "-s needs a socket path" >&2; exit 2; }; sock=$2; shift ;;
    -x) [ $# -ge 2 ] || { echo "-x needs an address" >&2; exit 2; }; deny=$2; shift ;;
    --fake) fake=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
[ "$(id -u)" -ne 0 ] || { echo "run as the desktop user, not root: root always writes, so the reader refusals cannot be shown" >&2; exit 2; }
for tool in python3 curl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "$tool is needed" >&2; exit 2; }
done

me=$(id -un)
curl_path=$(realpath "$(command -v curl)")
operator_file=/etc/snitch/operator
operator=$(head -n1 "$operator_file" 2>/dev/null | tr -d '[:space:]' || true)
case "$deny" in */*) deny_prefix=$deny ;; *:*) deny_prefix=$deny/128 ;; *) deny_prefix=$deny/32 ;; esac
case "$deny" in *:*) deny_url="https://[${deny%%/*}]/" ;; *) deny_url="https://${deny%%/*}/" ;; esac
tmp=$(mktemp -d)
failed=0
pid1=""
last_status=""   # the last status reply, for the state line
overlay=""       # the overlay path from status: the api-check rule must come from it
rule_added=0     # the trap removes the rule once B1 added it
rule_program=curl; rule_to=$deny_prefix   # the remove key; the add reply's text sets the real one
sub_pid=0; sub_log=""

# -- the socket client (python3: this VM's nc has no -U). One program, seven modes:
#    call <sock> <type> [field=value ...]  one request, prints the reply line with its id
#    sub <sock> <seconds>                  subscribe, prints every line for N seconds
#    get <json> <dotted.path>              a field: true/false, a string, a number
#    event <log> <addr> <path> <verdict>   exit 0 and the line when an event matches
#    bytes <reply> <addr> <path>           the largest bytesSent of the matching entries
#    rule <reply> <note> <source>          "program<TAB>to" of the first rule with the note (and source, when given)
#    added <reply>                         "program<TAB>to" from the add reply's text
py=$(cat <<'PY'
import json, re, socket, sys, time

INT_FIELDS = ("id", "port")

def connect(path):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5)
    try:
        s.connect(path)
    except OSError as e:
        print(f"connect {path}: {e}", file=sys.stderr)
        sys.exit(1)
    return s

def request(args):
    req = {"type": args[0], "id": 1}
    for kv in args[1:]:
        k, _, v = kv.partition("=")
        req[k] = int(v) if k in INT_FIELDS else v
    return req

def is_curl(obj, path):
    return obj.get("program") == "curl" or obj.get("path") == path

def value(v):
    if isinstance(v, bool):
        return "true" if v else "false"
    if v is None:
        return ""
    return v if isinstance(v, str) else json.dumps(v)

mode, args = sys.argv[1], sys.argv[2:]
if mode == "call":
    sock, req = args[0], request(args[1:])
    s = connect(sock)
    s.sendall((json.dumps(req) + "\n").encode())
    try:
        for raw in s.makefile("rb"):
            line = raw.decode()
            if json.loads(line).get("id") == req["id"]:
                sys.stdout.write(line)
                sys.exit(0)
    except socket.timeout:
        print("no reply within 5 s", file=sys.stderr)
        sys.exit(1)
    print("connection closed without a reply", file=sys.stderr)
    sys.exit(1)
elif mode == "sub":
    sock, secs = args[0], float(args[1])
    s = connect(sock)
    s.sendall((json.dumps({"type": "subscribe", "id": 1}) + "\n").encode())
    deadline, buf = time.monotonic() + secs, b""
    while time.monotonic() < deadline:
        s.settimeout(max(0.05, deadline - time.monotonic()))
        try:
            chunk = s.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        buf += chunk
        while b"\n" in buf:
            line, buf = buf.split(b"\n", 1)
            sys.stdout.write(line.decode() + "\n")
            sys.stdout.flush()
elif mode == "get":
    obj = json.loads(args[0])
    for key in args[1].split("."):
        obj = obj.get(key) if isinstance(obj, dict) else None
    print(value(obj))
elif mode == "event":
    log, addr, path, verdict = args
    for line in open(log, encoding="utf-8", errors="replace"):
        try:
            obj = json.loads(line)
        except ValueError:
            continue
        if obj.get("type") == "event" and obj.get("addr") == addr and is_curl(obj, path) and obj.get("verdict") == verdict:
            sys.stdout.write(line)
            sys.exit(0)
    sys.exit(1)
elif mode == "bytes":
    reply, addr, path = json.loads(args[0]), args[1], args[2]
    print(max((e.get("bytesSent", 0) for e in reply.get("entries") or [] if e.get("addr") == addr and is_curl(e, path)), default=0))
elif mode == "rule":
    reply, note, source = json.loads(args[0]), args[1], args[2]
    for r in reply.get("rules") or []:
        if r.get("note") == note and (not source or r.get("source") == source):
            print(r.get("program", "") + "\t" + r.get("to", ""))
            sys.exit(0)
    sys.exit(1)
elif mode == "added":
    m = re.match(r"rule added: (\S+) to (\S+)", json.loads(args[0]).get("text", ""))
    if not m:
        sys.exit(1)
    print(m.group(1) + "\t" + m.group(2))
PY
)
pyrun() { python3 -I -c "$py" "$@"; }
api() { pyrun call "$sock" "$@"; }            # api <type> [field=value ...]: the reply line
jget() { pyrun get "$1" "$2"; }               # jget <json> <dotted.path>

step() { # step <name> <command...>: prints PASS/FAIL, counts failures
  local name=$1; shift
  if "$@"; then echo "  PASS  $name"; else echo "  FAIL  $name"; failed=$((failed + 1)); fi
}
must() { # must <name> <command...>: like step, but a failure ends the run (later steps are meaningless)
  local before=$failed
  step "$@"
  if [ "$failed" -gt "$before" ]; then echo "stopping: the remaining steps need this one"; exit 1; fi
}
now_ms() { date +%s%3N; }
wait_for() { # wait_for <seconds> <interval> <command...>: polls until the command succeeds
  local deadline interval=$2
  deadline=$(( $(now_ms) + $1 * 1000 )); shift 2
  until "$@"; do
    [ "$(now_ms)" -ge "$deadline" ] && return 1
    sleep "$interval"
  done
}
note() { echo "        $*"; }

# -- replies
reply_ok() { [ "$(jget "$1" type)" = reply ] && [ "$(jget "$1" ok)" = true ]; }
reply_refused() { [ "$(jget "$1" type)" = error ] && [ "$(jget "$1" error)" = "$2: write requires the operator" ]; }
show() { note "$(printf '%s' "$1" | head -c 300)"; }   # the reply (or error) line, bounded
status_read() { # fills last_status; a connect failure prints the client's reason
  local out rc=0
  out=$(api status 2>"$tmp/err") || rc=$?
  if [ "$rc" -ne 0 ]; then note "$(cat "$tmp/err")"; return 1; fi
  last_status=$out
}
status_running() { status_read && [ "$(jget "$last_status" status.running)" = true ]; }

# -- the subscription: a client kept open in the background, its lines in $sub_log. python3
#    runs directly (not through pyrun) so $! is its pid and stop_sub ends it, not a subshell.
start_sub() { # start_sub <seconds>: returns once the subscribe reply arrived
  sub_log=$(mktemp "$tmp/sub.XXXXXX")
  python3 -I -c "$py" sub "$sock" "$1" >"$sub_log" 2>&1 &
  sub_pid=$!
  wait_for 3 0.1 grep -Eq '"type": ?"reply"' "$sub_log"
}
stop_sub() {
  if [ "$sub_pid" -ne 0 ]; then kill "$sub_pid" 2>/dev/null || true; wait "$sub_pid" 2>/dev/null || true; sub_pid=0; fi
}
event_seen() { pyrun event "$sub_log" "$1" "$curl_path" "$2" >/dev/null; } # event_seen <addr> <verdict>
show_events() { # what the subscription saw for the address, when the expected verdict did not come
  local n
  n=$(grep -Ec '"type": ?"event"' "$sub_log" || true)
  note "events seen: $n; for $1: $(grep -E "\"addr\": ?\"$1\"" "$sub_log" | head -c 300 || true)"
  note "an identical event within the 10 s dedupe window is not sent: wait 10 s between runs"
}
curl_rc=0; curl_err=""
curl_probe() { # curl_probe: one connect to the deny address; the exit and the verbose trace kept
  curl_rc=0
  curl_err=$(curl -sS -v --max-time 3 -o /dev/null "$deny_url" 2>&1) || curl_rc=$?
}
curl_denied() { # the kernel refused the connect: exit 7 and the errno text (curl 8.x hides it without -v)
  [ "$curl_rc" -eq 7 ] && grep -qi 'failed: Operation not permitted' <<<"$curl_err"
}
curl_connected() { [ "$curl_rc" -ne 7 ]; } # any exit but 7: the connect went through
probe_event() { # probe_event <verdict>: subscribe, curl to the deny address, the matching event within 1 s
  start_sub 8 || { note "no subscribe reply within 3 s: $(head -c 300 "$sub_log")"; stop_sub; return 1; }
  curl_probe
  local rc=0
  wait_for 1 0.1 event_seen "${deny%%/*}" "$1" || rc=1
  [ "$rc" -eq 0 ] || show_events "${deny%%/*}"
  stop_sub
  return "$rc"
}

# -- bytes (A3)
bytes_of() { # bytes_of <addr>: the entry's bytesSent in the 15m snapshot, 0 without one
  local out
  out=$(api snapshot window=15m 2>/dev/null) || { echo 0; return; }
  pyrun bytes "$out" "$1" "$curl_path"
}
bytes_grew() { [ "$(bytes_of "$1")" -gt "$2" ]; }

# -- rules (B)
rule_listed() { # the api-check rule from the overlay is in the rules listing (refreshes the remove key)
  local out key
  out=$(api rules 2>/dev/null) || return 1
  key=$(pyrun rule "$out" api-check "$overlay") || return 1
  IFS=$'\t' read -r rule_program rule_to <<<"$key"
}
rule_gone() { ! rule_listed; }
add_reply=""
rule_add() { # the path first (curl is undeclared in the deployed rules); a run after an earlier
  # one finds curl declared by the overlay ("executable is program curl: use that name"), so a
  # second try by name follows any error but the refusal. An accepted add sets the remove key
  # from the reply's text at once: the trap must not guess it.
  local key
  add_reply=$(api rule.add "path=$curl_path" "to=$deny_prefix" verdict=deny note=api-check 2>&1) || true
  if ! reply_ok "$add_reply" && ! reply_refused "$add_reply" rule.add; then
    note "by path: $add_reply"
    add_reply=$(api rule.add program=curl "to=$deny_prefix" verdict=deny note=api-check 2>&1) || true
  fi
  reply_ok "$add_reply" || return 0
  rule_added=1
  if key=$(pyrun added "$add_reply"); then IFS=$'\t' read -r rule_program rule_to <<<"$key"
  else note "add reply without 'rule added: <program> to <to>': removing by $rule_program -> $rule_to"; fi
}
remove_reply=""
rule_remove() {
  remove_reply=$(api rule.remove "program=$rule_program" "to=$rule_to" 2>&1) || true
  reply_ok "$remove_reply" && rule_added=0
  reply_ok "$remove_reply"
}

# -- the final line, from the trap: an aborted run still shows the state
state_line() {
  local st trial kept kill
  status_read >/dev/null 2>&1 || true
  st=$last_status
  if [ -z "$st" ]; then echo "state: mode unknown trial unknown kept unknown kill unknown (no status reply)"; return; fi
  trial=$(jget "$st" status.trial); kept=$(jget "$st" status.kept); kill=$(jget "$st" status.kill)
  case "$kept" in true) kept=yes ;; false) kept=no ;; *) kept=unknown ;; esac
  case "$kill" in true) kill=SET ;; false) kill=clear ;; *) kill=unknown ;; esac
  echo "state: mode $(jget "$st" status.mode) trial ${trial:-none} kept $kept kill $kill"
}
finish() { if [ "$failed" -eq 0 ]; then exit 0; else exit 1; fi; }
cleanup() {
  set +e
  stop_sub
  if [ "$rule_added" -eq 1 ]; then
    if rule_remove; then echo "trap: rule.remove $rule_program -> $rule_to (api-check rule gone)"; else echo "trap: rule.remove failed: $remove_reply"; fi
  fi
  state_line
  echo "failed steps: $failed"
  rm -rf "$tmp"
}
trap cleanup EXIT

echo "== snitchd API as $me through $sock"
if [ -n "$operator" ]; then
  if [ "$operator" = "$me" ]; then echo "operator: $operator ($operator_file) is this user: writes expected to be accepted"
  else echo "operator: $operator ($operator_file); this user is a reader: writes expected to be refused"; fi
else
  echo "operator: none readable at $operator_file: this user is a reader (root alone writes)"
fi
[ "$fake" -eq 0 ] || echo "fake: no kernel behind $sock; B asserts the API's replies and events, not curl's fate"

must "A1 connect: status reply with running true"      status_running
pid1=$(jget "$last_status" status.pid)
version=$(jget "$last_status" status.version)
overlay=$(jget "$last_status" status.rules.overlay)
step "A1 status: version '$version', pid $pid1"           test -n "$version"
mode=$(jget "$last_status" status.mode)
step "A1 status: mode monitor (A2 and B2 expect allow-monitor)"   test "$mode" = monitor
step "A2 event for curl -> $deny: allow-monitor within 1 s"   probe_event allow-monitor
counting=$(jget "$last_status" status.counting)
if [ "$counting" = true ]; then
  before=$(bytes_of 1.1.1.1)
  curl -sS --max-time 5 -o /dev/null https://1.1.1.1/ >/dev/null 2>&1 || true
  step "A3 bytesSent for curl -> 1.1.1.1 grows past $before within 5 s"   wait_for 5 0.5 bytes_grew 1.1.1.1 "$before"
else
  echo "  skip  A3 bytes: status says counting false (the cookie helper is off on this kernel)"
fi

rule_add
if [ "$operator" = "$me" ]; then
  step "A4 rule.add as the operator $me: accepted"        reply_ok "$add_reply"
else
  step "A4 rule.add as reader $me: refused"               reply_refused "$add_reply" rule.add
fi
reply_ok "$add_reply" || reply_refused "$add_reply" rule.add || show "$add_reply"

if [ "$rule_added" -eq 1 ]; then
  echo "-- B: this user writes (the daemon accepted rule.add: $rule_program -> $rule_to)"
  step "B1 rule deny $rule_program -> $rule_to listed from the overlay within 5 s"   wait_for 5 0.5 rule_listed
  step "B1 event for curl -> $deny: deny-rule within 1 s"      probe_event deny-rule
  if [ "$fake" -eq 0 ]; then step "B1 curl $deny denied with EPERM (deny-rule is enforced in every mode)" curl_denied
  else echo "  skip  B1 curl EPERM: --fake (curl exit $curl_rc, no kernel decided)"; fi
  if [ "$fake" -eq 0 ] && ! curl_denied; then note "curl exit $curl_rc: $(grep -iE 'connect|failed' <<<"$curl_err" | head -c 200 || true)"; fi
  step "B2 rule.remove $rule_program -> $rule_to: accepted"    rule_remove
  reply_ok "$remove_reply" || show "$remove_reply"
  step "B2 rule gone from the listing within 5 s"              wait_for 5 0.5 rule_gone
  step "B2 event for curl -> $deny: allow-monitor again within 1 s"   probe_event allow-monitor
  if [ "$fake" -eq 0 ]; then step "B2 curl $deny connects again (exit $curl_rc != 7)" curl_connected
  else echo "  skip  B2 curl reconnect: --fake (curl exit $curl_rc)"; fi
else
  echo "  skip  B: rule.add was not accepted for $me (run as the operator to cover B)"
fi

if reply_refused "$add_reply" rule.add; then
  trial_reply=$(api trial duration=1m 2>&1) || true
  step "A5 trial as reader $me: refused"                       reply_refused "$trial_reply" trial
  reply_refused "$trial_reply" trial || show "$trial_reply"
else
  echo "  skip  A5 trial refusal: $me writes; run as another user to show the refusal"
fi

step "A6 status: running true"                               status_running
step "A6 status: pid $pid1 unchanged (the daemon ran throughout)"   test "$(jget "$last_status" status.pid)" = "$pid1"
finish
