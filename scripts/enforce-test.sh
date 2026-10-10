#!/bin/bash
# shellcheck disable=SC2329,SC2317  # the step helpers are invoked through step(), cleanup through the trap (SC2317 on older shellcheck)
# enforce-test: the first deny-by-default run of snitchd, on this machine, under a trap.
#
# Phase 1 (always, monitor mode, nothing is blocked): the generated rules file loads, a curl
# event shows "program curl" (the resolver's executable identity equals the kernel's), and the
# local probe target answers. --check-only stops here.
# Phase 2 (after the confirmation or -y): enforce for -d seconds with rules that allow curl to
# the -a address on tcp/443 and the session tooling (Claude Code) to anywhere, nothing else.
#   C1 curl https://ALLOW   -> ok, log shows "allow (rule)" for curl
#   C2 curl https://DENY    -> EPERM, log shows "DENY (default)" for curl
#   C3 local probe          -> ok (the built-in local-network allow, not a rule)
#   K1 kill switch on       -> curl DENY ok;  K2 off -> EPERM again
#   P1 SIGSTOP the daemon   -> after 16 s curl DENY ok (heartbeat stale);  P2 SIGCONT -> EPERM within 3 s
# Phase 3 (after its own confirmation or -y; --skip-trial leaves it out): the trial flow under
# the same rules. The daemon runs without -mode, so the trial and kept files (on temp paths,
# not /var/lib/snitch) decide its mode, with -d + 240 s as the ceiling it exits at; the snitchd
# verbs, pointed at the same temp paths, drive it. Every wait polls every 0.5 s.
#   T1-T3  trial 2m         -> "enforce until" printed, curl DENY EPERM within 5 s, local probe ok,
#                              log "mode: enforce (trial until"
#   T4     restart daemon   -> EPERM again within 5 s (the deadline file outlives the daemon)
#   T5-T6  end              -> curl DENY ok within 5 s, "trial ended by the operator" logged
#   T7-T9  trial 1m         -> EPERM, then ok within 65 s and "trial ended at its deadline" logged
#   T10    trial file from another boot, written by hand -> removed within 5 s, "trial ended at boot"
#   T11    trial 2m, then end -at-boot -> trial file gone and curl ok within 5 s
#   T12-13 trial 2m, keep   -> trial file gone, kept file present, still EPERM after 5 s;
#                              unkeep -> ok within 5 s
#   T14    trial 2m, kill switch on -> ok; off -> EPERM             (K1/K2 under a trial)
#   T15    SIGSTOP 16 s -> ok (heartbeat stale); SIGCONT -> EPERM within 3 s  (P1/P2 under a trial)
#   T16-17 status exits 0 with "daemon: running"; after end + stop it exits 1 with "not running"
# The trap on EXIT runs `snitchd end` on the temp state dir, resumes and stops the daemon,
# clears the kill switch, writes mode monitor into the control map and prints those facts plus
# whether a trial or kept file is left. Exit code = number of failed steps.
#
# Run as root with the hypervisor console open: sudo scripts/enforce-test.sh [-y] [-d 120]
#   [-a 1.1.1.1] [-x 9.9.9.9] [-l 10.0.0.1:53] [-b /tmp/snitchd] [--check-only] [--skip-trial]
set -u

yes=0; check_only=0; skip_trial=0; duration=120; allow=1.1.1.1; deny=9.9.9.9; local_probe=""; bin=/tmp/snitchd
while [ $# -gt 0 ]; do
  case "$1" in
    -y) yes=1 ;;
    --check-only) check_only=1 ;;
    --skip-trial) skip_trial=1 ;;
    -d) duration=$2; shift ;;
    -a) allow=$2; shift ;;
    -x) deny=$2; shift ;;
    -l) local_probe=$2; shift ;;
    -b) bin=$2; shift ;;
    *) echo "unknown option $1" >&2; exit 2 ;;
  esac
  shift
done
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo): bpftool and the BPF LSM hooks need it" >&2; exit 2; }
[ -x "$bin" ] || { echo "daemon binary $bin missing: go build -o $bin ./cmd/snitchd" >&2; exit 2; }
if [ -z "$local_probe" ]; then
  local_probe="$(ip route show default | awk '{print $3; exit}'):53"
fi

work=$(mktemp -d /tmp/snitch-enforce.XXXXXX)
log=$work/daemon.log
rules=$work/rules.toml
state=$work/state     # phase 3: the daemon's -state-dir (trial and enforce files), never /var/lib/snitch
status=$work/status   # phase 3: the daemon's -status file, never /run/snitch/status
ceiling=$((duration + 240))   # phase 3: the daemon's -duration; the flow needs about 4 minutes
pid=""
failed=0
step() { # step <name> <expected 0|1 for ok> <command...>: prints PASS/FAIL, counts failures
  local name=$1 want=$2; shift 2
  if "$@"; then got=0; else got=1; fi
  if [ "$got" -eq "$want" ]; then echo "  PASS  $name"; else echo "  FAIL  $name"; failed=$((failed + 1)); fi
}
kill_map() { bpftool map update pinned /sys/fs/bpf/snitch/kill key 0 0 0 0 value "$1" 0 0 0; }
attached() { bpftool prog show 2>/dev/null | grep -c 'socket_connect\|socket_sendmsg'; }
curl_ok() { curl -sS --max-time 5 -o /dev/null "https://$1/" 2>/dev/null; }
curl_eperm() { # curl must fail with EPERM: exit 7 and, in the verbose trace, the errno text
  # ("connect to … failed: Operation not permitted"); without -v curl 8.x hides the errno
  local err; err=$(curl -sS -v --max-time 5 -o /dev/null "https://$1/" 2>&1); local rc=$?
  [ "$rc" -eq 7 ] && grep -qi 'failed: Operation not permitted' <<<"$err"
}
local_ok() { timeout 3 bash -c "exec 3<>/dev/tcp/${local_probe%:*}/${local_probe#*:}" 2>/dev/null; }
log_has() { grep -q "$1" "$log"; }
log_count() { grep -c "$1" "$log"; }
log_grew() { [ "$(log_count "$1")" -gt "$2" ]; }   # log_grew <pattern> <count before>: a new line, not an old one
wait_for() { # wait_for <seconds> <command...>: polls every 0.5 s until the command succeeds
  local deadline=$((SECONDS + $1)); shift
  until "$@"; do
    [ "$SECONDS" -ge "$deadline" ] && return 1
    sleep 0.5
  done
}
file_word() { if [ -e "$1" ]; then echo present; else echo absent; fi; }

# phase 3 helpers: the verbs on the temp paths (verb flags go before the duration); stdin is
# /dev/null so a prompt (zero rules) is declined and shows as a FAIL instead of hanging
ctl() { local verb=$1; shift; "$bin" "$verb" -state-dir "$state" -status "$status" "$@" </dev/null; }
verb_ok() { # verb_ok <verb> [args]: exit 0; the verb's output is shown on failure
  local out; out=$(ctl "$@" 2>&1) && return 0
  echo "        snitchd $*: $out"; return 1
}
trial_ok() { # trial_ok <duration>: the trial verb exits 0 and announces the deadline
  local out; out=$(ctl trial "$1" 2>&1) || { echo "        snitchd trial $1: $out"; return 1; }
  grep -q 'enforce until' <<<"$out"
}
following() { ctl status 2>/dev/null | grep -q 'source files'; }   # the daemon writes the status file and follows the files
status_is() { # status_is <exit code> <daemon line prefix>
  ctl status > "$work/status.out" 2>&1; local rc=$?
  [ "$rc" -eq "$1" ] && grep -q "^daemon: *$2" "$work/status.out"
}
trial_gone() { [ ! -e "$state/trial" ]; }
kept_only() { [ ! -e "$state/trial" ] && [ -e "$state/enforce" ]; }
foreign_trial() { # a trial file from another boot: the follower must end it "at boot" and remove it
  local tmp=$state/trial.tmp
  printf 'start=%s\nend=%s\nboot=00000000-0000-0000-0000-000000000000\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(date -u -d '+10 min' +%Y-%m-%dT%H:%M:%SZ)" > "$tmp" && mv "$tmp" "$state/trial"
}

cleanup() {
  set +e
  if [ -d "$state" ]; then "$bin" end -state-dir "$state" -status "$status" >/dev/null 2>&1; fi   # best effort: no trial, nothing kept
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then kill -CONT "$pid"; kill -TERM "$pid"; wait "$pid" 2>/dev/null; fi
  if [ -e /sys/fs/bpf/snitch/kill ]; then
    kill_map 0 2>/dev/null
    bpftool map update pinned /sys/fs/bpf/snitch/control key 0 0 0 0 value 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 2>/dev/null
    mode=$(bpftool map lookup pinned /sys/fs/bpf/snitch/control key 0 0 0 0 -j | python3 -c 'import json,sys; v=json.load(sys.stdin)["formatted"]["value"]; print("monitor" if v["mode"] == 0 else "ENFORCE", "heartbeat", v["heartbeat_ns"])' 2>/dev/null || echo unreadable)
    kill_value=$(bpftool map lookup pinned /sys/fs/bpf/snitch/kill key 0 0 0 0 -j | python3 -c 'import json,sys; print(json.load(sys.stdin)["formatted"]["value"])' 2>/dev/null || echo unreadable)
    echo "reset: mode: $mode (read back); kill switch value: $kill_value (read back)"
  fi
  echo "reset: attached snitch programs: $(attached)"
  echo "reset: trial file: $(file_word "$state/trial"); kept file: $(file_word "$state/enforce")"
  rm -rf "$work"
  echo "failed steps: $failed"
}
trap cleanup EXIT

cat > "$rules" <<R
# generated by scripts/enforce-test.sh; deleted at exit
[[program]]
name  = "curl"
paths = ["/usr/bin/curl"]

[[program]]
name  = "claude"
paths = ["/home/*/.local/share/claude/versions/*"]
note  = "the session this test is driven from must keep working"

[[rule]]
program = "curl"
to      = "$allow/32"
proto   = "tcp"
port    = 443
verdict = "allow"

[[rule]]
program = "claude"
to      = "0.0.0.0/0"
verdict = "allow"

[[rule]]
program = "claude"
to      = "::/0"
verdict = "allow"
R

launch() { # launch <seconds> <flags...>: the daemon on the rules file, bounded; pid in $pid
  local secs=$1; shift
  : > "$log"
  "$bin" -rules "$rules" "$@" -duration "${secs}s" > "$log" 2>&1 &
  pid=$!
  sleep 1.5
  kill -0 "$pid" 2>/dev/null || { echo "daemon did not start:"; cat "$log"; return 1; }
}
start_daemon() { launch "$2" -mode "$1"; }                         # start_daemon <mode> <seconds>: phases 1 and 2
start_follow() { launch "$1" -state-dir "$state" -status "$status"; }   # start_follow <seconds>: phase 3, the files decide
stop_daemon() { kill -TERM "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; pid=""; }

echo "== phase 1: monitor, identity pre-check (nothing is blocked)"
start_daemon monitor 20 || exit 1
step "rules loaded: 2 programs resolved"      0 log_has 'rules: 2 programs (2 resolved'
curl_ok "$allow"; sleep 0.5
step "curl event names 'program curl' (identity matches the kernel)" 0 log_has 'program curl'
step "curl $allow reachable in monitor mode"  0 curl_ok "$allow"
step "curl $deny reachable in monitor mode"   0 curl_ok "$deny"
step "local probe $local_probe answers"       0 local_ok
stop_daemon
if [ $failed -gt 0 ]; then echo "pre-check failed: not entering enforce"; exit 1; fi
if [ $check_only -eq 1 ]; then echo "check-only: done"; exit 0; fi

echo
echo "== phase 2: ENFORCE for ${duration}s. Everything not in the generated rules is denied for every"
echo "   program on this machine (local network excepted). Keep the hypervisor console open."
if [ $skip_trial -ne 1 ]; then echo "   Phase 3 (the trial flow) follows, behind its own prompt."; fi
if [ $yes -ne 1 ]; then
  read -r -p "Console open? Proceed with enforce for ${duration}s? [y/N] " answer
  [ "$answer" = y ] || { echo "declined"; exit 0; }
fi
start_daemon enforce "$duration" || exit 1
echo "-- rules"
step "C1 curl $allow:443 allowed"              0 curl_ok "$allow"
step "C1 log: allow (rule) for curl"           0 log_has 'allow (rule).*program curl'
step "C2 curl $deny:443 denied with EPERM"     0 curl_eperm "$deny"
step "C2 log: DENY (default) for curl"         0 log_has 'DENY (default).*program curl'
step "C3 local probe $local_probe still works" 0 local_ok
echo "-- kill switch"
kill_map 1
step "K1 kill switch on: curl $deny works"     0 curl_ok "$deny"
kill_map 0
step "K2 kill switch off: curl $deny denied"   0 curl_eperm "$deny"
echo "-- heartbeat"
kill -STOP "$pid"
sleep 16
step "P1 daemon stopped 16 s: curl $deny works (heartbeat stale)" 0 curl_ok "$deny"
kill -CONT "$pid"
sleep 3
step "P2 daemon resumed: curl $deny denied again" 0 curl_eperm "$deny"
echo "-- done: stopping the daemon"
stop_daemon
step "hooks detached after exit" 0 test "$(attached)" -eq 0
if [ $skip_trial -eq 1 ]; then echo "skip-trial: done"; exit $failed; fi

echo
echo "== phase 3: TRIAL flow for up to ${ceiling}s under the same rules. The daemon runs without -mode;"
echo "   snitchd trial/keep/unkeep/end on temp files switch it. Keep the hypervisor console open."
if [ $yes -ne 1 ]; then
  read -r -p "Console open? Proceed with the trial flow (up to ${ceiling}s)? [y/N] " answer
  [ "$answer" = y ] || { echo "declined"; exit $failed; }
fi
mkdir -m 700 "$state"
p3_start=$SECONDS
start_follow "$ceiling" || exit 1
step "T0 daemon follows the files (status: source files)" 0 wait_for 10 following
echo "-- trial, restart, end"
step "T1 snitchd trial 2m: exit 0, prints 'enforce until'"     0 trial_ok 2m
step "T2 curl $deny denied with EPERM within 5 s"               0 wait_for 5 curl_eperm "$deny"
step "T2 local probe $local_probe still works"                  0 local_ok
step "T3 log: mode: enforce (trial until"                       0 log_has 'mode: enforce (trial until'
stop_daemon
start_follow $((ceiling - (SECONDS - p3_start))) || exit 1
step "T4 restarted daemon: curl $deny denied within 5 s"        0 wait_for 5 curl_eperm "$deny"
step "T4 log: mode: enforce (trial until) again"                0 log_has 'mode: enforce (trial until'
n=$(log_count 'trial ended by the operator')
step "T5 snitchd end: exit 0"                                   0 verb_ok end
step "T6 curl $deny works within 5 s"                           0 wait_for 5 curl_ok "$deny"
step "T6 log: trial ended by the operator"                      0 log_grew 'trial ended by the operator' "$n"
echo "-- deadline"
step "T7 snitchd trial 1m: exit 0"                              0 trial_ok 1m
step "T8 curl $deny denied within 5 s"                          0 wait_for 5 curl_eperm "$deny"
step "T9 curl $deny works within 65 s (deadline)"               0 wait_for 65 curl_ok "$deny"
step "T9 log: trial ended at its deadline"                      0 log_has 'trial ended at its deadline'
echo "-- boot revert"
foreign_trial
step "T10 foreign-boot trial file removed within 5 s"           0 wait_for 5 trial_gone
step "T10 log: trial ended at boot"                             0 log_has 'trial ended at boot'
step "T10 curl $deny still works (monitor)"                     0 curl_ok "$deny"
n=$(log_count 'trial ended by the operator')
step "T11 snitchd trial 2m: exit 0"                             0 trial_ok 2m
step "T11 curl $deny denied within 5 s"                         0 wait_for 5 curl_eperm "$deny"
step "T11 snitchd end -at-boot: exit 0"                         0 verb_ok end -at-boot
step "T11 trial file gone within 5 s"                           0 wait_for 5 trial_gone
step "T11 curl $deny works within 5 s"                          0 wait_for 5 curl_ok "$deny"
step "T11 log: trial ended by the operator"                     0 log_grew 'trial ended by the operator' "$n"
echo "-- keep, unkeep"
step "T12 snitchd trial 2m: exit 0"                             0 trial_ok 2m
step "T12 curl $deny denied within 5 s"                         0 wait_for 5 curl_eperm "$deny"
step "T12 snitchd keep: exit 0"                                 0 verb_ok keep
step "T12 trial file gone, kept file present"                   0 kept_only
sleep 5
step "T12 curl $deny still denied after 5 s (enforce kept)"     0 curl_eperm "$deny"
step "T12 log: mode: enforce (enforce kept)"                    0 log_has 'mode: enforce (enforce kept'
step "T13 snitchd unkeep: exit 0"                               0 verb_ok unkeep
step "T13 curl $deny works within 5 s"                          0 wait_for 5 curl_ok "$deny"
step "T13 log: enforce unkept"                                  0 log_has 'enforce unkept'
step "T13 kept file gone"                                       0 test ! -e "$state/enforce"
echo "-- kill switch and heartbeat under a trial"
step "T14 snitchd trial 2m: exit 0"                             0 trial_ok 2m
step "T14 curl $deny denied within 5 s"                         0 wait_for 5 curl_eperm "$deny"
kill_map 1
step "T14 kill switch on: curl $deny works"                     0 curl_ok "$deny"
kill_map 0
step "T14 kill switch off: curl $deny denied"                   0 curl_eperm "$deny"
kill -STOP "$pid"
sleep 16
step "T15 daemon stopped 16 s: curl $deny works (heartbeat stale)" 0 curl_ok "$deny"
kill -CONT "$pid"
step "T15 daemon resumed: curl $deny denied within 3 s"         0 wait_for 3 curl_eperm "$deny"
echo "-- status, end, stop"
step "T16 snitchd status: exit 0, daemon running"               0 status_is 0 running
step "T16 snitchd end: exit 0"                                  0 verb_ok end
step "T16 curl $deny works within 5 s"                          0 wait_for 5 curl_ok "$deny"
stop_daemon
step "hooks detached after exit"                                0 test "$(attached)" -eq 0
step "T17 snitchd status after stop: exit 1, daemon not running (within 20 s)" 0 wait_for 20 status_is 1 'not running'
exit $failed
