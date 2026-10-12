#!/bin/bash
# shellcheck disable=SC2329,SC2317  # the step helpers are invoked through step(), cleanup through the trap (SC2317 on older shellcheck)
# deploy-check: prove the deployed snitchd service step by step (spec deploy-service, Req 5).
#
# Phase A (always, read-only): the service is active and both units are enabled; the version
# the daemon runs equals the installed binary's (an older daemon writes a status record without
# the key, and `snitchd trial` would refuse: the remedy is a service restart, printed, not
# done); `snitchd status` exits 0 with mode monitor, no trial, nothing kept, kill clear; this
# boot's journal has the startup line and the rules summary; two probes, each checked against
# the journal after a cursor taken before it:
#   apt-get update          -> an event attributed to the apt rule ("program apt ... rule")
#   curl https://DENY/      -> a monitor event for curl ("allow (monitor) ... curl")
# Phase B (--trial, after the [y/N] prompt, with the serial console open): `snitchd trial 2m`
# prints "enforce until", status says enforce, curl to DENY fails with EPERM, the local probe
# (-l) and apt-get update still work, status is back to monitor by the deadline (130 s), and the
# journal has the start and end lines. The five dev tools run as the desktop user with
# 15-second timeouts; each must exit 0 during enforce and have no DENY in the trial journal.
# The trap on EXIT runs `snitchd end` (best effort) once a
# trial was started, and prints the final state line in every case.
# Both phases end with one line to paste into research.md:
#   state: service <active|inactive> mode <m> trial <none|...> kept <no|yes> kill <clear|SET>
# The script never writes under /var/lib/snitch or /run/snitch except through `snitchd trial`
# and `snitchd end`, never touches the kill map and never restarts the service.
#
# usage: sudo scripts/deploy-check.sh [--trial] [-x <deny addr>] [-l host:port] [-h]
#   SNITCHD=/path overrides the binary (default /usr/local/sbin/snitchd)
# Exit 0: every step passed; 1: a step failed (the early steps stop the run); 2: usage.
set -euo pipefail

usage() {
  cat <<'U'
usage: sudo scripts/deploy-check.sh [--trial] [-x <deny addr>] [-l host:port] [-h]
  phase A (always, read-only): service active, units enabled, version equals the binary,
    status monitor / no trial / nothing kept / kill clear, startup and rules lines in the
    journal, an apt rule event and a curl monitor event
  phase B (--trial, after a [y/N] prompt, serial console open): snitchd trial 2m, EPERM for
    the deny address, local probe and apt still fine, monitor again by the deadline
  -x <addr>    address no rule covers (default 9.9.9.9)
  -l host:port local-network probe for phase B (optional, e.g. 10.0.0.1:53)
  -h           this text
  SNITCHD=/path overrides the binary (default /usr/local/sbin/snitchd)
exit 0 all steps passed, 1 a step failed, 2 usage
U
}

trial=0; deny=9.9.9.9; local_probe=""
while [ $# -gt 0 ]; do
  case "$1" in
    --trial) trial=1 ;;
    -x) [ $# -ge 2 ] || { echo "-x needs an address" >&2; exit 2; }; deny=$2; shift ;;
    -l) [ $# -ge 2 ] || { echo "-l needs host:port" >&2; exit 2; }; local_probe=$2; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
[ "$(id -u)" -eq 0 ] || { echo "run as root (sudo): the snitchd verbs and the journal need it" >&2; exit 2; }

bin=${SNITCHD:-/usr/local/sbin/snitchd}
unit=snitchd.service
boot_unit=snitchd-trial-boot.service
failed=0
trial_started=0   # the trap runs `snitchd end` only once phase B wrote a trial file

step() { # step <name> <command...>: prints PASS/FAIL, counts failures
  local name=$1; shift
  if "$@"; then echo "  PASS  $name"; else echo "  FAIL  $name"; failed=$((failed + 1)); fi
}
must() { # must <name> <command...>: like step, but a failure ends the run (later steps are meaningless)
  local before=$failed
  step "$@"
  if [ "$failed" -gt "$before" ]; then echo "stopping: the remaining steps need this one"; exit 1; fi
}

# -- facts from systemctl and snitchd status
active() { systemctl is-active --quiet "$unit"; }
enabled() { systemctl is-enabled --quiet "$1"; }
status_out=""
read_status() { # fills status_out; returns the verb's exit code
  local rc=0
  status_out=$("$bin" status 2>&1 </dev/null) || rc=$?
  return "$rc"
}
status_value() { # status_value <key>: the value of "<key>:   <value>" from the last read_status
  awk -v k="$1:" '$1 == k { $1 = ""; sub(/^ +/, ""); print; exit }' <<<"$status_out"
}
status_is() { # status_is <key> <word>: the value's first word
  local v
  v=$(status_value "$1")
  [ "${v%% *}" = "$2" ]
}
status_monitor() { read_status || true; status_is mode monitor; }
status_enforce() { read_status || true; status_is mode enforce; }

# -- journal: this boot, or after a cursor taken before a probe
journal_boot() { journalctl -u "$unit" -b --no-pager -o cat 2>/dev/null || true; }
cursor=""; since=""
take_cursor() { # the position before a probe; a journal without entries gives none, then the time is the fallback
  cursor=$(journalctl -u "$unit" -n0 --show-cursor --no-pager 2>/dev/null | sed -n 's/^-- cursor: //p' || true)
  since=$(date '+%Y-%m-%d %H:%M:%S')
}
journal_after() {
  if [ -n "$cursor" ]; then
    journalctl -u "$unit" --after-cursor "$cursor" --no-pager -o cat 2>/dev/null || true
  else
    journalctl -u "$unit" --since "$since" --no-pager -o cat 2>/dev/null || true
  fi
}
# grep -q would close the pipe early and, under pipefail, fail a matching pipeline: read all first
boot_has() { grep -Eq "$1" <<<"$(journal_boot)"; }
after_has() { grep -Eq "$1" <<<"$(journal_after)"; }
wait_for() { # wait_for <seconds> <interval> <command...>: polls until the command succeeds
  local deadline=$((SECONDS + $1)) interval=$2; shift 2
  until "$@"; do
    [ "$SECONDS" -ge "$deadline" ] && return 1
    sleep "$interval"
  done
}

# -- probes
apt_ok() { apt-get update -o Acquire::Retries=0 >/dev/null 2>&1; }
curl_probe() { curl -sS --max-time 5 -o /dev/null "https://$1/" >/dev/null 2>&1 || true; }
curl_connects() { # the connect went through: any exit but 7 (a certificate mismatch counts as connected)
  local rc=0
  curl -sS --max-time 5 -o /dev/null "https://$1/" >/dev/null 2>&1 || rc=$?
  [ "$rc" -ne 7 ]
}
curl_eperm() { # curl must fail with EPERM: exit 7 and, in the verbose trace, the errno text
  # ("connect to … failed: Operation not permitted"); without -v curl 8.x hides the errno
  local err rc=0
  err=$(curl -sS -v --max-time 5 -o /dev/null "https://$1/" 2>&1) || rc=$?
  [ "$rc" -eq 7 ] && grep -qi 'failed: Operation not permitted' <<<"$err"
}
local_ok() { timeout 3 bash -c "exec 3<>/dev/tcp/${local_probe%:*}/${local_probe#*:}" 2>/dev/null; }

# -- dev tools: use the desktop user's home, login PATH and credentials, not root's.
desktop_user=${SUDO_USER:-}
if [ -z "$desktop_user" ] || [ "$desktop_user" = root ]; then
  desktop_user=$(head -n1 /etc/snitch/operator 2>/dev/null | tr -d '[:space:]' || true)
fi
tool_results=()
trial_journal=""
dev_tools() {
  local tool command rc
  for tool in gh git uv cargo go; do
    rc=1
    case "$tool" in
      gh) command='gh api /rate_limit' ;;
      git) command='git ls-remote https://github.com/norandom/snitch' ;;
      uv) command=$(cat <<'CMD'
download_dir=$(mktemp -d) || exit 1
trap 'rm -rf "$download_dir"' EXIT
uv pip download --no-deps -d "$download_dir" six
CMD
        ) ;;
      cargo) command='cargo search --limit 1 serde' ;;
      go) command='go list -m -versions golang.org/x/sys' ;;
    esac
    if [ -n "$desktop_user" ] && [ "$desktop_user" != root ] && status_enforce; then
      rc=0
      timeout --kill-after=1s 15s runuser -u "$desktop_user" -- bash -lc "cd ~ && $command" </dev/null >/dev/null 2>&1 || rc=$?
      # A command finishing after the trial ends cannot prove that enforce allowed it.
      status_enforce || rc=1
    fi
    tool_results+=("$rc")
  done
}
dev_tool_passed() {
  local tool=$1 rc=$2
  [ "$rc" -eq 0 ] || return 1
  # describe() starts denial lines with DENY; programOf() supplies the configured name
  # or an executable path plus " (unknown)". Match the field, never the comm column.
  ! grep -Eq "^DENY .*  program ($tool|[^ ]*/$tool \(unknown\))([[:space:]]|$)" <<<"$trial_journal"
}
report_dev_tools() {
  local tool index=0
  for tool in gh git uv cargo go; do
    step "T3 $tool as $desktop_user: exit 0 during trial, no DENY for its program in trial journal" dev_tool_passed "$tool" "${tool_results[$index]}"
    index=$((index + 1))
  done
}

# -- the verbs (phase B only)
trial_ok() { # the trial verb exits 0 and announces the deadline
  local out rc=0
  out=$("$bin" trial 2m 2>&1 </dev/null) || rc=$?
  trial_started=1
  if [ "$rc" -ne 0 ]; then echo "        snitchd trial 2m: $out"; return 1; fi
  grep -q 'enforce until' <<<"$out"
}

# -- the final line, from the trap: an aborted run still shows the state
state_word() { # state_word <key> <fallback>: the value's first word, or the fallback
  local v
  v=$(status_value "$1")
  v=${v%% *}
  echo "${v:-$2}"
}
state_line() {
  local svc kill
  if active 2>/dev/null; then svc=active; else svc=inactive; fi
  read_status 2>/dev/null || true
  kill=$(state_word kill unknown)
  if [ "$kill" = set ]; then kill=SET; fi
  echo "state: service $svc mode $(state_word mode unknown) trial $(state_word trial unknown) kept $(state_word kept unknown) kill $kill"
}
finish() { if [ "$failed" -eq 0 ]; then exit 0; else exit 1; fi; }
cleanup() {
  set +e
  if [ "$trial_started" -eq 1 ]; then
    if "$bin" end >/dev/null 2>&1 </dev/null; then echo "trap: snitchd end (no trial left)"; else echo "trap: snitchd end failed (check snitchd status)"; fi
  fi
  if [ -x "$bin" ]; then state_line; else echo "state: service inactive mode unknown trial unknown kept unknown kill unknown ($bin missing)"; fi
  echo "failed steps: $failed"
}
trap cleanup EXIT

echo "== phase A: the deployed service, read-only"
must "$unit active"                                   active
step "$unit enabled"                                   enabled "$unit"
step "$boot_unit enabled"                              enabled "$boot_unit"
must "binary $bin present"                             test -x "$bin"
read_status || true
running=$(status_value version)
installed=$("$bin" -version 2>&1 </dev/null || true)
if [ -n "$installed" ] && [ "$running" = "$installed" ]; then
  echo "  PASS  version $installed: the daemon runs the installed binary"
else
  echo "  FAIL  version: daemon '${running:-?}', binary '${installed:-?}'"
  echo "the daemon runs another build: sudo systemctl restart $unit"
  failed=$((failed + 1)); exit 1
fi
must "snitchd status exits 0 (daemon running)"         read_status
step "status: mode monitor"                            status_is mode monitor
step "status: trial none"                              status_is trial none
step "status: kept no"                                 status_is kept no
step "status: kill clear"                              status_is kill clear
step "journal (this boot): startup line"               boot_has 'snitchd [^ ]+: mode .*hooks lsm/socket_connect'
step "journal (this boot): rules summary"              boot_has 'rules: [0-9]+ programs \('
take_cursor
apt_rc=0; apt_ok || apt_rc=$?
step "probe: apt-get update exits 0"                   test "$apt_rc" -eq 0
step "journal: event for program apt with its rule"    wait_for 5 0.5 after_has 'program apt .*rule '
take_cursor
curl_probe "$deny"
step "journal: monitor event for curl to $deny"        wait_for 5 0.5 after_has 'allow \(monitor\).*curl'

if [ "$trial" -ne 1 ]; then finish; fi
echo
echo "== phase B: TRIAL, deny by default for 2 minutes. Everything no rule allows is denied for"
echo "   every program on this host (local network excepted). Keep the serial console open."
read -r -p "Console open? Start the 2-minute trial? [y/N] " answer || answer=n
if [ "$answer" != y ]; then echo "declined: trial skipped"; finish; fi
if [ "$failed" -gt 0 ]; then echo "phase A had failures: not starting the trial"; exit 1; fi
take_cursor
step "T1 snitchd trial 2m: exit 0, prints 'enforce until'"   trial_ok
step "T1 status: mode enforce within 5 s"                    wait_for 5 0.5 status_enforce
dev_tools
step "T2 curl $deny denied with EPERM within 5 s"            wait_for 5 0.5 curl_eperm "$deny"
if [ -n "$local_probe" ]; then step "T2 local probe $local_probe still works" local_ok; fi
step "T2 apt-get update still exits 0"                       apt_ok
step "T3 journal: mode: enforce (trial until"                after_has 'mode: enforce \(trial until'
step "T4 status: mode monitor within 130 s (deadline)"       wait_for 130 2 status_monitor
trial_journal=$(journal_after)
report_dev_tools
step "T4 journal: trial ended at its deadline"               after_has 'mode: monitor \(trial ended at its deadline\)'
step "T4 curl $deny connects again within 5 s"               wait_for 5 0.5 curl_connects "$deny"
finish
