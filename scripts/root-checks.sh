#!/bin/sh
# root-checks: the root-only gate checks, batched (c-hardening; the developer runs them, the
# pipeline cannot: they load BPF programs into this host's kernel). Run from your own user with
# sudo; paste the output where it is needed.
#
# usage: sudo scripts/root-checks.sh [--at <rev>] [repo-dir]
#   --at <rev>  test exactly that commit: a temporary detached worktree, removed afterwards
#   repo-dir    the checkout to test (default: the one this script lives in)
#
# What it does, and nothing else:
#   1. builds the daemon as you (not root), from the tree under test
#   2. DNS tap root tests: scripts/dns-progtest.sh (cgroup_skb programs; any kernel with BTF),
#      including the hostile-input corpus (TestDNSProgCorpus)
#   3. only where `bpf` is in the active LSM list (the dev VM): a bounded MONITOR-mode run of
#      the built daemon for 75 s on a private socket, with scripts/api-check.sh against it as
#      you. Never enforce mode. If snitchd.service is active it is stopped for the run (that
#      only detaches the programs: everything is allowed meanwhile) and started again after.
#      The kill switch value found at the start is restored on exit.
# exit 0 every step that ran passed, 1 a step failed, 2 usage or not run through sudo
set -u
at="" repo=""
while [ $# -gt 0 ]; do
  case $1 in
    --at) [ $# -ge 2 ] || { echo "--at needs a revision"; exit 2; }; at=$2; shift ;;
    -h|--help) sed -n '6,8p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    -*) echo "unknown option $1"; exit 2 ;;
    *) repo=$1 ;;
  esac
  shift
done
[ -n "$repo" ] || repo=$(cd "$(dirname "$0")/.." && pwd)
[ "$(id -u)" -eq 0 ] || { echo "run with sudo"; exit 2; }
user=${SUDO_USER:-}
[ -n "$user" ] && [ "$user" != root ] || { echo "run via sudo from your own user"; exit 2; }
if [ -n "$at" ]; then
  wt=$(sudo -u "$user" mktemp -d /tmp/root-checks.XXXXXX)
  sudo -u "$user" git -C "$repo" worktree add -q --detach "$wt" "$at" || { echo "no such revision: $at"; exit 2; }
  # shellcheck disable=SC2064  # expand now: the paths are fixed for this run
  trap "sudo -u '$user' git -C '$repo' worktree remove --force '$wt'" EXIT
  repo_main=$repo
  repo=$wt
fi
cd "$repo" || exit 2
bin=$(sudo -u "$user" mktemp /tmp/snitchd-ch.XXXXXX)
sock=/tmp/snitchd-ch.sock
status_file=/tmp/snitchd-ch.status
rc=0

echo "== host $(uname -r); lsm: $(cat /sys/kernel/security/lsm)"
echo "== tree $(sudo -u "$user" git rev-parse --short HEAD), $(sudo -u "$user" git status --porcelain | wc -l) uncommitted paths"

echo "== 1 build (as $user)"
if sudo -u "$user" -H sh -c "cd '$repo' && go build -o '$bin' ./cmd/snitchd"; then
  "$bin" -version
else
  echo "BUILD FAIL"; exit 1
fi

echo "== 2 DNS root tests"
if scripts/dns-progtest.sh; then echo "RESULT dns-progtest PASS"; else echo "RESULT dns-progtest FAIL"; rc=1; fi

if ! grep -qw bpf /sys/kernel/security/lsm; then
  echo "== 3 SKIPPED: bpf is not in the active LSM list here; run this script on the dev VM"
  echo "== done rc=$rc"; exit $rc
fi

echo "== 3 bounded monitor run + API check"
kill_map=/sys/fs/bpf/snitch/kill
kill_before=""
[ -e "$kill_map" ] && kill_before=$(bpftool -j map lookup pinned "$kill_map" key 0 0 0 0 2>/dev/null)
was_active=no
if systemctl is-active -q snitchd.service; then was_active=yes; fi
# shellcheck disable=SC2329  # invoked through the trap
restore() {
  [ -n "${dpid:-}" ] && kill "$dpid" 2>/dev/null
  case "$kill_before" in
    *'"value":["0x01"'*|*'"value":[1,'*) bpftool map update pinned "$kill_map" key 0 0 0 0 value 1 0 0 0 ;;
    *) [ -e "$kill_map" ] && bpftool map update pinned "$kill_map" key 0 0 0 0 value 0 0 0 0 ;;
  esac
  [ "$was_active" = yes ] && systemctl start snitchd.service
  rm -f "$sock"
  [ -n "${wt:-}" ] && sudo -u "$user" git -C "$repo_main" worktree remove --force "$wt"
}
trap restore EXIT INT TERM
[ "$was_active" = yes ] && { echo "stopping snitchd.service for the run"; systemctl stop snitchd.service; }
"$bin" -mode monitor -duration 75s -api "$sock" -status "$status_file" &
dpid=$!
i=0; while [ ! -S "$sock" ] && [ $i -lt 50 ]; do sleep 0.2; i=$((i+1)); done
[ -S "$sock" ] || { echo "RESULT monitor-run FAIL: no API socket"; exit 1; }
echo "RESULT monitor-run started (pid $dpid)"
if sudo -u "$user" -H "$repo/scripts/api-check.sh" -s "$sock"; then echo "RESULT api-check PASS"; else echo "RESULT api-check FAIL"; rc=1; fi
printf '%s\n' '{"type":"status","id":1}' | sudo -u "$user" python3 -c '
import socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(sys.stdin.buffer.read()); s.settimeout(2)
print("STATUS", s.recv(65536).decode().strip())' "$sock" || true
wait "$dpid"; drc=$?; dpid=""
echo "RESULT monitor-run exit $drc (0 = ended on its own after -duration)"
[ $drc -eq 0 ] || rc=1
echo "== done rc=$rc"
exit $rc
