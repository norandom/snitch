#!/bin/sh
# fail-open: from a console as root, make snitch allow everything, right now, and show it.
#   1. kill switch on  (the kernel program allows all while it is set; survives daemon restarts)
#   2. stop the daemon (SIGCONT first in case it was SIGSTOPped; its exit detaches the hooks)
#   3. heartbeat zeroed (belt and braces: a stale or absent heartbeat means allow)
# Afterwards nothing enforces. Clear the kill switch again before the next test run:
#   bpftool map update pinned /sys/fs/bpf/snitch/kill key 0 0 0 0 value 0 0 0 0
# Needs no network and no daemon. Usage: sudo scripts/fail-open.sh
set -u
PATH=$PATH:/usr/sbin:/sbin
[ "$(id -u)" -eq 0 ] || { echo "run as root" >&2; exit 2; }
if [ -e /sys/fs/bpf/snitch/kill ]; then
  bpftool map update pinned /sys/fs/bpf/snitch/kill key 0 0 0 0 value 1 0 0 0 && echo "kill switch: ON (allow everything)"
else
  echo "no pinned snitch maps: the daemon never ran since boot, nothing enforces"
fi
if pkill -CONT -x snitchd 2>/dev/null; then :; fi
if pkill -TERM -x snitchd 2>/dev/null; then sleep 1; echo "snitchd: stopped"; else echo "snitchd: not running"; fi
if [ -e /sys/fs/bpf/snitch/control ]; then
  bpftool map update pinned /sys/fs/bpf/snitch/control key 0 0 0 0 value 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 && echo "heartbeat: zeroed (stale = allow)"
fi
echo "attached snitch programs: $(bpftool prog show 2>/dev/null | grep -c 'socket_connect\|socket_sendmsg')"
