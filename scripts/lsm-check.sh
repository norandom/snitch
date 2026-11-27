#!/bin/sh
# lsm-check: read-only host check for BPF LSM activation (spec lsm-activation, Req 8.5).
#
# Inspects the running kernel's active LSM list, /proc/cmdline, the packaged GRUB drop-in
# and lsm-cmdline helper, a dry-run preview of what lsm-cmdline would emit for this host,
# and (if reachable) the snitchd API socket's status.hook field.
#
# Fail-safe implications: strictly read-only — never invokes sudo, never modifies any file
# or boot setting, and never touches BPF maps. Exits 0 when bpf is in /sys/kernel/security/lsm,
# 1 otherwise, and 2 on invalid CLI arguments.
#
# usage: scripts/lsm-check.sh [-api PATH] [-h|--help]
set -eu
LC_ALL=C
export LC_ALL

usage() {
	cat <<'U'
usage: scripts/lsm-check.sh [-api PATH] [-h|--help]
  read-only host check for BPF LSM activation (never uses sudo or modifies files)
  -api <path>  daemon Unix socket path (default /run/snitch/api.sock)
  -h, --help   this text
exit 0 when bpf is active in /sys/kernel/security/lsm, 1 otherwise, 2 on bad args
U
}

trim_ws() {
	val=$1
	while :; do
		case "$val" in
			[[:space:]]*) val=${val#?} ;;
			*[[:space:]]) val=${val%?} ;;
			*) break ;;
		esac
	done
	printf '%s' "$val"
}

read_grub_vars() {
	grub_file=/etc/default/grub
	[ -r "$grub_file" ] || return 0
	awk '
	function unquote(s,    q, rest, i, c) {
		sub(/^[[:space:]]+/, "", s)
		if (substr(s, 1, 1) == "\"" || substr(s, 1, 1) == "\047") {
			q = substr(s, 1, 1)
			rest = substr(s, 2)
			for (i = 1; i <= length(rest); i++) {
				c = substr(rest, i, 1)
				if (c == "\\" && q == "\"" && i < length(rest)) {
					i++
					continue
				}
				if (c == q) {
					return substr(rest, 1, i - 1)
				}
			}
			return rest
		}
		sub(/[[:space:]]*(#.*)?$/, "", s)
		return s
	}
	/^[[:space:]]*GRUB_CMDLINE_LINUX=/ {
		sub(/^[[:space:]]*GRUB_CMDLINE_LINUX=/, "")
		v_linux = unquote($0)
	}
	/^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=/ {
		sub(/^[[:space:]]*GRUB_CMDLINE_LINUX_DEFAULT=/, "")
		v_default = unquote($0)
	}
	END {
		out = v_linux
		if (v_default != "") {
			out = (out == "" ? v_default : out " " v_default)
		}
		if (out != "") {
			print out
		}
	}
	' "$grub_file" 2>/dev/null || true
}

api=/run/snitch/api.sock
while [ "$#" -gt 0 ]; do
	case "$1" in
		-api|--api)
			[ "$#" -ge 2 ] && [ -n "$2" ] || { printf '%s\n' "lsm-check: -api needs a socket path" >&2; exit 2; }
			api=$2
			shift
			;;
		-api=*|--api=*)
			api=${1#*=}
			[ -n "$api" ] || { printf '%s\n' "lsm-check: -api needs a socket path" >&2; exit 2; }
			;;
		-h|--help)
			usage
			exit 0
			;;
		--)
			shift
			[ "$#" -eq 0 ] || { printf 'lsm-check: unexpected argument: %s\n' "$1" >&2; usage >&2; exit 2; }
			break
			;;
		*)
			printf 'lsm-check: unknown option: %s\n' "$1" >&2
			usage >&2
			exit 2
			;;
	esac
	shift
done

lsm_file=/sys/kernel/security/lsm
bpf_active=0
if [ -r "$lsm_file" ] && raw=$(cat "$lsm_file" 2>/dev/null && printf x); then
	lsm_list=$(trim_ws "${raw%x}")
	if [ -n "$lsm_list" ]; then
		case ",$lsm_list," in
			*,bpf,*)
				bpf_active=1
				printf 'active lsm (%s): %s (bpf: active)\n' "$lsm_file" "$lsm_list"
				;;
			*)
				printf 'active lsm (%s): %s (bpf: inactive)\n' "$lsm_file" "$lsm_list"
				;;
		esac
	else
		printf 'active lsm (%s): (empty)\n' "$lsm_file"
	fi
else
	printf 'active lsm (%s): (unreadable)\n' "$lsm_file"
fi

cmdline_file=/proc/cmdline
if [ -r "$cmdline_file" ] && cmdline=$(cat "$cmdline_file" 2>/dev/null); then
	lsm_tokens=""
	set -f
	for tok in $cmdline; do
		case "$tok" in
			lsm=*)
				lsm_tokens="${lsm_tokens:+$lsm_tokens }$tok"
				;;
		esac
	done
	set +f
	if [ -n "$lsm_tokens" ]; then
		printf 'cmdline lsm= (%s): %s\n' "$cmdline_file" "$lsm_tokens"
	else
		printf 'cmdline lsm= (%s): none\n' "$cmdline_file"
	fi
else
	printf 'cmdline lsm= (%s): (unreadable)\n' "$cmdline_file"
fi

dropin=/etc/default/grub.d/snitch-lsm.cfg
if [ -e "$dropin" ]; then
	mode=$(stat -c '%a' "$dropin" 2>/dev/null || printf 'unknown')
	printf 'grub drop-in (%s): installed (mode %s)\n' "$dropin" "$mode"
else
	printf 'grub drop-in (%s): not installed\n' "$dropin"
fi

helper_sys=/usr/lib/snitch/lsm-cmdline
if [ -e "$helper_sys" ]; then
	mode=$(stat -c '%a' "$helper_sys" 2>/dev/null || printf 'unknown')
	if [ -x "$helper_sys" ]; then
		exec_note="executable"
	else
		exec_note="not executable"
	fi
	printf 'lsm-cmdline helper (%s): installed (mode %s, %s)\n' "$helper_sys" "$mode" "$exec_note"
else
	printf 'lsm-cmdline helper (%s): not installed\n' "$helper_sys"
fi

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" 2>/dev/null && pwd) || script_dir=""
repo_helper=""
if [ -n "$script_dir" ]; then
	repo_helper="$script_dir/../packaging/lsm-cmdline.sh"
fi

grub_vars=$(read_grub_vars)
helper_kind=""
helper_cmd=""
if [ -x "$helper_sys" ]; then
	helper_kind="installed $helper_sys"
	helper_cmd=$helper_sys
elif [ -n "$repo_helper" ] && [ -r "$repo_helper" ]; then
	helper_kind="repo fallback $repo_helper"
	helper_cmd=$repo_helper
fi

if [ -n "$helper_cmd" ]; then
	if [ "$helper_cmd" = "$helper_sys" ]; then
		helper_param=$("$helper_cmd" -l "$lsm_file" -c "$cmdline_file" -- "$grub_vars" 2>/dev/null || true)
		helper_explain=$("$helper_cmd" --explain -l "$lsm_file" -c "$cmdline_file" -- "$grub_vars" 2>/dev/null || true)
	else
		helper_param=$(sh "$helper_cmd" -l "$lsm_file" -c "$cmdline_file" -- "$grub_vars" 2>/dev/null || true)
		helper_explain=$(sh "$helper_cmd" --explain -l "$lsm_file" -c "$cmdline_file" -- "$grub_vars" 2>/dev/null || true)
	fi
	printf 'helper preview (%s):\n' "$helper_kind"
	printf '  param:   %s\n' "${helper_param:-(none)}"
	printf '  explain: %s\n' "${helper_explain:-(none)}"
else
	printf 'helper preview: (helper not found)\n'
fi

if ! command -v python3 >/dev/null 2>&1; then
	printf 'daemon status.hook (%s): (python3 not available; cannot query %s)\n' "$api" "$api"
elif [ ! -S "$api" ]; then
	printf 'daemon status.hook (%s): (daemon not reachable on %s)\n' "$api" "$api"
else
	hook_line=$(python3 -I -c '
import json, socket, sys

sock_path = sys.argv[1]
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.settimeout(2.0)
try:
    s.connect(sock_path)
    s.sendall(b"{\"type\":\"status\",\"id\":1}\n")
    buf = bytearray()
    while b"\n" not in buf and len(buf) < 65536:
        chunk = s.recv(4096)
        if not chunk:
            break
        buf.extend(chunk)
except OSError:
    print(f"(daemon not reachable on {sock_path})")
    sys.exit(0)
finally:
    s.close()

line = buf.split(b"\n", 1)[0].decode("utf-8", "replace").strip()
if not line:
    print(f"(daemon not reachable on {sock_path})")
    sys.exit(0)
try:
    reply = json.loads(line)
except ValueError:
    print(f"(daemon not reachable on {sock_path})")
    sys.exit(0)

if not isinstance(reply, dict) or not reply.get("ok") or not isinstance(reply.get("status"), dict):
    print(f"(daemon not reachable on {sock_path})")
    sys.exit(0)

hook = reply["status"].get("hook")
if not isinstance(hook, dict):
    print("(not reported)")
    sys.exit(0)

state = str(hook.get("state") or "unknown").replace("\n", " ").replace("\r", " ")
pending = "true" if hook.get("pending") else "false"
unsupported = "true" if hook.get("unsupported") else "false"
reason = str(hook.get("reason") or "(none)").replace("\n", " ").replace("\r", " ")
print(f"state={state} pending={pending} unsupported={unsupported} reason={reason}")
' "$api" 2>/dev/null) || hook_line="(daemon not reachable on $api)"
	printf 'daemon status.hook (%s): %s\n' "$api" "${hook_line:-(daemon not reachable on $api)}"
fi

if [ "$bpf_active" -eq 1 ]; then
	exit 0
fi
exit 1
