#!/bin/sh
# shellcheck disable=SC2317,SC2329  # step helpers are called via step()/must(); cleanup/on_signal run via trap
# tui-check (spec tui, task 8.6, requirements 15.4, 15.5): host check for snitch.
# Run as an ordinary user, never as root.
#
# usage: scripts/tui-check.sh [-api PATH] [--trial] [-h]
set -eu

usage() {
  cat <<'U'
usage: scripts/tui-check.sh [-api PATH] [--trial] [-h]
  run as an ordinary user, never as root (exit 2)
  -api <path>  daemon Unix socket path (default /run/snitch/api.sock)
  --trial      also check T -> y -> deadline -> E -> monitor (requires explicit operator go)
  -h           this text
exit 0 every step passed (or skipped cleanly for fake/reader), 1 a step failed, 2 usage/refusal
U
}

api=/run/snitch/api.sock
trial=0
while [ $# -gt 0 ]; do
  case "$1" in
    -api|--api)
      [ $# -ge 2 ] && [ -n "$2" ] || { printf '%s\n' "-api needs a socket path" >&2; exit 2; }
      api=$2
      shift
      ;;
    -api=*|--api=*)
      api=${1#*=}
      [ -n "$api" ] || { printf '%s\n' "-api needs a socket path" >&2; exit 2; }
      ;;
    --trial)
      trial=1
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      printf 'unknown option: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
  shift
done

[ "$(id -u)" -ne 0 ] || { printf '%s\n' "run as an ordinary user, not root" >&2; exit 2; }
for tool in go python3 curl; do
  command -v "$tool" >/dev/null 2>&1 || { printf '%s is needed\n' "$tool" >&2; exit 2; }
done

cd "$(dirname "$0")/.."

me=$(id -un)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/tui-check.XXXXXX")
BIN="$tmp/snitch"
operator_file=/etc/snitch/operator
testnet_addr=192.0.2.1
testnet_cidr=192.0.2.1/32

passed=0
skipped=0
failed=0
is_fake=0
is_writer=0
peer_uid=""
daemon_ver=""
daemon_source=""
daemon_kill=0
daemon_learn=0
overlay=""
rule_added=0
trial_started=0
cleaned=0

note() { printf '        %s\n' "$*"; }

step() {
  step_name=$1
  shift
  if "$@"; then
    printf '  PASS  %s\n' "$step_name"
    passed=$((passed + 1))
  else
    printf '  FAIL  %s\n' "$step_name"
    failed=$((failed + 1))
  fi
}

skip() {
  printf '  SKIP  %s\n' "$1"
  note "$2"
  skipped=$((skipped + 1))
}

must() {
  must_before=$failed
  step "$@"
  if [ "$failed" -ne "$must_before" ]; then
    printf '%s\n' "stopping: remaining steps need this one"
    exit 1
  fi
}

role_guess() {
  pyrun role-guess "$operator_file" "$me"
}

py_helper=$(cat <<'PY'
import fcntl
import json
import os
import pty
import re
import select
import socket
import stat
import struct
import subprocess
import sys
import termios
import time

sock_path = sys.argv[1]
cmd = sys.argv[2]
args = sys.argv[3:]


def peer_uid(conn):
    raw = conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12)
    _, uid, _ = struct.unpack("III", raw)
    return uid


def api_exchange(req):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(sock_path)
    try:
        uid = peer_uid(s)
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while b"\n" not in buf:
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        line = buf.split(b"\n", 1)[0].decode("utf-8", "replace")
        return uid, json.loads(line)
    finally:
        s.close()


def clean_ansi(raw):
    text = re.sub(rb"\x1b\[[0-9;?]*[HJK]|\r\n|\n", b"\n", raw)
    text = re.sub(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)", b" ", text)
    return text.decode("utf-8", "replace")


class PtySession:
    def __init__(self, bin_path, api_path):
        self.master, slave = pty.openpty()
        fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 30, 100, 0, 0))

        def preexec():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)

        self.proc = subprocess.Popen(
            [bin_path, "-api", api_path],
            stdin=slave,
            stdout=slave,
            stderr=slave,
            preexec_fn=preexec,
            close_fds=True,
        )
        os.close(slave)
        self.buf = b""

    def drain(self, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            timeout = min(0.05, max(0.0, end - time.monotonic()))
            r, _, _ = select.select([self.master], [], [], timeout)
            if self.master in r:
                try:
                    chunk = os.read(self.master, 65536)
                    if not chunk:
                        break
                    self.buf += chunk
                except OSError:
                    break

    def wait_for(self, needle, timeout=6.0, since=0):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.drain(0.08)
            txt = clean_ansi(self.buf[since:])
            if needle in txt:
                return txt
            if self.proc.poll() is not None:
                break
        return None

    def send(self, data, pause=0.10):
        os.write(self.master, data)
        self.drain(pause)

    def close(self, quit_timeout=3.0):
        try:
            if self.proc.poll() is None:
                os.write(self.master, b"q")
                rc = self.proc.wait(timeout=quit_timeout)
            else:
                rc = self.proc.wait(timeout=quit_timeout)
            return rc
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
            return -1
        finally:
            try:
                os.close(self.master)
            except OSError:
                pass


def check_nondumpable(pid):
    status_path = f"/proc/{pid}/status"
    with open(status_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.startswith("Dumpable:"):
                val = line.split(":", 1)[1].strip()
                if val != "0":
                    raise RuntimeError(f"Dumpable={val}, want 0")
    mem_path = f"/proc/{pid}/mem"
    st = os.stat(mem_path)
    if st.st_uid != 0:
        raise RuntimeError(f"{mem_path} uid={st.st_uid}, want 0 (non-dumpable)")
    try:
        with open(mem_path, "rb"):
            raise RuntimeError(f"opened {mem_path} unexpectedly")
    except PermissionError:
        pass


def runtime_snitch_entries(rt_dir):
    if not rt_dir or not os.path.isdir(rt_dir):
        return []
    return sorted(e for e in os.listdir(rt_dir) if "snitch" in e)


def find_rule(overlay_path, to_cidr):
    _, reply = api_exchange({"type": "rules", "id": 1})
    if not reply.get("ok"):
        raise RuntimeError(f"rules failed: {reply}")
    for r in reply.get("rules", []):
        if r.get("source") == overlay_path and r.get("to") == to_cidr:
            return r
    return None


def remove_rule(overlay_path, to_cidr):
    _, reply = api_exchange({"type": "rules", "id": 1})
    if not reply.get("ok"):
        return False
    removed = 0
    for r in reply.get("rules", []):
        if r.get("source") == overlay_path and r.get("to") == to_cidr:
            req = {
                "type": "rule.remove",
                "id": 2,
                "program": r.get("program", ""),
                "to": r.get("to", ""),
                "proto": r.get("protocol", ""),
                "port": r.get("port", 0),
            }
            _, rem_reply = api_exchange(req)
            if not rem_reply.get("ok"):
                raise RuntimeError(f"rule.remove failed: {rem_reply}")
            removed += 1
    return removed > 0


if cmd == "probe":
    uid, reply = api_exchange({"type": "status", "id": 1})
    if reply.get("type") != "reply" or not reply.get("ok") or not isinstance(reply.get("status"), dict):
        print(f"bad status reply: {reply}", file=sys.stderr)
        sys.exit(1)
    st = reply["status"]
    out = {
        "peer_uid": uid,
        "running": bool(st.get("running")),
        "mode": st.get("mode", ""),
        "version": st.get("version", ""),
        "source": st.get("source", ""),
        "kill": bool(st.get("kill")),
        "learning": bool(st.get("learning")),
        "overlay": (st.get("rules") or {}).get("overlay", ""),
    }
    print(json.dumps(out))

elif cmd == "json-field":
    obj = json.loads(args[0])
    val = obj[args[1]]
    if isinstance(val, bool):
        print("1" if val else "0")
    else:
        print(val)

elif cmd == "check-status-json":
    raw = args[0]
    want_foreign = args[1] == "1"
    want_kill = args[2] == "1"
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise SystemExit("status output is not a JSON object")
    for k in ("text", "class", "tooltip"):
        if k not in obj or not isinstance(obj[k], str):
            raise SystemExit(f"missing or non-string field: {k}")
    if obj["class"] not in ("allow", "deny", "down"):
        raise SystemExit(f"unexpected class: {obj['class']}")
    if want_foreign or want_kill:
        if obj["class"] != "down":
            raise SystemExit(f"expected class=down, got {obj['class']}")
    elif obj["class"] != "allow":
        raise SystemExit(f"expected class=allow in monitor mode, got {obj['class']}")
    print(f"class={obj['class']} text={obj['text']!r}")

elif cmd == "pty-smoke":
    bin_path, rt_dir = args[0], args[1]
    before_rt = runtime_snitch_entries(rt_dir)
    sess = PtySession(bin_path, sock_path)
    try:
        if sess.wait_for("snitch | last ", timeout=6.0) is None:
            raise RuntimeError("overview header did not render on PTY")
        if sess.wait_for("mode: monitor", timeout=4.0) is None:
            raise RuntimeError("overview did not show mode: monitor")
        check_nondumpable(sess.proc.pid)
        during_rt = runtime_snitch_entries(rt_dir)
        if during_rt != before_rt or (rt_dir and os.path.exists(os.path.join(rt_dir, "snitch"))):
            raise RuntimeError(f"runtime dir modified while running: {during_rt}")
        mark = len(sess.buf)
        sess.send(b"e", pause=0.12)
        if sess.wait_for("EGRESS  last ", timeout=4.0, since=mark) is None:
            raise RuntimeError("egress graph did not render on 'e'")
        mark = len(sess.buf)
        sess.send(b"e", pause=0.12)
        if sess.wait_for("connection", timeout=4.0, since=mark) is None:
            raise RuntimeError("overview did not return on second 'e'")
        rc = sess.close()
        if rc != 0:
            raise RuntimeError(f"snitch exited {rc} on 'q'")
        after_rt = runtime_snitch_entries(rt_dir)
        if after_rt != before_rt or (rt_dir and os.path.exists(os.path.join(rt_dir, "snitch"))):
            raise RuntimeError(f"runtime dir modified after exit: {after_rt}")
    except Exception:
        sess.close()
        raise

elif cmd == "snapshot-has":
    target = args[0]
    deadline = time.monotonic() + 6.0
    while time.monotonic() < deadline:
        _, reply = api_exchange({"type": "snapshot", "id": 1, "window": "1h"})
        if reply.get("ok"):
            for e in reply.get("entries", []):
                if e.get("addr") == target:
                    print(f"program={e.get('program', '')} verdict={e.get('verdict', '')}")
                    sys.exit(0)
        time.sleep(0.3)
    sys.exit(1)

elif cmd == "pty-block-unblock":
    bin_path, overlay_path, target_addr, target_cidr = args[0], args[1], args[2], args[3]
    if find_rule(overlay_path, target_cidr) is not None:
        raise RuntimeError(f"overlay already has a rule for {target_cidr}")
    sess = PtySession(bin_path, sock_path)
    try:
        if sess.wait_for("snitch | last ", timeout=6.0) is None:
            raise RuntimeError("overview header did not render")
        if sess.wait_for("mode: monitor", timeout=4.0) is None:
            raise RuntimeError("daemon not connected in overview")
        mark = len(sess.buf)
        sess.send(b"/", pause=0.12)
        if sess.wait_for("/_", timeout=3.0, since=mark) is None:
            raise RuntimeError("search bar did not open on '/'")
        mark = len(sess.buf)
        sess.send(target_addr.encode(), pause=0.12)
        sess.send(b"\r", pause=0.15)
        if sess.wait_for(f"search: {target_addr}", timeout=4.0, since=mark) is None:
            raise RuntimeError("search filter did not apply")
        if sess.wait_for(f"{target_addr}:", timeout=4.0, since=mark) is None:
            raise RuntimeError(f"filtered address row for {target_addr} did not render")
        sess.send(b"\x1b[H", pause=0.10)  # home
        found_row = False
        for _ in range(12):
            mark = len(sess.buf)
            sess.send(b"\r", pause=0.08)    # open row if collapsed
            sess.send(b"\x1b[B", pause=0.10)  # down
            if sess.wait_for(f"› {target_addr}:", timeout=0.35, since=mark) is not None:
                found_row = True
                break
        if not found_row:
            raise RuntimeError(f"could not select address row for {target_addr}")
        sess.drain(0.12)
        mark = len(sess.buf)
        sess.send(b"x", pause=0.15)
        added = None
        deadline = time.monotonic() + 6.0
        while time.monotonic() < deadline:
            added = find_rule(overlay_path, target_cidr)
            if added is not None:
                break
            time.sleep(0.25)
        if added is None or added.get("verdict") != "deny":
            raise RuntimeError(f"deny rule for {target_cidr} did not appear in rules: {added}")
        # Wait for TUI BLOCKED log entry and 500 ms row rebuild with refreshed rules before unblocking
        if sess.wait_for("BLOCKED ", timeout=5.0, since=mark) is None:
            raise RuntimeError("TUI did not log BLOCKED after x")
        sess.drain(0.7)
        mark = len(sess.buf)
        sess.send(b"x", pause=0.15)
        gone = False
        deadline = time.monotonic() + 6.0
        while time.monotonic() < deadline:
            if find_rule(overlay_path, target_cidr) is None:
                gone = True
                break
            time.sleep(0.25)
        if not gone:
            raise RuntimeError(f"deny rule for {target_cidr} still present after second x")
        if sess.wait_for("UNBLOCKED ", timeout=5.0, since=mark) is None:
            raise RuntimeError("TUI did not log UNBLOCKED after second x")
        rc = sess.close()
        if rc != 0:
            raise RuntimeError(f"snitch exited {rc} on 'q'")
    except Exception:
        sess.close()
        raise

elif cmd == "pty-trial":
    bin_path = args[0]
    sess = PtySession(bin_path, sock_path)
    try:
        if sess.wait_for("snitch | last ", timeout=6.0) is None:
            raise RuntimeError("overview header did not render")
        if sess.wait_for("mode: monitor", timeout=4.0) is None:
            raise RuntimeError("overview did not show mode: monitor")
        mark = len(sess.buf)
        time.sleep(0.12)
        sess.send(b"T", pause=0.12)
        if sess.wait_for("[y/N]", timeout=4.0, since=mark) is None:
            raise RuntimeError("trial confirmation prompt did not appear on 'T'")
        mark = len(sess.buf)
        time.sleep(0.75)  # strictly > 0.6 s confirmation gate
        sess.send(b"y", pause=0.20)
        # Handle optional daemon no-rules prompt if it appears
        q_txt = sess.wait_for("Start the trial? [y/N]", timeout=1.5, since=mark)
        if q_txt is not None:
            mark = len(sess.buf)
            time.sleep(0.75)
            sess.send(b"y", pause=0.20)
        if sess.wait_for("enforce (trial until ", timeout=6.0, since=mark) is None:
            raise RuntimeError("trial deadline not shown after T -> y")
        _, st_reply = api_exchange({"type": "status", "id": 1})
        st = st_reply.get("status") or {}
        if st.get("mode") != "enforce" or not st.get("trial"):
            raise RuntimeError(f"API status not in trial enforce: {st}")
        mark = len(sess.buf)
        sess.drain(0.12)
        sess.send(b"E", pause=0.15)
        if sess.wait_for("monitor", timeout=6.0, since=mark) is None:
            raise RuntimeError("overview did not return to monitor on 'E'")
        deadline = time.monotonic() + 6.0
        restored = False
        while time.monotonic() < deadline:
            _, st_reply = api_exchange({"type": "status", "id": 1})
            st = st_reply.get("status") or {}
            if st.get("mode") == "monitor" and not st.get("trial"):
                restored = True
                break
            time.sleep(0.25)
        if not restored:
            raise RuntimeError("API status did not return to monitor after 'E'")
        rc = sess.close()
        if rc != 0:
            raise RuntimeError(f"snitch exited {rc} on 'q'")
    except Exception:
        sess.close()
        raise

elif cmd == "pty-hook-inactive":
    bin_path, fake_bin, fake_sock = args[0], args[1], args[2]
    try:
        os.unlink(fake_sock)
    except FileNotFoundError:
        pass
    fake = subprocess.Popen(
        [fake_bin, "-api", fake_sock],
        stdin=subprocess.PIPE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    sess = None
    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            if os.path.exists(fake_sock):
                break
            if fake.poll() is not None:
                err = fake.stderr.read().decode("utf-8", "replace")
                raise RuntimeError(f"fakedaemon exited early ({fake.returncode}): {err}")
            time.sleep(0.05)
        else:
            raise RuntimeError(f"fakedaemon socket {fake_sock} did not appear")
        fake.stdin.write(b"hook pending\n")
        fake.stdin.flush()
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(1.0)
            try:
                s.connect(fake_sock)
                s.sendall(b'{"type":"status","id":1}\n')
                buf = b""
                while b"\n" not in buf:
                    chunk = s.recv(65536)
                    if not chunk:
                        break
                    buf += chunk
                reply = json.loads(buf.split(b"\n", 1)[0].decode("utf-8", "replace"))
                hook = (reply.get("status") or {}).get("hook") or {}
                if hook.get("state") == "inactive" and hook.get("pending") is True:
                    break
            except (OSError, ValueError):
                pass
            finally:
                s.close()
            time.sleep(0.05)
        else:
            raise RuntimeError("fakedaemon did not transition to hook pending")
        sess = PtySession(bin_path, fake_sock)
        if sess.wait_for("NO KERNEL HOOK", timeout=6.0) is None:
            raise RuntimeError("overview header missing NO KERNEL HOOK tag on PTY")
        want_line = "kernel hook inactive: connections not seen or blocked - reboot to activate"
        if sess.wait_for(want_line, timeout=6.0) is None:
            raise RuntimeError(f"overview bottom missing {want_line!r} on PTY")
        rc = sess.close()
        sess = None
        if rc != 0:
            raise RuntimeError(f"snitch exited {rc} on 'q'")
    finally:
        if sess is not None:
            sess.close()
        try:
            if fake.poll() is None and fake.stdin:
                fake.stdin.write(b"quit\n")
                fake.stdin.flush()
                fake.stdin.close()
            fake.wait(timeout=2.0)
        except Exception:
            fake.kill()
            fake.wait()
        if fake.stderr:
            fake.stderr.close()
        try:
            os.unlink(fake_sock)
        except OSError:
            pass

elif cmd == "role-guess":
    op_file, user_name = args[0], args[1]
    try:
        st = os.lstat(op_file)
    except OSError:
        sys.exit(1)
    if not stat.S_ISREG(st.st_mode) or st.st_uid != 0 or (stat.S_IMODE(st.st_mode) & 0o022) != 0:
        sys.exit(1)
    with open(op_file, "r", encoding="utf-8", errors="replace") as f:
        first = f.readline().strip()
    sys.exit(0 if first and first == user_name else 1)

elif cmd == "cleanup-rule":
    overlay_path, to_cidr = args[0], args[1]
    if overlay_path and remove_rule(overlay_path, to_cidr):
        print("removed")

elif cmd == "cleanup-end":
    _, reply = api_exchange({"type": "end", "id": 1})
    if reply.get("ok"):
        print("ended")

else:
    raise SystemExit(f"unknown command: {cmd}")
PY
)

pyrun() {
  python3 -I -u -c "$py_helper" "$api" "$@"
}

step_build() {
  go build -o "$BIN" ./cmd/snitch || return 1
  ver=$("$BIN" -version) || return 1
  [ -n "$ver" ] || return 1
  note "snitch $ver ($BIN)"
}

step_daemon_probe() {
  probe_json=$(pyrun probe) || return 1
  running=$(pyrun json-field "$probe_json" running) || return 1
  mode=$(pyrun json-field "$probe_json" mode) || return 1
  peer_uid=$(pyrun json-field "$probe_json" peer_uid) || return 1
  daemon_ver=$(pyrun json-field "$probe_json" version) || return 1
  daemon_source=$(pyrun json-field "$probe_json" source) || return 1
  daemon_kill=$(pyrun json-field "$probe_json" kill) || return 1
  daemon_learn=$(pyrun json-field "$probe_json" learning) || return 1
  overlay=$(pyrun json-field "$probe_json" overlay) || return 1
  [ "$running" = "1" ] || { note "daemon reports running=false"; return 1; }
  if [ "$mode" != "monitor" ]; then
    printf 'REFUSED: daemon on %s is in mode %s; monitor mode only (exit 2)\n' "$api" "$mode"
    exit 2
  fi
  if [ "$daemon_ver" = "fake" ] || [ "$peer_uid" != "0" ]; then
    is_fake=1
    note "stand-in / non-root socket detected (version=$daemon_ver peer_uid=$peer_uid)"
  else
    if role_guess; then
      is_writer=1
      note "real daemon in monitor mode (peer_uid=0, writer=$me, overlay=${overlay:-none})"
    else
      note "real daemon in monitor mode (peer_uid=0, reader=$me)"
    fi
  fi
}

step_status_json() {
  status_out=$("$BIN" status -api "$api") || return 1
  status_summary=$(pyrun check-status-json "$status_out" "$is_fake" "$daemon_kill") || return 1
  note "$status_summary"
}

step_pty_smoke() {
  rt_dir=${XDG_RUNTIME_DIR:-}
  pyrun pty-smoke "$BIN" "$rt_dir" || return 1
  note "overview rendered, egress graph toggled (e), non-dumpable, XDG_RUNTIME_DIR clean, quit 0"
}

step_pty_hook_inactive() {
  go build -o "$tmp/fakedaemon" ./tools/fakedaemon || return 1
  pyrun pty-hook-inactive "$BIN" "$tmp/fakedaemon" "$tmp/hook-fake.sock" || return 1
  note "NO KERNEL HOOK header tag and pending bottom warning rendered on PTY, quit 0"
}

step_testnet_connect() {
  curl -sS --connect-timeout 1 --max-time 1 "https://$testnet_addr/" >/dev/null 2>&1 || true
  snap_info=$(pyrun snapshot-has "$testnet_addr") || {
    note "no 1h snapshot row found for $testnet_addr after connect attempt"
    return 1
  }
  note "row present for $testnet_addr ($snap_info)"
}

step_pty_block_unblock() {
  rule_added=1
  pyrun pty-block-unblock "$BIN" "$overlay" "$testnet_addr" "$testnet_cidr" || return 1
  rule_added=0
  note "blocked $testnet_cidr via x, verified in rules, unblocked via x, confirmed gone"
}

step_pty_trial() {
  trial_started=1
  pyrun pty-trial "$BIN" || return 1
  trial_started=0
  note "trial started (T -> y), deadline shown, ended (E), monitor restored"
}

cleanup() {
  [ "$cleaned" -eq 0 ] || return 0
  cleaned=1
  set +e
  if [ "$is_fake" -eq 0 ]; then
    if [ "$trial_started" -eq 1 ]; then
      if pyrun cleanup-end >/dev/null 2>&1; then
        note "trap: sent end to restore monitor mode"
      fi
    fi
    if [ "$rule_added" -eq 1 ] && [ -n "$overlay" ]; then
      if pyrun cleanup-rule "$overlay" "$testnet_cidr" >/dev/null 2>&1; then
        note "trap: removed $testnet_cidr overlay rule"
      fi
    fi
  fi
  rm -rf "$tmp"
}

on_signal() {
  cleanup
  exit 130
}

trap cleanup EXIT
trap on_signal INT TERM

printf '== tui-check against %s as %s\n' "$api" "$me"
must "build snitch binary from tree" step_build
must "daemon answers on $api in monitor mode" step_daemon_probe
step "snitch status prints valid JSON" step_status_json
step "overview PTY: start, egress graph (e), non-dumpable, runtime dir clean, quit (q)" step_pty_smoke
step "PTY hook inactive: NO KERNEL HOOK tag and pending bottom warning, quit (q)" step_pty_hook_inactive

if [ "$is_fake" -eq 1 ]; then
  skip "TEST-NET ($testnet_addr) connect makes row exist" \
    "fakedaemon/non-root socket has no kernel eBPF capture; requires real snitchd"
  skip "PTY block/unblock on $testnet_addr and verify via rules" \
    "fakedaemon runs as non-root (FOREIGN socket: writes are off)"
else
  step "TEST-NET ($testnet_addr) connect (1s, expected to fail) makes row exist" step_testnet_connect
  if [ "$is_writer" -eq 1 ]; then
    step "PTY search $testnet_addr, open rows, x block -> rules, x unblock -> gone" step_pty_block_unblock
  else
    skip "PTY block/unblock on $testnet_addr and verify via rules" \
      "reader: $operator_file does not name $me (create with: echo $me | sudo tee $operator_file >/dev/null && sudo chmod 0644 $operator_file)"
  fi
fi

if [ "$trial" -eq 1 ]; then
  if [ "$is_fake" -eq 1 ]; then
    skip "trial (--trial): T, y, deadline, E, monitor" \
      "fakedaemon runs as non-root (FOREIGN socket: writes are off)"
  elif [ "$is_writer" -eq 0 ]; then
    skip "trial (--trial): T, y, deadline, E, monitor" \
      "reader: $operator_file does not name $me"
  elif [ "$daemon_source" != "files" ]; then
    skip "trial (--trial): T, y, deadline, E, monitor" \
      "daemon source=$daemon_source (started with -mode, does not follow trial files)"
  elif [ "$daemon_kill" -eq 1 ] || [ "$daemon_learn" -eq 1 ]; then
    skip "trial (--trial): T, y, deadline, E, monitor" \
      "kill switch or learning mode is active on daemon"
  else
    printf '  --trial will temporarily switch snitchd to enforce mode via T -> y and immediately end it with E.\n'
    printf '  Way back: snitchd end, scripts/fail-open.sh, or this script trap.\n'
    printf "  Type 'yes' to continue: "
    read -r confirm_go || confirm_go=""
    if [ "$confirm_go" = "yes" ]; then
      step "trial (--trial): T, y, deadline shown, E, monitor restored" step_pty_trial
    else
      skip "trial (--trial): T, y, deadline, E, monitor" "operator did not confirm 'yes'"
    fi
  fi
fi

printf '== summary: %d passed, %d skipped, %d failed\n' "$passed" "$skipped" "$failed"
[ "$failed" -eq 0 ]
