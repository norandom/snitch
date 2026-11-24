#!/bin/sh
# setup: the one rooted step a fresh host needs before any snitch client can ask a
# question — name the operator. The deployment creates /etc/snitch and the operator
# file; run by hand (a host without the deployment, a development host), this helper
# does the same: the directory 0755 (readers must traverse it) and the operator file
# root-owned 0644, naming on its first line the one user besides root who may answer
# questions and write over the API (README "Install"; rules the tray's role guess
# copies from the daemon and checks the same way: a regular file owned by root with
# no group or other write bit, first line naming the user).
#
# Fail-safe implications: this script grants nothing by itself — the daemon reads the
# file and decides by peer credentials; it never touches the daemon, the rules files
# or systemd, and refuses to replace a named operator without --force so a second
# hoster cannot unknowingly lock the first one out of the questions.
#
# Usage: sudo scripts/setup.sh [--force] [USER]
#   USER defaults to $SUDO_USER (the one who ran sudo); pass a name to name somebody
#   else. --force replaces an existing operator file that names another user.
set -eu

# The who and where; variables sit here so a host can be reviewed in one place.
operator_dir=/etc/snitch
operator_file=$operator_dir/operator

usage() { echo "usage: sudo scripts/setup.sh [--force] [USER]" >&2; exit 2; }
die() { echo "setup: $1" >&2; exit 1; }

force=0
user=
while [ $# -gt 0 ]; do
  case $1 in
    --force) force=1 ;;
    -h | --help) usage ;;
    -*) usage ;;
    *) [ -z "$user" ] || usage; user=$1 ;;
  esac
  shift
done
# Under sudo the invoking user is known; overrun plain root shells must say a name.
[ -n "$user" ] || user=${SUDO_USER:-}
[ -n "$user" ] || die "which user should the operator file name? pass one: sudo scripts/setup.sh USER"

[ "$(id -u)" -eq 0 ] || die "this writes /etc/snitch as root; run: sudo scripts/setup.sh${user:+ $user}"
id "$user" >/dev/null 2>&1 || die "no such user on this host: $user (a typo would silently read-only every user)"

# An operator file that already names somebody is a decision, not drift; only --force
# replaces it, and the run says who it named before.
if [ -e "$operator_file" ] && [ "$force" -eq 0 ]; then
  named=$(sed -n '1p' "$operator_file" || true)
  die "operator file exists and names '${named:-nobody}'; pass --force to name '$user' instead"
fi

# The directory and the file, written the way the daemon's rules read them.
mkdir -p "$operator_dir"
chmod 0755 "$operator_dir"
if [ -e "$operator_file" ]; then
  replaced=1
else
  replaced=0
fi
printf '%s\n' "$user" > "$operator_file"
chown root:root "$operator_file"
chmod 0644 "$operator_file"

# Verify the daemon's acceptance rules one by one (the tray's role guess mirrors
# them; a check here catches a umask or a mount oddity a plain write would hide).
[ -f "$operator_file" ] || die "the operator file is not a regular file: $operator_file"
[ "$(stat -c %u "$operator_file")" -eq 0 ] || die "the operator file is not owned by root: $operator_file"
mode=$(stat -c %a "$operator_file")
# The daemon's rule is "no write bit for group nor others" (role.go copies it); the
# find octal tests are the portable sh reading of those two bits (-perm -020 group,
# -perm -002 others).
if [ -n "$(find "$operator_file" -perm -020 -print -quit)" ] ||
  [ -n "$(find "$operator_file" -perm -002 -print -quit)" ]; then
  die "a group or other write bit is set (mode $mode): $operator_file"
fi
first=$(sed -n '1p' "$operator_file")
[ "$first" = "$user" ] || die "the first line does not name '$user' as written: '$first'"

echo "operator file $operator_file names '$user' (root-owned, mode $mode, dir 0755)"
if [ "$replaced" -eq 1 ]; then
  echo "replaced an earlier operator file (--force)"
fi
echo "the tray will offer Allow and Block to '$user'; other users read only"
