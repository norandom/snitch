#!/bin/sh
# On removal, stop snitchd and disable it and its boot revert while the unit
# files still exist, so no enable link outlives the package and no daemon keeps
# running a deleted binary. Stopping detaches the programs: fail-open. Upgrades
# are left alone (postinst restarts a running daemon). Never fails.
set -eu

case "${1:-}" in
	remove) ;;
	*) exit 0 ;;
esac

command -v systemctl >/dev/null 2>&1 || exit 0

if [ -d "${DPKG_ROOT:-}/run/systemd/system" ]; then
	systemctl stop snitchd.service >/dev/null 2>&1 ||
		printf 'snitch: stopping snitchd.service failed\n'
fi
if [ -n "${DPKG_ROOT:-}" ]; then
	set -- --root="$DPKG_ROOT"
else
	set --
fi
systemctl "$@" disable snitchd.service snitchd-trial-boot.service >/dev/null 2>&1 ||
	printf 'snitch: disabling snitchd at boot failed; run systemctl disable snitchd.service snitchd-trial-boot.service\n'

exit 0
