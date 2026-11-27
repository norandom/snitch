#!/bin/sh
# Regenerate GRUB configuration after package removal or purge so the next
# boot drops snitch's lsm= setting. Never fails.
set -eu

case "${1:-}" in
	remove|purge)
		if [ -d "${DPKG_ROOT:-}/boot/grub" ] && command -v update-grub >/dev/null 2>&1; then
			update-grub || printf 'snitch: update-grub failed; run update-grub manually to refresh boot config\n'
		fi
		;;
esac

exit 0
