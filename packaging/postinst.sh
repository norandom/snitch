#!/bin/sh
# Configure the next boot for the bpf LSM on GRUB hosts, or print manual
# instructions when GRUB is absent. Never enables units or touches rules.
set -eu

case "${1:-}" in
	configure) ;;
	*) exit 0 ;;
esac

grub_default="${DPKG_ROOT:-}/etc/default/grub"
grub_vars=""
if [ -r "$grub_default" ]; then
	grub_vars=$(
		set +eu
		GRUB_CMDLINE_LINUX=""
		GRUB_CMDLINE_LINUX_DEFAULT=""
		# shellcheck disable=SC1090
		. "$grub_default" >/dev/null 2>&1 || true
		printf '%s %s' "${GRUB_CMDLINE_LINUX:-}" "${GRUB_CMDLINE_LINUX_DEFAULT:-}"
	) || grub_vars=""
fi

helper="${DPKG_ROOT:-}/usr/lib/snitch/lsm-cmdline"

if [ -d "${DPKG_ROOT:-}/boot/grub" ]; then
	if command -v update-grub >/dev/null 2>&1; then
		if ! update-grub; then
			printf 'snitch: update-grub failed; GRUB configuration was not regenerated\n'
		fi
		if [ -x "$helper" ]; then
			"$helper" --explain -- "$grub_vars" || true
		fi
	else
		printf 'snitch: update-grub not found; GRUB configuration was not regenerated (run update-grub to apply)\n'
		if [ -x "$helper" ]; then
			"$helper" --manual -- "$grub_vars" || true
		fi
	fi
else
	if [ -x "$helper" ]; then
		"$helper" --manual -- "$grub_vars" || true
	fi
fi

exit 0
