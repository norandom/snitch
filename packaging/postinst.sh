#!/bin/sh
# Configure the next boot for the bpf LSM on GRUB hosts, or print manual
# instructions when GRUB is absent; enable snitchd and its boot revert at boot
# on a fresh install (or an upgrade from before 1.2.0), and restart snitchd if
# it is running. Never starts a stopped unit, never touches rules.
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

# Autostart: enable the daemon with its boot revert (fail-safe 5: never one
# without the other) on a fresh install, or on an upgrade from a version that
# did not enable it. Later upgrades keep an operator's disable. The unit never
# passes -mode, so a boot starts in monitor unless the operator kept enforce.
# Works offline (symlinks only), and under ${DPKG_ROOT} through --root.
prev="${2:-}"
want_enable=0
if [ -z "$prev" ]; then
	want_enable=1
elif command -v dpkg >/dev/null 2>&1 && dpkg --compare-versions "$prev" lt 1.2.0; then
	want_enable=1
fi
if [ "$want_enable" = 1 ] && command -v systemctl >/dev/null 2>&1; then
	if [ -n "${DPKG_ROOT:-}" ]; then
		set -- --root="$DPKG_ROOT"
	else
		set --
	fi
	if systemctl "$@" enable snitchd-trial-boot.service snitchd.service >/dev/null 2>&1; then
		printf 'snitch: enabled snitchd.service and snitchd-trial-boot.service at boot (monitor mode)\n'
	else
		printf 'snitch: enabling snitchd at boot failed; run systemctl enable snitchd-trial-boot.service snitchd.service\n'
	fi
fi

# Restart a running daemon so an upgrade takes effect now. try-restart never
# starts or enables a unit that is stopped. Skipped without a booted systemd
# under ${DPKG_ROOT:-} (chroots, image builds, containers without systemd).
if [ -d "${DPKG_ROOT:-}/run/systemd/system" ] && command -v systemctl >/dev/null 2>&1; then
	systemctl daemon-reload >/dev/null 2>&1 || true
	if systemctl is-active --quiet snitchd.service; then
		if systemctl try-restart snitchd.service; then
			printf 'snitch: restarted snitchd.service to run the installed version\n'
		else
			printf 'snitch: restarting snitchd.service failed; run systemctl restart snitchd.service\n'
		fi
	fi
fi

exit 0
