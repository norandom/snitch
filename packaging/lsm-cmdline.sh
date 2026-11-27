#!/bin/sh
# lsm-cmdline: emit the kernel lsm= parameter (or nothing) for GRUB based on
# the running kernel's active LSM list, /proc/cmdline, and installed kernel configs.
# Always exits 0 so boot-loader generation and package installs never fail.
set -eu
LC_ALL=C
export LC_ALL

mode=emit
listfile=/sys/kernel/security/lsm
cmdlinefile=/proc/cmdline
bootdir=/boot
explicit_l=0

while [ "$#" -gt 0 ]; do
	case "$1" in
		--explain) mode=explain; shift ;;
		--manual) mode=manual; shift ;;
		-l) [ "$#" -ge 2 ] || exit 0; listfile=$2; explicit_l=1; shift 2 ;;
		-c) [ "$#" -ge 2 ] || exit 0; cmdlinefile=$2; shift 2 ;;
		-k) [ "$#" -ge 2 ] || exit 0; bootdir=$2; shift 2 ;;
		--) shift; break ;;
		-*) shift ;;
		*) break ;;
	esac
done

grubvars=""
if [ "$#" -gt 0 ]; then
	grubvars=$*
fi

has_bpf() {
	case ",$1," in
		*,bpf,*) return 0 ;;
		*) return 1 ;;
	esac
}

same_pid1_root() {
	r1=$(stat -Lc '%d:%i' / 2>/dev/null) || return 1
	r2=$(stat -Lc '%d:%i' /proc/1/root 2>/dev/null) || return 1
	[ -n "$r1" ] && [ "$r1" = "$r2" ]
}

read_valid_list() {
	[ -r "$listfile" ] || return 1
	raw=$(cat "$listfile" 2>/dev/null && printf x) || return 1
	raw=${raw%x}
	while :; do
		case "$raw" in
			[[:space:]]*) raw=${raw#?} ;;
			*[[:space:]]) raw=${raw%?} ;;
			*) break ;;
		esac
	done
	case "$raw" in
		""|*[!a-z0-9_,]*) return 1 ;;
	esac
	printf '%s' "$raw"
}

check_kernels() {
	kernel_count=0
	kernel_err=""
	set +f
	for k in "$bootdir"/vmlinuz-*; do
		[ -e "$k" ] || continue
		kernel_count=$((kernel_count + 1))
		base=${k##*/}
		ver=${base#vmlinuz-}
		cfg="$bootdir/config-$ver"
		if [ ! -e "$cfg" ]; then
			kernel_err="$base has missing config ($cfg)"
			return 1
		fi
		if [ ! -r "$cfg" ]; then
			kernel_err="$base has unreadable config ($cfg)"
			return 1
		fi
		if ! grep -qx 'CONFIG_BPF_LSM=y' "$cfg" 2>/dev/null; then
			kernel_err="$base lacks CONFIG_BPF_LSM=y"
			return 1
		fi
	done
	if [ "$kernel_count" -eq 0 ]; then
		kernel_err="no kernel found under $bootdir"
		return 1
	fi
	return 0
}

cmdline_has_lsm() {
	[ -r "$cmdlinefile" ] || return 1
	cmdline=$(cat "$cmdlinefile" 2>/dev/null) || return 1
	set -f
	for tok in $cmdline; do
		case "$tok" in
			lsm=*) set +f; return 0 ;;
		esac
	done
	set +f
	return 1
}

find_admin_lsm() {
	admin_found=0
	admin_val=""
	set -f
	for tok in $grubvars; do
		case "$tok" in
			lsm=*)
				admin_found=1
				admin_val=${tok#lsm=}
				case "$admin_val" in
					\"*\") admin_val=${admin_val#\"}; admin_val=${admin_val%\"} ;;
					\'*\') admin_val=${admin_val#\'}; admin_val=${admin_val%\'} ;;
				esac
				;;
		esac
	done
	set +f
}

list_ok=0
list=""
if list=$(read_valid_list); then
	list_ok=1
fi

if [ "$mode" = manual ]; then
	if [ "$list_ok" -eq 1 ]; then
		if has_bpf "$list"; then
			printf 'snitch: add to the kernel command line: lsm=%s\n' "$list"
		else
			printf 'snitch: add to the kernel command line: lsm=%s,bpf\n' "$list"
		fi
	else
		printf 'snitch: add to the kernel command line: lsm=<your list>,bpf\n'
	fi
	exit 0
fi

find_admin_lsm
if [ "$admin_found" -eq 1 ]; then
	if [ "$mode" = explain ]; then
		if has_bpf "$admin_val"; then
			printf 'snitch: bpf is already in your lsm= boot setting; leaving it unchanged\n'
		else
			printf 'snitch: boot configuration already sets lsm=; add bpf to your own lsm= setting\n'
		fi
	fi
	exit 0
fi

if [ "$list_ok" -ne 1 ]; then
	if [ "$mode" = explain ]; then
		printf 'snitch: cannot read the active LSM list; boot configuration unchanged\n'
	fi
	exit 0
fi

if has_bpf "$list" && ! cmdline_has_lsm; then
	if [ "$mode" = explain ]; then
		printf 'snitch: bpf is already active by default; no boot parameter needed\n'
	fi
	exit 0
fi

if ! check_kernels; then
	if [ "$mode" = explain ]; then
		printf 'snitch: leaving boot configuration unchanged: %s\n' "$kernel_err"
	fi
	exit 0
fi

if has_bpf "$list"; then
	out=$list
	explain_msg="snitch: bpf kernel hook is active; kept lsm=$out in boot configuration"
else
	out="$list,bpf"
	explain_msg="snitch: configured next boot with lsm=$out; a reboot is needed for snitch to see connections"
fi

if [ "$mode" = explain ]; then
	printf '%s\n' "$explain_msg"
	exit 0
fi

if [ "$explicit_l" -eq 0 ] && ! same_pid1_root; then
	exit 0
fi

case "$out" in
	""|*[!a-z0-9_,]*) exit 0 ;;
esac
printf 'lsm=%s\n' "$out"
exit 0
