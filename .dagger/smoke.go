// The in-container deb smoke (ci-debs tasks 6.1-6.4, requirements 4.3, 4.4,
// 5.3, 5.4): the deb installed and driven for real in each contract distro's
// own userspace, inside containers, from one `dagger call`. The assertions
// are the design's nine groups, every one named in the log as it passes or
// fails, and any failure exits non-zero naming its group.
//
// The mechanism was decided by probing, and the committed shape is what the
// probes left standing:
//
//   - A dagger engine container cannot run systemd. Every exec the engine
//     runs shares one pid namespace whose PID 1 is runc's own init shim (a
//     probe exec landed at NSpid 19 while `ps` showed 1 .init), so /sbin/init
//     in an exec is never PID 1 and refuses - "Explicit --user argument
//     required to run as user manager", exit 1. The unprivileged-namespace
//     route is closed too: `unshare --user` in an engine container fails with
//     "Operation not permitted".
//   - The docker recipe the research pinned (privileged, --cgroupns=host,
//     tmpfs on /run and /run/lock, policy-rc.d exit 0, ENV container=docker)
//     boots a real systemd to `is-system-running: running` and starts a
//     oneshot unit to `Result=success / ExecMainStatus=0` - probed both raw
//     on this docker-ce host and through the engine (see the smoke's
//     docker-socket step).
//   - So the smoke drives the host's docker daemon through its socket, which
//     the function takes as an argument: the GHA runner and every docker-ce
//     or rootful-podman workstation expose /var/run/docker.sock, and the
//     socket is the same door in CI and locally, which is the parity the
//     feature exists for (R1.2). The engine-run driver container holds only
//     the pinned docker CLI (a transport, never a build tool), the deb under
//     test, and the assertion scripts; the sibling containers it boots under
//     the host daemon are the actual per-distro smoke containers.
package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/snitch/internal/dagger"
)

// smokeDriverScript is the smoke's coordinator, running in the engine's
// driver container. It boots the sibling (the research's docker recipe, plus
// a tmpfs over /sys/fs/bpf: bpffs is where eBPF pins must live, so an empty
// tmpfs there makes the loaded-maps step fail where every kernel behaves the
// same and the daemon can never reach a host-global LSM attach on a machine
// whose LSM list does include bpf - both doors then see the one expected
// journal signature, and the smoke can never attach anything), waits for
// systemd to reach a stable state, stages the deb, and runs one script per
// assertion group through `docker exec -i bash -s` (stdin, so group scripts
// never nest shell inside shell). Step lines print as they complete; a
// failing group prints its own evidence line before exiting non-zero, so the
// failing group is always named in the log. The EXIT trap removes the
// sibling: a privileged container must never outlive its smoke run, whatever
// the run's outcome. Every value the scripts parameterize rides the
// environment (DISTRO, IMAGE, DEBFILE, PKGVER), never string interpolation -
// the debTreeScript rule, same reason.
const smokeDriverScript = `#!/usr/bin/env bash
set -uo pipefail
exec > >(tee /smoke/smoke.log) 2>&1

D="$DISTRO"
S="snitch-smoke-$D-$$-$RANDOM"

step() { echo "smoke: $D: $*"; }
die()  { echo "smoke: $D: $*"; exit 1; }
cleanup() { docker rm -f "$S" >/dev/null 2>&1 || true; }
trap cleanup EXIT

# The sibling: the distro smoke container itself, systemd as PID 1. policy-rc.d
# is written after the systemd install (the probed order: nothing in the base
# tries to invoke an init before systemd exists), and it is exit 0 so apt in
# the container can configure packages without starting daemons out from
# under the boot.
docker rm -f "$S" >/dev/null 2>&1 || true
docker run -d --name "$S" \
	--privileged \
	--cgroupns=host \
	--tmpfs /run \
	--tmpfs /run/lock \
	--tmpfs /sys/fs/bpf \
	-e container=docker \
	"$IMAGE" bash -c '
		apt-get update -qq &&
		apt-get install -y -qq systemd systemd-sysv dbus >/dev/null 2>&1 &&
		printf "exit 0\n" > /usr/sbin/policy-rc.d &&
		chmod +x /usr/sbin/policy-rc.d &&
		exec /sbin/init
	' >/dev/null || die "sibling boot: docker run refused"

# Wait for the boot, bounded: while apt is still installing, systemctl does
# not exist yet ("starting"); systemd then reports offline, and finally
# running (degraded is accepted: the docker environment fails units that have
# nothing to do with the deb, and every deb assertion below names its own
# state anyway). 60 tries * 5 s covers the ~2 min install on a cold host.
state=starting
for _ in $(seq 1 60); do
	state=$(docker exec "$S" systemctl is-system-running 2>/dev/null || echo starting)
	case "$state" in
		running|degraded) break ;;
		failed) die "sibling boot: systemd reached state failed" ;;
	esac
	sleep 5
done
case "$state" in
	running|degraded) step "sibling boot: systemd is-system-running: $state" ;;
	*) die "sibling boot: systemd never reached a stable state (last: $state)" ;;
esac

# The deb under test, staged through the same socket (docker cp streams the
# driver's copy; the sibling never reaches back into the engine).
docker cp "/deb/$DEBFILE" "$S:/deb.deb" || die "stage: the deb never reached the sibling"
step "stage: $DEBFILE"

# The tray exercise's props: the stand-in the module built (a pipeline tool,
# never inside any package) and the repo's tray-check harness, staged beside
# the installed package.
docker exec "$S" install -d -m 0755 /smoke
docker cp /smoke/fakedaemon "$S:/smoke/fakedaemon" || die "stage: the stand-in never reached the sibling"
docker cp /smoke/tray-check.sh "$S:/smoke/tray-check.sh" || die "stage: the harness never reached the sibling"
docker exec "$S" chmod 0755 /smoke/fakedaemon

# group runs one assertion group's script inside the sibling. The group's
# script prints its evidence and, on failure, its own FAIL line before its
# non-zero exit; the driver adds the verdict, so both the detail and the
# group's name are in the log.
group() {
	local name=$1 script=$2
	if docker exec -i -e DISTRO="$D" -e PKGVER="$PKGVER" "$S" bash -s < "/smoke/groups/$script"; then
		step "$name: PASS"
	else
		die "$name: FAIL"
	fi
}

group "1 conffile-keep over the authored rules" "1-conffile-keep.sh"
group "2 fresh install" "2-fresh-install.sh"
group "3 unit verify" "3-unit-verify.sh"
group "4 trial-boot start" "4-trial-boot.sh"
group "5 daemon journal signature" "5-daemon-journal.sh"
group "6 installed-path check" "6-installed-check.sh"
	group "7 tray -version from PATH" "7-tray-version.sh"
group "8 tray headless" "8-tray-headless.sh"

# Group 9 runs HERE, not in the sibling: lintian judges the deb FILE against
# the policy profile - no installed state involved - and this driver IS the
# distro (same base image, same apt, its own lintian), which is what R5.4's
# per-distro tags mean: forky's 2.144 and ubuntu's 2.129 each render their own
# verdict over the one published deb. The committed threshold is --fail-on
# error: an error-class tag fails the smoke (after the package's own shipped
# overrides are honored - overrides live inside the deb, lintian reads them
# from there), while warnings and info print for the record the docs task
# lists. --display-info widens the record to the info class; --show-overrides
# keeps what was overridden visible, so the record shows the whole truth.
if lintian --profile debian --display-info --show-overrides --color never --fail-on error "/deb/$DEBFILE"; then
	step "9 lintian: PASS"
else
	die "9 lintian: FAIL: an above-threshold tag (the lines above name it)"
fi
`

// smokeConffileKeepScript is assertion group 1 (the design's conffile
// contract, 4.3/4.6): a rules.toml that predates the package - authored by the
// deploy flow, not by dpkg - survives the package's first install untouched,
// and the shipped sample is parked beside it instead of clobbering it. The
// authored content is a valid rules file (the deploy flow writes real rules,
// not markers), and the parked suffix this dpkg writes in the
// no-previous-version case is .dpkg-dist (probed on the pinned forky
// dpkg-deb 1.23.11: .dpkg-new belongs to the upgrade-over-registered-conffile
// case, and this group's scenario is the first install).
const smokeConffileKeepScript = `#!/usr/bin/env bash
set -uo pipefail
die() { echo "smoke: $DISTRO: 1 conffile-keep: FAIL: $*"; exit 1; }
say() { echo "smoke: $DISTRO: 1 conffile-keep: $*"; }

# The pre-authored rules of a deployed host (deploy-service's pyinfra flow
# owns /etc/snitch; the sample this package ships is only the fresh start).
install -d -m 0755 /etc/snitch
cat > /etc/snitch/rules.toml <<'AUTHORED'
# rules.toml - authored on this host by the deploy flow, never by the package.
[[program]]
name  = "backup"
paths = ["/usr/local/bin/backup"]

[[rule]]
program = "backup"
to      = "backup.example.internal"
proto   = "tcp"
port    = 443
verdict = "allow"
note    = "the backup job's repository, allowed by name"
AUTHORED
sha256sum /etc/snitch/rules.toml > /tmp/authored.sha

dpkg -i --force-confdef --force-confold /deb.deb >/tmp/g1.out 2>&1 || {
	rc=$?
	cat /tmp/g1.out
	die "dpkg -i over the authored rules exited $rc"
}
grep -q "Setting up snitch" /tmp/g1.out || { cat /tmp/g1.out; die "dpkg never set the package up"; }

# The authored file must survive byte-for-byte (sha over itself, before and
# after, is the byte-for-byte comparison).
sha256sum -c /tmp/authored.sha >/dev/null || die "the authored rules.toml was NOT preserved"

# And the shipped sample must be parked, byte-equal to the deb's own member.
[ -f /etc/snitch/rules.toml.dpkg-dist ] || die "no parked sample at /etc/snitch/rules.toml.dpkg-dist"
dpkg-deb --fsys-tarfile /deb.deb | tar -xO ./etc/snitch/rules.toml > /tmp/sample.toml \
	|| die "the deb's sample member could not be extracted"
cmp -s /tmp/sample.toml /etc/snitch/rules.toml.dpkg-dist \
	|| die "the parked file is not byte-equal to the deb's shipped sample"
cmp -s /tmp/sample.toml /etc/snitch/rules.toml \
	&& die "the shipped sample replaced the authored file - the conffile mechanism is broken"

say "authored rules preserved byte-for-byte ($(cut -d" " -f1 /tmp/authored.sha)); sample parked as /etc/snitch/rules.toml.dpkg-dist"
`

// smokeFreshInstallScript is assertion group 2 (4.3's fresh-install state,
// proven as the design's "fresh container" scenario): purge first - dpkg -P
// takes the container back to a no-traces state, conffiles included even when
// locally modified (probed), so group 1's authored era leaves nothing behind -
// then a plain dpkg -i must install and configure the package with no
// dependencies pulled in, and every payload file the design's table lists
// must land byte-equal to the deb's own members, the two binaries executable.
const smokeFreshInstallScript = `#!/usr/bin/env bash
set -uo pipefail
die() { echo "smoke: $DISTRO: 2 fresh install: FAIL: $*"; exit 1; }
say() { echo "smoke: $DISTRO: 2 fresh install: $*"; }

dpkg --purge snitch >/dev/null 2>&1 || die "dpkg --purge left the package behind"
dpkg -i /deb.deb >/tmp/g2.out 2>&1 || {
	rc=$?
	cat /tmp/g2.out
	die "dpkg -i on the fresh container exited $rc"
}

# Installed and configured, no unmet dependencies ("install ok installed" is
# unreachable while dependencies - which the package declares none of - wait).
dpkg -s snitch > /tmp/g2.s 2>/dev/null || die "dpkg -s knows nothing of snitch"
grep -q "^Status: install ok installed" /tmp/g2.s || die "status is not install ok installed (unmet dependencies?)"
grep -q "^Version: $PKGVER" /tmp/g2.s || die "installed version is not $PKGVER"

# The payload table, every file byte-equal to the deb's own member: the units
# unpacked at /usr/lib/systemd/system, the sample at /etc/snitch/rules.toml,
# the binaries at their payload paths, the desktop entry, doc, overrides.
mkdir -p /tmp/expect
dpkg-deb --fsys-tarfile /deb.deb | tar -x -C /tmp/expect || die "the deb's members could not be extracted"
for f in \
	etc/snitch/rules.toml \
	usr/lib/systemd/system/snitchd.service \
	usr/lib/systemd/system/snitchd-trial-boot.service \
	usr/local/sbin/snitchd \
	usr/bin/snitch \
	usr/share/applications/snitch-tray.desktop \
	usr/share/doc/snitch/copyright \
	usr/share/doc/snitch/changelog.Debian.gz \
	usr/share/lintian/overrides/snitch
do
	[ -f "/tmp/expect/$f" ] || die "the deb ships no $f"
	[ -e "/$f" ] || die "/$f did not land on the fresh install"
	cmp -s "/tmp/expect/$f" "/$f" || die "/$f is not byte-equal to the deb's member"
done
test -x /usr/local/sbin/snitchd && test -x /usr/bin/snitch \
	|| die "a shipped binary lost its executable bit"

say "Status 'install ok installed', version $PKGVER; all 9 payload files byte-equal to the deb; binaries executable"
`

// smokeUnitVerifyScript is assertion group 3 (5.3's parse verification):
// systemd-analyze verify on both shipped units in the installed location -
// the distro's own systemd judging the package's units. The verifier's exit
// code is the verdict; any note it prints is evidence, not pass criteria.
const smokeUnitVerifyScript = `#!/usr/bin/env bash
set -uo pipefail
die() { echo "smoke: $DISTRO: 3 unit verify: FAIL: $*"; exit 1; }
say() { echo "smoke: $DISTRO: 3 unit verify: $*"; }
out=$(systemd-analyze verify /usr/lib/systemd/system/snitchd.service /usr/lib/systemd/system/snitchd-trial-boot.service 2>&1) || {
	echo "$out"
	die "$(echo "$out" | head -1)"
}
[ -z "$out" ] || say "verifier notes: $(echo "$out" | head -3)"
say "systemd-analyze verify: both shipped units clean"
`

// smokeTrialBootScript is assertion group 4 (5.3's headless-trial assert):
// the trial-boot oneshot needs no kernel objects, so it must fully run in the
// container - Result=success, ExecMainStatus=0 (the daemon's end -at-boot
// path, against the StateDirectory the unit itself provisions). The units
// landed on a booted system, so daemon-reload runs first - the same step an
// operator's deploy flow runs after placing units.
const smokeTrialBootScript = `#!/usr/bin/env bash
set -uo pipefail
die() { echo "smoke: $DISTRO: 4 trial-boot: FAIL: $*"; exit 1; }
say() { echo "smoke: $DISTRO: 4 trial-boot: $*"; }
systemctl daemon-reload || die "daemon-reload refused the installed units"
systemctl start snitchd-trial-boot.service || die "the oneshot did not start"
show=$(systemctl show snitchd-trial-boot.service -p Result -p ExecMainStatus)
echo "$show" | grep -qx "Result=success" || { echo "$show"; die "Result is not success"; }
echo "$show" | grep -qx "ExecMainStatus=0" || { echo "$show"; die "ExecMainStatus is not 0"; }
journalctl -u snitchd-trial-boot.service --no-pager -q | tail -3
say "the oneshot fully ran headless: Result=success, ExecMainStatus=0"
`

// smokeDaemonJournalScript is assertion group 5 (5.3's expected state of the
// real daemon on a headless container): snitchd.service starts, its daemon
// resolves the binary (systemd found ExecStart) and the rules (its own first
// startup step, whose mode line only prints when the rules parsed), then
// fails at the kernel step - the pinned-maps load, stopped by the /sys/fs/bpf
// tmpfs the sibling boots with, on every host the same way. The journal
// therefore must carry the pin-dir/load/attach failure signature and must
// not carry any missing-file error: a missing ExecStart binary or an absent
// rules file is a packaging error, not an environment limitation.
const smokeDaemonJournalScript = `#!/usr/bin/env bash
set -uo pipefail
die() { echo "smoke: $DISTRO: 5 daemon journal: FAIL: $*"; exit 1; }
say() { echo "smoke: $DISTRO: 5 daemon journal: $*"; }
systemctl start snitchd.service || true   # the daemon is expected to exit on the kernel step; the journal is the assert
sleep 6                                    # RestartSec=2: at least one full restart cycle leaves its signature
j=$(journalctl -u snitchd.service --no-pager -q)
[ -n "$j" ] || die "the journal holds nothing for snitchd.service"
sig=$(echo "$j" | grep -E "snitchd: (pin dir|load|attach):" | head -1) || die "no pin-dir/load/attach failure signature in the journal"
echo "$sig"
if echo "$j" | grep -iq "no such file"; then
	echo "$j" | grep -i "no such file" | head -3
	die "the journal carries a missing-file error - a packaging error, not a kernel limitation"
fi
echo "$j" | grep -q "snitchd: mode: monitor (" || die "the daemon never reached its mode decision - the rules never loaded"
systemctl stop snitchd.service 2>/dev/null || true   # stop the restart churn; the signature stays recorded in the journal
say "signature present with no missing-file error; rules parsed (mode decided) before the kernel step"
`

// smokeInstalledCheckScript is assertion group 6 (4.3's fresh-install start
// condition proven as far as headless allows): the installed daemon's own
// rules check over the installed sample path must exit 0. The check prints
// one unresolvable-path line per program this container does not have - the
// daemon's documented tolerated state, mapped not enforced (the same output
// the deb assembly accepted when it proved the sample before packing it).
const smokeInstalledCheckScript = `#!/usr/bin/env bash
set -uo pipefail
die() { echo "smoke: $DISTRO: 6 installed check: FAIL: $*"; exit 1; }
say() { echo "smoke: $DISTRO: 6 installed check: $*"; }
out=$(/usr/local/sbin/snitchd check -rules /etc/snitch/rules.toml 2>&1) || {
	rc=$?
	echo "$out"
	die "snitchd check exited $rc"
}
[ -n "$out" ] && echo "$out" | tail -3
say "snitchd check -rules /etc/snitch/rules.toml: exit 0 on the installed sample"
`

// smokeTrayVersionScript is assertion group 7 (4.4, 5.3): the tray binary
// the deskop entry's Exec= and every operator shell must resolve does
// resolve from PATH, and it answers the version it was linked with - the
// same assertion every build function runs, here against the installed
// package's own binary instead of the build's output.
const smokeTrayVersionScript = `#!/usr/bin/env bash
set -uo pipefail
die() { echo "smoke: $DISTRO: 7 tray -version: FAIL: $*"; exit 1; }
say() { echo "smoke: $DISTRO: 7 tray -version: $*"; }
p=$(command -v snitch) || die "snitch does not resolve from PATH"
v=$(snitch -version) || die "snitch -version exited non-zero"
[ "$v" = "v$PKGVER" ] || die "snitch -version answered '$v', expected 'v$PKGVER'"
say "resolved from PATH at $p; answers $v"
`

// smokeTrayHeadlessScript is assertion group 8 (5.3's tray exercise "as far
// as a headless container allows"): the INSTALLED tray binary - /usr/bin/snitch
// the deb just unpacked - against the pipeline-built stand-in, on a private
// session bus the wrapper owns, driven by the repo's own tray-check harness in
// its --headless pulse. The tray is a per-user program (at the desktop it is
// the operator, never root, and the harness refuses root itself), so the
// sibling runs it as a plain user like the desktop would; the harness's own
// step lines are the evidence, its exit code the verdict.
const smokeTrayHeadlessScript = `#!/usr/bin/env bash
set -uo pipefail
die() { echo "smoke: $DISTRO: 8 tray headless: FAIL: $*"; exit 1; }
say() { echo "smoke: $DISTRO: 8 tray headless: $*"; }
id -u tray >/dev/null 2>&1 || useradd -m tray || die "the tray user could not be created"
# dbus-run-session brings up a private bus for the harness alone; the installed
# tray reaches it through the session address, busctl (the systemd package's)
# through the same, and the stand-in serves its socket in the harness's own
# temp dir - nothing of this touches the system bus or the host.
if su - tray -c 'exec dbus-run-session -- bash /smoke/tray-check.sh --bin /usr/bin/snitch --fake /smoke/fakedaemon --headless'; then
	say "the installed tray registered its item, presented its states, and exited 0 under SIGTERM"
else
	rc=$?
	die "the headless tray exercise exited $rc (the A-numbered step lines above carry the evidence)"
fi
`

// Smoke is the deb's in-container proof on one contract distro (R5.3): the
// same deb the release publishes, installed and driven inside the distro's
// own userspace, systemd as PID 1 included, every assertion group named in
// the log and every failure exiting non-zero naming its group. The deb comes
// from the module's own assembly - Smoke runs Deb inside, whose DistroProof
// gates it (clean tree, tag on HEAD) and whose forky-built binaries the proof
// checksummed, so the smoke can only ever exercise the one deb this commit
// and tag produce; the engine caches that whole chain, so a Deb that just
// ran (or just ran in another distro's smoke) is free. Not a +check: the
// answer is a verdict, but a verdict that runs minutes of containers per
// distro on every `dagger check` would make the seven-check lint contract a
// lie by performance - the smoke is invoked when a release asks for it.
func (c *Snitch) Smoke(
	ctx context.Context,
	// The repository root: the checkout Deb's guards assert and the assembly
	// consumes verbatim.
	// +defaultPath="/"
	source *dagger.Directory,
	// The distro whose smoke runs; selects the image pin for both the driver
	// and the sibling systemd container.
	distro Distro,
	// The release tag in its `v`-prefixed form (e.g. v0.4.0): Deb's contract,
	// and the version the fresh-install and PATH assertions compare against.
	version string,
	// The host docker daemon's unix socket (e.g. /var/run/docker.sock on the
	// GHA runner and on a docker-ce workstation). The sibling smoke containers
	// are real systemd containers; provisioning them through the host daemon is
	// the one way that runs identically in CI and locally.
	dockerSocket *dagger.Socket,
) error {
	if version == "" {
		fmt.Printf("smoke: %s: version: FAIL\n", distro)
		return fmt.Errorf("smoke: %s: version: the release tag is required (e.g. v0.4.0)", distro)
	}
	image, err := distroImage(distro)
	if err != nil {
		fmt.Printf("smoke: %s: distro: FAIL\n", distro)
		return fmt.Errorf("smoke: %s: %w", distro, err)
	}
	// The one deb this commit and tag can produce, from the same module the
	// release runs: DistroProof inside Deb refuses anything else, so the
	// smoke and the published asset cannot diverge (5.5's single-deb rule).
	deb, err := c.Deb(ctx, source, version)
	if err != nil {
		fmt.Printf("smoke: %s: deb: FAIL\n", distro)
		return fmt.Errorf("smoke: %s: deb: %w", distro, err)
	}
	fmt.Printf("smoke: %s: deb\n", distro)
	return c.smokeDistro(ctx, distro, image, deb, fakeDaemon(source), source.File("scripts/tray-check.sh"), version, dockerSocket)
}

// DebRelease is the release job's one command (ci-debs task 6.5, R5.5, the
// design's `dagger call deb-release` dispatch): the whole deb lane in one
// invocation - the proof, the assembly, the smoke on both contract distros
// (lintian inside each) - answering with the one artifact set the release
// publishes: the deb and its bare-filename sha256 sidecar. ONE Deb call
// produces the deb this invocation regards: its DistroProof gates the source
// (clean tree, tag on HEAD) and caches, and the same deb directory passes to
// both distros' smokes, so no invocation can ever mix binaries from two
// commits or two tags (5.5's single-published-deb rule holds inside the
// pipeline, not just across it). Not a +check, for the same reason as Deb
// itself: the answer is the artifact, the seven-check lint contract keeps
// its shape, and a release asks for this gate by name when it wants it.
func (c *Snitch) DebRelease(
	ctx context.Context,
	// The repository root: the checkout whose guards the proof asserts and
	// whose packaging inputs the assembly consumes verbatim.
	// +defaultPath="/"
	source *dagger.Directory,
	// The release tag in its `v`-prefixed form (e.g. v0.4.0): ReleaseBuild's
	// and Deb's contract - a tag on HEAD, no default, because a defaulted one
	// would defeat the guard behind it.
	version string,
	// The host docker daemon's unix socket (e.g. /var/run/docker.sock): the
	// smokes' siblings are real systemd containers provisioned through the
	// host daemon, identically in CI and locally.
	dockerSocket *dagger.Socket,
) (*dagger.Directory, error) {
	if version == "" {
		fmt.Println("deb-release: version: FAIL")
		return nil, fmt.Errorf("deb-release: version: the release tag is required (e.g. v0.4.0)")
	}
	// The one deb this invocation touches: Deb runs the proof inside (both
	// distros build, the lists agree or the assembly never starts), prints
	// the whole chain's own step lines, and returns the exact directory the
	// smokes below exercise and the caller exports.
	deb, err := c.Deb(ctx, source, version)
	if err != nil {
		fmt.Println("deb-release: deb: FAIL")
		return nil, fmt.Errorf("deb-release: deb: %w", err)
	}
	fmt.Println("deb-release: deb")
	// The tray exercise's props, built once for both smokes (the same cached
	// build either side would reach for).
	fake := fakeDaemon(source)
	trayCheck := source.File("scripts/tray-check.sh")
	// Both contract distros, the design's diagram order (ubuntu, then
	// forky). Each smoke prints its own group lines and PASS verdict; the
	// composite names the distro that failed and publishes nothing - the
	// caller's --output never runs at all.
	for _, distro := range []Distro{DistroUbuntu2604, DistroDebianForky} {
		image, err := distroImage(distro)
		if err != nil {
			fmt.Printf("deb-release: smoke %s: FAIL\n", distro)
			return nil, fmt.Errorf("deb-release: smoke %s: %w", distro, err)
		}
		if err := c.smokeDistro(ctx, distro, image, deb, fake, trayCheck, version, dockerSocket); err != nil {
			fmt.Printf("deb-release: smoke %s: FAIL\n", distro)
			return nil, fmt.Errorf("deb-release: smoke %s: %w", distro, err)
		}
		fmt.Printf("deb-release: smoke %s\n", distro)
	}
	fmt.Println("deb-release: PASS")
	// The deb and its sidecar, unchanged: the same directory Deb answered
	// with, so the release publishes what the smokes proved.
	return deb, nil
}

// smokeDistro runs one distro's smoke in the driver container: the socket
// probe, then the driver script (sibling boot, staging, the assertion
// groups), then the smoke log printed verbatim - the pass lines carry the
// run's own evidence (the preserved sha, the payload comparison, and later
// the trial-boot Result and the journal signature), succeed or fail.
func (c *Snitch) smokeDistro(
	ctx context.Context,
	distro Distro,
	image string,
	deb *dagger.Directory,
	fake *dagger.File,
	trayCheck *dagger.File,
	version string,
	dockerSocket *dagger.Socket,
) error {
	ctr := smokeContainer(distro, image, version, deb, fake, trayCheck, dockerSocket)

	// The socket probe: the daemon behind the argument must answer before any
	// of the smoke's work runs - a wrong socket is the smoke's infrastructure
	// error, named here, not a group failure.
	server, err := ctr.WithExec([]string{"docker", "version", "--format", "{{.Server.Version}}"}).Stdout(ctx)
	if err != nil {
		fmt.Printf("smoke: %s: docker socket: FAIL\n", distro)
		return fmt.Errorf("smoke: %s: docker socket: the daemon behind the argument did not answer: %w", distro, err)
	}
	fmt.Printf("smoke: %s: docker socket: daemon %s\n", distro, strings.TrimSpace(server))

	// The smoke itself. The driver script tees its whole transcript into
	// /smoke/smoke.log, so the run's evidence can be printed verbatim from
	// either path; on failure the failing group's own line is in it.
	ctr = ctr.WithExec([]string{"bash", "/smoke/run.sh"})
	if err := c.smokeLog(ctx, ctr, distro); err != nil {
		return err
	}
	fmt.Printf("smoke: %s: PASS\n", distro)
	return nil
}

// smokeLog syncs the smoke exec and prints the transcript the driver left
// behind, wrapping the engine's error on failure (the transcript names the
// failing group; the engine error carries the exit).
func (c *Snitch) smokeLog(ctx context.Context, ctr *dagger.Container, distro Distro) error {
	if _, err := ctr.Sync(ctx); err != nil {
		if log, lerr := ctr.File("/smoke/smoke.log").Contents(ctx); lerr == nil {
			fmt.Print(log)
		}
		fmt.Printf("smoke: %s: FAIL\n", distro)
		return fmt.Errorf("smoke: %s: the smoke run exited non-zero: %w", distro, err)
	}
	if log, lerr := ctr.File("/smoke/smoke.log").Contents(ctx); lerr == nil {
		fmt.Print(log)
	} else {
		fmt.Printf("smoke: %s: FAIL\n", distro)
		return fmt.Errorf("smoke: %s: the smoke transcript was not written: %w", distro, lerr)
	}
	return nil
}

// smokeContainer is the driver environment: the distro's own base image (the
// driver IS the distro - its apt, its tar, its diffutils - and lintian runs
// here for the same reason, R5.4's per-distro policy tags judged by the
// distro's own lintian), the TLS trust store and curl for the one download
// (the pinned static docker CLI, sha-verified exactly like the go tarball:
// the CLI is a transport to the host daemon, pinned per version because it is
// not the distro under test - the driver's docker.sock talks to whatever
// daemon the host provides). The deb mounts under /deb together with the
// group scripts, and the socket mounts where the docker CLI expects it. The
// driver runs as root on purpose: it reads no git (no guards run here - Deb's
// proof already ran), so the runner-uid pattern has nothing to own.
func smokeContainer(distro Distro, image, version string, deb *dagger.Directory, fake *dagger.File, trayCheck *dagger.File, dockerSocket *dagger.Socket) *dagger.Container {
	return dag.Container().
		From(image).
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{"apt-get", "install", "-y", "--no-install-recommends", aptCaCertificates, aptCurl, aptLintian}).
		WithExec([]string{"sh", "-c",
			"curl -fsSL -o /tmp/docker.tgz " + dockerCLIURL + " && " +
				"echo '" + dockerCLISHA256 + "  /tmp/docker.tgz' | sha256sum -c - && " +
				"tar -C /usr/local/bin --strip-components=1 -xzf /tmp/docker.tgz docker/docker && " +
				"rm /tmp/docker.tgz && docker --version"}).
		WithEnvVariable("DISTRO", string(distro)).
		WithEnvVariable("IMAGE", image).
		WithEnvVariable("DEBFILE", "snitch_"+strings.TrimPrefix(version, "v")+"_amd64.deb").
		WithEnvVariable("PKGVER", strings.TrimPrefix(version, "v")).
		WithEnvVariable("DOCKER_HOST", "unix:///var/run/docker.sock").
		WithUnixSocket("/var/run/docker.sock", dockerSocket).
		WithMountedDirectory("/deb", deb).
		WithMountedFile("/smoke/fakedaemon", fake).
		WithMountedFile("/smoke/tray-check.sh", trayCheck).
		WithNewFile("/smoke/run.sh", smokeDriverScript).
		WithNewFile("/smoke/groups/1-conffile-keep.sh", smokeConffileKeepScript).
		WithNewFile("/smoke/groups/2-fresh-install.sh", smokeFreshInstallScript).
		WithNewFile("/smoke/groups/3-unit-verify.sh", smokeUnitVerifyScript).
		WithNewFile("/smoke/groups/4-trial-boot.sh", smokeTrialBootScript).
		WithNewFile("/smoke/groups/5-daemon-journal.sh", smokeDaemonJournalScript).
		WithNewFile("/smoke/groups/6-installed-check.sh", smokeInstalledCheckScript).
		WithNewFile("/smoke/groups/7-tray-version.sh", smokeTrayVersionScript).
		WithNewFile("/smoke/groups/8-tray-headless.sh", smokeTrayHeadlessScript)
}

// fakeDaemon builds the tray exercise's stand-in: the harness's own build
// line (`go build -o ... ./tools/fakedaemon`, the line tray-check.sh runs at
// the desktop) in the checks' pinned golang:1.26.8 container, whose Go caches
// the module already keeps warm. The binary is a pipeline tool and ships
// nowhere - never in the deb, never exported - it exists so the installed
// tray has something honest to talk to: the stand-in serves the daemon's API
// on a private socket and answers the commands the harness types at it.
func fakeDaemon(source *dagger.Directory) *dagger.File {
	return releaseBuildContainer(source).
		WithExec([]string{"go", "build", "-o", "/tmp/fakedaemon", "./tools/fakedaemon"}).
		File("/tmp/fakedaemon")
}
