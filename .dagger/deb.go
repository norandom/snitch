// The deb assembly (ci-debs task 5.4): the package as one function on the
// facade. The answer an artifact-producing phase gives is the artifact, so
// `deb` returns the directory holding `snitch_<version>_amd64.deb` and its
// bare-filename sha256 sidecar (the caller's --output), never a verdict;
// `dagger check` keeps exactly the eight checks of the lint contract, which
// is why this is a plain function and not a +check. The binary source is
// DistroProof's own return - the forky dist the proof just verified
// checksum-for-checksum - so the package can only ever pack the
// distro-identical pair the proof vouched for, and engine caching makes
// running the proof inside the assembly free after a standalone one.
package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/snitch/internal/dagger"
)

// debTreeScript assembles the package tree exactly per design.md's payload
// table and normalizes it. Every property in it is the design's
// reproducibility recipe (7.2), each one source- or probe-verified before
// this file was written; the script runs with the assembled values riding
// the container's environment (DEB_VERSION, SOURCE_DATE_EPOCH), never
// interpolated into the text - a tag-shaped string stays data in every
// field, filename, sed replacement and shell word it touches.
const debTreeScript = `set -e
umask 022

# The tree, one path per the payload table, every mode explicit: dpkg-deb
# does not normalize modes (research probe - a umask leak ships as a
# permission bit), so 022 plus install -m is the recipe, not a habit.
install -d -m 0755 \
	/pkg/DEBIAN \
	/pkg/usr/local/sbin \
	/pkg/usr/bin \
	/pkg/usr/lib/snitch \
	/pkg/usr/lib/systemd/system \
	/pkg/usr/share/applications \
	/pkg/etc/default/grub.d \
	/pkg/etc/snitch \
	/pkg/usr/share/doc/snitch \
	/pkg/usr/share/lintian/overrides

# The binaries the proof covered, nothing else: snitchd at the frozen unit
# contract path both shipped units name in ExecStart, the tray where the
# desktop entry's Exec= and every PATH resolve it.
install -m 0755 /dist/snitchd /pkg/usr/local/sbin/snitchd
install -m 0755 /dist/snitch-linux-amd64 /pkg/usr/bin/snitch

# The repository's own files, shipped byte-identical (the payload table's
# source column): units unpacked and never enabled by the package, the
# desktop entry where sessions resolve it, the GRUB drop-in and its helper,
# the verified sample as the conffile payload, the license where policy puts
# it, and the overrides record with its written justifications.
install -m 0644 /src/systemd/snitchd.service /pkg/usr/lib/systemd/system/snitchd.service
install -m 0644 /src/systemd/snitchd-trial-boot.service /pkg/usr/lib/systemd/system/snitchd-trial-boot.service
install -m 0644 /src/desktop/snitch-tray.desktop /pkg/usr/share/applications/snitch-tray.desktop
install -m 0644 /src/packaging/grub-snitch-lsm.cfg /pkg/etc/default/grub.d/snitch-lsm.cfg
install -m 0755 /src/packaging/lsm-cmdline.sh /pkg/usr/lib/snitch/lsm-cmdline
install -m 0644 /src/examples/rules.toml /pkg/etc/snitch/rules.toml
install -m 0644 /src/LICENSE /pkg/usr/share/doc/snitch/copyright
install -m 0644 /src/packaging/lintian-overrides /pkg/usr/share/lintian/overrides/snitch

# changelog.Debian: the one generated file. A function of the version and
# the epoch's deterministic date and nothing else - no builder clock
# anywhere. gzip -9n: -n stores no original name and no timestamp, the two
# gzip header fields that would otherwise differ between clean rooms. The
# date runs under LC_ALL=C so its month and weekday spellings are the C
# locale's, not the builder's environment - the same pin the md5sums sort
# below carries; the changelog's bytes stay a function of the epoch alone.
# The maintainer line is packaging/control's Maintainer verbatim.
{
	printf 'snitch (%s) unstable; urgency=medium\n\n' "$DEB_VERSION"
	printf '  * Built from the release tag by the ci-debs pipeline; the binaries\n'
	printf '    are the distro-proofed pair, byte-identical from the Ubuntu 26.04\n'
	printf '    and Debian forky build containers.\n'
	printf '\n -- %s  %s\n' 'Marius Ciepluch <wishinet@gmail.com>' "$(LC_ALL=C date -u -R -d "@$SOURCE_DATE_EPOCH")"
} > /pkg/usr/share/doc/snitch/changelog.Debian
gzip -9n -c /pkg/usr/share/doc/snitch/changelog.Debian > /pkg/usr/share/doc/snitch/changelog.Debian.gz
rm /pkg/usr/share/doc/snitch/changelog.Debian
chmod 0644 /pkg/usr/share/doc/snitch/changelog.Debian.gz

# DEBIAN/control: the committed packaging/control with Version and
# Installed-Size injected - the two fields the payload table marks
# build-computed. Installed-Size sums the payload st_size and rounds up to
# KiB: content bytes, never block counts, which vary with the builder's
# filesystem and would leak the builder into the control file.
KIB=$(find /pkg/usr /pkg/etc -type f -printf '%s\n' | awk '{s+=$1} END {printf "%d", (s+1023)/1024}')
sed -e "s|^Version:.*|Version: $DEB_VERSION|" \
	-e "s|^Installed-Size:.*|Installed-Size: $KIB|" \
	/src/packaging/control > /pkg/DEBIAN/control
chmod 0644 /pkg/DEBIAN/control
install -m 0644 /src/packaging/conffiles /pkg/DEBIAN/conffiles
install -m 0755 /src/packaging/postinst.sh /pkg/DEBIAN/postinst
install -m 0755 /src/packaging/postrm.sh /pkg/DEBIAN/postrm

# DEBIAN/md5sums: every payload file, the conffile included per modern dpkg
# convention, one canonical order (LC_ALL=C sort over null-separated
# names), paths relative to the package root with no ./ prefix - the form
# dpkg's own verification reads. Enumerating etc and usr excludes the
# DEBIAN/ members, as the table's "shipped files" scope requires.
cd /pkg
find etc usr -type f -print0 | LC_ALL=C sort -z | xargs -0 md5sum > DEBIAN/md5sums
chmod 0644 DEBIAN/md5sums

# Every mtime set exactly to the epoch, after assembly: SOURCE_DATE_EPOCH
# clamps newer mtimes but preserves older ones (research's probe), so a
# recipe that only exported the variable could ship whatever predated the
# commit; the touch is what makes the tree a function of the commit alone.
find /pkg -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
`

// The reproducibility record (7.2): the deb's sha256 is a function of these
// properties and nothing else - each is pinned where it lives, so a rebuild
// that holds them fixed can only rebuild the same bytes.
//
//   - the commit: DistroProof's guards (clean tree, tag on HEAD) refuse
//     everything else, and the preserved VCS stamp carries the commit into
//     both binaries; the proof's printed checksums are the binaries'
//     identity for that commit and reach the deb as its only binaries
//   - SOURCE_DATE_EPOCH: HEAD's committer timestamp, read from the owned
//     .git at assembly time; it sets every tree mtime exactly (the script's
//     touch) and dpkg-deb's archive member stamps
//   - the version: the tag with its leading `v` stripped, charset-guarded;
//     it names the deb, the sidecar, the control field and the changelog
//   - the builder: debian:forky (pins.go's imageDebian), whose dpkg-deb
//     1.23.11 the run's build line records; member ordering and ar headers
//     are dpkg-deb's deterministic path (dpkg >= 1.18.5)
//   - compression: -Znone - no compressor version anywhere near the
//     archive's bytes; gzip -9n touches only the changelog's own content,
//     with no stored name and no stored timestamp
//   - ownership and modes: --root-owner-group, umask 022, explicit install
//     -m everywhere - dpkg-deb normalizes neither, so both are the recipe's
//     to pin
//   - file lists: DEBIAN/md5sums' LC_ALL=C sorted enumeration, the
//     Installed-Size st_size sum, and the changelog's LC_ALL=C date - all
//     content-derived, never builder-environment-derived
//
// The clean-room rebuild (two invocations with cold engine state between
// them, holding these properties fixed) is the 7.2 evidence: identical
// sha256s or the recipe is wrong somewhere on this list.

// Deb assembles `snitch_<version>_amd64.deb` (requirements 4.1-4.6, 7.2):
// the distro-proofed forky binaries packaged together with the repository's
// units, desktop entry and verified sample, in the pinned debian:forky
// builder, deterministically. The flow is guards-first like every build
// function here: DistroProof runs inside and refuses (clean tree, tag on
// HEAD) before any packaging work - the assembly is only ever one step of
// the same proven chain that links the binaries.
func (c *Snitch) Deb(
	ctx context.Context,
	// The repository root: the checkout whose guards DistroProof asserts,
	// whose packaging/ inputs, units, desktop entry, license and sample
	// the tree packs verbatim, and whose owned .git the epoch reads.
	// +defaultPath="/"
	source *dagger.Directory,
	// The release tag in its `v`-prefixed form (e.g. v0.4.0): the same
	// contract ReleaseBuild and DistroProof take - a tag on HEAD, no
	// default, because every honest invocation knows its tag and a
	// defaulted one would defeat the guard behind it.
	version string,
) (*dagger.Directory, error) {
	// An empty version would name a package for nothing; the same refusal
	// as the other build functions, by name, before any work runs.
	if version == "" {
		fmt.Println("deb: version: FAIL")
		return nil, fmt.Errorf("deb: version: the release tag is required (e.g. v0.4.0)")
	}
	// The package version: the tag stripped of its leading `v` (design's
	// 4.1 derivation: v0.4.0 → 0.4.0). Debian versions are a closed
	// charset - digits, letters, . + - ~ - and this string lands in a
	// control field, a filename, the changelog and a sed replacement; a
	// tag outside it would assemble a broken package from valid pieces
	// instead of failing, so it is refused here in the guards' style.
	pkgVersion := strings.TrimPrefix(version, "v")
	if pkgVersion == "" || strings.IndexFunc(pkgVersion, badDebVersionChar) >= 0 {
		fmt.Println("deb: version: FAIL")
		return nil, fmt.Errorf("deb: version: %q is not a package version (a v-prefixed tag of digits, letters, dots, and -+~)", version)
	}

	// The binary source is the proof itself (the design pins the deb to
	// the forky builder's dpkg-deb, which reaches exactly this directory
	// through DistroProof's return): both distros build, the lists agree
	// or the whole assembly never starts, and the forky dist - the very
	// binaries the comparison covered - is what the tree packs. Any
	// refusal inside the proof is the deb's binary-source failure.
	dist, err := c.DistroProof(ctx, source, version)
	if err != nil {
		fmt.Println("deb: binary-source: FAIL")
		return nil, fmt.Errorf("deb: binary-source: %w", err)
	}
	fmt.Println("deb: binary-source")

	// The assembly state: the pinned builder, the owned source and proof
	// mounts, and the values the recipe reads as environment variables.
	ctr := debContainer(source, dist).
		WithEnvVariable("DEB_VERSION", pkgVersion)

	// The sample this package ships as a conffile, proven by the daemon's
	// own root-less check before it is packed: the forky-built snitchd the
	// proof just produced runs `check` against the repo file the tree
	// installs at /etc/snitch/rules.toml. The check exits 0 on a valid
	// file while still printing one `unresolved:` line per path pattern
	// with no executable on this container - the daemon's own tolerated
	// state (it maps what exists and starts), so exit status alone is
	// the verdict, and the output prints as the run's evidence.
	sample, err := ctr.
		WithExec([]string{"/dist/snitchd", "check", "-rules", "examples/rules.toml"}).
		Stdout(ctx)
	if err != nil {
		fmt.Println("deb: sample check: FAIL")
		return nil, fmt.Errorf("deb: sample check: %w", err)
	}
	fmt.Print(sample)
	fmt.Println("deb: sample check")

	// The epoch: SOURCE_DATE_EPOCH is the HEAD commit's timestamp (`git
	// log -1 --pretty=%ct`), read from the owned .git mount by the running
	// uid - the guards pattern, because git refuses a repository owned by
	// another uid. The same source that satisfied the tag guard makes this
	// the same number both doors compute for the same commit. The epoch
	// belongs to the tree step (it is a tree property before dpkg-deb
	// ever sees it), so its refusal is the tree's.
	epoch, err := ctr.WithExec([]string{"git", "-C", "/src", "log", "-1", "--pretty=%ct"}).Stdout(ctx)
	if err != nil {
		fmt.Println("deb: tree: FAIL")
		return nil, fmt.Errorf("deb: tree: %w", err)
	}
	sde := strings.TrimSpace(epoch)
	if sde == "" {
		fmt.Println("deb: tree: FAIL")
		return nil, fmt.Errorf("deb: tree: SOURCE_DATE_EPOCH: %s holds no commit time", version)
	}
	ctr = ctr.WithEnvVariable("SOURCE_DATE_EPOCH", sde)

	// The tree itself, exactly the payload table: binaries from the proof's
	// dist, repository files byte-identical, generated control/changelog/
	// md5sums, every mode explicit, every mtime set to the epoch. The
	// script's own comments carry the recipe's per-property reasons.
	ctr = ctr.WithExec([]string{"sh", "-c", debTreeScript})
	if _, err := ctr.Sync(ctx); err != nil {
		fmt.Println("deb: tree: FAIL")
		return nil, fmt.Errorf("deb: tree: %w", err)
	}
	fmt.Printf("deb: tree: SOURCE_DATE_EPOCH %s\n", sde)

	// The pinned builder's identity is 7.2 evidence, so the dpkg-deb that
	// builds steps forward and names itself (the golang image's Go did the
	// same in DistroBuild). Everything that can vary a byte is pinned by
	// now; dpkg-deb's own ordering and ar headers have been deterministic
	// since 1.18.x, which is why the version line is evidence and not a
	// variable to control.
	builder, err := ctr.WithExec([]string{"sh", "-c", "dpkg-deb --version | head -n 1"}).Stdout(ctx)
	if err != nil {
		fmt.Println("deb: build: FAIL")
		return nil, fmt.Errorf("deb: build: %w", err)
	}

	// The build itself, the design's exact flag set: --root-owner-group so
	// the builder's uid/gid cannot leak into the archive, -Znone so
	// compression is removed entirely rather than made uniform (the
	// liblzma 5.8.3/5.8.4 skew between the distros would otherwise make
	// "the same bytes" depend on which distro packed them),
	// --uniform-compression so all members follow the one setting, and
	// an explicit archive path so the deb's name is a function of the
	// version, not of the directory the tree happened to sit in.
	debFile := "snitch_" + pkgVersion + "_amd64.deb"
	ctr = ctr.WithExec([]string{
		"dpkg-deb", "--root-owner-group", "--uniform-compression",
		"-Znone", "--build", "/pkg", "/out/" + debFile,
	})
	if _, err := ctr.Sync(ctx); err != nil {
		fmt.Println("deb: build: FAIL")
		return nil, fmt.Errorf("deb: build: %w", err)
	}
	fmt.Printf("deb: build: %s\n", strings.TrimSpace(builder))

	// The sidecar, written beside the deb so it carries the bare filename
	// - `sha256sum -c` form, the shape release assets use (pins.go's
	// release-asset note). The checksum lines print as the run's own
	// evidence, like every build function's proof of what it produced.
	ctr = ctr.WithExec([]string{"sh", "-c",
		"cd /out && sha256sum " + debFile + " > " + debFile + ".sha256"})
	if _, err := ctr.Sync(ctx); err != nil {
		fmt.Println("deb: sha256: FAIL")
		return nil, fmt.Errorf("deb: sha256: %w", err)
	}
	out := ctr.Directory("/out")
	sum, err := out.File(debFile + ".sha256").Contents(ctx)
	if err != nil {
		fmt.Println("deb: sha256: FAIL")
		return nil, fmt.Errorf("deb: sha256: %w", err)
	}
	fmt.Print(sum)
	fmt.Println("deb: sha256")
	fmt.Println("deb: PASS")
	// /out holds exactly the deb and its sidecar; the caller's --output
	// decides where they land, never the source tree on the host.
	return out, nil
}

// badDebVersionChar reports whether a rune cannot appear in the package
// version: deb versions admit digits, letters and . + - ~ (a leading colon
// would become an epoch marker, whitespace and shell metacharacters would
// not survive the fields, the filename or the sed replacements that carry
// the version), so the guard refuses any tag outside it loudly instead of
// letting the assembly build a package no dpkg would trust.
func badDebVersionChar(r rune) bool {
	switch {
	case r >= '0' && r <= '9':
		return false
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z':
		return false
	case r == '.' || r == '+' || r == '-' || r == '~':
		return false
	}
	return true
}

// debContainer is the assembly environment: debian:forky (pins.go's
// imageDebian) - the pinned 7.2 builder, dpkg-deb 1.23.11, whose version
// the run records - with the one piece of scaffolding the bare base lacks:
// git, because SOURCE_DATE_EPOCH reads the mounted repository's history
// and the golang image's git is not there (distroBuildContainer's aptGit
// reason, without curl: nothing here fetches, the binaries arrive as the
// proof's directory, not a download). The runner-uid pattern again: uid
// 1001, name runner, and the owned /src mount is load-bearing exactly as
// it is for the build guards - git refuses to read a repository owned by
// another uid, so the owned mount is what lets the epoch read the checkout
// the same way every stamp and guard before it did. /pkg and /out are
// pre-created 0755 and handed to the runner, so assembly writes need no
// root anywhere: --root-owner-group pins the archive's ownership anyway,
// and keeping the whole chain one uid means file ownership inside the
// builder is byte-irrelevant, not just archive-irrelevant.
func debContainer(source, dist *dagger.Directory) *dagger.Container {
	return dag.Container().
		From(imageDebian).
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{"apt-get", "install", "-y", "--no-install-recommends", aptGit}).
		WithExec([]string{"useradd", "-m", "-u", "1001", "runner"}).
		WithExec([]string{"install", "-d", "-m", "0755", "-o", "1001", "-g", "1001", "/pkg", "/out"}).
		WithUser("runner").
		WithEnvVariable("HOME", "/home/runner").
		WithMountedDirectory("/src", source, dagger.ContainerWithMountedDirectoryOpts{Owner: "1001:1001"}).
		WithMountedDirectory("/dist", dist, dagger.ContainerWithMountedDirectoryOpts{Owner: "1001:1001"}).
		WithWorkdir("/src")
}
