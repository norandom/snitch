// The pin registry: every container image, tool version and versioned input
// the pipeline resolves, decided in one file (ci-debs design, task 1). A pin
// changes by editing this file and nothing else; an upstream move (rebuild,
// retag, apt upload) then surfaces as a pipeline failure at its first
// consumer, which is the reviewable moment. Each value below was verified at
// its source when first pinned; the comments record where and when.
package main

const (
	// The pipeline engine, one version everywhere. dagger.json pins the same
	// version ("engineVersion": "v0.21.12"); this value also feeds the
	// `version` input of the dispatch action, whose docs require the form
	// `vX.Y.Z or 'latest'` ("latest" would drift the engine between runs, so
	// the exact release tag is the only acceptable value here).
	daggerVersion = "v0.21.12"

	// The thin dispatcher the lint and release workflows use to call this
	// module. Pinned by release tag like every action in this repo
	// (checkout@v4, setup-go@v5, setup-uv@v10.2.0, codeql-action@v4);
	// latest release of github.com/dagger/dagger-for-github is v8.4.1
	// (2026-03-17, checked in its releases list). Its action contract moves
	// with Dagger: revalidate this pin on any Dagger major/minor bump
	// (ci-debs design, Revalidation Triggers).
	daggerGitHubAction = "dagger/dagger-for-github@v8.4.1"
)

const (
	// Today's checks container: the Go of go.mod's floor exactly (1.26.8, what
	// setup-go go-version-file installs in lint.yml), so the fmt/go/caps
	// container checks with the same toolchain that builds the release
	// binaries. Checks would otherwise differ from builds by a patch release
	// on a moving tag.
	imageGoChecks = "golang:1.26.8"

	// The distro-proof pair: both sides of the release contract get a native
	// build plus an install of the deb in their own userspace. These suite
	// aliases are rolling tags (their digests move with every base rebuild);
	// the design pins them by name deliberately — the distro is the variable
	// under test, and a rebuild is expected input, not a broken pin.
	imageUbuntu = "ubuntu:26.04"

	// Debian "forky" is the Debian 14 (trixie successor) suite alias, the
	// current development distro of this project's workstation.
	imageDebian = "debian:forky"

	// The bindings check's base (c-hardening 7.1): the same forky, but by
	// digest, because here the bytes are the subject, not the distro. The
	// committed internal/bpf/ objects are tied to clang 21.1.8-13 and libbpf
	// 1.7.0-1 as this image's apt resolved them: regenerated in it and
	// cmp-identical to the committed files (c-hardening research,
	// "Regeneration procedure (task 1.1)", 2026-11-25; again for 7.1 the same
	// day, and through the dated snapshot below). imageDebian above stays a
	// rolling tag on purpose for the distro-proof lanes. This value must equal
	// IMAGE in scripts/bindings-regen.sh (the bindings check enforces it); the
	// package versions, the snapshot.debian.org timestamp (20261123T000000Z,
	// the one this image was built from) and the expected `clang --version`
	// line live only in that script, the single source the check and a
	// maintainer's --docker run both read, so none of them is repeated here.
	imageBindings = "debian@sha256:f3671d5a279b1ae356c7318ce6cdb84c600c2063d708ee97d3cce607bebfb85a"

	// The Go linter layer. The official image is rebuilt when the Go it was
	// built against changes (upstream builds it FROM golang:1.27 with
	// GOTOOLCHAIN auto), so a tag alone does not freeze the bytes: the digest
	// pins the image this pipeline actually runs. Digest of the v2.15.0 tag
	// from Docker Hub (registry API, looked up 2026-11-24). The alternative
	// v2.15.0-alpine tag carries digest sha256:2ba875b990f1d8501ad4ec19be1ea
	// 0701e316ec3a4b764f7b129f62f01318bbf if a smaller image ever wins; the
	// default variant is what the design chose (golangci's documented form
	// stays nearest to the Go it lints for).
	imageGolangciLint = "golangci/golangci-lint:v2.15.0@sha256:fbfcfd12a6f8d7f1b97b3362ca80fc2a244d46863148c73cb88e7793af96c481"

	// The shell layer. Current stable upstream release v0.11.0 (2025-08-04,
	// the newest tag on Docker Hub and the newest GitHub release at
	// 2026-11-24). Pinned by explicit version tag per the design — never the
	// mutable `stable`/`latest` tags, which koalaman retargets without a
	// release.
	imageShellcheck = "koalaman/shellcheck:v0.11.0"

	// The uv-providing image: both Python-ish checks resolve their tools with
	// uvx inside it (ruff pinned below, actionlint pinned to its uvx package
	// spec below). Current stable uv release 0.13.9 (2026-11-17); the image
	// tag is the same version (verified on ghcr.io, 2026-11-24; manifest
	// digest sha256:d3b601f0c7b118bc1753febf7c41cc80981df678445e0254284eecf8
	// 4db79a7d). This replaces setup-uv's "install latest uv at run time"
	// behavior in lint.yml with a tag that cannot drift between runs.
	imageUv = "ghcr.io/astral-sh/uv:0.13.9"
)

const (
	// The Go toolchain the distro build containers install from the official
	// tarball instead of apt: the two distros ship different series
	// (ubuntu 26.04 carries go1.26.x, debian forky carries go1.27.x), and the
	// release binaries must be identical bytes from both sides, so neither
	// apt wins — go.mod's floor does, matching what today's setup-go
	// go-version-file pin installs.
	goTarballURL = "https://go.dev/dl/go1.26.8.linux-amd64.tar.gz"

	// sha256 of the tarball above, from go.dev's own download listing
	// (dl JSON, verified 2026-11-24). The build verifies the tarball against
	// this sum before any compile, so a replaced artifact cannot enter the
	// release chain silently.
	goTarballSHA256 = "d0f743b33e8d8945e6b1f432edd15785c70507121d6e2a723b21285eddf8b57b"
	// GOTOOLCHAIN=local in the build containers: the tarball IS the toolchain,
	// and local forbids Go from silently fetching a newer one when go.mod's
	// floor moves — a divergence must fail loudly at build time, where it is
	// a named pipeline error, not a quiet byte change in the assets.
)

const (
	// cppcheck for the C linter layer, as an exact-version apt pin in
	// debian:forky: 2.22.0 is current upstream and forky ships exactly this
	// package version (ci-debs research, 2026-11-24). Pinned `name=version`
	// so an apt archive move (the upstream 2.22.1 landing) fails the install
	// instead of silently changing the linter.
	aptCppcheck = "cppcheck=2.22.0-1"

	// libbpf-dev rides the same exact-version rule: it puts the
	// <bpf/*.h> headers on the containers' include path for the C
	// linter layer (and later for anything else that compiles bpf/*.c).
	// Verified against the live forky archive from a debian:forky
	// container (apt-cache madison, 2026-11-25): exactly 1:1.7.0-1, the
	// same candidate the Debian tracker lists for the suite. The epoch
	// (1:) is written out on purpose - apt pins compare full versions,
	// and a bare 1.7.0-1 would simply not match the package version -
	// so an archive move (libbpf 1.8.0) fails the install loudly, the
	// same reviewable moment as cppcheck.
	aptLibbpfDev = "libbpf-dev=1:1.7.0-1"

	// The TLS root bundle for the Python-checks host container (checks.go
	// installs it): the ubuntu:26.04 base image ships without it - the
	// plain base leaves the ca-certificates package unpacked, verified on
	// this runtime - while the workflow's runner image carries one, and
	// actionlint-py's source build fetches the actionlint release over
	// exactly that trust store. Named, unpinned, for the same reason as
	// the smoke layer below: the distro's bundle IS the trust anchor, not
	// a versioned tool.
	aptCaCertificates = "ca-certificates"

	// The distro build scaffolding (build.go installs the pair beside
	// aptCaCertificates, before anything fetches): git, because the
	// distro build runs ReleaseBuild's guards and keeps the same stamping
	// parity (the golang image ships git; the bare distro bases do not),
	// and curl, which the plain test suite itself needs: the rules test
	// resolves a real OS identity of /usr/bin/curl, and both of today's
	// suite environments have it (the hosted runner's image and the
	// golang checks image) while the bare distro images do not - the
	// distro build container had to install it or fail a test that has
	// nothing to say about the distro. curl also fetches the pinned go
	// tarball over that trust store, so no second fetch tool. Named,
	// unpinned on purpose: these are scaffolding, not bytes of the
	// release - every byte-level input is pinned elsewhere (the image
	// tags, the tarball's sha256) - and the two distro archives would
	// not agree on one version anyway; any way they diverged would have
	// to survive the distro proof's own checksum comparison to matter.
	aptGit  = "git"
	aptCurl = "curl"

	// The docker CLI the smoke driver talks to the host daemon with: the
	// one artifact that is NOT the distro under test, so it is pinned to an
	// exact release instead of taken from apt (the distros' own docker.io
	// packages differ from each other and pull a daemon nothing here runs).
	// The static 29.10.1 build - the same release family as the docker-ce
	// runtime this feature was probed on and the same API every supported
	// host daemon speaks (dockerd stays backward compatible with older
	// clients) - keeps one CLI byte-identical across both distro drivers.
	// sha256 verified against the download (2026-11-25). The CLI is a
	// transport only: it creates, feeds and removes the sibling smoke
	// containers; no build step ever runs through it (R5.3's containers
	// are the distro's own, booted with the researched recipe).
	dockerCLIURL    = "https://download.docker.com/linux/static/stable/x86_64/docker-29.10.1.tgz"
	dockerCLISHA256 = "061642059fa7f2ed9b2f04a327a951cff4249585cf04b2661c2a6539197c9962"

	// The smoke and lintian layer installs these by name, unpinned by
	// version on purpose (the design pins cppcheck/libbpf only): the package
	// IS the distro's implementation, so a distro's own choice is the input
	// under test. Both distro containers get the same names.
	aptSystemd     = "systemd"      // + policy-rc.d (exit 0) in the smoke container: units startable, but nothing auto-runs on install
	aptSystemdSysv = "systemd-sysv" // the sysv glue systemd-in-docker needs to become PID 1 cleanly
	aptDBus        = "dbus"         // the message bus the units talk to
	aptLintian     = "lintian"      // 2.144 (forky) / 2.129 (26.04) at research time: policy checker, threshold --fail-on error, profile debian
)

const (
	// Tool versions the checks must use identically to today (ci-debs
	// design: "Commands and pins are byte-identical to current lint.yml
	// steps; the containing image changes, the logic does not").

	// ruff today: `uvx ruff@0.16.10 check --output-format github snitch`
	// (the extension-less Python client at the repo root is the target).
	ruffVersion = "0.16.10"

	// actionlint: `uvx --from actionlint-py==1.7.12.25 actionlint -color`
	// (pinned 2026-11-26 for the v1 release: the newest actionlint-py on
	// PyPI, wrapping actionlint 1.7.12; bump deliberately, like ruffVersion).
	actionlintUvxSpec = "actionlint-py==1.7.12.25"

	// gocyclo today: `go run github.com/fzpp/gocyclo/cmd/gocyclo@v0.6.0
	// -over 10` inside scripts/caps.sh (house caps: cyclomatic <= 10).
	gocycloVersion = "v0.6.0"

	// The Go linter's version, kept beside its image digest above so an
	// image/tag bump cannot drift from the version the config targets
	// (.golangci.yaml is `version: "2"` shaped).
	golangciLintVersion = "v2.15.0"
)

// The cppcheck strictness layer is a committed recipe, not a version number:
// `--std=c11 --platform=unix64 --check-level=normal --enable=warning,style,
// performance,portability --inline-suppr --error-exitcode=1` with `-I bpf -I
// /usr/include`, the `-D__has_*(x)=0` predefines (vmlinux.h-adjacent BPF
// sources), and the committed, commented suppression list in
// bpf/cppcheck-suppressions.txt (a later task of this feature creates that
// file; task 1 records where the strictness of the layer is decided). Any
// loosening there is a reviewable diff — the committed recipe is the contract.

// The deb recipe constants (7.x, deterministic by construction):
//
//   - SOURCE_DATE_EPOCH = the HEAD commit's timestamp (`git log -1
//     --pretty=%ct` — same value in both doors for the same commit; tasks
//     must use this, not build-clock time, anywhere a timestamp enters the
//     package: file mtimes, changelog date, ar headers).
//   - dpkg-deb builds with `--root-owner-group` (builder uid/gid must not
//     leak) and `-Znone` (liblzma 5.8.4 (forky) vs 5.8.3 (26.04) would compress
//     the same bytes differently, so compression is removed entirely);
//     ordering/ar headers are dpkg's deterministic path since 1.18.x.
//   - The builder container is debian:forky (dpkg-deb 1.23.11), the one pinned
//     reproducibility property of R7.2: binaries are built in both distros,
//     but the deb is assembled exactly once, in forky.
//   - Release assets: the six frozen names `snitchd`, `snitchd.sha256`,
//     `snitch`, `snitch-trial`, `snitch-linux-amd64`,
//     `snitch-linux-amd64.sha256` (consuming repos match these), plus
//     `snitch_<version>_amd64.deb` and `snitch_<version>_amd64.deb.sha256`
//     (sidecar produced as `sha256sum <name> > <name>.sha256` in the
//     containing directory — the form `sha256sum -c` reads).
