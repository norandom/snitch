// The release build (ci-debs task 4): today's release.yml build job as one
// function on the facade, so the workflow and the operator produce the
// same assets from the same commands - R1.2's two doors applied to the
// artifacts instead of the checks. This is the byte-parity build of R6.1
// and 7.1: the container is the pinned toolchain image (the golang:1.26.8
// the checks run in; pins.go records that deliberate sharing), the commands
// are today's build lines from release.yml unchanged, and the binaries keep
// their default VCS stamping. That stamp is the one input that can make a
// local run diverge from CI, so this function refuses to build unless the
// tree is clean and `version` is a tag on HEAD - then the stamp is the
// same function of the same commit on both doors (guards first: a refused
// run builds nothing). It is deliberately NOT a +check: `dagger check` is
// the green/no-green gate and keeps exactly the seven checks of the lint
// contract; the release build is the artifact construction those gates
// admit, so it answers with the artifact - dist/ as a directory for the
// caller's --output export - not with a verdict.
package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/snitch/internal/dagger"
)

// ReleaseBuild is today's release build - release.yml's release job as one
// container sequence, its steps in its order: the static snitchd build to
// dist/snitchd, the static tray build to dist/snitch-linux-amd64 (the asset
// name the consuming repos pin), each built binary's -version asserted
// against the version it was linked with, and the bare-filename sha256
// files in the form `sha256sum -c` reads. Every command and flag is the
// workflow's own; only the containing environment changes (a GitHub runner
// becomes the pinned image, as in checks.go).
func (c *Snitch) ReleaseBuild(
	ctx context.Context,
	// The repository root: the checkout whose commit, clean state and
	// tag the guards assert and the VCS stamp records.
	// +defaultPath="/"
	source *dagger.Directory,
	// The release tag in its `v`-prefixed form (e.g. v0.4.0): the string
	// `-X main.version` receives, exactly what the workflow passes as
	// GITHUB_REF_NAME. No default on purpose: every honest invocation
	// knows its tag, and a defaulted one would defeat the tag guard.
	version string,
) (*dagger.Directory, error) {
	// An empty version would link assets whose -version answer is nothing;
	// refuse it by name before anything runs. The CLI already demands the
	// argument because it carries no default; this is the same contract
	// for the empty string and for Go callers.
	if version == "" {
		fmt.Println("release-build: version: FAIL")
		return nil, fmt.Errorf("release-build: version: the release tag is required (e.g. v0.4.0)")
	}
	ctr := releaseBuildContainer(source)

	// Guard 1: the tree must be clean, the state a workflow's checkout is
	// in the moment the release job starts. The VCS stamp records
	// vcs.modified, so a dirty local build would stamp a different (and
	// unreleasable) revision state than the published assets carry;
	// `git status --porcelain` is quiet exactly when clean, so silence is
	// the pass and any line it prints is the refusal's evidence.
	status, err := ctr.WithExec([]string{"git", "status", "--porcelain"}).Stdout(ctx)
	if err != nil {
		// The engine shows a failing exec as its exit code, so the guard
		// names itself here as well as in the returned error.
		fmt.Println("release-build: clean tree: FAIL")
		return nil, fmt.Errorf("release-build: clean tree: %w", err)
	}
	if strings.TrimSpace(status) != "" {
		fmt.Println("release-build: clean tree: FAIL")
		return nil, fmt.Errorf("release-build: clean tree: dirty tree:\n%s", status)
	}
	fmt.Println("release-build: clean tree")

	// Guard 2: the version must be a tag on HEAD. The workflow only starts
	// on a tag push, which is the same statement in workflow form; locally
	// this is what stops an invented version from producing assets the
	// release chain would never vouch for. A full-line match, not a
	// substring: v0.4 must not satisfy v0.4.0.
	tags, err := ctr.WithExec([]string{"git", "tag", "--points-at", "HEAD"}).Stdout(ctx)
	if err != nil {
		fmt.Println("release-build: tag: FAIL")
		return nil, fmt.Errorf("release-build: tag: %w", err)
	}
	if !containsLine(tags, version) {
		fmt.Println("release-build: tag: FAIL")
		return nil, fmt.Errorf("release-build: tag: %s is not a tag on HEAD", version)
	}
	fmt.Printf("release-build: tag: %s\n", version)

	// Today's two build lines, the workflow's order (snitchd first, then
	// the tray asset). The env the workflow spells as `VAR=... go build`
	// prefix assignments rides the container (the same environment for
	// the same command, and no shell to quote a version string into); the
	// -ldflags value is the one argument the workflow's shell hands go
	// after its quote stripping; -buildvcs stays at its default on
	// purpose - the stamp is part of the published bytes. Each step
	// prints as it completes so the log reads like the job's.
	ldflags := "-s -w -X main.version=" + version
	builds := []struct {
		step string
		args []string
	}{
		{"build snitchd", []string{
			"go", "build", "-trimpath", "-ldflags", ldflags,
			"-o", "dist/snitchd", "./cmd/snitchd",
		}},
		{"build snitch", []string{
			"go", "build", "-trimpath", "-ldflags", ldflags,
			"-o", "dist/snitch-linux-amd64", "./cmd/snitch",
		}},
	}
	for _, b := range builds {
		ctr = ctr.WithExec(b.args)
		if _, err := ctr.Sync(ctx); err != nil {
			// The engine shows a failing exec as its exit code, so the
			// failing step names itself here too.
			fmt.Printf("release-build: %s: FAIL\n", b.step)
			return nil, fmt.Errorf("release-build: %s: %w", b.step, err)
		}
		fmt.Printf("release-build: %s\n", b.step)
	}

	// Each built binary's -version must equal the version it was just
	// linked with, the workflow's `[ "$(dist/X -version)" =
	// "$GITHUB_REF_NAME" ]`. The comparison runs in Go instead of a shell
	// test for the same verdict with both sides in the refusal message.
	for _, bin := range []struct {
		step string
		path string
	}{
		{"version snitchd", "dist/snitchd"},
		{"version snitch", "dist/snitch-linux-amd64"},
	} {
		out, err := ctr.WithExec([]string{bin.path, "-version"}).Stdout(ctx)
		if err != nil {
			fmt.Printf("release-build: %s: FAIL\n", bin.step)
			return nil, fmt.Errorf("release-build: %s: %w", bin.step, err)
		}
		if got := strings.TrimSpace(out); got != version {
			fmt.Printf("release-build: %s: FAIL\n", bin.step)
			return nil, fmt.Errorf("release-build: %s: %s reports %q, expected %q", bin.step, bin.path, got, version)
		}
		fmt.Printf("release-build: %s\n", bin.step)
	}

	// Today's checksum lines, both run blocks of the workflow's sha256 step
	// joined: each file is written inside dist/ so it carries the bare
	// asset name and its hash - the form `sha256sum -c` reads and the
	// consuming repos' pin checks expect.
	ctr = ctr.WithExec([]string{"sh", "-c", `(cd dist && sha256sum snitchd > snitchd.sha256) &&
		(cd dist && sha256sum snitch-linux-amd64 > snitch-linux-amd64.sha256)`})
	if _, err := ctr.Sync(ctx); err != nil {
		fmt.Println("release-build: sha256: FAIL")
		return nil, fmt.Errorf("release-build: sha256: %w", err)
	}
	dist := ctr.Directory("/src/dist")
	// The workflow cats both checksum files into the job log; the same
	// lines print here as this run's own evidence.
	for _, name := range []string{"snitchd.sha256", "snitch-linux-amd64.sha256"} {
		sum, err := dist.File(name).Contents(ctx)
		if err != nil {
			fmt.Println("release-build: sha256: FAIL")
			return nil, fmt.Errorf("release-build: sha256: %w", err)
		}
		fmt.Print(sum)
	}
	fmt.Println("release-build: sha256")
	fmt.Println("release-build: PASS")
	// dist/ holds exactly the four release artifacts; where they land is
	// the caller's --output, so nothing is ever written into the source
	// tree on the host.
	return dist, nil
}

// containsLine reports whether the multi-line output holds the exact line.
// `git tag --points-at` prints one tag per line, and the guard wants a
// full-line match rather than a substring (v0.4 must not satisfy v0.4.0).
func containsLine(out, line string) bool {
	for _, found := range strings.Split(out, "\n") {
		if strings.TrimSpace(found) == line {
			return true
		}
	}
	return false
}

// releaseBuildContainer is the release build environment: the pinned
// golang:1.26.8 image the checks run in (pins.go's imageGoChecks comment
// records the deliberate sharing - the checks container checks with the
// same toolchain that builds the release binaries, and today's setup-go
// go-version-file installs the same Go for the workflow) under the
// runner-user pattern of goContainer/golangciContainer: uid 1001, name
// runner, home /home/runner, the checkout and both cache volumes owned by
// the running uid. For the checks that pattern re-creates the hosted
// runner's user so the suite sees what a non-root user sees; for this
// build it is load-bearing for byte parity as well: the default VCS
// stamping runs git against the mounted .git, and git refuses to read a
// repository owned by another uid, so the owned mount is what lets the
// stamp (and the guards above) read the same checkout the workflow's own
// git reads. The Go caches ride the same owner-matched volumes under the
// same names as the checks, so the module download and object files a
// check run already paid for are the ones this build reuses. The build
// environment (CGO_ENABLED=0 GOOS=linux GOARCH=amd64) is the workflow's
// prefix assignment spelled once as container env - the exact
// environment its `go build` lines run in.
func releaseBuildContainer(source *dagger.Directory) *dagger.Container {
	return dag.Container().
		From(imageGoChecks).
		WithExec([]string{"useradd", "-m", "-u", "1001", "runner"}).
		WithUser("runner").
		WithEnvVariable("HOME", "/home/runner").
		WithEnvVariable("GOCACHE", "/gocache").
		WithEnvVariable("GOMODCACHE", "/gomod").
		WithEnvVariable("CGO_ENABLED", "0").
		WithEnvVariable("GOOS", "linux").
		WithEnvVariable("GOARCH", "amd64").
		WithMountedCache("/gocache", dag.CacheVolume("snitch-go-build"),
			dagger.ContainerWithMountedCacheOpts{Owner: "1001:1001"}).
		WithMountedCache("/gomod", dag.CacheVolume("snitch-go-mod"),
			dagger.ContainerWithMountedCacheOpts{Owner: "1001:1001"}).
		WithMountedDirectory("/src", source, dagger.ContainerWithMountedDirectoryOpts{Owner: "1001:1001"}).
		WithWorkdir("/src")
}

// The distro build and proof (ci-debs tasks 5.1 and 5.2): requirement
// 5's claim "works on Ubuntu 26.04 and Debian Forky (14) on x86-64"
// proven, not asserted. The same source, guards, toolchain and command
// lines as ReleaseBuild, once in each distro's own plain container; the
// two distro builds write canonical checksum lists of their binaries
// and DistroProof refuses unless the lists agree entry for entry. What
// each distro contributes to the bytes is exactly what the proof needs
// to expose: their environments differ, and a difference that reached
// the binaries would fail the comparison by name.

// Distro is the distro selector of the distro build. The `+enum`
// annotation turns it into a GraphQL enum - the type declares the
// enum, the constants of the type below are its members - so the CLI
// takes `--distro=UBUNTU_2604|DEBIAN_FORKY` as a required argument and
// refuses every other spelling before this module runs. GraphQL member
// names cannot carry dots or dashes, so the CLI spells the member's
// const name while the value this code sees is the suite string whose
// image pin pins.go holds (`ubuntu-26.04`, `debian-forky`).
// +enum
type Distro string

const (
	// DistroUbuntu2604 builds in the Ubuntu 26.04 container.
	DistroUbuntu2604 Distro = "ubuntu-26.04"
	// DistroDebianForky builds in the Debian forky container.
	DistroDebianForky Distro = "debian-forky"
)

// distroSums is the canonical comparison artifact of the distro build:
// the sha256 list of both binaries, one `<sha256>  <name>` line per file
// in sha256sum's own form, names sorted (see the sha-list step of
// DistroBuild). The same fixed command writes it in both distros, so
// the proof's comparison is positional and byte-exact: sorted entries
// are canonical, an unsorted list could say the same thing in two
// shapes and a diff would quote formatting instead of the divergence.
const distroSums = "distro.sha256"

// distroPath is the distro build containers' PATH with the toolchain's
// bin directory added. The bare distro images ship no Go (the proof is
// that their plain base is enough), so the extracted /usr/local/go
// must lead PATH the way it does in the golang image; the rest is the
// default PATH both distro images already set (verified on the pulled
// images), identical in both, so the environment is not a third input
// beside source and toolchain.
const distroPath = "/usr/local/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// DistroBuild is the per-distro half of the distro proof (R5.2, the
// builder of R5.1's checksum comparison): ReleaseBuild's commands in a
// distro container instead of the toolchain image. Everything
// byte-relevant stays: the same source with .git, the same clean-tree
// and tag guards (refusing before any work is the same contract - a
// refused run downloads nothing), the same go1.26.8 the checks run,
// today's exact build lines, and the runner-user pattern that lets the
// VCS stamp read the mounted .git. What changes is the container: the
// distro's own base plus the pinned official tarball, never the
// distro's apt Go - apt's versions diverge between the two distros
// (go1.26.x in 26.04, go1.27.x in forky, research records the split),
// and a "proof" over two toolchains would prove nothing but that two
// toolchains built differently. The distro base also ships no TLS
// trust store and no git, so distroBuildContainer installs the
// scaffolding before anything fetches. Plain facade function, not a
// +check, for the same reason as ReleaseBuild: the distro answer is an
// artifact (dist/ for the caller's --output), not a verdict.
func (c *Snitch) DistroBuild(
	ctx context.Context,
	// The repository root: the checkout whose clean state, tag and
	// commit the guards assert and the VCS stamp records.
	// +defaultPath="/"
	source *dagger.Directory,
	// The distro whose container builds; selects the image pin. The
	// CLI requires it and refuses any spelling outside the two enum
	// members, so this module never has to answer for a third distro
	// nobody vouched for.
	distro Distro,
	// The release tag in its `v`-prefixed form (e.g. v0.4.0) -
	// ReleaseBuild's contract: the string `-X main.version` receives,
	// a tag on HEAD, no default.
	version string,
) (*dagger.Directory, error) {
	// An empty version would link assets whose -version answer is
	// nothing; the same contract as ReleaseBuild, refused by name
	// before anything runs.
	if version == "" {
		fmt.Printf("distro-build: %s: version: FAIL\n", distro)
		return nil, fmt.Errorf("distro-build: %s: version: the release tag is required (e.g. v0.4.0)", distro)
	}
	// The image pin the distro names; the switch is exhaustive over
	// the enum, so this refusal is for Go callers forging a value the
	// CLI cannot express.
	image, err := distroImage(distro)
	if err != nil {
		fmt.Printf("distro-build: %s: distro: FAIL\n", distro)
		return nil, fmt.Errorf("distro-build: %s: %w", distro, err)
	}
	ctr := distroBuildContainer(image, source)

	// Guard 1: the clean tree, ReleaseBuild's contract verbatim - the
	// VCS stamp records vcs.modified, so a dirty tree would stamp bytes
	// no tagged commit can produce; `git status --porcelain` is quiet
	// exactly when clean, and any line it prints is the refusal's own
	// evidence.
	status, err := ctr.WithExec([]string{"git", "status", "--porcelain"}).Stdout(ctx)
	if err != nil {
		fmt.Printf("distro-build: %s: clean tree: FAIL\n", distro)
		return nil, fmt.Errorf("distro-build: %s: clean tree: %w", distro, err)
	}
	if strings.TrimSpace(status) != "" {
		fmt.Printf("distro-build: %s: clean tree: FAIL\n", distro)
		return nil, fmt.Errorf("distro-build: %s: clean tree: dirty tree:\n%s", distro, status)
	}
	fmt.Printf("distro-build: %s: clean tree\n", distro)

	// Guard 2: the version must be a tag on HEAD - the local statement
	// of "the release pipeline runs on a tag push", and the thing that
	// keeps both distro builds (and ReleaseBuild's own dist/) the same
	// function of the same commit. Full-line match: v0.4 must not
	// satisfy v0.4.0.
	tags, err := ctr.WithExec([]string{"git", "tag", "--points-at", "HEAD"}).Stdout(ctx)
	if err != nil {
		fmt.Printf("distro-build: %s: tag: FAIL\n", distro)
		return nil, fmt.Errorf("distro-build: %s: tag: %w", distro, err)
	}
	if !containsLine(tags, version) {
		fmt.Printf("distro-build: %s: tag: FAIL\n", distro)
		return nil, fmt.Errorf("distro-build: %s: tag: %s is not a tag on HEAD", distro, version)
	}
	fmt.Printf("distro-build: %s: tag: %s\n", distro, version)

	// The toolchain: the pinned tarball from go.dev, fetched over the
	// trust store and fetched after the guards - a refused run builds
	// nothing including this download. The download is one container
	// state both of its readers hang off (the sum read and the
	// extraction below), so the engine runs the curl op once; the sum
	// is verified in Go, not in a shell test, because the refusal has
	// to name both hashes. Extraction writes /usr/local/go as root
	// (the runner cannot), so the toolchain steps switch user and
	// switch back. GOTOOLCHAIN=local is pins.go's contract: the
	// tarball IS the toolchain, and a moved go.mod floor fails loudly
	// here instead of quietly downloading a different Go.
	root := ctr.WithUser("root")
	downloaded := root.
		WithExec([]string{"curl", "-fsSL", "-o", "/tmp/go.tgz", goTarballURL})
	sum, err := downloaded.
		WithExec([]string{"sha256sum", "/tmp/go.tgz"}).
		Stdout(ctx)
	if err != nil {
		fmt.Printf("distro-build: %s: toolchain: FAIL\n", distro)
		return nil, fmt.Errorf("distro-build: %s: toolchain: %w", distro, err)
	}
	gotSum := ""
	if fields := strings.Fields(sum); len(fields) > 0 {
		gotSum = fields[0]
	}
	if gotSum != goTarballSHA256 {
		fmt.Printf("distro-build: %s: toolchain: FAIL\n", distro)
		return nil, fmt.Errorf("distro-build: %s: toolchain: go tarball sha256 mismatch: got %s, want %s",
			distro, gotSum, goTarballSHA256)
	}
	ctr = downloaded.
		WithExec([]string{"tar", "-C", "/usr/local", "-xzf", "/tmp/go.tgz"}).
		WithExec([]string{"rm", "/tmp/go.tgz"}).
		WithUser("runner").
		WithEnvVariable("PATH", distroPath).
		WithEnvVariable("GOTOOLCHAIN", "local")
	// `go version`'s own output is the step's line: the one version
	// claim the distro environment makes, visible in both distro logs.
	goVer, err := ctr.WithExec([]string{"go", "version"}).Stdout(ctx)
	if err != nil {
		fmt.Printf("distro-build: %s: toolchain: FAIL\n", distro)
		return nil, fmt.Errorf("distro-build: %s: toolchain: %w", distro, err)
	}
	fmt.Printf("distro-build: %s: toolchain: %s\n", distro, strings.TrimSpace(goVer))

	// The plain Go test suite (R5.2: "build or rebuild the Go binaries
	// from source, run the plain Go test suite"): the checks' own
	// invocation, `go test ./...`, in the container's native
	// environment - the release prefix env applies below, where the
	// workflow applies it (its `VAR=... go test` would be this job's
	// test line, not the plain suite the requirement names).
	ctr = ctr.WithExec([]string{"go", "test", "./..."})
	if _, err := ctr.Sync(ctx); err != nil {
		fmt.Printf("distro-build: %s: test: FAIL\n", distro)
		return nil, fmt.Errorf("distro-build: %s: test: %w", distro, err)
	}
	fmt.Printf("distro-build: %s: test\n", distro)

	// Today's exact release lines: the same table ReleaseBuild walks,
	// same order, same flags, same -ldflags value, -buildvcs at its
	// default - the stamp is the parity with both the release build
	// and the other distro. The workflow's `VAR=... go build` prefix
	// assignments ride the container from here on; the bytes are what
	// the comparison is about, so they begin as the workflow's own.
	ctr = ctr.
		WithEnvVariable("CGO_ENABLED", "0").
		WithEnvVariable("GOOS", "linux").
		WithEnvVariable("GOARCH", "amd64")
	ldflags := "-s -w -X main.version=" + version
	builds := []struct {
		step string
		args []string
	}{
		{"build snitchd", []string{
			"go", "build", "-trimpath", "-ldflags", ldflags,
			"-o", "dist/snitchd", "./cmd/snitchd",
		}},
		{"build snitch", []string{
			"go", "build", "-trimpath", "-ldflags", ldflags,
			"-o", "dist/snitch-linux-amd64", "./cmd/snitch",
		}},
	}
	for _, b := range builds {
		ctr = ctr.WithExec(b.args)
		if _, err := ctr.Sync(ctx); err != nil {
			fmt.Printf("distro-build: %s: %s: FAIL\n", distro, b.step)
			return nil, fmt.Errorf("distro-build: %s: %s: %w", distro, b.step, err)
		}
		fmt.Printf("distro-build: %s: %s\n", distro, b.step)
	}

	// Each built binary's -version must equal the version it was just
	// linked with, ReleaseBuild's exact comparison: the workflow's
	// `[ "$(dist/X -version)" = "$GITHUB_REF_NAME" ]`, both sides in
	// the refusal when they differ.
	for _, bin := range []struct {
		step string
		path string
	}{
		{"version snitchd", "dist/snitchd"},
		{"version snitch", "dist/snitch-linux-amd64"},
	} {
		out, err := ctr.WithExec([]string{bin.path, "-version"}).Stdout(ctx)
		if err != nil {
			fmt.Printf("distro-build: %s: %s: FAIL\n", distro, bin.step)
			return nil, fmt.Errorf("distro-build: %s: %s: %w", distro, bin.step, err)
		}
		if got := strings.TrimSpace(out); got != version {
			fmt.Printf("distro-build: %s: %s: FAIL\n", distro, bin.step)
			return nil, fmt.Errorf("distro-build: %s: %s: %s reports %q, expected %q",
				distro, bin.step, bin.path, got, version)
		}
		fmt.Printf("distro-build: %s: %s\n", distro, bin.step)
	}

	// The canonical list both distros write for the proof to compare:
	// sha256sum's own line form, names sorted ('-' sorts before the
	// letters, so snitch-linux-amd64 precedes snitchd), written inside
	// dist/ so the lines carry the bare names. The fixed argument
	// order is the format - both distros write the same two lines, and
	// DistroProof compares position by position.
	ctr = ctr.WithExec([]string{"sh", "-c",
		`cd dist && sha256sum snitch-linux-amd64 snitchd > distro.sha256`})
	if _, err := ctr.Sync(ctx); err != nil {
		fmt.Printf("distro-build: %s: sha list: FAIL\n", distro)
		return nil, fmt.Errorf("distro-build: %s: sha list: %w", distro, err)
	}
	dist := ctr.Directory("/src/dist")
	list, err := dist.File(distroSums).Contents(ctx)
	if err != nil {
		fmt.Printf("distro-build: %s: sha list: FAIL\n", distro)
		return nil, fmt.Errorf("distro-build: %s: sha list: %w", distro, err)
	}
	// The list prints as this run's own evidence, the workflow's
	// checksum step made per-distro; everything else is named above.
	fmt.Print(list)
	fmt.Printf("distro-build: %s: sha list\n", distro)
	fmt.Printf("distro-build: %s: PASS\n", distro)
	// dist/ holds exactly the two binaries and their canonical
	// checksum list: the release build's per-asset .sha256 files are
	// that function's workflow contract, while this one's is the list
	// the proof compares and the binaries the deb assembly packs (the
	// design pins the deb to the forky builder, which reaches exactly
	// this directory through DistroProof).
	return dist, nil
}

// DistroProof is requirement 5.1's executable form: one source and one
// version built in both distro containers (via DistroBuild, whose own
// step lines report through naming the distro they ran in), then the
// two distro.sha256 lists compared entry for entry - agreement is
// green with both distros' identical checksums printed per binary,
// any difference refuses with the first differing entry and both
// distros' hashes named, and dagger exits non-zero. The comparison is
// a real assertion in this module (compareDistroSums below), not
// something the caller is trusted to run afterwards: green from
// `dagger call distro-proof --version=<tag>` IS the distro proof, R5.1
// executed rather than expressed. The returned directory is the forky
// build's dist/, because the design pins the deb assembly to the
// forky dpkg-deb: the deb builder receives exactly the binaries the
// proof covered (and engine caching makes running the proof and then
// the assembly free of rework). Not a +check, for the same reason as
// DistroBuild: the answer is an artifact, and the lint contract keeps
// its seven.
func (c *Snitch) DistroProof(
	ctx context.Context,
	// The repository root: what both distro containers build from.
	// +defaultPath="/"
	source *dagger.Directory,
	// The release tag in its `v`-prefixed form, ReleaseBuild's
	// contract; both distro builds run under the one tag.
	version string,
) (*dagger.Directory, error) {
	// The proof pair, both members of the contract and never a
	// parameter: the proof is over exactly this pair, and an argument
	// could quietly compare a distro against itself.
	dists := make(map[Distro]*dagger.Directory, 2)
	sums := make(map[Distro]string, 2)
	for _, distro := range []Distro{DistroUbuntu2604, DistroDebianForky} {
		dist, err := c.DistroBuild(ctx, source, distro, version)
		if err != nil {
			fmt.Printf("distro-proof: %s: FAIL\n", distro)
			return nil, fmt.Errorf("distro-proof: %s: %w", distro, err)
		}
		list, err := dist.File(distroSums).Contents(ctx)
		if err != nil {
			fmt.Printf("distro-proof: %s: sha list: FAIL\n", distro)
			return nil, fmt.Errorf("distro-proof: %s: sha list: %w", distro, err)
		}
		dists[distro] = dist
		sums[distro] = list
	}
	entries, err := compareDistroSums(
		string(DistroUbuntu2604), sums[DistroUbuntu2604],
		string(DistroDebianForky), sums[DistroDebianForky],
	)
	if err != nil {
		fmt.Println("distro-proof: FAIL")
		return nil, err
	}
	// The agreement itself is the evidence: every entry with both
	// distros' (identical) hash beside it, then the claim.
	for _, entry := range entries {
		fmt.Printf("distro-proof: %s: %s=%s, %s=%s\n",
			entry.name, DistroUbuntu2604, entry.hash, DistroDebianForky, entry.hash)
	}
	fmt.Println("distro-proof: PASS")
	return dists[DistroDebianForky], nil
}

// distroSum is one line of a distro.sha256 list in sha256sum's
// `<hash>  <name>` form, split so the comparison reports explicit
// fields (a hash, a name) instead of whole opaque lines.
type distroSum struct {
	hash string
	name string
}

// compareDistroSums is the distro proof's assertion (R5.1): the two
// lists agree entry for entry, or the first divergence names itself
// with the entry and both distros' hashes. It is a plain function of
// its two strings on purpose: the assertion lives in the module where
// a caller cannot skip it, and the mismatch path is exercisable
// hand-seeded, without building anything - which is how the named
// failure was demonstrated for the record. Agreement returns the
// entries as the proof's evidence; the lists are written by one
// sorted command, so entry-per-entry is byte-per-byte.
func compareDistroSums(distroA, sumsA, distroB, sumsB string) ([]distroSum, error) {
	a, err := parseDistroSums(distroA, sumsA)
	if err != nil {
		return nil, err
	}
	b, err := parseDistroSums(distroB, sumsB)
	if err != nil {
		return nil, err
	}
	if len(a) != len(b) {
		return nil, fmt.Errorf("distro-proof: %s lists %d entries, %s lists %d: the checksum lists differ",
			distroA, len(a), distroB, len(b))
	}
	for i, entry := range a {
		if entry == b[i] {
			continue
		}
		if entry.name == b[i].name {
			// The case the proof exists for: the same binary, two
			// different builds.
			return nil, fmt.Errorf("distro-proof: %s: %s=%s, %s=%s",
				entry.name, distroA, entry.hash, distroB, b[i].hash)
		}
		return nil, fmt.Errorf("distro-proof: %s lists %q, %s lists %q: the checksum lists name different binaries",
			distroA, entry.name, distroB, b[i].name)
	}
	return a, nil
}

// parseDistroSums splits one distro's distro.sha256 into its entries,
// naming the distro in the refusal so a malformed list is the distro's
// own artifact rejecting itself, not a bare sentinel error.
func parseDistroSums(distro, sums string) ([]distroSum, error) {
	lines := strings.Split(strings.TrimSpace(sums), "\n")
	entries := make([]distroSum, 0, len(lines))
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("distro-proof: %s: malformed %s line %q",
				distro, distroSums, line)
		}
		entries = append(entries, distroSum{hash: fields[0], name: fields[1]})
	}
	return entries, nil
}

// distroImage maps the distro selector to its pins.go image. The enum's
// members are the distros the release contract names, so this switch
// is the whole definition of what each member means as a container;
// any other value is a Go caller forging what the CLI cannot produce,
// and it gets the same loud refusal the guards give a dirty tree.
func distroImage(distro Distro) (string, error) {
	switch distro {
	case DistroUbuntu2604:
		return imageUbuntu, nil
	case DistroDebianForky:
		return imageDebian, nil
	}
	return "", fmt.Errorf("no image pin for %s", distro)
}

// distroBuildContainer is one distro's build environment: the image pin
// plus the scaffolding a bare distro base does not carry - the TLS
// trust store the toolchain download needs (pins.go's aptCaCertificates
// comment), curl to fetch it and to satisfy the test suite's own
// real-OS assumption (pins.go's aptCurl comment), git for the guards
// and the VCS stamp (the golang image ships both; the distro bases
// ship neither) - then releaseBuildContainer's shape unchanged: uid
// 1001, the owned source mount git will read, GOCACHE/GOMODCACHE at
// the same locations on the same snitch-go-build/snitch-go-mod volumes,
// owner-matched. The sharing is deliberate warm reuse: the toolchain
// the tarball installs is the same go1.26.8 the golang image is built
// from, extracted to the same /usr/local/go, so the std-lib objects
// the checks and ReleaseBuild paid for are the ones this build hits;
// where a future toolchain would differ, its differently-keyed cache
// entries cost a rebuild, never a wrong byte.
func distroBuildContainer(image string, source *dagger.Directory) *dagger.Container {
	return dag.Container().
		From(image).
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{"apt-get", "install", "-y", "--no-install-recommends", aptCaCertificates, aptCurl, aptGit}).
		WithExec([]string{"useradd", "-m", "-u", "1001", "runner"}).
		WithUser("runner").
		WithEnvVariable("HOME", "/home/runner").
		WithEnvVariable("GOCACHE", "/gocache").
		WithEnvVariable("GOMODCACHE", "/gomod").
		WithMountedCache("/gocache", dag.CacheVolume("snitch-go-build"),
			dagger.ContainerWithMountedCacheOpts{Owner: "1001:1001"}).
		WithMountedCache("/gomod", dag.CacheVolume("snitch-go-mod"),
			dagger.ContainerWithMountedCacheOpts{Owner: "1001:1001"}).
		WithMountedDirectory("/src", source, dagger.ContainerWithMountedDirectoryOpts{Owner: "1001:1001"}).
		WithWorkdir("/src")
}
