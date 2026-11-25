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
