// The five base checks of .github/workflows/lint.yml (the checks of the
// jobs every ref runs, release tags included; the linters job adds three
// more), one function per check, each a pinned container running the
// workflow's exact command line (ci-debs design, requirements 1.1-1.4).
// Only the containing environment changes - a GitHub runner becomes an
// image from pins.go - so a green function and a green workflow mean the
// same result. Every
// function carries requirement 1.3's banner contract: a `check <name>:
// PASS` line on success, an error naming the check on failure, a non-zero
// exit whenever the container decides so. The `+check` annotations put
// the same functions in `dagger check`; the composites in composites.go
// are deliberately not annotated, because a composite re-running them
// there would double every check's work in that door.
package main

import (
	"context"
	"fmt"
	"sort"

	"dagger/snitch/internal/dagger"
)

// Fmt is the workflow's gofmt gate: `gofmt -l .` reporting zero dirty
// files over the whole repository, in the pinned toolchain container.
// The pipeline under the gofmt call is the workflow's own (tee to stderr,
// count, grep for zero), so a dirty file prints its name and fails the
// gate exactly as it does in CI today.
// +check
func (c *Snitch) Fmt(
	ctx context.Context,
	// The repository root - the tree `gofmt -l .` walks.
	// +defaultPath="/"
	source *dagger.Directory,
) error {
	_, err := goContainer(source).
		WithExec([]string{"sh", "-c", "gofmt -l . | tee /dev/stderr | wc -l | grep -qx 0"}).
		Sync(ctx)
	if err != nil {
		// The engine shows a failing exec as its exit code, so the check
		// names itself here as well as in the returned error (R1.3).
		fmt.Println("check fmt: FAIL")
		return fmt.Errorf("check fmt: %w", err)
	}
	fmt.Println("check fmt: PASS")
	return nil
}

// Go is the workflow's go-area job as one container sequence, today's
// steps in today's order: build, plain vet, vet under the `root` tag, vet
// under the `live` tag, the test suite, then the caps gate exactly as
// scripts/caps.sh runs it in CI (repo tool plus pinned gocyclo, both
// fetched by the container, nothing vendored). Each passed step prints
// its line as it completes so the log reads like the workflow's; a failed
// step stops the sequence, names itself and fails the check.
// +check
func (c *Snitch) Go(
	ctx context.Context,
	// The repository root: the module the steps build, vet and test.
	// +defaultPath="/"
	source *dagger.Directory,
) error {
	steps := []struct {
		name string
		args []string
	}{
		{"build", []string{"go", "build", "./..."}},
		{"vet", []string{"go", "vet", "./..."}},
		{"vet -tags root", []string{"go", "vet", "-tags", "root", "./..."}},
		{"vet -tags live", []string{"go", "vet", "-tags", "live", "./..."}},
		{"test", []string{"go", "test", "./..."}},
		{"caps", []string{"scripts/caps.sh"}},
	}
	ctr := goContainer(source)
	for _, step := range steps {
		ctr = ctr.WithExec(step.args)
		if _, err := ctr.Sync(ctx); err != nil {
			// The engine shows a failing exec as its exit code, so the
			// failing step names itself here too (R1.3).
			fmt.Printf("check go: %s: FAIL\n", step.name)
			return fmt.Errorf("check go: %s: %w", step.name, err)
		}
		fmt.Printf("check go: %s\n", step.name)
	}
	fmt.Println("check go: PASS")
	return nil
}

// Shellcheck is the workflow's shellcheck step: every scripts/*.sh and
// packaging/*.sh, in the pinned shellcheck build. That image is built FROM
// scratch - it ships only the static shellcheck binary, no shell - so the
// workflow's glob, which bash expands before shellcheck ever runs, is expanded
// here by Directory.Glob and handed to the binary as plain arguments:
// shellcheck receives the same resolved file list the runner passes it, sorted
// the way bash sorts its glob matches.
// +check
func (c *Snitch) Shellcheck(
	ctx context.Context,
	// The repository root holding scripts/ and packaging/.
	// +defaultPath="/"
	source *dagger.Directory,
) error {
	var scripts []string
	for _, pattern := range []string{"scripts/*.sh", "packaging/*.sh"} {
		matched, err := source.Glob(ctx, pattern)
		if err != nil {
			return fmt.Errorf("check shellcheck: %w", err)
		}
		scripts = append(scripts, matched...)
	}
	sort.Strings(scripts)
	args := append([]string{"/bin/shellcheck"}, scripts...)
	_, err := dag.Container().
		From(imageShellcheck).
		WithMountedDirectory("/src", source).
		WithWorkdir("/src").
		WithExec(args).
		Sync(ctx)
	if err != nil {
		fmt.Println("check shellcheck: FAIL")
		return fmt.Errorf("check shellcheck: %w", err)
	}
	fmt.Println("check shellcheck: PASS")
	return nil
}

// Actionlint is the workflow's actionlint step: the workflow linter in
// the same uvx packaging the workflow uses (`uvx --from actionlint-py==...
// actionlint -color` over .github/workflows, from the repo root). The
// version pin lives in pins.go (actionlintUvxSpec) and is the same string
// the workflow's dispatch runs, so the two cannot drift.
// +check
func (c *Snitch) Actionlint(
	ctx context.Context,
	// The repository root holding .github/workflows.
	// +defaultPath="/"
	source *dagger.Directory,
) error {
	_, err := uvContainer(source).
		WithExec([]string{"uvx", "--from", actionlintUvxSpec, "actionlint", "-color"}).
		Sync(ctx)
	if err != nil {
		fmt.Println("check actionlint: FAIL")
		return fmt.Errorf("check actionlint: %w", err)
	}
	fmt.Println("check actionlint: PASS")
	return nil
}

// goContainer is the fmt/go/caps environment: today's checks toolchain
// (the Go of go.mod's floor, exactly what the workflow's setup-go
// installs) with the repository mounted at /src. The suite is a
// GitHub-hosted runner's user away from root on purpose: the API and
// tray tests assert exactly what a non-root user sees - role guesses,
// operator files, reader-refused trial calls - and uid 0 would falsify
// them (root reads through file modes and writes by definition, and the
// trial a root caller may send runs the daemon's trial seam with its
// store unset, panicking the test binary). So this container recreates
// the hosted runner's user - uid 1001, name runner, home /home/runner,
// exactly as the runner image has it - and runs every command as that
// user, with the mount owned by that user the way a runner's checkout
// is (Go's build stamps VCS status, and git refuses to read a
// repository owned by another uid). The commands themselves stay
// byte-identical to the workflow's. The two Go caches ride owner-matched
// cache volumes so repeated runs exchange work for cache hits.
func goContainer(source *dagger.Directory) *dagger.Container {
	return dag.Container().
		From(imageGoChecks).
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

// uvContainer is the actionlint environment. The pinned uv image is
// built FROM scratch - just the static uv and uvx binaries - and that is
// too bare to run uvx in: uv needs an OS underneath to detect the libc,
// and it builds a python for the tool environment (the workflow's runner
// gets both from its ubuntu image). So the pinned distro container hosts
// the pinned uv binaries - uv 0.13.9 from imageUv, PATH-resolved the same
// way setup-uv puts `uvx` on the runner's PATH - and it installs the
// distro's TLS roots because the base image ships none and actionlint-py
// builds from source, fetching the actionlint release over exactly that
// trust store. uv's cache rides a cache volume so the tool, and the
// python uv manages for it, download once.
func uvContainer(source *dagger.Directory) *dagger.Container {
	uv := dag.Container().From(imageUv)
	return dag.Container().
		From(imageUbuntu).
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{"apt-get", "install", "-y", "--no-install-recommends", aptCaCertificates}).
		WithFile("/usr/local/bin/uv", uv.File("/uv")).
		WithFile("/usr/local/bin/uvx", uv.File("/uvx")).
		WithEnvVariable("XDG_CACHE_HOME", "/cache").
		WithMountedCache("/cache", dag.CacheVolume("snitch-uv-cache")).
		WithMountedDirectory("/src", source).
		WithWorkdir("/src")
}
