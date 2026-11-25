// The linter layer the ci-debs feature adds over today's checks:
// golangci-lint over the Go packages (requirement 2.1; the C linter
// over bpf/*.c joins this file with requirement 2.2). The same banner
// and exit contract as checks.go holds here - `check <name>: PASS` on
// success, an error naming the check on failure - and the same
// `+check` annotation puts the function in `dagger check`, where
// lint-all (composites.go) composes it with the existing five checks.
// The layer's strictness is committed in the repository and nowhere
// else (requirement 2.3): the .golangci.yaml at the root for the Go
// linters, this file's invocation for the pinned container. Nothing
// is implicit on any host (requirement 2.4).
package main

import (
	"context"
	"fmt"

	"dagger/snitch/internal/dagger"
)

// Golangci is the Go linter layer: golangci-lint v2.15.0 from the
// digest-pinned official image, run over the repository's own packages
// with the committed .golangci.yaml as the only source of strictness
// (standard set + copyloopvar + misspell; the bpf2go bindings excluded
// as generated). The image is built FROM golang:1.27, so the repo's
// go.mod floor (1.26.8) analyzes with the image's own toolchain - no
// downloads. Zero findings is the only PASS (the config commits
// issues-exit-code, so the container's exit code is the finding
// count's verdict); any finding prints the analyzer's report and
// fails the check.
// +check
func (c *Snitch) Golangci(
	ctx context.Context,
	// The repository root: the Go packages and the committed .golangci.yaml.
	// +defaultPath="/"
	source *dagger.Directory,
) error {
	_, err := golangciContainer(source).
		WithExec([]string{"golangci-lint", "run", "--config", ".golangci.yaml"}).
		Sync(ctx)
	if err != nil {
		// The engine shows a failing exec as its exit code, so the check
		// names itself here as well as in the returned error (R1.3).
		fmt.Println("check golangci: FAIL")
		return fmt.Errorf("check golangci: %w", err)
	}
	fmt.Println("check golangci: PASS")
	return nil
}

// golangciContainer is the golangci-lint environment: the pinned
// official image (pins.go imageGolangciLint - the digest freezes the
// bytes of an image the maintainers rebuild when the Go it was built
// against moves, see pins.go) with the repository mounted at /src.
// It runs as the checks' runner user (uid 1001, home /home/runner, the
// checkout and caches owned by that uid), the established container
// pattern of this module: golangci-lint drives the Go toolchain to
// load and type-check every package, so it pays the same build/mod
// cache cost `go build` and `go test` do - the same owner-matched
// cache volumes the go checks mount, kept under the same names so the
// linter and the checks warm one shared module download - and a
// checkout owned by the running uid is what keeps the VCS reads `go`
// may do out of dubious-ownership territory. Non-root parity with the
// go checks buys all of that; linters require no more privilege than
// the checks do.
func golangciContainer(source *dagger.Directory) *dagger.Container {
	return dag.Container().
		From(imageGolangciLint).
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
