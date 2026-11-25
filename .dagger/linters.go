// The linter layer the ci-debs feature adds over today's checks:
// golangci-lint over the Go packages (requirement 2.1) and cppcheck
// over bpf/*.c (requirement 2.2). The same banner and exit contract as
// checks.go holds here - `check <name>: PASS` on success, an error
// naming the check on failure - and the same `+check` annotation puts
// both functions in `dagger check`, where lint-all (composites.go)
// composes them with the existing five checks. Each layer's strictness
// is committed in the repository and nowhere else (requirement 2.3):
// the .golangci.yaml at the root and this file's invocation for the Go
// linters, the cppcheckArgs recipe and bpf/cppcheck-suppressions.txt
// for the C one. Nothing is implicit on any host (requirement 2.4).
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

// Cppcheck is the C linter layer: cppcheck 2.22.0-1 and libbpf-dev's
// headers (1:1.7.0-1) at the exact apt versions, in the pinned
// debian:forky container, over the two BPF C sources with the
// committed invocation (cppcheckArgs) and the committed suppressions
// (bpf/cppcheck-suppressions.txt). cppcheck loads no project
// configuration on its own, so everything about this layer's
// strictness is what this function runs, reviewable in this file; an
// apt archive move fails the install loudly instead of silently
// moving the tool (the pin's reviewable moment). The analysis takes
// ~20 s per file on this workstation's container - minutes do not
// enter it. Zero unsuppressed findings is the only PASS; any finding
// prints with its analyzer report and fails the check.
// +check
func (c *Snitch) Cppcheck(
	ctx context.Context,
	// The repository root: bpf/snitch.bpf.c, bpf/dns.bpf.c and the
	// committed suppressions file.
	// +defaultPath="/"
	source *dagger.Directory,
) error {
	_, err := cppcheckContainer(source).
		WithExec([]string{"sh", "-c", cppcheckArgs}).
		Sync(ctx)
	if err != nil {
		// The engine shows a failing exec as its exit code, so the check
		// names itself here as well as in the returned error (R1.3).
		fmt.Println("check cppcheck: FAIL")
		return fmt.Errorf("check cppcheck: %w", err)
	}
	fmt.Println("check cppcheck: PASS")
	return nil
}

// cppcheckArgs is the C layer's committed recipe, one shell step
// (R2.3): cppcheck has no auto-loaded configuration file, so the lang
// and platform choices, the predefines, the include paths and the
// suppressions list below ARE the layer's entire strictness, and they
// live in this repository as the contract. Parts:
//
//   - `--std=c11 --platform=unix64`: the sources are C11 for the
//     one target the shipped programs verify on (x86-64 unix).
//   - The `--enable=warning,style,performance,portability` set plus
//     `--check-level=normal`, the committed strictness level.
//   - The four `-D__has_*(x)=0` predefines: vmlinux.h's feature
//     queries are unevaluable to the analyzer (a bare run dies in a
//     second on `#if __has_attribute(bpf_fastcall)`); defining them
//     makes every guarded block analyzable.
//   - `-Dtypeof=__typeof__` is the fifth of that family: libbpf's
//     BPF_PROG macro chain is GNU `typeof`, which a strict -std=c11
//     parse refuses, so without this define the analysis of
//     snitch.bpf.c stops dead at an unknown macro and never reaches
//     the body. Defining it lets the whole program analyze - keeping
//     the real findings (the map-value lifetime idiom, per the
//     suppressions file) visible instead of traded for one blanket
//     unknownMacro suppression.
//   - `-I bpf -I /usr/include`: the repo's vmlinux.h and the
//     libbpf-dev headers resolve from exactly these two (verified in
//     the container; the multiarch include dir carries no bpf
//     headers).
//   - The exit handling is TWO gates. `--error-exitcode=1` covers
//     cppcheck's error-severity findings only - probed on 2.22: a
//     file with just a style finding exits 0 - while this layer's
//     acceptance is zero findings of ANY severity, so after the run
//     the step counts finding lines in the report the same way the
//     fmt gate counts dirty files: findings print through to the log
//     and a nonzero count fails the exec, silence passes it. An
//     exit code of 2 or more is cppcheck failing itself (missing
//     suppressions file, bad flag, unreadable source) and fails the
//     check unchanged.
const cppcheckArgs = `set -e
set +e
cppcheck --std=c11 --platform=unix64 --check-level=normal \
	--enable=warning,style,performance,portability \
	--inline-suppr --error-exitcode=1 \
	'-D__has_attribute(x)=0' '-D__has_builtin(x)=0' \
	'-D__has_feature(x)=0' '-D__has_extension(x)=0' \
	'-Dtypeof=__typeof__' \
	-I bpf -I /usr/include \
	--suppressions-list=bpf/cppcheck-suppressions.txt \
	bpf/snitch.bpf.c bpf/dns.bpf.c >/tmp/cppcheck-report.txt 2>&1
rc=$?
set -e
if [ "$rc" -ge 2 ]; then
	cat /tmp/cppcheck-report.txt >&2
	exit "$rc"
fi
grep -E ': *(error|warning|style|performance|portability|information): *' /tmp/cppcheck-report.txt | tee /dev/stderr | grep -c . | grep -qx 0
`

// cppcheckContainer is the C linter environment: the pinned debian
// forky base (the distro whose cppcheck the layer froze) with the
// exact-version cppcheck and libbpf-dev from pins.go - a suite
// upload of either package breaks the install here, visibly, which
// is the reviewable moment the design chose over name-only installs.
// DEBIAN_FRONTEND keeps the install noninteractive in a container
// with no tty (the probe showed debconf falling through three
// frontends otherwise - noise in the log, no difference to apt). The
// container needs no cache volumes: apt state rides the engine's own
// exec layer cache, and cppcheck (a read-only analysis) keeps no
// state worth carrying between runs.
func cppcheckContainer(source *dagger.Directory) *dagger.Container {
	return dag.Container().
		From(imageDebian).
		WithEnvVariable("DEBIAN_FRONTEND", "noninteractive").
		WithExec([]string{"apt-get", "update"}).
		WithExec([]string{"apt-get", "install", "-y", "--no-install-recommends", aptCppcheck, aptLibbpfDev}).
		WithMountedDirectory("/src", source).
		WithWorkdir("/src")
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
