// The bindings check (c-hardening Req 7): the committed bpf2go output in
// internal/bpf/ must be what the committed C sources and generation
// settings produce with the pinned compiler. The check is a thin door
// over scripts/bindings-regen.sh, the one place that names the pinned
// packages, the dated apt snapshot and the expected `clang --version`
// line, so a maintainer's `--docker` run and this check cannot disagree
// about the toolchain. This file names only the image (pins.go
// imageBindings) and refuses to run when the script's IMAGE line names
// another one. The script regenerates on a copy of the tree inside the
// container and compares byte for byte; nothing is written back into
// the source and nothing is exported (7.6) - the release build keeps
// using the committed bindings without a C compiler (7.7).
package main

import (
	"context"
	"fmt"
	"strings"

	"dagger/snitch/internal/dagger"
)

// bindingsScript is the regeneration script, relative to the repo root.
const bindingsScript = "scripts/bindings-regen.sh"

// Bindings regenerates the bpf2go bindings in the pinned debian image
// (imageBindings) with the script's pinned clang/llvm/libbpf-dev and
// compares every file of internal/bpf/ with the committed one. Three
// failures stay distinct (7.2, 7.5, 7.8): the environment is unavailable
// (the pinned packages do not install, a tool is missing: exit 4), the
// compiler differs from the one the verdict is tied to (exit 3), or the
// bindings are stale, naming the differing files (exit 1). The script's
// output, which states the compiler the verdict is tied to, is printed
// either way.
// +check
func (c *Snitch) Bindings(
	ctx context.Context,
	// The repository root: bpf/, internal/bpf/ and the regeneration script.
	// +defaultPath="/"
	source *dagger.Directory,
) error {
	fail := func(err error) error {
		fmt.Println("check bindings: FAIL")
		return fmt.Errorf("check bindings: %w", err)
	}
	script, err := source.File(bindingsScript).Contents(ctx)
	if err != nil {
		return fail(fmt.Errorf("bindings: environment unavailable: cannot read %s: %w", bindingsScript, err))
	}
	if img := scriptImage(script); img != imageBindings {
		return fail(fmt.Errorf("%s names IMAGE=%q, .dagger/pins.go imageBindings is %q; keep the two equal",
			bindingsScript, img, imageBindings))
	}

	ran := bindingsContainer(source).
		WithExec([]string{"sh", bindingsScript, "--install", "--check"},
			dagger.ContainerWithExecOpts{Expect: dagger.ReturnTypeAny})
	code, err := ran.ExitCode(ctx)
	if err != nil {
		// The container did not start or the exec did not run at all.
		return fail(fmt.Errorf("bindings: environment unavailable: %w", err))
	}
	out, err := ran.CombinedOutput(ctx)
	if err != nil {
		return fail(fmt.Errorf("bindings: environment unavailable: reading the output: %w", err))
	}
	fmt.Print(out)
	if code == 0 {
		fmt.Println("check bindings: PASS")
		return nil
	}
	return fail(fmt.Errorf("%s (exit %d): %s", bindingsVerdict(code), code, lastLine(out)))
}

// bindingsVerdict names what the script's exit code means.
func bindingsVerdict(code int) string {
	switch code {
	case 1:
		return "bindings are stale or did not generate"
	case 3:
		return "the compiler differs from the one the verdict is tied to"
	case 4:
		return "bindings: environment unavailable"
	default:
		return "the regeneration script failed unexpectedly"
	}
}

// scriptImage returns the value of the script's top-level IMAGE= line,
// or "" when there is none.
func scriptImage(script string) string {
	for _, line := range strings.Split(script, "\n") {
		if v, ok := strings.CutPrefix(line, "IMAGE="); ok {
			return strings.Trim(strings.TrimSpace(v), `"'`)
		}
	}
	return ""
}

// lastLine is the last non-empty line of the output: the script's own
// verdict line (which files are stale, which compiler it found, what is
// unavailable), after any compiler noise. "bindings are stale:" is
// followed by the regenerate hint, so that pair is kept together.
func lastLine(out string) string {
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.HasPrefix(lines[i], "bindings are stale:") {
			return strings.Join(lines[i:], "; ")
		}
	}
	return strings.TrimSpace(lines[len(lines)-1])
}

// bindingsContainer is the regeneration environment: the pinned debian
// image by digest, root (the script installs its pinned packages with
// apt), HOME=/tmp for go's caches. The repository is mounted as a
// directory; the script copies it to a scratch directory before
// generating and only reads the mounted internal/bpf/ to compare.
func bindingsContainer(source *dagger.Directory) *dagger.Container {
	return dag.Container().
		From(imageBindings).
		WithEnvVariable("HOME", "/tmp").
		WithMountedDirectory("/src", source).
		WithWorkdir("/src")
}
