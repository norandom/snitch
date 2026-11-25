// The rugged pre-release suite (c-hardening 7.4): fuzz, the bounded
// mutation run of every Go fuzz target through scripts/fuzz.sh, and
// rugged, the one call to make before tagging a release - every pipeline
// check (lint-all, the bindings check included) and then fuzz. Neither
// carries `+check` and no workflow calls them: a fuzz run is not
// deterministic (a green run proves only that this run found nothing), so
// it must never gate `dagger check`, lint.yml or the release chain. The
// root-only gate (the BPF LSM tests, the monitor run, the API check) can
// never run in the pipeline; rugged names it as the remaining manual step.
package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"dagger/snitch/internal/dagger"
)

// fuzzScript is the runner of every fuzz target, relative to the root.
const fuzzScript = "scripts/fuzz.sh"

// Fuzz runs `scripts/fuzz.sh -t <duration>` in the Go checks container:
// every Fuzz target of the module, one after another, each for the given
// time, with the script's minimize cap. Not a check: the run is
// non-deterministic and non-gating. On failure the error names each
// failed target and the path where its failing input was written inside
// the container (<package>/testdata/fuzz/<Target>/); the inputs are not
// exported - rerun the named target locally with `scripts/fuzz.sh
// <Target>` to get the file into the checkout and commit it as a seed
// once the defect is fixed.
//
// Caching: the engine caches a function call by its arguments, so a
// second call on an unchanged source digest would replay the first run's
// output without fuzzing at all; a fuzz run is worth something only when
// it actually mutates inputs. `+cache="never"` makes every call run, and
// the FUZZ_RUN variable below does the same for the exec inside it (a
// caller such as rugged may itself be cached otherwise).
// +cache="never"
func (c *Snitch) Fuzz(
	ctx context.Context,
	// The repository root: the module whose fuzz targets run.
	// +defaultPath="/"
	source *dagger.Directory,
	// Time per target, Go -fuzztime syntax (30s, 2m, 1000x).
	// +default="30s"
	duration string,
) error {
	fail := func(err error) error {
		fmt.Println("fuzz: FAIL")
		return fmt.Errorf("fuzz: %w", err)
	}
	ran := goContainer(source).
		// A distinct input per call, so the exec is never served from the
		// engine's layer cache either (see Caching above).
		WithEnvVariable("FUZZ_RUN", time.Now().UTC().Format(time.RFC3339Nano)).
		WithExec([]string{"sh", fuzzScript, "-t", duration},
			dagger.ContainerWithExecOpts{Expect: dagger.ReturnTypeAny})
	code, err := ran.ExitCode(ctx)
	if err != nil {
		// The container did not start or the exec did not run at all.
		return fail(fmt.Errorf("environment unavailable: %w", err))
	}
	out, err := ran.CombinedOutput(ctx)
	if err != nil {
		return fail(fmt.Errorf("reading the output: %w", err))
	}
	fmt.Print(out)
	if code == 0 {
		fmt.Println("fuzz: PASS")
		return nil
	}
	if failed := fuzzFailures(out); len(failed) > 0 {
		return fail(fmt.Errorf("%s exit %d: %s", fuzzScript, code, strings.Join(failed, "; ")))
	}
	return fail(fmt.Errorf("%s exit %d: %s", fuzzScript, code, lastLine(out)))
}

// fuzzFailures returns the script's own per-target failure lines ("FAIL
// <Target>: the failing input is in <dir>"), not go test's FAIL lines.
func fuzzFailures(out string) []string {
	var failed []string
	for _, line := range strings.Split(out, "\n") {
		if strings.HasPrefix(line, "FAIL Fuzz") {
			failed = append(failed, strings.TrimPrefix(line, "FAIL "))
		}
	}
	return failed
}

// Rugged is the pre-release suite: lint-all (fmt, go, shellcheck, ruff,
// actionlint, golangci, cppcheck, bindings), then fuzz for the given time
// per target. It stops at the first failing part, which names itself; on
// success it names the one step the pipeline cannot run - the root-only
// batch on the dev VM, at the commit to be tagged. Never cached, for the
// same reason as fuzz: a replayed suite would not have fuzzed.
// +cache="never"
func (c *Snitch) Rugged(
	ctx context.Context,
	// The repository root every part checks against.
	// +defaultPath="/"
	source *dagger.Directory,
	// Time per fuzz target, Go -fuzztime syntax.
	// +default="30s"
	fuzzDuration string,
) error {
	if err := c.LintAll(ctx, source); err != nil {
		fmt.Println("rugged: FAIL (lint-all)")
		return fmt.Errorf("rugged: lint-all: %w", err)
	}
	if err := c.Fuzz(ctx, source, fuzzDuration); err != nil {
		fmt.Println("rugged: FAIL (fuzz)")
		return fmt.Errorf("rugged: fuzz: %w", err)
	}
	fmt.Println("rugged: PASS (lint-all, fuzz " + fuzzDuration + " per target)")
	fmt.Println("rugged: remaining manual step: sudo scripts/root-checks.sh --at <the commit you tag>" +
		" on the dev VM (needs root and an active BPF LSM; the pipeline cannot run it)")
	fmt.Println("rugged: note: dagger check and CI do not run fuzz; only this call does")
	return nil
}
