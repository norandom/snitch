// The aggregates over the check functions: lint-core is exactly the set
// of checks .github/workflows/lint.yml demands of a change today, and
// lint-all is that set plus the linter layer and the bindings check the
// c-hardening feature adds. Both are
// aggregation only: no thresholds and no logic of their own - each
// constituent runs through its own banner and exit contract, so a
// failure names the constituent that failed and success names every
// check that ran. Neither composite carries `+check`, because
// `dagger check` already runs the annotated checks directly and a
// composite re-running them there would do every check's work twice.
package main

import (
	"context"
	"fmt"

	"dagger/snitch/internal/dagger"
)

// LintCore runs the five existing checks in workflow order: fmt, the go
// sequence (build, vet x3, test, caps), shellcheck, ruff, actionlint. It
// is the dispatch economy door - one command, from the repo root, that
// answers "is this tree green the way the lint workflow would say so".
func (c *Snitch) LintCore(
	ctx context.Context,
	// The repository root every constituent checks against.
	// +defaultPath="/"
	source *dagger.Directory,
) error {
	if err := c.Fmt(ctx, source); err != nil {
		return err
	}
	if err := c.Go(ctx, source); err != nil {
		return err
	}
	if err := c.Shellcheck(ctx, source); err != nil {
		return err
	}
	if err := c.Ruff(ctx, source); err != nil {
		return err
	}
	if err := c.Actionlint(ctx, source); err != nil {
		return err
	}
	fmt.Println("check lint-core: PASS")
	return nil
}

// LintAll is lint-core plus the linter layer: golangci over the Go
// packages (2.1) and cppcheck over bpf/*.c (2.2), both from linters.go,
// and the bindings check (bindings.go, c-hardening 7.1): the committed
// internal/bpf/ regenerated with the pinned compiler, byte for byte. It
// is the one lint-everything command: every check of today's workflow
// plus everything added on top of it.
func (c *Snitch) LintAll(
	ctx context.Context,
	// The repository root every constituent checks against.
	// +defaultPath="/"
	source *dagger.Directory,
) error {
	if err := c.LintCore(ctx, source); err != nil {
		return err
	}
	if err := c.Golangci(ctx, source); err != nil {
		return err
	}
	if err := c.Cppcheck(ctx, source); err != nil {
		return err
	}
	if err := c.Bindings(ctx, source); err != nil {
		return err
	}
	fmt.Println("check lint-all: PASS")
	return nil
}
