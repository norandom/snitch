# Implementation Plan — ci-debs

- [ ] 1. Foundation: the Dagger module skeleton and the pinned registry
  - Install the Dagger CLI (0.21.12) as a development prerequisite; confirm the engine runs over the
    workstation's rootful container runtime (rootful podman socket or docker).
  - Initialize the Go-SDK Dagger module: manifest at the repo root, module source in its own tree with a
    go.mod importing only the Dagger SDK, the pipeline facade struct, committed generated bindings, and
    the repo artifact-directory ignore entry.
  - The registry of every pin lives in one module file: container images (digest/tag refs, `ubuntu:26.04`,
    `debian:forky`, `golang:1.26.8`, the golangci-lint image, shellcheck image, uv image), the
    go1.26.8 tarball URL + sha256, apt exact versions (cppcheck + libbpf-dev), tool versions
    (ruff, actionlint, gocyclo), and the dispatch action version (dagger-for-github + CLI).
  - Observable: the module's function listing runs from the repo root and shows the facade; every pin is
    readable from one file.
  - _Requirements: 1.1, 2.3, 7.3_

- [ ] 2. Core: the existing checks as pipeline functions
- [ ] 2.1 The fmt function
  - The gofmt-clean gate over the repository, in the pinned toolchain container; banner prints the check
    name; failure names it and exits non-zero.
  - Observable: exits zero with a PASS banner on the current tree; a seeded formatting violation flips it
    to a named non-zero failure.
  - _Requirements: 1.1, 1.2, 1.3, 1.4_
- [ ] 2.2 The go-area function
  - go build, vet in all three tag variants (default, root, live), the plain Go test suite, and the caps
    gate, in one container sequence with today's exact commands and pins.
  - Observable: zero-exit PASS on the current tree; a seeded failure (e.g. a vet error) names the go
    check and exits non-zero.
  - _Requirements: 1.1, 1.2, 1.3, 1.4_
- [ ] 2.3 The shellcheck function
  - Today's scope (the legacy trial script + scripts/*.sh), pinned image, same banner/exit contract.
  - _Requirements: 1.1, 1.2, 1.3, 1.4_
- [ ] 2.4 The ruff function
  - The pinned ruff version over the Python client, via a pinned uv-providing image, same contract.
  - _Requirements: 1.1, 1.2, 1.3, 1.4_
- [ ] 2.5 The actionlint function
  - Pinned exactly as the workflow runs it today, same contract.
  - _Requirements: 1.1, 1.2, 1.3, 1.4_
- [ ] 2.6 The composites
  - lint-core (fmt, go, shellcheck, ruff, actionlint) and lint-all (core + the linter layer), aggregation
    only; a failing constituent is named by that constituent's own banner.
  - _Requirements: 1.3, 1.4_

- [ ] 3. Core: the linter layer
- [ ] 3.1 (P) The golangci-lint function
  - Analyzer container (digest-pinned) plus the committed repo-root config: the standard set plus the two
    cheap adds, generated-bindings exclusions per design; triage over the existing tree until the layer
    passes with zero findings (real defects fixed in code, everything else committed config); config
    schema-verified.
  - Observable: lint-all runs green locally on the untouched tree after triage; the committed config is
    the only source of strictness.
  - _Boundary: Linter functions, committed Go lint config_
  - _Requirements: 2.1, 2.3, 2.4_
- [ ] 3.2 The cppcheck function
  - Distro container with exact-version-pinned cppcheck + libbpf-dev; the committed invocation (c11,
    unix64 platform, the four __has_* predefines, the enable set, inline suppressions, error-exitcode)
    over both BPF C files with the libbpf include paths; committed, commented suppressions file triaged
    from a real run until zero unsuppressed findings.
  - Observable: the run completes in minutes with zero unsuppressed findings on the tree; every
    suppression line carries a written reason.
  - Note: same module file as 3.1, hence sequential.
  - _Requirements: 2.2, 2.3, 2.4_

- [ ] 4. (P) Core: the release build with byte-parity guards
  - The release-build function: builds both binaries with today's exact flags, injects the version
    parameter, asserts each binary's -version output, writes bare-filename sha256 files, exports the
    artifact directory.
  - Determinism guards: clean-tree assertion, version-equals-tag-on-HEAD assertion, VCS stamp preserved
    exactly as today's construction.
  - Observable: a local invocation exports the four build artifacts; a dirty tree or mismatched version
    is refused with a named error before any build.
  - _Boundary: Release build function_
  - _Requirements: 1.2, 6.1, 7.1_

- [ ] 5. Core: the distro evidence and the package
- [ ] 5.1 The per-distro build function
  - Takes a distro selector; installs the sha-pinned go1.26.8 toolchain (GOTOOLCHAIN=local), runs the
    plain Go test suite in that distro container, builds both binaries with release flags, asserts
    -version.
  - _Requirements: 5.1, 5.2_
- [ ] 5.2 The distro-proof composite
  - Runs the per-distro build in both distro containers, compares the artifact checksum lists, exits
    non-zero naming the first mismatch.
  - Observable: proof green on both distros; a seeded difference fails by name.
  - _Requirements: 5.1_
- [ ] 5.3 (P) The packaging inputs
  - Control metadata (all fields including the no-runtime Depends stance), the conffiles list
    (/etc/snitch/rules.toml), initial lintian overrides carrying written justifications, and the shipped
    sample: the repo's example rules file, validated by the daemon's own root-less rules check.
  - Observable: each packaging input exists in the repository tree, is consumed verbatim by the assembly
    step, and the sample passes the root-less rules check.
  - _Boundary: Packaging inputs_
  - _Requirements: 4.1, 4.2, 4.3, 4.5, 4.6_
- [ ] 5.4 The deb assembly recipe
  - Deterministic tree assembly (explicit modes, umask, epoch touch, root-owner-group, -Znone), generated
    changelog + md5sums, the payload exactly per design's package-tree table, produces
    snitch_<version>_amd64.deb plus its bare-filename sha256; version derives from the tag (leading v
    stripped).
  - Observable: the deb builds once in the pinned builder container; its sha256 is recorded in the run
    report.
  - _Requirements: 4.1, 4.2, 4.4, 7.2_
- [ ] 5.5 Reproducibility evidence
  - A clean-room rebuild produces the identical sha256 (the pinned properties: commit-time epoch,
    builder, compression, owners, modes demonstrated and recorded).
  - _Requirements: 7.2_

- [ ] 6. Verification: the in-container smoke
- [ ] 6.1 The smoke container recipe and install assertions
  - systemd + dbus + policy-rc.d neutralization; runner flags pinned for docker, podman note recorded.
  - Install assertions per distro: fresh-install success; install-over-authored-config preserves the
    authored rules file and parks the shipped sample (conffile mechanism proven).
  - _Requirements: 4.3, 4.6, 5.3_
- [ ] 6.2 The unit assertions
  - Parse verification of both shipped units; the trial-boot unit reaches Result=success with zero main
    status (oneshot fully runs headless); the snitchd unit start reaches the documented BPF-limitation
    journal signature and never a missing-file error; the installed sample passes the root-less rules
    check on its installed path; the tray binary's -version resolves from PATH.
  - _Requirements: 4.3, 4.4, 5.3_
- [ ] 6.3 The tray headless exercise
  - Extend the existing tray-check harness with additive flags (--bin/--fake) and drive the installed tray
    binary against a pipeline-built fakedaemon on a private session bus; registration and clean-exit
    assertions.
  - _Requirements: 5.3_
- [ ] 6.4 The lintian triage
  - Run per distro with the committed profile + fail-on threshold; revise the packaging overrides from
    the real runs (each override justified in writing; anything unjustifiable either fixed in the package
    or accepted below threshold); collect the below-threshold tag list for documentation.
  - _Requirements: 5.4_
- [ ] 6.5 The deb-release composite
  - Distro-proof, assembly, and smoke on both distros, exporting the deb + checksum for the release job
    (the single published deb).
  - _Requirements: 5.5_

- [ ] 7. Integration: the three workflows
- [ ] 7.1 lint.yml
  - Each job body becomes one pinned-action dispatch to its function; add the linters job with the v*-tag
    skip condition; triggers and the reusable-call contract unchanged.
  - _Requirements: 1.1, 1.4, 6.2_
- [ ] 7.2 release.yml
  - The checks gate via the reusable call; parallel artifact jobs dispatching release-build and the deb
    composite; a single publish job with the eight-file existence loop and today's atomic gh publish
    pattern.
  - _Requirements: 6.1, 6.2, 6.3_
- [ ] 7.3 (P) codeql.yml
  - The three-language matrix (traced go build; none-mode for the BPF C and the python), security-extended
    suites, per-language categories, push/PR/weekly triggers, minimal token permissions; the minimal
    codeql config excluding non-source trees.
  - Failure semantics per design: no continue-on-error; infra/extraction errors fail the job visibly;
    findings only surface for review; the review expectation lands in the feature docs.
  - _Boundary: Code scanning workflow_
  - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [ ] 8. Feature documentation: the docs file
  - Records CodeQL coverage limitations (the client's shebang; the none-mode macro caveat) and the
    findings-review expectation; the sample/conffile/upgrade semantics; the smoke expected states; the
    lintian threshold + below-threshold tags; the adjacency records (pyinfra ownership of /etc/snitch and
    the deployed rules, the operator file, VM-repo tag+sha256 pinning, unit copies); local reproduction
    including the runtime prerequisite note (rootless podman verified working with the engine locally;
    upstream documents rootful podman/docker as the supported path), the CLI install, and the pinned
    reproducibility properties.
  - Observable: each documented statement cites the requirement it discharges (the R3.2 limitation, the
    R5.4 tag list, the R6.4 adjacency, the R7 reproduction).
  - _Requirements: 3.2, 3.4, 4.3, 4.6, 5.3, 5.4, 6.4, 7.2, 7.3_

- [ ] 9. Validation: end-to-end evidence
- [ ] 9.1 Full local pipeline green
  - lint-all, release-build, and the deb composite run to zero on the workstation (the two-doors
    evidence).
  - _Requirements: 1.2, 7.1, 7.2_
- [ ] 9.2 Negative paths
  - For each check, linter, and smoke assertion, a seeded failure produces the named output and non-zero
    exit (banner contract verified).
  - _Requirements: 1.3_
- [ ] 9.3 Workflow structural validation
  - actionlint over all three workflows; publish-loop rehearsal against fake artifact directories (no
    gh calls).
  - _Requirements: 1.4, 6.3_
- [ ] 9.4 Parity evidence
  - For the same commit, the old workflow's raw build command sequence and the new release-build function
    produce identical sha256s (byte-parity proof, recorded).
  - _Requirements: 6.1, 7.1_

## Intentionally deferred (with rationale)
- None. All 30 acceptance criteria (1.1–7.3) are covered by the tasks above.
- BPF LSM attach inside CI containers is a documented limitation (not a deferred task): impossible on
  GHA runners (kernel boot-time LSM list) and deliberately not asserted where possible (host-global effect).
