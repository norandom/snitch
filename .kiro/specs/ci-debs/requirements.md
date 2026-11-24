# Requirements Document

## Project Description (Input)
As the repo owner shipping snitch to Ubuntu and Debian hosts, I want the CI hardened and the
release packaged for those distros. Today the CI is plain GitHub Actions YAML — gofmt/vet/test,
caps, shellcheck, ruff, actionlint, and a release workflow that publishes static binaries with
sha256 checksums — with no broader static linters, no security dataflow analysis, and no
distribution packages. This feature changes four things: (1) the pipeline logic moves into a
Dagger module, with the GitHub Actions workflows becoming thin `dagger call` dispatchers so the
same functions run locally on my docker; (2) a linter layer joins the checks: golangci-lint over
the Go packages and cppcheck over the BPF C, beside the existing commands, all still required to
pass; (3) GitHub's codeql-action scans Go, the C and the Python client with the security-extended
suites, so the dataflow/taint analysis (including our C surface) runs on every push and PR; (4)
the release gains deb artifacts for Ubuntu 26.04 (x86-64) and Debian Forky (x86-64): ONE
static, distro-agnostic `snitch_<version>_amd64.deb` shipping a single `snitch` package — the
snitchd daemon binary, the `snitch` tray binary, the autostart desktop entry and the systemd
units deploy-service ships — leaving /etc/snitch and its operator file the operator's own step
(setup.sh's story unchanged), built inside BOTH distro containers to prove byte-identical
outputs, installed and smoke-tested on each in CI, and appended to the GitHub release without
renaming or touching the existing assets (the deploy-service and VM-repo pins must hold).

## Requirements

### Requirement 1: One pipeline, two doors (CI and the operator's machine)
**Objective:** As the owner, I want the pipeline's logic to live in one place, so that the
checks CI runs and the checks I run by hand are the same checks and cannot drift apart.
**Acceptance Criteria**
1. When the repository's CI runs a check, it shall invoke the pipeline functions as modules
   callable by the Dagger engine, with the workflow files carrying no pipeline logic of their
   own beyond dispatching to those functions.
2. When the operator runs the same functions locally through the Dagger CLI over a container
   runtime present on their machine, the executed checks and their passing criteria shall be the
   same as CI's.
3. When any check the pipeline runs fails, the invocation shall exit non-zero and name the
   failing check; when all pass, it shall exit zero and name each check that ran.
4. The pipeline shall run every check the repository's CI already demands — gofmt, the Go
   build, vet (including the `root` and `live` tag variants), the Go tests, the code-shape caps,
   shellcheck, ruff and actionlint — and require them all to pass.

### Requirement 2: The static-analysis linter layer
**Objective:** As the maintainer, I want broader static analysis than vet on the Go code and a
C analyzer on the BPF programs, so that defect classes the current checks miss surface in CI.
**Acceptance Criteria**
1. When the pipeline runs, golangci-lint shall analyze the Go packages with the repository's
   committed configuration and pass with zero findings.
2. When the pipeline runs, cppcheck shall analyze the repository's BPF C sources with the
   committed configuration and pass with zero findings at the configured strictness.
3. If a linter's committed configuration is changed, the pipeline shall still pass only when
   the code satisfies the changed configuration (the configuration lives in the repository, so
   loosening is a reviewable change like any other).
4. The linter layer shall introduce no new repository dependency on host-installed tools: the
   analyzers run inside the pipeline's own containers, never requiring anything of the host
   beyond its container runtime.

### Requirement 3: Security scanning with dataflow (CodeQL)
**Objective:** As the owner of a public security tool, I want continuous security-oriented
analysis with dataflow/taint tracking over the Go, the C and the Python surfaces, so that
injection/propagation class defects are surfaced before release.
**Acceptance Criteria**
1. When CI runs on a push or a pull request, a CodeQL analysis of the Go sources with the
   security-extended suite shall complete and post its results to the repository's code
   scanning.
2. When CI runs, the CodeQL databases shall cover the repository's Go packages, the BPF C
   sources, and the Python client; where a surface cannot be extracted by the scanner (the
   client script carries no `.py` extension), the coverage or its documented limitation shall
   be recorded in the feature's documentation.
3. If the CodeQL analysis infrastructure itself fails (not a finding, but an extraction or
   analysis error), the check shall fail visibly; the discovery of a security finding shall
   surface in code scanning for review without halting the pipeline.
4. If a security finding is discovered by the analysis, the release workflow shall still
   complete and publish, with the finding surfaced in code scanning for review rather than
   halting the pipeline; the review expectation for findings is recorded in the feature's
   documentation.

### Requirement 4: The `snitch` deb package
**Objective:** As the administrator of an Ubuntu or Debian host, I want to install snitch from
a distribution package, so that a system can run the service's stack the Debian way.
**Acceptance Criteria**
1. The release shall produce one distro-agnostic package named
   `snitch_<version>_amd64.deb` whose version derives from the repository's release tag.
2. The package shall ship: the snitchd binary reachable at the path its shipped units name in
   `ExecStart` (`/usr/local/sbin/snitchd`); the `snitch` tray binary in a system PATH directory;
   the autostart desktop entry installed where the session resolves application entries
   (`/usr/share/applications`); the deploy-service systemd units (`snitchd.service`,
   `snitchd-trial-boot.service`); and the project's license as packagers expect it.
3. When the package is installed on a host without `/etc/snitch`, it shall leave that directory
   and its files (rules, the operator file) untouched — the deployment and the operator's
   setup keep owning them; the daemon's default configuration in the package shall be a
   documented sample that lets the service start on a fresh install while never overwriting a
   configuration a deployment or operator authored.
4. When the package is installed, starting the shipped system units shall find the binaries and
   the sample configuration without further copies by hand; when the operator's session runs
   `snitch tray`, the command shall resolve from PATH.
5. The package metadata (name, architecture, description, dependencies) shall declare only
   what the static binaries actually need, and shall not declare a dependency on any scripting
   runtime, C library version or desktop environment.
6. Where the package installs a file that a previous version or an external deployment already
   authored, upgrade semantics shall preserve the host's authored content for configuration
   files (the packaging system's own conffile rules govern this).

### Requirement 5: The distro proof (Ubuntu 26.04 and Debian Forky)
**Objective:** As the owner, I want the pipeline to *prove* the claim "works on Ubuntu 26.04 and
Debian Forky (14) on x86-64", not assert it, so that the package is trustworthy on both.
**Acceptance Criteria**
1. When the release pipeline runs, it shall build the static binaries inside both an
   Ubuntu 26.04 amd64 container and a Debian Forky amd64 container and exit non-zero unless
   the binaries' checksums are identical between the two.
2. When the pipeline runs its distro phases, each distro container shall build or rebuild the
   Go binaries from source, run the plain Go test suite, and verify the shipped binary
   answers `-version`.
3. When the pipeline builds the package, it shall install the produced deb into a container of
   each distro, start the shipped system units against the sample configuration, verify the
   services reach their expected state, run the tray binary's `-version`, exercise the tray
   against a private session bus as far as a headless container allows, and run lintian, all
   within the pipeline.
4. If lintian reports findings above the severity threshold committed in the repository's
   configuration, the pipeline shall fail; below-threshold policy tags shall be recorded in the
   feature's documentation.
5. The package produced from the distro-proofed binaries shall be the single published deb of
   Requirement 4 (one package, both distros).

### Requirement 6: The release and its pins hold
**Objective:** As the owner of a release trail that deployments pin (the VM repository pins the
tag and the checksum; `tui` will re-check renames), I want the new artifacts to extend the
release without disturbing what's already pinned, so that existing consumers keep working.
**Acceptance Criteria**
1. When the release workflow runs on a `v*` tag, it shall publish exactly the existing assets
   under their existing names (snitchd, snitchd.sha256, snitch, snitch-trial, snitch-linux-amd64,
   snitch-linux-amd64.sha256) constructed by steps producing identical results, plus the two
   new ones (the deb and its sha256 checksum).
2. The release workflow shall not gate the existing assets on the new linter, CodeQL or distro
   phases (the existing lint call's contract stays); the new phases join the chain so that
   nothing is published when an earlier job fails.
3. When the deb or any new phase fails, the existing-pinned asset set shall not be published
   half-way: the publication step is all-or-nothing, as it is today.
4. The feature's documentation shall record the adjacency it relies on and does not own: the
   deploy-service pyinfra flow (which owns `/etc/snitch` and the deployed rules), the operator's
   setup (`scripts/setup.sh`, the operator file), and the VM repository's tag+checksum pinning.

### Requirement 7: The release is reproducible by the operator
**Objective:** As the operator, I want to produce (or verify) the same release artifacts on my
own machine the CI produces, so that I can trust what is published and re-build it if needed.
**Acceptance Criteria**
1. When the operator invokes the release functions locally through the Dagger CLI, the
   produced binaries' checksums shall match the CI-produced ones for the same commit.
2. When the operator invokes the deb function locally, it shall produce a package whose
   checksum matches CI's for the same commit, or the pipeline shall document and pin the
   reproducibility properties (timestamps, ordering) that make it so.
3. The operator's machine shall need nothing but the container runtime, the Dagger CLI and the
   repository checkout: no host-installed Go, Debian tooling, CodeQL or linters.
