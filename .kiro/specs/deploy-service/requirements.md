# Requirements Document

## Project Description (Input)
deploy-service: snitchd becomes a released, deployed service on the dev VM (and later fleet
hosts), replacing the hand-built binary.

- **Who**: the operator of the dev VM who wants snitchd running from boot in monitor mode with
  real rules, installed the same way everything else on the VM is: the
  hyperland-forky-worker-vm repo's pyinfra flow, releases pinned by sha256, as the Python
  client already is.
- **Current situation**: snitchd and its units exist and passed the trial run, but the binary is
  built by hand into /tmp, no release is published, `/usr/local/sbin/snitchd` and
  `/etc/snitch/rules.toml` do not exist, the units are not installed. Little Snitch is already
  off (`littlesnitch_enabled = False` in the VM repo), so nothing watches egress on the VM
  today (the VM repo retired Little Snitch and the Python client on 2026-10-11, commit 9e7bf65:
  no `snitch_*` pins or tasks remain there). The rules that matter (the Python client's baseline and dev-tool rules: Claude Code,
  Codex, gh, git, apt, npm, uv, pip, cargo, go, podman, helm, kubectl, the bar) exist only in
  Python form.
- **What should change**: a GitHub release workflow builds a static snitchd for amd64 on a tag
  and publishes it with a sha256. The VM repo gets a snitchd task (a `snitchd_enabled` switch,
  version and sha256 pinned in group_data, binary installed to `/usr/local/sbin`, the two units
  installed and enabled, `/etc/snitch/rules.toml` deployed from a repo file, `/var/lib/snitch`
  and `/run/snitch` created by systemd), so the daemon runs from boot in monitor mode. A rules
  file for this VM translated from the Python baseline and dev tools where the destination is
  an address or a local-network rule; the domain-only rules are listed as deferred to the DNS
  tap spec; the gaps are filled by a learning run. The READMEs of both repos say how to deploy
  and how to run a trial. Verification on the dev VM: after the deploy the service is active,
  `snitchd status` exits 0, a curl event shows a rule, and a 2-minute trial through
  `snitchd trial` passes with the operator's go and the serial console open.

## Introduction

snitchd works and its trial flow is proven, but it only exists as a binary built by hand into
`/tmp`. Nothing watches egress on the dev VM today, since Little Snitch is already switched off
there. This feature makes snitchd a deployed service the same way everything else on the VM is
deployed: a tagged release with a checksum, a task in the VM repo pinned to that release, a rules
file in the repo, and a verified first deploy that ends with a real trial. Two repositories are
involved; this spec lives in snitch and owns both halves.

## Boundary Context

- **In scope**: the release (build on a tag, checksum published); the VM repo task (switch,
  pinned version and checksum, binary, units, rules file, enabled service in monitor mode) and
  the switch's off state; the rules file for this VM translated from the Python client's
  baseline and dev-tool rules where the destination is an address or the local network; a
  learning run to fill the gaps; documentation in both repos; verification on the dev VM
  including a two-minute trial.
- **Out of scope**: rules by domain name (the DNS tap spec; the domain-only rules are listed
  as deferred, not silently dropped); fleet hosts beyond the dev VM (the task must not prevent
  them: one base rules file, per-host overlays later); the Nix flake; removing Little Snitch's
  packages or the Python client from the VM (they stay installed and off); changes to the
  daemon, the verbs or the units beyond what deployment reveals.
- **Adjacent expectations**: the VM repo's deploy flow (pyinfra, local deploy as root via
  sudo, releases pinned by sha256 in group data) is the vehicle; the daemon's own fail-safes
  and the trial flow are relied on, not changed; the serial console is the way back.

## Requirements

### Requirement 1: A release to pin
**Objective:** As the operator, I want snitchd published as a versioned, checksummed artifact,
so that hosts install a known binary and not whatever was built last.

#### Acceptance Criteria
1. When a version tag is pushed to the snitch repository, the release workflow shall build
   snitchd for 64-bit x86 Linux as a static binary without needing a C compiler at build time,
   and shall publish the binary and its sha256 as release assets under that tag.
2. The release shall carry the version in the binary (`snitchd -version` prints the tag), so
   that `snitchd status` and the journal can say which build is running.
3. If the build or the tests fail, the workflow shall publish nothing.
4. The release workflow shall run the same checks as the lint workflow before building, so a
   release never bypasses them.

### Requirement 2: Deployed by the VM repo
**Objective:** As the operator, I want snitchd installed and enabled by the same deploy I use for
everything else on the VM, so that a fresh VM gets it and an existing one is updated by changing
two pinned values.

#### Acceptance Criteria
1. The VM repo shall gain a `snitchd_enabled` switch and pinned `snitchd_version` and
   `snitchd_sha256` values in its group data, in the naming style of its other pins (the
   Python client's `snitch_*` values were retired on 2026-10-11 in commit 9e7bf65 of that repo).
2. While `snitchd_enabled` is true, when the deploy runs, the task shall download the pinned
   release, verify its checksum before installing, install the binary to `/usr/local/sbin`,
   install the two unit files, deploy the rules file to `/etc/snitch/rules.toml`, enable the
   boot-revert unit (never start it: it would end a live trial), and enable and start the
   service.
3. If the checksum does not match, the task shall fail before replacing anything on the host
   and shall say which checksum it saw.
4. When the pinned version changes and the deploy runs, the task shall install the new binary
   and restart the service, and the service shall come back in monitor mode (or kept enforce,
   if that was recorded) within 5 seconds.
5. While `snitchd_enabled` is false, when the deploy runs, the task shall stop and disable the
   service and the boot-revert unit and shall leave the binary, the rules and the state files in
   place, so that enabling again needs no download.
6. When the rules file in the repo changes and the deploy runs, the task shall replace
   `/etc/snitch/rules.toml` and the running daemon shall pick it up without a restart (its own
   reload), visible as a new summary line in the journal within 5 seconds.
7. The task shall never pass a mode flag or a duration to the service and shall never touch the
   kill switch, the trial file or the kept-enforce file.
8. The deploy shall be idempotent: a second run with nothing changed shall report no changes.

### Requirement 3: Rules for this VM
**Objective:** As the operator, I want the rules I already trust from the Python client to be the
daemon's rules, so that the first trial on this VM is about the rules I know, not about guessing.

#### Acceptance Criteria
1. The VM repo shall carry the rules file for this VM, deployed to `/etc/snitch/rules.toml`,
   and the file shall load in the daemon's parser (checked in the VM repo's CI with the pinned
   snitchd binary or its parser, so a broken rules file never reaches a host).
2. The rules file shall contain every baseline and dev-tool rule of the Python client whose
   destination is an address, an address range, any destination (the whole address space:
   hypr-rdp, DNS, DHCP, time sync, apt) or the local network, with the same programs (paths and
   globs) and a note saying where each rule came from; local-network rules need no entry
   because the local network is allowed inside the BPF program, but their programs are declared.
3. For each Python rule whose destination is a domain name, the rules file shall contain a
   comment naming the program and the domains, marked as deferred to the DNS tap spec, so the
   list of what is missing is visible in the file itself.
4. The Claude Code program (the session tooling) shall be allowed to the Anthropic address
   ranges the Python client already lists, and the rules file shall say that a trial without
   this rule cuts the operator's own session.
5. After the service runs in monitor mode for at least one working day on this VM, a learning
   run shall produce a learned file, and the operator shall review it; the rules that are
   wanted are merged into the repo's rules file in a follow-up commit; the learned file itself
   shall not be deployed.
6. Programs that the Python client deliberately left out (general-purpose tools such as curl)
   shall stay out, so that they are reported and later asked about rather than allowed.

### Requirement 4: Documentation in both repositories
**Objective:** As the operator, I want each repo to say its part, so that a year from now the
deploy and the trial can be repeated without this conversation.

#### Acceptance Criteria
1. The snitch README shall describe the release (how a tag becomes a release, what the assets
   are) and shall point at the VM repo for deployment.
2. The VM repo README shall describe the snitchd task: the switch, the pinned values, where
   the rules file lives, how to update the version, how to run a trial (`snitchd trial`,
   `status`, `end`, the serial console as the way back) and how to turn the daemon off.
3. The VM repo's README line saying snitchd replaces Little Snitch "once it ships" shall say
   that snitchd now watches egress and how it is switched, and the task table shall list the
   snitchd task.

### Requirement 5: Verified on the dev VM
**Objective:** As the operator, I want the first deploy proven step by step, so that the service
is trusted before it runs unattended.

#### Acceptance Criteria
1. When the task has run on the dev VM with the switch on, the service shall be active, the
   boot-revert unit enabled, `snitchd status` shall exit 0 with mode monitor and the rules
   summary from the deployed file, and the journal shall show the startup lines.
2. When a program with a rule connects (`apt-get update`: the apt methods have an
   any-destination rule), the journal shall show an event attributed to that rule; when a
   program without a rule connects (curl to an address no rule covers), the journal shall show
   a monitor event.
3. When the operator reboots the dev VM once after the deploy, the service shall be active
   again in monitor mode with no trial recorded, and the operator's RDP session shall come back.
4. With the operator's go and the serial console open, a two-minute trial started with
   `snitchd trial` shall deny a connection no rule allows, keep the operator's session alive,
   and end by itself in monitor mode; the journal shall show the start and end lines.
5. The deployed state after all checks shall be: service active, monitor, no trial, nothing
   kept, kill switch clear, recorded in the spec's research log.
6. If any check fails, the operator shall be able to turn the daemon off with the switch and a
   deploy, or from the console with `scripts/fail-open.sh`, and the failure shall be recorded
   before anything is fixed.
